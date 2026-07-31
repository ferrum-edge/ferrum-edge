//! Native SMTP / email notification channel.
//!
//! Delivers a [`Notification`] as a plain-text UTF-8 email through an operator
//! configured SMTP relay. Two TLS postures are supported and one of them is
//! always used:
//!
//! - `starttls` (default): plaintext TCP connect, `EHLO`, `STARTTLS`, then the
//!   whole session restarts inside TLS.
//! - `implicit_tls`: TLS handshake immediately after TCP connect (SMTPS, 465).
//!
//! Plaintext SMTP is intentionally not offered. This channel transmits operator
//! credentials and alert bodies that routinely name internal proxies and
//! upstreams, so there is no downgrade path: a relay that does not advertise
//! `STARTTLS` fails the send instead of continuing in the clear, and `AUTH` is
//! structurally unreachable before a completed handshake (the authenticated
//! phase only accepts a [`TlsEstablished`] token minted at handshake
//! completion).
//!
//! Certificate verification is likewise always on. Unlike the log-shipping
//! sinks, this channel deliberately does **not** honor `FERRUM_TLS_NO_VERIFY`:
//! a skipped verification here hands the SMTP password to whatever answers the
//! TCP connect. Custom trust anchors go through the ordinary gateway
//! conventions instead (`FERRUM_TLS_CA_BUNDLE_PATH`, plus
//! `FERRUM_TLS_CRL_FILE_PATH` revocation).
//!
//! Everything crossing the wire is bounded: recipient count, address length,
//! template length, rendered subject/body size, per-phase timeouts, SMTP reply
//! line length, reply line count, and total reply bytes. Delivery errors are
//! structured ([`SmtpFailure`]) and carry a phase plus a numeric SMTP reply
//! code only — never server text, never credentials.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use rustls::pki_types::{CertificateRevocationListDer, ServerName};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::{OnceCell, Semaphore};
use tokio_rustls::TlsConnector;

use crate::plugins::utils::http_client::PluginHttpClient;
use crate::plugins::utils::{parse_socket_host, resolve_tcp_endpoint};

use super::super::notification::{Notification, NotificationField};
use super::super::templating::{render_template_bounded, validate_template};
use super::webhook::base_vars;
use super::{EnvVarLookup, resolve_optional_string_with_lookup};

/// Static plugin/subsystem label used for DNS-resolution diagnostics.
const CHANNEL_LABEL: &str = "notification_email";

/// Fan-out bound for one channel. `proxy_alerts` already applies a global
/// `max_concurrent_dispatches` budget, but an SMTP session is far longer-lived
/// than a webhook POST, so each email channel additionally caps how many
/// sessions it will hold open at once. Exhaustion fails the send immediately
/// (visible `warn!` from the caller) rather than queueing — same philosophy as
/// the dispatch semaphore.
const MAX_CONCURRENT_SESSIONS: usize = 4;

/// Recipients per channel. An alert channel is an operator distribution list,
/// not a mailing system; 32 is generous and keeps `RCPT TO` rounds bounded.
const MAX_RECIPIENTS: usize = 32;

/// RFC 5321 §4.5.3.1.3 caps a forward/reverse path at 256 octets including the
/// angle brackets, so the bare address is bounded at 254.
const MAX_ADDRESS_BYTES: usize = 254;
const MAX_LOCAL_PART_BYTES: usize = 64;
const MAX_DOMAIN_BYTES: usize = 255;

/// Operator-supplied template bounds, checked at construction.
const MAX_SUBJECT_TEMPLATE_BYTES: usize = 1024;
const MAX_BODY_TEMPLATE_BYTES: usize = 64 * 1024;

/// Rendered-output bounds, enforced during template substitution (not only
/// after). Templates can reference caller-supplied variables and repeat them,
/// so the rendered size is not implied by the template size. Oversized output
/// is truncated with a visible marker rather than dropping the alert.
const MAX_SUBJECT_BYTES: usize = 512;
const MAX_BODY_BYTES: usize = 32 * 1024;
/// Hard cap on the generated `${fields}` block — names, values, separators,
/// and the truncation marker all count. A caller with many or huge
/// notification fields cannot inflate retained message data past this ceiling.
const MAX_FIELDS_BLOCK_BYTES: usize = 8 * 1024;
const MAX_FIELD_VALUE_BYTES: usize = 512;

/// RFC 5321 §4.5.3.1.5 caps a reply line at 512 octets. Accept a little slack
/// for real-world ESMTP banners, then fail closed.
const MAX_REPLY_LINE_BYTES: usize = 1024;
const MAX_REPLY_LINES: usize = 64;
const MAX_REPLY_TOTAL_BYTES: usize = 16 * 1024;

/// RFC 5322 §2.1.1 line limit; header folding targets this.
const MAX_HEADER_LINE_BYTES: usize = 900;

const MIN_TIMEOUT_MS: u64 = 100;
const MAX_CONNECT_TIMEOUT_MS: u64 = 60_000;
const MAX_COMMAND_TIMEOUT_MS: u64 = 120_000;
const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 5_000;
const DEFAULT_COMMAND_TIMEOUT_MS: u64 = 10_000;

const DEFAULT_SUBJECT_TEMPLATE: &str = "[${severity}] ${title}";
const DEFAULT_BODY_TEMPLATE: &str = "${body}\n\n${fields}";

/// Template variables this channel adds on top of the generic notification
/// variables exported by [`super::NOTIFICATION_TEMPLATE_VARS`].
#[allow(dead_code)] // Documented surface; consumed by docs/tests, not by main.rs.
pub const EMAIL_TEMPLATE_VARS: &[&str] = &["fields"];

/// Authoritative closed key set for a `type: email` channel definition.
/// Construction admission, `openapi.yaml`'s `ProxyAlertsEmailChannel`, and
/// `docs/notifications.md` must stay in lockstep with this list.
pub const EMAIL_CHANNEL_KEYS: &[&str] = &[
    "type",
    "smtp_host",
    "smtp_port",
    "tls_mode",
    "tls_server_name",
    "username",
    "username_env",
    "password",
    "password_env",
    "from",
    "to",
    "subject_template",
    "body_template",
    "helo_name",
    "connect_timeout_ms",
    "command_timeout_ms",
];

/// TLS posture for the SMTP session. Both variants complete a verified TLS
/// handshake before any credential or message data is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsMode {
    /// Connect in the clear, `EHLO`, then `STARTTLS` and restart the session
    /// inside TLS. Fails closed when the relay does not advertise `STARTTLS`.
    StartTls,
    /// Handshake immediately after TCP connect (SMTPS).
    ImplicitTls,
}

impl TlsMode {
    fn parse(raw: &str, channel: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().replace('-', "_").as_str() {
            "starttls" => Ok(Self::StartTls),
            "implicit_tls" => Ok(Self::ImplicitTls),
            "none" | "plaintext" | "disabled" | "insecure" => Err(format!(
                "channel '{channel}' (email): 'tls_mode' must be 'starttls' or 'implicit_tls' — \
                 plaintext SMTP is not supported because this channel carries credentials and \
                 internal topology names"
            )),
            other => Err(format!(
                "channel '{channel}' (email): unknown 'tls_mode' '{other}' (expected 'starttls' or 'implicit_tls')"
            )),
        }
    }

    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::StartTls => "starttls",
            Self::ImplicitTls => "implicit_tls",
        }
    }

    const fn default_port(&self) -> u16 {
        match self {
            Self::StartTls => 587,
            Self::ImplicitTls => 465,
        }
    }
}

/// Resolved SMTP credentials. Never `Debug`-printed, never serialized, never
/// interpolated into an error.
#[derive(Clone)]
struct SmtpCredentials {
    username: Arc<str>,
    password: Arc<str>,
}

/// Zero-sized proof that a verified TLS handshake completed on the stream about
/// to be used. Constructed only at the two handshake completion sites, and
/// required by [`deliver_authenticated`], so no refactor can move `AUTH` or the
/// message body ahead of TLS without also fabricating this token.
struct TlsEstablished;

pub struct EmailChannel {
    name: Arc<str>,
    smtp_host: Arc<str>,
    /// `Some` when `smtp_host` is a DNS name (warmup/preflight target). `None`
    /// for IP literals.
    warmup_hostname: Option<Arc<str>>,
    smtp_port: u16,
    tls_mode: TlsMode,
    /// Verified identity for the handshake. Defaults to `smtp_host`.
    tls_server_name: ServerName<'static>,
    tls_server_name_display: Arc<str>,
    credentials: Option<SmtpCredentials>,
    from: Arc<str>,
    to: Arc<[Arc<str>]>,
    subject_template: Arc<str>,
    body_template: Arc<str>,
    helo_name: Arc<str>,
    connect_timeout: Duration,
    command_timeout: Duration,
    /// Built lazily on first dispatch (the CA-bundle read is filesystem I/O and
    /// runs on `spawn_blocking`), then reused for the channel's lifetime.
    tls_config: Arc<OnceCell<Arc<rustls::ClientConfig>>>,
    sessions: Arc<Semaphore>,
}

impl Clone for EmailChannel {
    fn clone(&self) -> Self {
        Self {
            name: Arc::clone(&self.name),
            smtp_host: Arc::clone(&self.smtp_host),
            warmup_hostname: self.warmup_hostname.clone(),
            smtp_port: self.smtp_port,
            tls_mode: self.tls_mode,
            tls_server_name: self.tls_server_name.clone(),
            tls_server_name_display: Arc::clone(&self.tls_server_name_display),
            credentials: self.credentials.clone(),
            from: Arc::clone(&self.from),
            to: Arc::clone(&self.to),
            subject_template: Arc::clone(&self.subject_template),
            body_template: Arc::clone(&self.body_template),
            helo_name: Arc::clone(&self.helo_name),
            connect_timeout: self.connect_timeout,
            command_timeout: self.command_timeout,
            tls_config: Arc::clone(&self.tls_config),
            sessions: Arc::clone(&self.sessions),
        }
    }
}

/// Hand-written so credentials can never reach a log line, a panic message, or
/// a `#[derive(Debug)]` dump of the enclosing channel map.
impl fmt::Debug for EmailChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EmailChannel")
            .field("name", &self.name)
            .field("smtp_host", &self.smtp_host)
            .field("smtp_port", &self.smtp_port)
            .field("tls_mode", &self.tls_mode.as_str())
            .field("tls_server_name", &self.tls_server_name_display)
            .field("from", &self.from)
            .field("recipients", &self.to.len())
            .field("authenticated", &self.credentials.is_some())
            .finish()
    }
}

#[allow(dead_code)] // Accessors are part of the reusable channel surface.
impl EmailChannel {
    pub fn new(name: &str, value: &Value) -> Result<Self, String> {
        Self::new_with_env_lookup(name, value, &|name| std::env::var(name))
    }

    pub(crate) fn new_with_env_lookup(
        name: &str,
        value: &Value,
        env_lookup: EnvVarLookup<'_>,
    ) -> Result<Self, String> {
        let raw_host = value
            .get("smtp_host")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| format!("channel '{name}' (email): 'smtp_host' is required"))?;
        let socket_host =
            parse_socket_host(&format!("channel '{name}' (email)"), "smtp_host", raw_host)?;

        let tls_mode = match value.get("tls_mode") {
            Some(v) => {
                let raw = v.as_str().ok_or_else(|| {
                    format!("channel '{name}' (email): 'tls_mode' must be a string")
                })?;
                TlsMode::parse(raw, name)?
            }
            None => TlsMode::StartTls,
        };

        let smtp_port = match value.get("smtp_port") {
            Some(v) => {
                let port = v.as_u64().ok_or_else(|| {
                    format!("channel '{name}' (email): 'smtp_port' must be an integer")
                })?;
                if port == 0 || port > 65535 {
                    return Err(format!(
                        "channel '{name}' (email): 'smtp_port' must be between 1 and 65535 (got {port})"
                    ));
                }
                port as u16
            }
            None => tls_mode.default_port(),
        };

        let tls_server_name_display = match value.get("tls_server_name") {
            Some(v) => {
                let raw = v
                    .as_str()
                    .ok_or_else(|| {
                        format!("channel '{name}' (email): 'tls_server_name' must be a string")
                    })?
                    .trim();
                if raw.is_empty() {
                    return Err(format!(
                        "channel '{name}' (email): 'tls_server_name' must not be empty"
                    ));
                }
                raw.to_string()
            }
            None => socket_host.dial_host.clone(),
        };
        let tls_server_name = ServerName::try_from(tls_server_name_display.clone()).map_err(|e| {
            format!(
                "channel '{name}' (email): invalid TLS server name '{tls_server_name_display}': {e}"
            )
        })?;

        let username = resolve_optional_string_with_lookup(
            value,
            "username",
            "username_env",
            name,
            env_lookup,
        )?;
        let password = resolve_optional_string_with_lookup(
            value,
            "password",
            "password_env",
            name,
            env_lookup,
        )?;
        let credentials = match (username, password) {
            (Some(username), Some(password)) => {
                validate_credential_component(&username, "username", name)?;
                validate_credential_component(&password, "password", name)?;
                Some(SmtpCredentials {
                    username: Arc::from(username),
                    password: Arc::from(password),
                })
            }
            (Some(_), None) => {
                return Err(format!(
                    "channel '{name}' (email): 'username' is set without a password — supply 'password' or 'password_env'"
                ));
            }
            (None, Some(_)) => {
                return Err(format!(
                    "channel '{name}' (email): a password is set without 'username' or 'username_env'"
                ));
            }
            (None, None) => None,
        };

        let from = value
            .get("from")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| format!("channel '{name}' (email): 'from' is required"))?
            .to_string();
        validate_email_address(&from, "from", name)?;

        let to_values = value.get("to").and_then(Value::as_array).ok_or_else(|| {
            format!("channel '{name}' (email): 'to' is required and must be an array of addresses")
        })?;
        if to_values.is_empty() {
            return Err(format!(
                "channel '{name}' (email): 'to' must contain at least one recipient"
            ));
        }
        if to_values.len() > MAX_RECIPIENTS {
            return Err(format!(
                "channel '{name}' (email): 'to' must contain at most {MAX_RECIPIENTS} recipients (got {})",
                to_values.len()
            ));
        }
        let mut to: Vec<Arc<str>> = Vec::with_capacity(to_values.len());
        for entry in to_values {
            let address = entry
                .as_str()
                .ok_or_else(|| format!("channel '{name}' (email): 'to' entries must be strings"))?
                .trim();
            validate_email_address(address, "to", name)?;
            if to.iter().any(|existing| existing.as_ref() == address) {
                continue;
            }
            to.push(Arc::from(address));
        }

        let subject_template = optional_template(
            value,
            "subject_template",
            DEFAULT_SUBJECT_TEMPLATE,
            MAX_SUBJECT_TEMPLATE_BYTES,
            name,
        )?;
        let body_template = optional_template(
            value,
            "body_template",
            DEFAULT_BODY_TEMPLATE,
            MAX_BODY_TEMPLATE_BYTES,
            name,
        )?;

        // EHLO identity. Defaults to the sender's domain, which is a valid FQDN
        // that relays accept far more often than an invented label.
        let helo_name = match value.get("helo_name") {
            Some(v) => {
                let raw = v
                    .as_str()
                    .ok_or_else(|| {
                        format!("channel '{name}' (email): 'helo_name' must be a string")
                    })?
                    .trim()
                    .to_string();
                validate_helo_name(&raw, name)?;
                raw
            }
            None => from
                .rsplit('@')
                .next()
                .unwrap_or_default()
                .to_ascii_lowercase(),
        };

        let connect_timeout_ms = bounded_timeout_ms(
            value,
            "connect_timeout_ms",
            DEFAULT_CONNECT_TIMEOUT_MS,
            MAX_CONNECT_TIMEOUT_MS,
            name,
        )?;
        let command_timeout_ms = bounded_timeout_ms(
            value,
            "command_timeout_ms",
            DEFAULT_COMMAND_TIMEOUT_MS,
            MAX_COMMAND_TIMEOUT_MS,
            name,
        )?;

        Ok(Self {
            name: Arc::from(name),
            smtp_host: Arc::from(socket_host.dial_host.as_str()),
            warmup_hostname: socket_host.warmup_hostname.as_deref().map(Arc::from),
            smtp_port,
            tls_mode,
            tls_server_name,
            tls_server_name_display: Arc::from(tls_server_name_display),
            credentials,
            from: Arc::from(from),
            to: Arc::from(to),
            subject_template: Arc::from(subject_template),
            body_template: Arc::from(body_template),
            helo_name: Arc::from(helo_name),
            connect_timeout: Duration::from_millis(connect_timeout_ms),
            command_timeout: Duration::from_millis(command_timeout_ms),
            tls_config: Arc::new(OnceCell::new()),
            sessions: Arc::new(Semaphore::new(MAX_CONCURRENT_SESSIONS)),
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn smtp_host(&self) -> &str {
        &self.smtp_host
    }

    pub fn smtp_port(&self) -> u16 {
        self.smtp_port
    }

    pub fn tls_mode(&self) -> TlsMode {
        self.tls_mode
    }

    pub fn tls_server_name(&self) -> &str {
        &self.tls_server_name_display
    }

    pub fn from(&self) -> &str {
        &self.from
    }

    pub fn recipients(&self) -> &[Arc<str>] {
        &self.to
    }

    pub fn helo_name(&self) -> &str {
        &self.helo_name
    }

    pub fn subject_template(&self) -> &str {
        &self.subject_template
    }

    pub fn body_template(&self) -> &str {
        &self.body_template
    }

    pub fn has_credentials(&self) -> bool {
        self.credentials.is_some()
    }

    /// Hostnames to pre-resolve during startup warmup/preflight. IP-literal
    /// hosts return nothing; credentials are never part of this surface because
    /// the SMTP endpoint is a bare host, not a credential-bearing URL.
    pub fn warmup_hostnames(&self) -> Vec<String> {
        self.warmup_hostname
            .as_deref()
            .map(|host| vec![host.to_string()])
            .unwrap_or_default()
    }

    /// Render the subject line from the notification plus caller extras.
    /// Control characters are folded to spaces before anything reaches a
    /// header, so a templated value can never inject an extra header.
    ///
    /// The 512-byte ceiling is enforced during substitution so a template that
    /// repeats a large value cannot allocate far beyond the advertised limit.
    pub fn render_subject(
        &self,
        notification: &Notification,
        extras: &HashMap<String, String>,
    ) -> Result<String, String> {
        let vars = self.template_vars(notification, extras);
        let rendered =
            render_template_bounded(&self.subject_template, &vars, MAX_SUBJECT_BYTES, "...")?;
        // Sanitization only shrinks or preserves length (controls → equal-width
        // spaces; trim may drop edges). Re-apply the ceiling so the advertised
        // bound remains absolute if that ever changes.
        Ok(truncate_utf8(
            &sanitize_header_text(&rendered),
            MAX_SUBJECT_BYTES,
            "...",
        ))
    }

    /// Render the message body from the notification plus caller extras.
    ///
    /// The 32 KiB ceiling is enforced during substitution so a template that
    /// repeats a large value cannot allocate far beyond the advertised limit.
    pub fn render_body(
        &self,
        notification: &Notification,
        extras: &HashMap<String, String>,
    ) -> Result<String, String> {
        let vars = self.template_vars(notification, extras);
        let rendered =
            render_template_bounded(&self.body_template, &vars, MAX_BODY_BYTES, "\n[truncated]")?;
        Ok(truncate_utf8(
            &sanitize_body_text(&rendered),
            MAX_BODY_BYTES,
            "\n[truncated]",
        ))
    }

    /// Build the complete `DATA` payload (headers + base64 body), CRLF-normalized
    /// and dot-stuffed, without the terminating `.` line.
    pub fn build_message(
        &self,
        notification: &Notification,
        extras: &HashMap<String, String>,
    ) -> Result<Vec<u8>, String> {
        let subject = self.render_subject(notification, extras)?;
        let body = self.render_body(notification, extras)?;

        let mut headers = String::new();
        headers.push_str("Date: ");
        headers.push_str(&notification.fired_at.to_rfc2822());
        headers.push('\n');
        headers.push_str("From: <");
        headers.push_str(&self.from);
        headers.push_str(">\n");
        headers.push_str(&fold_header("To", &address_list(&self.to)));
        headers.push_str("Subject: ");
        headers.push_str(&encode_subject(&subject));
        headers.push('\n');
        headers.push_str("Message-ID: <");
        headers.push_str(&uuid::Uuid::new_v4().to_string());
        headers.push('@');
        headers.push_str(&self.helo_name);
        headers.push_str(">\n");
        headers.push_str("MIME-Version: 1.0\n");
        headers.push_str("Content-Type: text/plain; charset=\"utf-8\"\n");
        headers.push_str("Content-Transfer-Encoding: base64\n");
        headers.push_str("Auto-Submitted: auto-generated\n");
        // Enum-derived static strings — no operator or caller input reaches these.
        headers.push_str("X-Ferrum-Notification-Severity: ");
        headers.push_str(notification.severity.as_str());
        headers.push('\n');
        headers.push_str("X-Ferrum-Notification-Event-Action: ");
        headers.push_str(notification.event_action.as_str());
        headers.push_str("\n\n");
        headers.push_str(&base64_body(&body));

        Ok(encode_data_payload(&headers))
    }

    fn template_vars(
        &self,
        notification: &Notification,
        extras: &HashMap<String, String>,
    ) -> HashMap<String, String> {
        let mut vars = extras.clone();
        // Generic notification variables win on collision so a caller cannot
        // shadow `${title}` / `${severity}`; matches the webhook channel.
        vars.extend(base_vars(notification));
        vars.insert("fields".to_string(), render_fields(notification));
        vars
    }

    pub async fn dispatch(
        &self,
        notification: &Notification,
        http: &PluginHttpClient,
    ) -> Result<(), String> {
        let extras: HashMap<String, String> = HashMap::new();
        self.dispatch_with_vars(notification, &extras, http).await
    }

    pub async fn dispatch_with_vars(
        &self,
        notification: &Notification,
        extras: &HashMap<String, String>,
        http: &PluginHttpClient,
    ) -> Result<(), String> {
        match self.dispatch_classified(notification, extras, http).await {
            crate::notifications::outcome::DeliveryAttempt::Success => Ok(()),
            crate::notifications::outcome::DeliveryAttempt::Failed { message, .. } => Err(message),
        }
    }

    /// Classified SMTP dispatch for the retrying delivery runner.
    pub async fn dispatch_classified(
        &self,
        notification: &Notification,
        extras: &HashMap<String, String>,
        http: &PluginHttpClient,
    ) -> crate::notifications::outcome::DeliveryAttempt {
        use crate::notifications::outcome::{DeliveryAttempt, FailureClass, classify_smtp_failure};
        let message = match self.build_message(notification, extras) {
            Ok(m) => m,
            Err(e) => {
                return DeliveryAttempt::failed(FailureClass::Permanent, e);
            }
        };
        let _permit = match Arc::clone(&self.sessions).try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                return DeliveryAttempt::failed(
                    FailureClass::Transient,
                    format!(
                        "email dispatch to {} skipped: channel already has {MAX_CONCURRENT_SESSIONS} SMTP sessions in flight",
                        self.endpoint_label()
                    ),
                );
            }
        };
        match self.send(&message, http).await {
            Ok(()) => DeliveryAttempt::Success,
            Err(failure) => {
                let class = classify_smtp_failure(&failure);
                DeliveryAttempt::failed(
                    class,
                    format!("email dispatch to {} {failure}", self.endpoint_label()),
                )
            }
        }
    }

    /// `host:port` — the only endpoint detail that appears in errors/logs.
    fn endpoint_label(&self) -> String {
        format!("{}:{}", self.smtp_host, self.smtp_port)
    }

    async fn send(&self, message: &[u8], http: &PluginHttpClient) -> Result<(), SmtpFailure> {
        let connector = self.tls_connector(http).await?;
        let guard = CredentialGuard::new(self.credentials.as_ref());

        let addr = tokio::time::timeout(
            self.connect_timeout,
            resolve_tcp_endpoint(
                &self.smtp_host,
                self.smtp_port,
                http.dns_cache(),
                CHANNEL_LABEL,
            ),
        )
        .await
        .map_err(|_| SmtpFailure::Timeout(SmtpPhase::Resolve))?
        .map_err(|_| SmtpFailure::Resolve)?;

        // Screen the *resolved* address, so a hostname that resolves into a
        // denied range (link-local metadata services, loopback in a locked-down
        // deployment) is refused just like a literal would be.
        if let Some(reason) = http.backend_allow_ips().deny_reason(&addr.ip()) {
            return Err(SmtpFailure::EgressDenied(reason));
        }

        let tcp = tokio::time::timeout(self.connect_timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| SmtpFailure::Timeout(SmtpPhase::Connect))?
            .map_err(|_| SmtpFailure::Connect)?;

        match self.tls_mode {
            TlsMode::ImplicitTls => {
                let tls = tokio::time::timeout(
                    self.connect_timeout,
                    connector.connect(self.tls_server_name.clone(), tcp),
                )
                .await
                .map_err(|_| SmtpFailure::Timeout(SmtpPhase::TlsHandshake))?
                .map_err(|_| SmtpFailure::TlsHandshake)?;
                let established = TlsEstablished;
                let mut conn = SmtpConn::new(tls, self.command_timeout, guard);
                conn.read_greeting().await?;
                let result = self
                    .deliver_authenticated(&mut conn, message, established)
                    .await;
                conn.quit().await;
                result
            }
            TlsMode::StartTls => {
                let mut plain = SmtpConn::new(tcp, self.command_timeout, guard.clone());
                plain.read_greeting().await?;
                let caps = plain.ehlo(&self.helo_name).await?;
                if !caps.starttls {
                    // Fail closed: no downgrade to cleartext delivery.
                    return Err(SmtpFailure::StartTlsUnsupported);
                }
                plain
                    .command("STARTTLS", SmtpPhase::StartTls, &[220])
                    .await?;
                // RFC 3207 §6: anything the peer pipelined ahead of the TLS
                // handshake is discarded by the protocol, so buffered bytes here
                // mean an injection attempt (or a broken relay). Refuse rather
                // than carry pre-TLS state across the boundary.
                let tcp = plain.into_inner_no_residual()?;
                let tls = tokio::time::timeout(
                    self.connect_timeout,
                    connector.connect(self.tls_server_name.clone(), tcp),
                )
                .await
                .map_err(|_| SmtpFailure::Timeout(SmtpPhase::TlsHandshake))?
                .map_err(|_| SmtpFailure::TlsHandshake)?;
                let established = TlsEstablished;
                let mut conn = SmtpConn::new(tls, self.command_timeout, guard);
                let result = self
                    .deliver_authenticated(&mut conn, message, established)
                    .await;
                conn.quit().await;
                result
            }
        }
    }

    /// Everything that touches credentials or message content. Reachable only
    /// with a [`TlsEstablished`] token, i.e. only inside a verified TLS session.
    async fn deliver_authenticated<S>(
        &self,
        conn: &mut SmtpConn<S>,
        message: &[u8],
        _tls: TlsEstablished,
    ) -> Result<(), SmtpFailure>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        // Post-handshake EHLO. Capabilities advertised before STARTTLS are
        // discarded per RFC 3207 §4.2 — only this reply is trusted.
        let caps = conn.ehlo(&self.helo_name).await?;

        if let Some(credentials) = self.credentials.as_ref() {
            conn.authenticate(credentials, &caps).await?;
        }

        conn.command(
            &format!("MAIL FROM:<{}>", self.from),
            SmtpPhase::MailFrom,
            &[250],
        )
        .await?;
        for recipient in self.to.iter() {
            conn.command(
                &format!("RCPT TO:<{recipient}>"),
                SmtpPhase::RcptTo,
                &[250, 251],
            )
            .await?;
        }
        conn.command("DATA", SmtpPhase::Data, &[354]).await?;
        conn.write_message(message).await?;
        conn.expect_reply(SmtpPhase::DataEnd, &[250]).await?;
        Ok(())
    }

    /// Build (once) the rustls client config for this channel.
    ///
    /// The CA-bundle read and PEM parse are filesystem work, so they run on
    /// `spawn_blocking`; the resulting `Arc<ClientConfig>` is cached in a
    /// `OnceCell` and shared by every later dispatch.
    async fn tls_connector(&self, http: &PluginHttpClient) -> Result<TlsConnector, SmtpFailure> {
        let ca_bundle_path = http.tls_ca_bundle_path().map(str::to_string);
        let crls: Vec<CertificateRevocationListDer<'static>> = http.tls_crls().to_vec();
        let config = self
            .tls_config
            .get_or_try_init(move || async move {
                tokio::task::spawn_blocking(move || build_client_config(ca_bundle_path, crls))
                    .await
                    .map_err(|_| SmtpFailure::TlsSetup)?
            })
            .await?;
        Ok(TlsConnector::from(Arc::clone(config)))
    }
}

/// Build an always-verifying rustls client config.
///
/// `FERRUM_TLS_NO_VERIFY` is deliberately not consulted here — see the module
/// docs. `FERRUM_TLS_CA_BUNDLE_PATH` replaces the webpki roots when set, and
/// `FERRUM_TLS_CRL_FILE_PATH` revocation applies via the shared verifier
/// builder, matching the proxy backend / DTLS / frontend mTLS surfaces.
fn build_client_config(
    ca_bundle_path: Option<String>,
    crls: Vec<CertificateRevocationListDer<'static>>,
) -> Result<Arc<rustls::ClientConfig>, SmtpFailure> {
    let root_store = match ca_bundle_path.as_deref() {
        Some(path) => {
            let source = crate::tls::source::CertSource::parse(
                path,
                crate::tls::source::MaterialKind::CaBundle,
            );
            let material = crate::tls::source::load_material_blocking(
                &source,
                crate::tls::source::MaterialKind::CaBundle,
            )
            .map_err(|_| SmtpFailure::TlsSetup)?;
            crate::tls::root_cert_store_from_pem_bundle(
                material.bytes.expose_secret(),
                "email notification CA bundle",
                &material.display_source_id,
            )
            .map_err(|_| SmtpFailure::TlsSetup)?
        }
        None => rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
    };

    let verifier = crate::tls::build_server_verifier_with_crls(root_store, &crls)
        .map_err(|_| SmtpFailure::TlsSetup)?;
    // Pin the ring provider explicitly so the channel does not depend on a
    // globally installed default (unit tests build channels without startup).
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| SmtpFailure::TlsSetup)?
    .with_webpki_verifier(verifier)
    .with_no_client_auth();
    Ok(Arc::new(config))
}

// ---------------------------------------------------------------------------
// SMTP session
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmtpPhase {
    Resolve,
    Connect,
    Greeting,
    Ehlo,
    StartTls,
    TlsHandshake,
    Auth,
    MailFrom,
    RcptTo,
    Data,
    DataEnd,
}

impl SmtpPhase {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Resolve => "dns resolution",
            Self::Connect => "tcp connect",
            Self::Greeting => "server greeting",
            Self::Ehlo => "EHLO",
            Self::StartTls => "STARTTLS",
            Self::TlsHandshake => "TLS handshake",
            Self::Auth => "authentication",
            Self::MailFrom => "MAIL FROM",
            Self::RcptTo => "RCPT TO",
            Self::Data => "DATA",
            Self::DataEnd => "message body",
        }
    }
}

/// Structured, pre-sanitized delivery failure.
///
/// Every variant is safe to log: server reply *text* is never carried, only the
/// numeric reply code, and credentials never appear in any variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SmtpFailure {
    Resolve,
    Connect,
    EgressDenied(&'static str),
    TlsSetup,
    TlsHandshake,
    StartTlsUnsupported,
    StartTlsResidualData,
    Timeout(SmtpPhase),
    Io(SmtpPhase),
    ClosedEarly(SmtpPhase),
    MalformedReply(SmtpPhase),
    ReplyTooLarge(SmtpPhase),
    UnexpectedCode { phase: SmtpPhase, code: u16 },
    CredentialReflected(SmtpPhase),
    NoSupportedAuthMechanism,
}

impl fmt::Display for SmtpFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Resolve => write!(f, "failed: DNS resolution failed"),
            Self::Connect => write!(f, "failed: TCP connect failed"),
            Self::EgressDenied(reason) => write!(
                f,
                "refused: address is blocked by the backend egress policy ({reason})"
            ),
            Self::TlsSetup => write!(
                f,
                "failed: could not build the TLS client configuration (check FERRUM_TLS_CA_BUNDLE_PATH / FERRUM_TLS_CRL_FILE_PATH)"
            ),
            Self::TlsHandshake => write!(
                f,
                "failed: TLS handshake failed (certificate verification is always enforced for email channels)"
            ),
            Self::StartTlsUnsupported => write!(
                f,
                "refused: server did not advertise STARTTLS and this channel never falls back to cleartext"
            ),
            Self::StartTlsResidualData => write!(
                f,
                "refused: server sent data before the STARTTLS handshake (possible command injection)"
            ),
            Self::Timeout(phase) => write!(f, "timed out during {}", phase.as_str()),
            Self::Io(phase) => write!(f, "failed: I/O error during {}", phase.as_str()),
            Self::ClosedEarly(phase) => {
                write!(
                    f,
                    "failed: server closed the connection during {}",
                    phase.as_str()
                )
            }
            Self::MalformedReply(phase) => {
                write!(f, "failed: malformed SMTP reply during {}", phase.as_str())
            }
            Self::ReplyTooLarge(phase) => write!(
                f,
                "failed: SMTP reply exceeded the response bounds during {}",
                phase.as_str()
            ),
            Self::UnexpectedCode { phase, code } => write!(
                f,
                "failed: server replied {code} during {} (reply text withheld)",
                phase.as_str()
            ),
            Self::CredentialReflected(phase) => write!(
                f,
                "failed: server reply during {} echoed configured credential material; session aborted",
                phase.as_str()
            ),
            Self::NoSupportedAuthMechanism => write!(
                f,
                "refused: credentials are configured but the server advertised no supported AUTH mechanism (PLAIN, LOGIN)"
            ),
        }
    }
}

/// Substrings that must never appear in a server reply. Guards against a relay
/// (or a MITM that somehow got a valid certificate) echoing credentials back in
/// a banner that a future change might surface in diagnostics.
///
/// Only *secret* material is watched in its plaintext form. The AUTH username
/// deliberately is not: it is normally the mailbox address, and relays routinely
/// echo addresses back (`250 2.1.0 <sender>... Sender ok`,
/// `550 5.1.1 no such user <rcpt>`), so treating it as a leak would abort
/// ordinary deliveries whenever the username matches the envelope sender or
/// happens to appear in the relay's own banner. Its base64 form stays a needle,
/// because that is the shape it takes on the wire during `AUTH LOGIN` and
/// nothing legitimate ever echoes it.
#[derive(Clone, Default)]
struct CredentialGuard {
    needles: Arc<Vec<String>>,
}

impl CredentialGuard {
    fn new(credentials: Option<&SmtpCredentials>) -> Self {
        let mut needles = Vec::new();
        if let Some(credentials) = credentials {
            // Very short values would false-positive on ordinary banner text.
            let password = credentials.password.as_ref();
            if password.len() >= 4 {
                needles.push(password.to_string());
            }
            for raw in [credentials.username.as_ref(), credentials.password.as_ref()] {
                if raw.len() >= 4 {
                    needles.push(base64::engine::general_purpose::STANDARD.encode(raw));
                }
            }
            needles.push(plain_auth_payload(credentials));
        }
        Self {
            needles: Arc::new(needles),
        }
    }

    fn reflects(&self, text: &str) -> bool {
        self.needles
            .iter()
            .any(|needle| text.contains(needle.as_str()))
    }
}

/// One parsed SMTP reply. `lines` holds only the text portion and is never
/// surfaced in errors — it exists so `EHLO` capabilities can be parsed.
struct SmtpReply {
    code: u16,
    lines: Vec<String>,
}

#[derive(Default)]
struct EhloCapabilities {
    starttls: bool,
    auth_plain: bool,
    auth_login: bool,
}

struct SmtpConn<S> {
    stream: BufReader<S>,
    command_timeout: Duration,
    guard: CredentialGuard,
}

impl<S> SmtpConn<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    fn new(stream: S, command_timeout: Duration, guard: CredentialGuard) -> Self {
        Self {
            stream: BufReader::new(stream),
            command_timeout,
            guard,
        }
    }

    /// Unwrap the transport for a STARTTLS upgrade, refusing to proceed when
    /// the peer pipelined bytes ahead of the handshake.
    fn into_inner_no_residual(self) -> Result<S, SmtpFailure> {
        if !self.stream.buffer().is_empty() {
            return Err(SmtpFailure::StartTlsResidualData);
        }
        Ok(self.stream.into_inner())
    }

    async fn read_greeting(&mut self) -> Result<(), SmtpFailure> {
        self.expect_reply(SmtpPhase::Greeting, &[220]).await?;
        Ok(())
    }

    async fn ehlo(&mut self, helo_name: &str) -> Result<EhloCapabilities, SmtpFailure> {
        let reply = self
            .command(&format!("EHLO {helo_name}"), SmtpPhase::Ehlo, &[250])
            .await?;
        let mut caps = EhloCapabilities::default();
        for line in &reply.lines {
            let upper = line.trim().to_ascii_uppercase();
            if upper == "STARTTLS" {
                caps.starttls = true;
            } else if let Some(mechanisms) = upper.strip_prefix("AUTH") {
                // Both the space-delimited (RFC 4954) and the legacy
                // `AUTH=PLAIN` forms appear in the wild.
                for mechanism in mechanisms
                    .trim_start_matches('=')
                    .split([' ', '=', '\t'])
                    .filter(|m| !m.is_empty())
                {
                    match mechanism {
                        "PLAIN" => caps.auth_plain = true,
                        "LOGIN" => caps.auth_login = true,
                        _ => {}
                    }
                }
            }
        }
        Ok(caps)
    }

    async fn authenticate(
        &mut self,
        credentials: &SmtpCredentials,
        caps: &EhloCapabilities,
    ) -> Result<(), SmtpFailure> {
        if caps.auth_plain {
            let payload = plain_auth_payload(credentials);
            self.command(&format!("AUTH PLAIN {payload}"), SmtpPhase::Auth, &[235])
                .await?;
            return Ok(());
        }
        if caps.auth_login {
            self.command("AUTH LOGIN", SmtpPhase::Auth, &[334]).await?;
            self.command(
                &base64::engine::general_purpose::STANDARD.encode(credentials.username.as_bytes()),
                SmtpPhase::Auth,
                &[334],
            )
            .await?;
            self.command(
                &base64::engine::general_purpose::STANDARD.encode(credentials.password.as_bytes()),
                SmtpPhase::Auth,
                &[235],
            )
            .await?;
            return Ok(());
        }
        Err(SmtpFailure::NoSupportedAuthMechanism)
    }

    /// Write one command line and read its reply.
    ///
    /// The command text itself is never echoed into an error — `AUTH` payloads
    /// travel through here.
    async fn command(
        &mut self,
        command: &str,
        phase: SmtpPhase,
        expected: &[u16],
    ) -> Result<SmtpReply, SmtpFailure> {
        let mut line = Vec::with_capacity(command.len() + 2);
        line.extend_from_slice(command.as_bytes());
        line.extend_from_slice(b"\r\n");
        self.write_all(&line, phase).await?;
        self.expect_reply(phase, expected).await
    }

    async fn write_message(&mut self, message: &[u8]) -> Result<(), SmtpFailure> {
        self.write_all(message, SmtpPhase::DataEnd).await?;
        self.write_all(b"\r\n.\r\n", SmtpPhase::DataEnd).await
    }

    async fn write_all(&mut self, bytes: &[u8], phase: SmtpPhase) -> Result<(), SmtpFailure> {
        let command_timeout = self.command_timeout;
        let write = async {
            self.stream
                .write_all(bytes)
                .await
                .map_err(|_| SmtpFailure::Io(phase))?;
            self.stream
                .flush()
                .await
                .map_err(|_| SmtpFailure::Io(phase))
        };
        match tokio::time::timeout(command_timeout, write).await {
            Ok(result) => result,
            Err(_) => Err(SmtpFailure::Timeout(phase)),
        }
    }

    async fn expect_reply(
        &mut self,
        phase: SmtpPhase,
        expected: &[u16],
    ) -> Result<SmtpReply, SmtpFailure> {
        let command_timeout = self.command_timeout;
        let reply = match tokio::time::timeout(command_timeout, self.read_reply(phase)).await {
            Ok(result) => result?,
            Err(_) => return Err(SmtpFailure::Timeout(phase)),
        };
        if !expected.contains(&reply.code) {
            return Err(SmtpFailure::UnexpectedCode {
                phase,
                code: reply.code,
            });
        }
        Ok(reply)
    }

    /// Read one (possibly multiline) SMTP reply under strict bounds.
    ///
    /// Fails closed on: an oversized line, too many continuation lines, an
    /// oversized total, a non-numeric or inconsistent code, a missing
    /// separator, an early close, or a reply that echoes credential material.
    async fn read_reply(&mut self, phase: SmtpPhase) -> Result<SmtpReply, SmtpFailure> {
        let mut code: Option<u16> = None;
        let mut lines: Vec<String> = Vec::new();
        let mut total = 0usize;
        let mut raw = Vec::new();

        loop {
            if lines.len() >= MAX_REPLY_LINES {
                return Err(SmtpFailure::ReplyTooLarge(phase));
            }
            read_line_bounded(&mut self.stream, MAX_REPLY_LINE_BYTES, &mut raw, phase).await?;
            total = total.saturating_add(raw.len());
            if total > MAX_REPLY_TOTAL_BYTES {
                return Err(SmtpFailure::ReplyTooLarge(phase));
            }

            let line = std::str::from_utf8(&raw)
                .map_err(|_| SmtpFailure::MalformedReply(phase))?
                .trim_end_matches(['\r', '\n']);
            if self.guard.reflects(line) {
                return Err(SmtpFailure::CredentialReflected(phase));
            }
            // Work on bytes for the fixed-position fields: a multibyte
            // character at offset 0..4 would otherwise make `&line[..3]` /
            // `&line[4..]` a panic instead of a rejection.
            let bytes = line.as_bytes();
            if bytes.len() < 3 || !bytes[..3].iter().all(u8::is_ascii_digit) {
                return Err(SmtpFailure::MalformedReply(phase));
            }
            let line_code = u16::from(bytes[0] - b'0') * 100
                + u16::from(bytes[1] - b'0') * 10
                + u16::from(bytes[2] - b'0');
            if !(100..=599).contains(&line_code) {
                return Err(SmtpFailure::MalformedReply(phase));
            }
            let separator = bytes.get(3).copied();
            if !matches!(separator, None | Some(b' ') | Some(b'-')) {
                return Err(SmtpFailure::MalformedReply(phase));
            }
            match code {
                None => code = Some(line_code),
                // RFC 5321 §4.2.1: every line of one reply carries the same code.
                Some(existing) if existing != line_code => {
                    return Err(SmtpFailure::MalformedReply(phase));
                }
                Some(_) => {}
            }

            // Byte 3 is ASCII (checked above), so offset 4 is a char boundary.
            let text = if bytes.len() > 4 { &line[4..] } else { "" };
            lines.push(text.to_string());
            if separator != Some(b'-') {
                return Ok(SmtpReply {
                    code: line_code,
                    lines,
                });
            }
        }
    }

    /// Best-effort `QUIT`. A relay that has already accepted the message must
    /// not turn a successful delivery into an error because it hung up first.
    async fn quit(&mut self) {
        let command_timeout = self.command_timeout;
        let _ = tokio::time::timeout(command_timeout, async {
            let _ = self.stream.write_all(b"QUIT\r\n").await;
            let _ = self.stream.flush().await;
        })
        .await;
    }
}

/// Read a single `\n`-terminated line without ever buffering more than `max`
/// bytes for it.
async fn read_line_bounded<S>(
    stream: &mut BufReader<S>,
    max: usize,
    out: &mut Vec<u8>,
    phase: SmtpPhase,
) -> Result<(), SmtpFailure>
where
    S: AsyncRead + Unpin,
{
    out.clear();
    loop {
        // Copy out of the fill buffer and record how much to release before
        // touching `stream` again, so the borrow of the peeked slice ends
        // before the `consume` call.
        let (complete, consumed) = {
            let available = stream
                .fill_buf()
                .await
                .map_err(|_| SmtpFailure::Io(phase))?;
            if available.is_empty() {
                return Err(SmtpFailure::ClosedEarly(phase));
            }
            match available.iter().position(|byte| *byte == b'\n') {
                Some(index) => {
                    if out.len() + index + 1 > max {
                        return Err(SmtpFailure::ReplyTooLarge(phase));
                    }
                    out.extend_from_slice(&available[..=index]);
                    (true, index + 1)
                }
                None => {
                    let len = available.len();
                    if out.len() + len > max {
                        return Err(SmtpFailure::ReplyTooLarge(phase));
                    }
                    out.extend_from_slice(available);
                    (false, len)
                }
            }
        };
        stream.consume(consumed);
        if complete {
            return Ok(());
        }
    }
}

fn plain_auth_payload(credentials: &SmtpCredentials) -> String {
    let mut raw = Vec::with_capacity(credentials.username.len() + credentials.password.len() + 2);
    raw.push(0u8);
    raw.extend_from_slice(credentials.username.as_bytes());
    raw.push(0u8);
    raw.extend_from_slice(credentials.password.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(raw)
}

// ---------------------------------------------------------------------------
// Message construction helpers
// ---------------------------------------------------------------------------

/// Render `Notification.fields` as `Name: value` lines for `${fields}`.
///
/// Hard-capped at [`MAX_FIELDS_BLOCK_BYTES`] including arbitrarily long field
/// names, the final field that crosses the boundary, separators, and the
/// truncation marker. Never materializes an unbounded sanitized copy of a
/// name or value merely to truncate it afterward.
fn render_fields(notification: &Notification) -> String {
    const MARKER: &str = "[fields truncated]\n";
    let mut out = String::new();
    for (index, field) in notification.fields.iter().enumerate() {
        if out.len() >= MAX_FIELDS_BLOCK_BYTES {
            apply_fields_truncation_marker(&mut out, MARKER);
            break;
        }
        if !append_field_line(&mut out, field, MARKER) {
            break;
        }
        if index + 1 < notification.fields.len() && out.len() >= MAX_FIELDS_BLOCK_BYTES {
            apply_fields_truncation_marker(&mut out, MARKER);
            break;
        }
    }
    debug_assert!(out.len() <= MAX_FIELDS_BLOCK_BYTES);
    out
}

/// Append one `name: value\n` line. Returns `false` when the block was
/// truncated to stay within [`MAX_FIELDS_BLOCK_BYTES`].
fn append_field_line(out: &mut String, field: &NotificationField, marker: &str) -> bool {
    if !push_sanitized_header_bounded(out, &field.name, MAX_FIELDS_BLOCK_BYTES) {
        apply_fields_truncation_marker(out, marker);
        return false;
    }
    if !push_exact_within(out, ": ", MAX_FIELDS_BLOCK_BYTES) {
        apply_fields_truncation_marker(out, marker);
        return false;
    }
    if !push_field_value_bounded(out, &field.value) {
        apply_fields_truncation_marker(out, marker);
        return false;
    }
    if !push_exact_within(out, "\n", MAX_FIELDS_BLOCK_BYTES) {
        apply_fields_truncation_marker(out, marker);
        return false;
    }
    true
}

fn push_exact_within(out: &mut String, piece: &str, max_bytes: usize) -> bool {
    if out.len() + piece.len() <= max_bytes {
        out.push_str(piece);
        true
    } else {
        false
    }
}

fn apply_fields_truncation_marker(out: &mut String, marker: &str) {
    let budget = MAX_FIELDS_BLOCK_BYTES.saturating_sub(marker.len());
    while out.len() > budget {
        out.pop();
    }
    out.push_str(marker);
}

/// Sanitize like [`sanitize_header_text`] but never produce more than
/// `max_bytes`. Returns `(text, complete)` where `complete` means `text`
/// equals the full `sanitize_header_text(raw)` result.
fn sanitize_header_text_bounded(raw: &str, max_bytes: usize) -> (String, bool) {
    let mut out = String::new();
    let mut iter = raw.chars();

    // Skip leading whitespace after control→space mapping (matches trim).
    let mut first = None;
    for ch in iter.by_ref() {
        let mapped = if ch.is_control() { ' ' } else { ch };
        if mapped.is_whitespace() {
            continue;
        }
        first = Some(mapped);
        break;
    }
    let Some(first) = first else {
        return (String::new(), true);
    };
    if first.len_utf8() > max_bytes {
        return (String::new(), false);
    }
    out.push(first);

    let mut trailing_ws_at: Option<usize> = None;
    for ch in iter.by_ref() {
        let mapped = if ch.is_control() { ' ' } else { ch };
        if out.len() + mapped.len_utf8() > max_bytes {
            if mapped.is_whitespace() {
                // Overflow on whitespace: complete iff the rest is only
                // trailing whitespace that sanitize would have trimmed.
                let rest_only_ws = iter.all(|c| {
                    let m = if c.is_control() { ' ' } else { c };
                    m.is_whitespace()
                });
                if rest_only_ws {
                    if let Some(start) = trailing_ws_at {
                        out.truncate(start);
                    }
                    return (out, true);
                }
                return (out, false);
            }
            return (out, false);
        }
        if mapped.is_whitespace() {
            if trailing_ws_at.is_none() {
                trailing_ws_at = Some(out.len());
            }
        } else {
            trailing_ws_at = None;
        }
        out.push(mapped);
    }
    if let Some(start) = trailing_ws_at {
        out.truncate(start);
    }
    (out, true)
}

fn push_sanitized_header_bounded(out: &mut String, raw: &str, max_bytes: usize) -> bool {
    let room = max_bytes.saturating_sub(out.len());
    let (piece, complete) = sanitize_header_text_bounded(raw, room);
    out.push_str(&piece);
    complete
}

/// Append a field value capped at [`MAX_FIELD_VALUE_BYTES`] (with `...`) while
/// also respecting the `${fields}` block ceiling. Allocates at most
/// `MAX_FIELD_VALUE_BYTES + 1` bytes for the sanitized value prefix.
fn push_field_value_bounded(out: &mut String, raw: &str) -> bool {
    const VALUE_MARKER: &str = "...";
    let block_room = MAX_FIELDS_BLOCK_BYTES.saturating_sub(out.len());
    if block_room == 0 {
        return false;
    }

    // Probe one byte past the per-value cap so we know whether value-level
    // truncation is required — without copying an unbounded value.
    let (sanitized, complete) =
        sanitize_header_text_bounded(raw, MAX_FIELD_VALUE_BYTES.saturating_add(1));
    let value = if !complete {
        truncate_utf8_with_marker(&sanitized, MAX_FIELD_VALUE_BYTES, VALUE_MARKER)
    } else if sanitized.len() > MAX_FIELD_VALUE_BYTES {
        truncate_utf8(&sanitized, MAX_FIELD_VALUE_BYTES, VALUE_MARKER)
    } else {
        sanitized
    };

    if out.len() + value.len() <= MAX_FIELDS_BLOCK_BYTES {
        out.push_str(&value);
        true
    } else {
        let mut end = block_room.min(value.len());
        while end > 0 && !value.is_char_boundary(end) {
            end -= 1;
        }
        out.push_str(&value[..end]);
        false
    }
}

fn address_list(addresses: &[Arc<str>]) -> String {
    addresses
        .iter()
        .map(|address| format!("<{address}>"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Emit `Name: value` folded onto continuation lines so no header line exceeds
/// the RFC 5322 limit. Folding happens on the `, ` separators already present
/// in an address list.
fn fold_header(name: &str, value: &str) -> String {
    let mut out = String::with_capacity(value.len() + name.len() + 4);
    out.push_str(name);
    out.push_str(": ");
    let mut line_len = name.len() + 2;
    let mut first = true;
    for part in value.split(", ") {
        if !first {
            if line_len + 2 + part.len() > MAX_HEADER_LINE_BYTES {
                out.push_str(",\n ");
                line_len = 1;
            } else {
                out.push_str(", ");
                line_len += 2;
            }
        }
        out.push_str(part);
        line_len += part.len();
        first = false;
    }
    out.push('\n');
    out
}

/// Encode a subject for a header field.
///
/// Pure-ASCII subjects are emitted verbatim (already stripped of control
/// characters). Anything else becomes a sequence of RFC 2047 base64
/// encoded-words, each short enough to satisfy the 75-character encoded-word
/// limit, folded onto continuation lines.
fn encode_subject(subject: &str) -> String {
    if subject.is_ascii() && !subject.contains("=?") {
        return subject.to_string();
    }
    // 45 raw bytes -> 60 base64 chars; plus the 12-char `=?UTF-8?B??=` wrapper
    // that is 72, under the 75-char encoded-word limit.
    const CHUNK_BYTES: usize = 45;
    let mut words: Vec<String> = Vec::new();
    let mut chunk = String::new();
    for ch in subject.chars() {
        if chunk.len() + ch.len_utf8() > CHUNK_BYTES {
            words.push(encoded_word(&chunk));
            chunk.clear();
        }
        chunk.push(ch);
    }
    if !chunk.is_empty() {
        words.push(encoded_word(&chunk));
    }
    words.join("\n ")
}

fn encoded_word(raw: &str) -> String {
    format!(
        "=?UTF-8?B?{}?=",
        base64::engine::general_purpose::STANDARD.encode(raw.as_bytes())
    )
}

/// Base64 the body with 76-character lines (RFC 2045 §6.8). Using base64 rather
/// than 8bit removes every line-length, bare-CR/LF, and leading-dot hazard from
/// operator- and caller-supplied text.
fn base64_body(body: &str) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(body.as_bytes());
    let mut out = String::with_capacity(encoded.len() + encoded.len() / 76 + 1);
    for (index, chunk) in encoded.as_bytes().chunks(76).enumerate() {
        if index > 0 {
            out.push('\n');
        }
        // `chunk` is base64 output: ASCII by construction.
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
    }
    out
}

/// CRLF-normalize and dot-stuff the assembled message.
///
/// Both passes are belt-and-braces: header values are already control-stripped
/// and the body is base64, so neither a bare LF nor a leading `.` can occur.
/// Running them anyway means a future header addition cannot silently
/// reintroduce SMTP data-phase termination.
fn encode_data_payload(message: &str) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(message.len() + 16);
    for (index, line) in message.split('\n').enumerate() {
        if index > 0 {
            out.extend_from_slice(b"\r\n");
        }
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.starts_with('.') {
            out.push(b'.');
        }
        out.extend_from_slice(line.as_bytes());
    }
    out
}

/// Collapse every control character (including CR/LF/TAB) to a space. This is
/// the header-injection defense for templated values.
fn sanitize_header_text(raw: &str) -> String {
    raw.chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect::<String>()
        .trim()
        .to_string()
}

/// Body text keeps newlines and tabs; every other control character goes.
/// CRLF and lone CR both normalize to a single LF so line counts stay stable
/// through the base64 transfer encoding.
fn sanitize_body_text(raw: &str) -> String {
    raw.replace("\r\n", "\n")
        .replace('\r', "\n")
        .chars()
        .filter(|ch| !ch.is_control() || *ch == '\n' || *ch == '\t')
        .collect()
}

/// Truncate on a UTF-8 boundary, appending `marker` when anything was removed.
fn truncate_utf8(raw: &str, max_bytes: usize, marker: &str) -> String {
    if raw.len() <= max_bytes {
        return raw.to_string();
    }
    truncate_utf8_with_marker(raw, max_bytes, marker)
}

fn truncate_utf8_with_marker(raw: &str, max_bytes: usize, marker: &str) -> String {
    let marker = marker_within_budget(marker, max_bytes);
    let budget = max_bytes - marker.len();
    let mut end = budget.min(raw.len());
    while end > 0 && !raw.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = raw[..end].to_string();
    out.push_str(marker);
    out
}

fn marker_within_budget(marker: &str, max_bytes: usize) -> &str {
    let mut end = marker.len().min(max_bytes);
    while end > 0 && !marker.is_char_boundary(end) {
        end -= 1;
    }
    &marker[..end]
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

fn optional_template(
    value: &Value,
    key: &str,
    default: &str,
    max_bytes: usize,
    channel: &str,
) -> Result<String, String> {
    let template = match value.get(key) {
        Some(v) => v
            .as_str()
            .ok_or_else(|| format!("channel '{channel}' (email): '{key}' must be a string"))?
            .to_string(),
        None => default.to_string(),
    };
    if template.is_empty() {
        return Err(format!(
            "channel '{channel}' (email): '{key}' must not be empty"
        ));
    }
    if template.len() > max_bytes {
        return Err(format!(
            "channel '{channel}' (email): '{key}' must be at most {max_bytes} bytes (got {})",
            template.len()
        ));
    }
    validate_template(&template)
        .map_err(|e| format!("channel '{channel}' (email): invalid '{key}': {e}"))?;
    Ok(template)
}

fn bounded_timeout_ms(
    value: &Value,
    key: &str,
    default: u64,
    max: u64,
    channel: &str,
) -> Result<u64, String> {
    let Some(raw) = value.get(key) else {
        return Ok(default);
    };
    let millis = raw
        .as_u64()
        .ok_or_else(|| format!("channel '{channel}' (email): '{key}' must be an integer"))?;
    if !(MIN_TIMEOUT_MS..=max).contains(&millis) {
        return Err(format!(
            "channel '{channel}' (email): '{key}' must be between {MIN_TIMEOUT_MS} and {max} ms (got {millis})"
        ));
    }
    Ok(millis)
}

/// Credentials must survive an SMTP command line intact. CR/LF or other control
/// bytes would let a crafted secret inject commands after the `AUTH` line.
fn validate_credential_component(raw: &str, field: &str, channel: &str) -> Result<(), String> {
    if raw.chars().any(char::is_control) {
        return Err(format!(
            "channel '{channel}' (email): resolved '{field}' must not contain control characters"
        ));
    }
    if raw.len() > 512 {
        return Err(format!(
            "channel '{channel}' (email): resolved '{field}' must be at most 512 bytes"
        ));
    }
    Ok(())
}

fn validate_helo_name(raw: &str, channel: &str) -> Result<(), String> {
    if raw.is_empty() || raw.len() > MAX_DOMAIN_BYTES {
        return Err(format!(
            "channel '{channel}' (email): 'helo_name' must be 1..={MAX_DOMAIN_BYTES} bytes"
        ));
    }
    validate_domain(raw)
        .map_err(|reason| format!("channel '{channel}' (email): invalid 'helo_name' ({reason})"))
}

/// Conservative RFC 5321 addr-spec check.
///
/// Deliberately stricter than the grammar: no quoted local parts, no address
/// literals, no comments. Those forms are legal but never needed for an alert
/// distribution list, and each is a parser-differential hazard between the
/// gateway, the relay, and the receiving MTA.
fn validate_email_address(address: &str, field: &str, channel: &str) -> Result<(), String> {
    let reject = |reason: &str| {
        Err(format!(
            "channel '{channel}' (email): invalid '{field}' address ({reason})"
        ))
    };
    if address.is_empty() {
        return reject("must not be empty");
    }
    if address.len() > MAX_ADDRESS_BYTES {
        return reject(&format!("must be at most {MAX_ADDRESS_BYTES} bytes"));
    }
    if !address.is_ascii() {
        return reject("must be ASCII (SMTPUTF8 addresses are not supported)");
    }
    if address
        .chars()
        .any(|ch| ch.is_control() || ch.is_whitespace())
    {
        return reject("must not contain whitespace or control characters");
    }
    let Some((local, domain)) = address.split_once('@') else {
        return reject("must contain exactly one '@'");
    };
    if domain.contains('@') {
        return reject("must contain exactly one '@'");
    }
    if local.is_empty() || local.len() > MAX_LOCAL_PART_BYTES {
        return reject(&format!(
            "local part must be 1..={MAX_LOCAL_PART_BYTES} bytes"
        ));
    }
    if local.starts_with('.') || local.ends_with('.') || local.contains("..") {
        return reject("local part must not start, end, or repeat with '.'");
    }
    const LOCAL_SPECIALS: &str = "!#$%&'*+-/=?^_`{|}~.";
    if !local
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || LOCAL_SPECIALS.contains(ch))
    {
        return reject("local part contains an unsupported character");
    }
    validate_domain(domain).map_err(|reason| {
        format!("channel '{channel}' (email): invalid '{field}' address ({reason})")
    })
}

fn validate_domain(domain: &str) -> Result<(), String> {
    if domain.is_empty() || domain.len() > MAX_DOMAIN_BYTES {
        return Err(format!("domain must be 1..={MAX_DOMAIN_BYTES} bytes"));
    }
    if !domain.is_ascii() {
        return Err("domain must be ASCII".to_string());
    }
    if domain.starts_with('.') || domain.ends_with('.') || domain.contains("..") {
        return Err("domain must not start, end, or repeat with '.'".to_string());
    }
    for label in domain.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err("domain labels must be 1..=63 bytes".to_string());
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err("domain labels must not start or end with '-'".to_string());
        }
        if !label
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
        {
            return Err("domain labels must be alphanumeric or '-'".to_string());
        }
    }
    Ok(())
}
