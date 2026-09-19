//! Tests for the native SMTP/email notification channel (`type: email`).
//!
//! Covers construction/admission (closed key set, TLS posture, addresses,
//! bounds), message construction (templating, header-injection defense,
//! truncation, encoding), and live delivery against a scripted local SMTP
//! fixture over both STARTTLS and implicit TLS.
//!
//! Every credential used here is a fixture-local literal; the redaction
//! assertions check that it never escapes into an error string.

use super::parse_channels;
use std::collections::HashMap;
use std::io::Write as _;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use chrono::{TimeZone, Utc};
use ferrum_edge::notifications::channels::{EmailChannel, NotificationChannel};
use ferrum_edge::notifications::{EventAction, Notification, NotificationField, Severity};
use ferrum_edge::plugins::utils::http_client::PluginHttpClient;
use serde_json::{Value, json};
use tempfile::NamedTempFile;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

const SMTP_USERNAME: &str = "alerts@example.com";
/// Fixture-local literal, never a real secret. Used to prove that credentials
/// do not leak into dispatch errors.
const SMTP_PASSWORD: &str = "fixture-only-smtp-secret";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn notification(event_action: EventAction) -> Notification {
    Notification {
        title: "[ALERT] proxy_5xx on api-gateway".to_string(),
        body: "5/100 requests matched [503] over 60s".to_string(),
        severity: Severity::High,
        event_action,
        source: Some("proxy_alerts:proxy_5xx".into()),
        subject_id: Some("api-gateway".into()),
        namespace: Some("ferrum".into()),
        fired_at: Utc.with_ymd_and_hms(2026, 5, 14, 10, 0, 0).unwrap(),
        fields: vec![
            NotificationField::new("Rule", "proxy_5xx"),
            NotificationField::new("Observed", "5.00%"),
        ],
    }
}

fn parse_one(def: Value) -> NotificationChannel {
    let map = parse_channels(&json!({ "ops_email": def })).expect("channel parses");
    (*map.get("ops_email").expect("channel present").clone()).clone()
}

fn parse_email(def: Value) -> EmailChannel {
    match parse_one(def) {
        NotificationChannel::Email(channel) => *channel,
        other => panic!("expected an email channel, got {}", other.kind()),
    }
}

fn parse_error(def: Value) -> String {
    parse_channels(&json!({ "ops_email": def })).expect_err("channel must be rejected")
}

fn minimal_def(port: u16) -> Value {
    json!({
        "type": "email",
        "smtp_host": "127.0.0.1",
        "smtp_port": port,
        "tls_server_name": "localhost",
        "from": "ferrum@example.com",
        "to": ["oncall@example.com"],
        "connect_timeout_ms": 5000,
        "command_timeout_ms": 5000
    })
}

fn no_extras() -> HashMap<String, String> {
    HashMap::new()
}

/// `PluginHttpClient` that trusts `ca_path` and nothing else — the email
/// channel always verifies, so the fixture CA has to be reachable this way.
fn client_with_ca(ca_path: &str) -> PluginHttpClient {
    use ferrum_edge::config::BackendEgressPolicy;
    use ferrum_edge::config::PoolConfig;
    use ferrum_edge::config::types::DEFAULT_NAMESPACE;
    use ferrum_edge::dns::{DnsCache, DnsConfig};

    PluginHttpClient::new(
        &PoolConfig::default(),
        DnsCache::new(DnsConfig::default()),
        1000,
        0,
        100,
        false,
        Some(ca_path),
        Arc::new(Vec::new()),
        DEFAULT_NAMESPACE,
        BackendEgressPolicy::unrestricted(),
        Arc::new(Vec::new()),
        0,
    )
}

// ---------------------------------------------------------------------------
// Construction / admission
// ---------------------------------------------------------------------------

#[test]
fn email_channel_parses_through_the_common_channel_map_with_defaults() {
    let channel = parse_email(json!({
        "type": "email",
        "smtp_host": "smtp.example.com",
        "from": "ferrum@example.com",
        "to": ["oncall@example.com", "sre@example.com"]
    }));

    assert_eq!(channel.name(), "ops_email");
    assert_eq!(channel.smtp_host(), "smtp.example.com");
    assert_eq!(channel.smtp_port(), 587, "starttls default port");
    assert_eq!(channel.tls_mode().as_str(), "starttls");
    assert_eq!(channel.tls_server_name(), "smtp.example.com");
    assert_eq!(channel.from(), "ferrum@example.com");
    assert_eq!(channel.recipients().len(), 2);
    assert_eq!(
        channel.helo_name(),
        "example.com",
        "defaults to from-domain"
    );
    assert!(!channel.has_credentials());
    assert_eq!(channel.subject_template(), "[${severity}] ${title}");
    assert_eq!(channel.body_template(), "${body}\n\n${fields}");
}

#[test]
fn email_literal_egress_admission_uses_the_resolved_policy() {
    use ferrum_edge::config::BackendAllowIps::{Both, Public};
    use ferrum_edge::config::BackendEgressPolicy;
    use ferrum_edge::plugins::proxy_alerts::ProxyAlerts;
    use ferrum_edge::plugins::validate_plugin_config_with_policy;

    let cases = [
        (Both, "", "", true, "169.254.169.254", false),
        (Both, "", "", true, "[fe80::1]", false),
        (Both, "", "", true, "[::ffff:169.254.169.254]", false),
        (Public, "", "", true, "127.0.0.1", false),
        (Public, "", "", true, "[::1]", false),
        (Public, "", "", true, "10.1.2.3", false),
        (Both, "", "10.0.0.0/8", true, "10.1.2.3", false),
        (Both, "", "", true, "10.1.2.3", true),
        (Public, "", "", true, "8.8.8.8", true),
        (Public, "10.0.0.0/8", "", true, "10.1.2.3", true),
        (Both, "169.254.169.254/32", "", true, "169.254.169.254", true),
        (Both, "", "", false, "169.254.169.254", true),
        // Construction must not resolve DNS, even with every address denied.
        (Both, "", "0.0.0.0/0,::/0", true, "smtp.invalid", true),
    ];
    for (mode, allow, deny, baseline, host, accepted) in cases {
        let policy = BackendEgressPolicy::from_env(mode.clone(), allow, deny, baseline).unwrap();
        let mut channel = minimal_def(587);
        channel["smtp_host"] = json!(host);
        let direct = EmailChannel::new("ops", &channel, &policy);
        assert_eq!(direct.is_ok(), accepted, "{mode}: {host}");
        if let Err(error) = direct {
            assert!(error.contains("`smtp_host`"), "{error}");
            assert!(error.contains("backend egress policy"), "{error}");
            assert!(!error.contains(host), "{error}");
        }
        let channels = json!({"ops": channel});
        assert_eq!(
            ferrum_edge::notifications::channels::parse_channels(&policy, &channels).is_ok(),
            accepted
        );
        let config = json!({
            "channels": channels,
            "rules": [{
                "name": "errors", "type": "status_code_count", "status_codes": [500],
                "threshold_count": 1, "channels": ["ops"]
            }]
        });
        assert_eq!(
            validate_plugin_config_with_policy("proxy_alerts", &config, &policy).is_ok(),
            accepted,
            "config admission: {mode}: {host}"
        );
        let http = PluginHttpClient::default_with_backend_allow_ips(policy);
        assert_eq!(ProxyAlerts::new(&config, http).is_ok(), accepted);
    }
}

#[tokio::test]
async fn email_send_rechecks_literals_and_resolved_hostnames_before_connecting() {
    use ferrum_edge::config::{BackendAllowIps, BackendEgressPolicy, PoolConfig};
    use ferrum_edge::dns::{DnsCache, DnsConfig};

    let listener = crate::port_registry::bind_tcp_listener("127.0.0.1:0".parse().unwrap()).unwrap();
    listener.set_nonblocking(true).unwrap();
    let (ca_file, _acceptor) = tls_materials("localhost");
    // Deliberately allow the DNS result so the SMTP per-send IP check, rather
    // than the cache's own policy, must refuse the connection.
    let dns = DnsCache::new(DnsConfig {
        global_overrides: HashMap::from([("smtp.invalid".to_string(), "127.0.0.1".to_string())]),
        ..Default::default()
    });
    let http = PluginHttpClient::new(
        &PoolConfig::default(),
        dns,
        1000,
        0,
        100,
        false,
        ca_file.path().to_str(),
        Arc::new(Vec::new()),
        ferrum_edge::config::types::DEFAULT_NAMESPACE,
        BackendEgressPolicy::from_allow_ips(BackendAllowIps::Public),
        Arc::new(Vec::new()),
        0,
    );
    for host in ["127.0.0.1", "smtp.invalid"] {
        let mut def = minimal_def(listener.local_addr().unwrap().port());
        def["smtp_host"] = json!(host);
        def["command_timeout_ms"] = json!(100);
        let channel = EmailChannel::new(
            "ops",
            &def,
            &BackendEgressPolicy::from_allow_ips(BackendAllowIps::Both),
        )
        .unwrap();
        let error = channel
            .dispatch(&notification(EventAction::Trigger), &http)
            .await
            .unwrap_err();
        assert!(
            error.contains("blocked by the backend egress policy"),
            "{error}"
        );
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
}

#[test]
fn email_channel_kind_and_warmup_hostnames_are_wired_into_the_enum() {
    let dns_channel = parse_one(json!({
        "type": "email",
        "smtp_host": "smtp.example.com",
        "from": "ferrum@example.com",
        "to": ["oncall@example.com"]
    }));
    assert_eq!(dns_channel.kind(), "email");
    assert_eq!(dns_channel.name(), "ops_email");
    assert_eq!(
        dns_channel.warmup_hostnames(),
        vec!["smtp.example.com".to_string()]
    );

    let ip_channel = parse_one(json!({
        "type": "email",
        "smtp_host": "10.1.2.3",
        "from": "ferrum@example.com",
        "to": ["oncall@example.com"]
    }));
    assert!(
        ip_channel.warmup_hostnames().is_empty(),
        "IP literals have nothing to pre-resolve"
    );
}

#[test]
fn implicit_tls_defaults_to_port_465() {
    let channel = parse_email(json!({
        "type": "email",
        "smtp_host": "smtp.example.com",
        "tls_mode": "implicit_tls",
        "from": "ferrum@example.com",
        "to": ["oncall@example.com"]
    }));
    assert_eq!(channel.smtp_port(), 465);
    assert_eq!(channel.tls_mode().as_str(), "implicit_tls");
}

#[test]
fn email_channel_rejects_unknown_keys() {
    let error = parse_error(json!({
        "type": "email",
        "smtp_host": "smtp.example.com",
        "smtp_hostt": "typo.example.com",
        "from": "ferrum@example.com",
        "to": ["oncall@example.com"]
    }));
    assert!(
        error.contains("smtp_hostt"),
        "unknown key must be named: {error}"
    );
}

#[test]
fn email_channel_rejects_channel_type_fields_from_other_variants() {
    let error = parse_error(json!({
        "type": "email",
        "smtp_host": "smtp.example.com",
        "webhook_url": "https://hooks.slack.com/services/T/B/X",
        "from": "ferrum@example.com",
        "to": ["oncall@example.com"]
    }));
    assert!(error.contains("webhook_url"), "{error}");
}

#[test]
fn plaintext_smtp_is_refused_at_admission() {
    for mode in ["none", "plaintext", "disabled", "insecure"] {
        let error = parse_error(json!({
            "type": "email",
            "smtp_host": "smtp.example.com",
            "tls_mode": mode,
            "from": "ferrum@example.com",
            "to": ["oncall@example.com"]
        }));
        assert!(
            error.contains("plaintext SMTP is not supported"),
            "mode={mode} error={error}"
        );
    }

    let error = parse_error(json!({
        "type": "email",
        "smtp_host": "smtp.example.com",
        "tls_mode": "ssl",
        "from": "ferrum@example.com",
        "to": ["oncall@example.com"]
    }));
    assert!(error.contains("unknown `tls_mode`"), "{error}");
}

#[test]
fn half_configured_credentials_are_refused() {
    let missing_password = parse_error(json!({
        "type": "email",
        "smtp_host": "smtp.example.com",
        "username": SMTP_USERNAME,
        "from": "ferrum@example.com",
        "to": ["oncall@example.com"]
    }));
    assert!(
        missing_password.contains("without a password"),
        "{missing_password}"
    );

    let missing_username = parse_error(json!({
        "type": "email",
        "smtp_host": "smtp.example.com",
        "password": SMTP_PASSWORD,
        "from": "ferrum@example.com",
        "to": ["oncall@example.com"]
    }));
    assert!(
        missing_username.contains("without `username`"),
        "{missing_username}"
    );
    assert!(
        !missing_username.contains(SMTP_PASSWORD),
        "admission errors must not echo the password"
    );
}

#[test]
fn credentials_resolve_through_the_env_convention() {
    let mut env = HashMap::new();
    env.insert(
        "FERRUM_TEST_SMTP_USERNAME_3329".to_string(),
        SMTP_USERNAME.to_string(),
    );
    env.insert(
        "FERRUM_TEST_SMTP_PASSWORD_3329".to_string(),
        SMTP_PASSWORD.to_string(),
    );

    let channel = ferrum_edge::_test_support::email_channel_new_with_env_for_test(
        "ops_email",
        &json!({
            "type": "email",
            "smtp_host": "smtp.example.com",
            "username_env": "FERRUM_TEST_SMTP_USERNAME_3329",
            "password_env": "FERRUM_TEST_SMTP_PASSWORD_3329",
            "from": "ferrum@example.com",
            "to": ["oncall@example.com"]
        }),
        &env,
    )
    .expect("channel parses");
    assert!(channel.has_credentials());

    let debug = format!("{channel:?}");
    assert!(
        !debug.contains(SMTP_PASSWORD) && !debug.contains(SMTP_USERNAME),
        "Debug output must not carry credentials: {debug}"
    );
    assert!(debug.contains("authenticated: true"), "{debug}");

    let missing = ferrum_edge::_test_support::email_channel_new_with_env_for_test(
        "ops_email",
        &json!({
            "type": "email",
            "smtp_host": "smtp.example.com",
            "username_env": "FERRUM_TEST_SMTP_USERNAME_3329",
            "password_env": "FERRUM_TEST_SMTP_ABSENT_3329",
            "from": "ferrum@example.com",
            "to": ["oncall@example.com"]
        }),
        &env,
    )
    .expect_err("channel must be rejected");
    assert!(missing.contains("is not set"), "{missing}");
}

#[test]
fn invalid_addresses_are_refused() {
    let long_local = format!("{}@example.com", "a".repeat(65));
    let long_address = format!("{}@example.com", "a".repeat(250));
    for address in [
        "not-an-address",
        "two@at@example.com",
        "@example.com",
        "user@",
        "user@.example.com",
        "user@example..com",
        "user@-example.com",
        ".user@example.com",
        "user.@example.com",
        "us..er@example.com",
        "user name@example.com",
        "user@example.com\r\nRCPT TO:<evil@example.com>",
        "üser@example.com",
        "user<@example.com",
        long_local.as_str(),
        long_address.as_str(),
    ] {
        let error = parse_error(json!({
            "type": "email",
            "smtp_host": "smtp.example.com",
            "from": "ferrum@example.com",
            "to": [address]
        }));
        assert!(
            error.contains("invalid `to` address"),
            "address={address} error={error}"
        );

        let from_error = parse_error(json!({
            "type": "email",
            "smtp_host": "smtp.example.com",
            "from": address,
            "to": ["oncall@example.com"]
        }));
        assert!(
            from_error.contains("invalid `from` address"),
            "address={address} error={from_error}"
        );
    }
}

#[test]
fn recipient_bounds_are_explicit() {
    let empty = parse_error(json!({
        "type": "email",
        "smtp_host": "smtp.example.com",
        "from": "ferrum@example.com",
        "to": []
    }));
    assert!(empty.contains("at least one recipient"), "{empty}");

    let too_many: Vec<String> = (0..33).map(|i| format!("oncall{i}@example.com")).collect();
    let overflow = parse_error(json!({
        "type": "email",
        "smtp_host": "smtp.example.com",
        "from": "ferrum@example.com",
        "to": too_many
    }));
    assert!(overflow.contains("at most 32 recipients"), "{overflow}");

    let duplicates = parse_email(json!({
        "type": "email",
        "smtp_host": "smtp.example.com",
        "from": "ferrum@example.com",
        "to": ["oncall@example.com", "oncall@example.com", "sre@example.com"]
    }));
    assert_eq!(duplicates.recipients().len(), 2, "duplicates collapse");
}

#[test]
fn host_port_timeout_and_template_bounds_are_explicit() {
    for (def, needle) in [
        (
            json!({"smtp_host": "https://smtp.example.com"}),
            "without scheme",
        ),
        (
            json!({"smtp_host": "smtp.example.com:587"}),
            "must not include brackets or a port",
        ),
        (json!({"smtp_port": 0}), "between 1 and 65535"),
        (json!({"smtp_port": 70000}), "between 1 and 65535"),
        (
            json!({"connect_timeout_ms": 10}),
            "must be between 100 and 60000 ms",
        ),
        (
            json!({"connect_timeout_ms": 60001}),
            "must be between 100 and 60000 ms",
        ),
        (
            json!({"command_timeout_ms": 0}),
            "must be between 100 and 120000 ms",
        ),
        (
            json!({"command_timeout_ms": 120001}),
            "must be between 100 and 120000 ms",
        ),
        (json!({"subject_template": "${unbalanced"}), "unbalanced"),
        (json!({"body_template": "${unbalanced"}), "unbalanced"),
        (json!({"subject_template": ""}), "must not be empty"),
        (
            json!({"helo_name": "not a hostname"}),
            "invalid `helo_name`",
        ),
        (
            json!({"tls_server_name": ""}),
            "`tls_server_name` must not be empty",
        ),
        (
            json!({"tls_server_name": "not a name"}),
            "invalid TLS server name",
        ),
    ] {
        let mut base = json!({
            "type": "email",
            "smtp_host": "smtp.example.com",
            "from": "ferrum@example.com",
            "to": ["oncall@example.com"]
        });
        for (key, value) in def.as_object().expect("override object") {
            base[key] = value.clone();
        }
        let error = parse_error(base);
        assert!(error.contains(needle), "needle={needle} error={error}");
    }

    let long_subject_template = format!("${{title}}{}", "x".repeat(2000));
    let subject_error = parse_error(json!({
        "type": "email",
        "smtp_host": "smtp.example.com",
        "from": "ferrum@example.com",
        "to": ["oncall@example.com"],
        "subject_template": long_subject_template
    }));
    assert!(
        subject_error.contains("at most 1024 bytes"),
        "{subject_error}"
    );

    let long_body_template = "y".repeat(70_000);
    let body_error = parse_error(json!({
        "type": "email",
        "smtp_host": "smtp.example.com",
        "from": "ferrum@example.com",
        "to": ["oncall@example.com"],
        "body_template": long_body_template
    }));
    assert!(body_error.contains("at most 65536 bytes"), "{body_error}");
}

// ---------------------------------------------------------------------------
// Message construction
// ---------------------------------------------------------------------------

#[test]
fn templates_reuse_notification_variables_and_caller_extras() {
    let channel = parse_email(json!({
        "type": "email",
        "smtp_host": "smtp.example.com",
        "from": "ferrum@example.com",
        "to": ["oncall@example.com"],
        "subject_template": "[${severity}] ${rule_name} on ${subject_id}",
        "body_template": "${body}\nns=${namespace} action=${event_action}\n${fields}"
    }));
    let mut extras = HashMap::new();
    extras.insert("rule_name".to_string(), "proxy_5xx".to_string());
    // A caller must not be able to shadow a generic notification variable.
    extras.insert("severity".to_string(), "info".to_string());

    let subject = channel
        .render_subject(&notification(EventAction::Trigger), &extras)
        .expect("subject renders");
    assert_eq!(subject, "[high] proxy_5xx on api-gateway");

    let body = channel
        .render_body(&notification(EventAction::Trigger), &extras)
        .expect("body renders");
    assert!(
        body.contains("5/100 requests matched [503] over 60s"),
        "{body}"
    );
    assert!(body.contains("ns=ferrum action=trigger"), "{body}");
    assert!(body.contains("Rule: proxy_5xx"), "{body}");
    assert!(body.contains("Observed: 5.00%"), "{body}");
}

#[test]
fn header_injection_through_template_values_is_neutralized() {
    let channel = parse_email(json!({
        "type": "email",
        "smtp_host": "smtp.example.com",
        "from": "ferrum@example.com",
        "to": ["oncall@example.com"]
    }));
    let mut hostile = notification(EventAction::Trigger);
    hostile.title = "pwn\r\nBcc: attacker@evil.test\r\n\r\ninjected".to_string();
    hostile.body = "line one\r\n.\r\nnot-the-end".to_string();

    let subject = channel
        .render_subject(&hostile, &no_extras())
        .expect("subject renders");
    assert!(
        !subject.contains('\r') && !subject.contains('\n'),
        "control characters must not survive into a header: {subject}"
    );

    let message = channel
        .build_message(&hostile, &no_extras())
        .expect("message builds");
    let rendered = String::from_utf8(message).expect("message is utf-8");
    let header_block = rendered.split("\r\n\r\n").next().expect("headers present");
    // The `Bcc:` text survives only as inert `Subject:` content: the CR/LF that
    // would have started a new field is folded to a space, so the header block
    // still carries exactly the fields the channel emits and nothing else. That
    // — not the absence of the literal substring — is the injection invariant.
    let field_names: Vec<String> = header_block
        .split("\r\n")
        // Folded continuation lines (RFC 5322 §2.2.3) start with WSP and are
        // part of the preceding field, not a new one.
        .filter(|line| !line.starts_with([' ', '\t']))
        .map(|line| match line.split_once(':') {
            Some((name, _)) => name.to_ascii_lowercase(),
            None => format!("<not a header field: {line}>"),
        })
        .collect();
    let expected_fields: Vec<String> = [
        "date",
        "from",
        "to",
        "subject",
        "message-id",
        "mime-version",
        "content-type",
        "content-transfer-encoding",
        "auto-submitted",
        "x-ferrum-notification-severity",
        "x-ferrum-notification-event-action",
    ]
    .iter()
    .map(|name| (*name).to_string())
    .collect();
    assert_eq!(
        field_names, expected_fields,
        "injected header survived: {header_block}"
    );
    // The base64 transfer encoding means the body can never contain the
    // data-phase terminator.
    assert!(
        !rendered.contains("\r\n.\r\n"),
        "body must not embed the DATA terminator"
    );
}

#[test]
fn message_carries_the_expected_headers_and_a_decodable_body() {
    let channel = parse_email(json!({
        "type": "email",
        "smtp_host": "smtp.example.com",
        "from": "ferrum@example.com",
        "to": ["oncall@example.com", "sre@example.com"]
    }));

    for (action, expected) in [
        (EventAction::Trigger, "trigger"),
        (EventAction::Resolve, "resolve"),
    ] {
        let note = notification(action);
        let message = channel
            .build_message(&note, &no_extras())
            .expect("message builds");
        let rendered = String::from_utf8(message).expect("message is utf-8");
        let (headers, body) = rendered
            .split_once("\r\n\r\n")
            .expect("header/body separator");

        assert!(headers.contains("From: <ferrum@example.com>"), "{headers}");
        assert!(
            headers.contains("To: <oncall@example.com>, <sre@example.com>"),
            "{headers}"
        );
        assert!(headers.contains("MIME-Version: 1.0"), "{headers}");
        assert!(
            headers.contains("Content-Transfer-Encoding: base64"),
            "{headers}"
        );
        assert!(
            headers.contains("Auto-Submitted: auto-generated"),
            "{headers}"
        );
        assert!(
            headers.contains("X-Ferrum-Notification-Severity: high"),
            "{headers}"
        );
        assert!(
            headers.contains(&format!("X-Ferrum-Notification-Event-Action: {expected}")),
            "{headers}"
        );
        assert!(
            headers.contains("Subject: [high] [ALERT] proxy_5xx"),
            "{headers}"
        );
        assert!(
            !rendered.contains('\n')
                || rendered.matches('\n').count() == rendered.matches("\r\n").count(),
            "every LF must be part of a CRLF pair"
        );

        let decoded = base64::engine::general_purpose::STANDARD
            .decode(body.replace("\r\n", ""))
            .expect("body is base64");
        let decoded = String::from_utf8(decoded).expect("decoded body is utf-8");
        assert!(
            decoded.contains("5/100 requests matched [503] over 60s"),
            "{decoded}"
        );
        assert!(decoded.contains("Rule: proxy_5xx"), "{decoded}");
    }
}

#[test]
fn non_ascii_subjects_are_rfc2047_encoded() {
    let channel = parse_email(json!({
        "type": "email",
        "smtp_host": "smtp.example.com",
        "from": "ferrum@example.com",
        "to": ["oncall@example.com"],
        "subject_template": "${title}"
    }));
    let mut note = notification(EventAction::Trigger);
    note.title = "üpstream ausgefallen — 503".to_string();

    let message = channel
        .build_message(&note, &no_extras())
        .expect("message builds");
    let rendered = String::from_utf8(message).expect("message is utf-8");
    assert!(rendered.contains("Subject: =?UTF-8?B?"), "{rendered}");
    for line in rendered.split("\r\n") {
        assert!(
            line.len() <= 998,
            "header/body lines must stay within the RFC 5322 limit: {line}"
        );
    }
}

#[test]
fn oversized_rendered_output_is_truncated_with_a_visible_marker() {
    let channel = parse_email(json!({
        "type": "email",
        "smtp_host": "smtp.example.com",
        "from": "ferrum@example.com",
        "to": ["oncall@example.com"],
        "subject_template": "${title}",
        "body_template": "${body}"
    }));
    let mut note = notification(EventAction::Trigger);
    note.title = "s".repeat(4000);
    note.body = "b".repeat(200_000);

    let subject = channel
        .render_subject(&note, &no_extras())
        .expect("subject renders");
    assert_eq!(subject.len(), 512, "subject is capped at 512 bytes");
    assert!(subject.ends_with("..."), "{subject}");
    assert!(subject.is_char_boundary(subject.len()));

    let body = channel
        .render_body(&note, &no_extras())
        .expect("body renders");
    assert!(body.len() <= 32 * 1024, "body is capped at 32 KiB");
    assert!(body.ends_with("[truncated]"), "truncation must be visible");
    assert!(body.is_char_boundary(body.len()));
}

#[test]
fn repeated_large_values_cannot_blow_past_subject_and_body_ceilings() {
    // A 64 KiB-class body template may repeat `${body}` / extras many times.
    // Rendering must stay within the advertised ceilings during substitution,
    // not only after a post-pass truncate of an unbounded intermediate string.
    let body_template = "${body}".repeat(8000); // 56_000 bytes, under the 64 KiB template cap
    assert!(body_template.len() <= 64 * 1024);
    let subject_template = "${huge}".repeat(140); // 980 bytes, under the 1 KiB subject template cap
    assert!(subject_template.len() <= 1024);

    let channel = parse_email(json!({
        "type": "email",
        "smtp_host": "smtp.example.com",
        "from": "ferrum@example.com",
        "to": ["oncall@example.com"],
        "subject_template": subject_template,
        "body_template": body_template
    }));

    let mut note = notification(EventAction::Trigger);
    note.body = "B".repeat(8_192);
    let mut extras = HashMap::new();
    extras.insert("huge".to_string(), "H".repeat(4_096));

    let subject = channel
        .render_subject(&note, &extras)
        .expect("subject renders");
    assert!(
        subject.len() <= 512,
        "repeated extras must not exceed the subject ceiling: {}",
        subject.len()
    );
    assert!(subject.ends_with("..."), "{subject}");
    assert!(std::str::from_utf8(subject.as_bytes()).is_ok());

    let body = channel.render_body(&note, &extras).expect("body renders");
    assert!(
        body.len() <= 32 * 1024,
        "repeated body values must not exceed the body ceiling: {}",
        body.len()
    );
    assert!(body.ends_with("[truncated]"), "{body}");
    assert!(std::str::from_utf8(body.as_bytes()).is_ok());
}

#[test]
fn exact_limit_and_limit_plus_one_keep_utf8_and_visible_markers() {
    let channel = parse_email(json!({
        "type": "email",
        "smtp_host": "smtp.example.com",
        "from": "ferrum@example.com",
        "to": ["oncall@example.com"],
        "subject_template": "${title}",
        "body_template": "${body}"
    }));

    // Exact subject ceiling: no truncation marker.
    let mut exact = notification(EventAction::Trigger);
    exact.title = "s".repeat(512);
    let subject = channel
        .render_subject(&exact, &no_extras())
        .expect("exact subject");
    assert_eq!(subject.len(), 512);
    assert!(
        !subject.ends_with("..."),
        "exact fit must not mark truncation"
    );
    assert!(subject.is_char_boundary(subject.len()));

    // One byte over: marker replaces the tail on a UTF-8 boundary.
    let mut over = notification(EventAction::Trigger);
    over.title = "s".repeat(513);
    let subject = channel
        .render_subject(&over, &no_extras())
        .expect("oversize subject");
    assert_eq!(subject.len(), 512);
    assert!(subject.ends_with("..."), "{subject}");

    // Multi-byte codepoint on the subject boundary must not split a char.
    let mut utf8 = notification(EventAction::Trigger);
    // 509 ASCII bytes + one 3-byte char = 512 exact without marker when fit;
    // 510 ASCII + 3-byte char = 513 → truncate before the multi-byte char.
    utf8.title = format!("{}{}", "a".repeat(510), "界");
    assert_eq!(utf8.title.len(), 513);
    let subject = channel
        .render_subject(&utf8, &no_extras())
        .expect("utf8 subject");
    assert!(subject.len() <= 512, "{}", subject.len());
    assert!(subject.ends_with("..."), "{subject}");
    assert!(std::str::from_utf8(subject.as_bytes()).is_ok());
    assert!(!subject.contains('\u{fffd}'));

    // Exact body ceiling / +1.
    let mut body_exact = notification(EventAction::Trigger);
    body_exact.body = "b".repeat(32 * 1024);
    let body = channel
        .render_body(&body_exact, &no_extras())
        .expect("exact body");
    assert_eq!(body.len(), 32 * 1024);
    assert!(!body.ends_with("[truncated]"));

    let mut body_over = notification(EventAction::Trigger);
    body_over.body = "b".repeat(32 * 1024 + 1);
    let body = channel
        .render_body(&body_over, &no_extras())
        .expect("oversize body");
    assert!(body.len() <= 32 * 1024, "{}", body.len());
    assert!(body.ends_with("[truncated]"), "{body}");
    assert!(std::str::from_utf8(body.as_bytes()).is_ok());
}

#[test]
fn fields_block_hard_caps_oversized_names_and_crossing_final_field() {
    let channel = parse_email(json!({
        "type": "email",
        "smtp_host": "smtp.example.com",
        "from": "ferrum@example.com",
        "to": ["oncall@example.com"],
        "subject_template": "${title}",
        "body_template": "${fields}"
    }));

    // A single enormous field name must not push ${fields} past 8 KiB, and
    // must not require copying the whole name just to truncate afterward.
    let mut huge_name = notification(EventAction::Trigger);
    huge_name.fields = vec![NotificationField::new("N".repeat(200_000), "value")];
    let fields = channel
        .render_body(&huge_name, &no_extras())
        .expect("fields render");
    assert!(
        fields.len() <= 8 * 1024,
        "fields block hard ceiling exceeded: {}",
        fields.len()
    );
    assert!(
        fields.contains("[fields truncated]"),
        "oversized name must surface the fields truncation marker: {fields}"
    );
    assert!(std::str::from_utf8(fields.as_bytes()).is_ok());

    // Fill to just under 8 KiB with complete lines, then one more field that
    // crosses the boundary. Each line is "f: " + 512×'v' + "\n" = 516 bytes.
    // 15 × 516 = 7740; remaining 452 < 516, so the 16th field forces truncation.
    let mut crossing = notification(EventAction::Trigger);
    crossing.fields = (0..16)
        .map(|_| NotificationField::new("f", "v".repeat(512)))
        .collect();
    let fields = channel
        .render_body(&crossing, &no_extras())
        .expect("crossing fields render");
    assert!(
        fields.len() <= 8 * 1024,
        "crossing final field must stay inside the hard ceiling: {}",
        fields.len()
    );
    assert!(
        fields.contains("[fields truncated]"),
        "crossing final field must mark truncation: {fields}"
    );
    assert!(std::str::from_utf8(fields.as_bytes()).is_ok());

    // Exact 8 KiB fill with no leftover field: no truncation marker required.
    // 8 KiB / 516 is not integral, so build one field whose sanitized line is
    // exactly 8192 bytes: name (8192 - 2 - 1 - 1) + ": " + "x" + "\n".
    let exact_name_len = 8 * 1024 - 4; // ": " + "x" + "\n"
    let mut exact = notification(EventAction::Trigger);
    exact.fields = vec![NotificationField::new("E".repeat(exact_name_len), "x")];
    let fields = channel
        .render_body(&exact, &no_extras())
        .expect("exact fields render");
    assert_eq!(fields.len(), 8 * 1024, "{fields}");
    assert!(
        !fields.contains("[fields truncated]"),
        "exact-fit fields block must not claim truncation"
    );

    // A multibyte codepoint that crosses the per-value probe boundary still
    // needs the visible value-level marker. The bounded sanitizer can return
    // fewer than 512 bytes while reporting incomplete, so length alone is not
    // proof that the full value fit.
    let mut unicode_boundary = notification(EventAction::Trigger);
    unicode_boundary.fields = vec![NotificationField::new(
        "f",
        format!("{}😀", "a".repeat(510)),
    )];
    let fields = channel
        .render_body(&unicode_boundary, &no_extras())
        .expect("unicode-boundary fields render");
    assert!(
        fields.contains(&format!("{}...", "a".repeat(509))),
        "truncated multibyte field value must retain its marker: {fields}"
    );
}

#[test]
fn built_message_stays_bounded_and_neutralizes_header_injection() {
    let body_template = "${body}".repeat(8000);
    let channel = parse_email(json!({
        "type": "email",
        "smtp_host": "smtp.example.com",
        "from": "ferrum@example.com",
        "to": ["oncall@example.com"],
        "subject_template": "[${severity}] ${title}",
        "body_template": body_template
    }));

    let mut note = notification(EventAction::Trigger);
    note.title = "alert\r\nBcc: attacker@evil.example\r\nX-Injected: yes".to_string();
    note.body = "Z".repeat(100_000);
    note.fields = vec![
        NotificationField::new("H".repeat(50_000), "V".repeat(50_000)),
        NotificationField::new("more\r\nInjected", "row\nTwo"),
    ];

    let message = channel
        .build_message(&note, &no_extras())
        .expect("message builds");
    let rendered = String::from_utf8(message).expect("message is utf-8");
    let (headers, body) = rendered
        .split_once("\r\n\r\n")
        .expect("header/body separator");

    // Injection defense is that CR/LF cannot start a new header field — the
    // literal "Bcc:" text may still appear inside Subject as inert content.
    let field_names: Vec<String> = headers
        .split("\r\n")
        .filter(|line| !line.starts_with([' ', '\t']))
        .map(|line| match line.split_once(':') {
            Some((name, _)) => name.to_ascii_lowercase(),
            None => format!("<not a header field: {line}>"),
        })
        .collect();
    let expected_fields: Vec<String> = [
        "date",
        "from",
        "to",
        "subject",
        "message-id",
        "mime-version",
        "content-type",
        "content-transfer-encoding",
        "auto-submitted",
        "x-ferrum-notification-severity",
        "x-ferrum-notification-event-action",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect();
    assert_eq!(
        field_names, expected_fields,
        "hostile subject/fields must not inject header fields"
    );

    for line in headers.lines() {
        assert!(
            line.len() <= 998,
            "header lines must stay within RFC 5322 limits: {line}"
        );
    }

    let decoded = base64::engine::general_purpose::STANDARD
        .decode(body.replace("\r\n", ""))
        .expect("body is base64");
    assert!(
        decoded.len() <= 32 * 1024,
        "wire body payload must respect the rendered body ceiling: {}",
        decoded.len()
    );
    let decoded_text = String::from_utf8(decoded).expect("decoded body is utf-8");
    assert!(
        decoded_text.len() <= 32 * 1024,
        "decoded body must stay bounded: {}",
        decoded_text.len()
    );
}

// ---------------------------------------------------------------------------
// Live SMTP fixture
// ---------------------------------------------------------------------------

/// Scripted replies for the fixture relay. Each field is written verbatim
/// (CRLF appended per line), so a test can inject multiline, malformed, or
/// oversized replies.
#[derive(Clone)]
struct SmtpScript {
    greeting: Vec<String>,
    ehlo_plain: Vec<String>,
    ehlo_tls: Vec<String>,
    starttls: Vec<String>,
    auth: Vec<String>,
    mail_from: Vec<String>,
    rcpt_to: Vec<String>,
    data: Vec<String>,
    data_end: Vec<String>,
}

impl SmtpScript {
    fn starttls_default() -> Self {
        Self {
            greeting: vec!["220 fixture ESMTP ready".to_string()],
            ehlo_plain: vec![
                "250-fixture".to_string(),
                "250-STARTTLS".to_string(),
                "250 8BITMIME".to_string(),
            ],
            ehlo_tls: vec![
                "250-fixture".to_string(),
                "250-SIZE 10485760".to_string(),
                "250 AUTH PLAIN LOGIN".to_string(),
            ],
            starttls: vec!["220 ready to start TLS".to_string()],
            auth: vec!["235 2.7.0 authentication succeeded".to_string()],
            mail_from: vec!["250 2.1.0 sender ok".to_string()],
            rcpt_to: vec!["250 2.1.5 recipient ok".to_string()],
            data: vec!["354 end data with <CRLF>.<CRLF>".to_string()],
            data_end: vec!["250 2.0.0 queued as ABC123".to_string()],
        }
    }

    fn implicit_default() -> Self {
        let mut script = Self::starttls_default();
        script.ehlo_plain = script.ehlo_tls.clone();
        script
    }
}

/// One line the fixture received, tagged with whether TLS was already active.
type Transcript = Arc<Mutex<Vec<(bool, String)>>>;

struct SmtpFixture {
    addr: SocketAddr,
    ca_path: NamedTempFile,
    transcript: Transcript,
    body: Arc<Mutex<String>>,
    handle: JoinHandle<()>,
}

impl SmtpFixture {
    fn received(&self) -> Vec<(bool, String)> {
        self.transcript.lock().expect("transcript lock").clone()
    }

    fn cleartext_commands(&self) -> Vec<String> {
        self.received()
            .into_iter()
            .filter(|(tls, _)| !tls)
            .map(|(_, line)| line)
            .collect()
    }

    fn saw(&self, prefix: &str) -> bool {
        self.received()
            .iter()
            .any(|(_, line)| line.to_ascii_uppercase().starts_with(prefix))
    }

    fn ca_path(&self) -> &str {
        self.ca_path.path().to_str().expect("ca path is utf-8")
    }

    fn channel_def(&self, extra: Value) -> Value {
        let mut def = minimal_def(self.addr.port());
        for (key, value) in extra.as_object().expect("override object") {
            def[key] = value.clone();
        }
        def
    }
}

/// Generate a CA plus a leaf certificate for `san`, returning the CA bundle
/// file and a ready `TlsAcceptor`.
fn tls_materials(san: &str) -> (NamedTempFile, TlsAcceptor) {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, KeyUsagePurpose};

    let ca_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("ca key");
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    let ca_cert = ca_params.self_signed(&ca_key).expect("self-signed ca");
    let issuer = Issuer::new(ca_params, ca_key);

    let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("leaf key");
    let leaf_params = CertificateParams::new(vec![san.to_string()]).expect("leaf params");
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &issuer)
        .expect("signed leaf");

    let mut ca_file = NamedTempFile::new().expect("ca bundle file");
    ca_file
        .write_all(ca_cert.pem().as_bytes())
        .expect("write ca bundle");
    ca_file.flush().expect("flush ca bundle");

    let certs = rustls_pemfile::certs(&mut leaf_cert.pem().as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .expect("parse leaf certificate");
    let key = rustls_pemfile::private_key(&mut leaf_key.serialize_pem().as_bytes())
        .expect("parse leaf key")
        .expect("leaf key present");
    let server_config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("server protocol versions")
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .expect("server config");

    (ca_file, TlsAcceptor::from(Arc::new(server_config)))
}

async fn write_lines<S>(stream: &mut S, lines: &[String])
where
    S: AsyncWrite + Unpin,
{
    let mut payload = String::new();
    for line in lines {
        payload.push_str(line);
        payload.push_str("\r\n");
    }
    let _ = stream.write_all(payload.as_bytes()).await;
    let _ = stream.flush().await;
}

/// Serve one SMTP phase. Returns the unwrapped transport when the client asked
/// for STARTTLS and the script accepted it.
async fn serve_phase<S>(
    stream: S,
    script: Arc<SmtpScript>,
    transcript: Transcript,
    body: Arc<Mutex<String>>,
    tls_active: bool,
    send_greeting: bool,
) -> Option<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut reader = BufReader::new(stream);
    if send_greeting {
        write_lines(&mut reader, &script.greeting).await;
    }
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) | Err(_) => return None,
            Ok(_) => {}
        }
        let received = line.trim_end_matches(['\r', '\n']).to_string();
        let upper = received.to_ascii_uppercase();
        // Record the command, but never the SASL payload — the transcript is
        // read back by assertions and printed on failure.
        let logged = if upper.starts_with("AUTH PLAIN") {
            "AUTH PLAIN <redacted>".to_string()
        } else {
            received.clone()
        };
        transcript
            .lock()
            .expect("transcript lock")
            .push((tls_active, logged));

        if upper.starts_with("EHLO") {
            let lines = if tls_active {
                &script.ehlo_tls
            } else {
                &script.ehlo_plain
            };
            write_lines(&mut reader, lines).await;
        } else if upper == "STARTTLS" {
            write_lines(&mut reader, &script.starttls).await;
            if script
                .starttls
                .last()
                .is_some_and(|line| line.starts_with("220"))
            {
                return Some(reader.into_inner());
            }
        } else if upper == "AUTH LOGIN" {
            write_lines(&mut reader, &["334 VXNlcm5hbWU6".to_string()]).await;
            line.clear();
            if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
                return None;
            }
            transcript
                .lock()
                .expect("transcript lock")
                .push((tls_active, "<auth-login-username>".to_string()));
            write_lines(&mut reader, &["334 UGFzc3dvcmQ6".to_string()]).await;
            line.clear();
            if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
                return None;
            }
            transcript
                .lock()
                .expect("transcript lock")
                .push((tls_active, "<auth-login-password>".to_string()));
            write_lines(&mut reader, &script.auth).await;
        } else if upper.starts_with("AUTH") {
            write_lines(&mut reader, &script.auth).await;
        } else if upper.starts_with("MAIL FROM") {
            write_lines(&mut reader, &script.mail_from).await;
        } else if upper.starts_with("RCPT TO") {
            write_lines(&mut reader, &script.rcpt_to).await;
        } else if upper == "DATA" {
            write_lines(&mut reader, &script.data).await;
            if script.data.last().is_some_and(|l| l.starts_with("354")) {
                let mut collected = String::new();
                loop {
                    line.clear();
                    match reader.read_line(&mut line).await {
                        Ok(0) | Err(_) => return None,
                        Ok(_) => {}
                    }
                    if line.trim_end_matches(['\r', '\n']) == "." {
                        break;
                    }
                    collected.push_str(&line);
                }
                *body.lock().expect("body lock") = collected;
                write_lines(&mut reader, &script.data_end).await;
            }
        } else if upper == "QUIT" {
            write_lines(&mut reader, &["221 2.0.0 bye".to_string()]).await;
            return None;
        } else {
            write_lines(&mut reader, &["500 5.5.2 unrecognized".to_string()]).await;
        }
    }
}

/// Spawn a one-shot scripted SMTP relay.
///
/// `implicit` selects SMTPS (handshake before the greeting); otherwise the
/// relay starts in cleartext and upgrades on STARTTLS.
async fn spawn_smtp_fixture(script: SmtpScript, implicit: bool, san: &str) -> SmtpFixture {
    let (ca_path, acceptor) = tls_materials(san);
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fixture");
    let addr = listener.local_addr().expect("fixture addr");
    let transcript: Transcript = Arc::new(Mutex::new(Vec::new()));
    let body = Arc::new(Mutex::new(String::new()));

    let script = Arc::new(script);
    let task_transcript = Arc::clone(&transcript);
    let task_body = Arc::clone(&body);
    let handle = tokio::spawn(async move {
        let Ok((tcp, _)) = listener.accept().await else {
            return;
        };
        if implicit {
            let Ok(tls) = acceptor.accept(tcp).await else {
                return;
            };
            let _ = serve_phase(tls, script, task_transcript, task_body, true, true).await;
            return;
        }
        let Some(upgraded) = serve_phase(
            tcp,
            Arc::clone(&script),
            Arc::clone(&task_transcript),
            Arc::clone(&task_body),
            false,
            true,
        )
        .await
        else {
            return;
        };
        let Ok(tls) = acceptor.accept(upgraded).await else {
            return;
        };
        let _ = serve_phase(tls, script, task_transcript, task_body, true, false).await;
    });

    SmtpFixture {
        addr,
        ca_path,
        transcript,
        body,
        handle,
    }
}

#[tokio::test]
async fn starttls_delivery_authenticates_only_inside_tls() {
    let fixture = spawn_smtp_fixture(SmtpScript::starttls_default(), false, "localhost").await;
    let channel = parse_email(fixture.channel_def(json!({
        "username": SMTP_USERNAME,
        "password": SMTP_PASSWORD
    })));

    channel
        .dispatch(
            &notification(EventAction::Trigger),
            &client_with_ca(fixture.ca_path()),
        )
        .await
        .expect("STARTTLS delivery succeeds");

    let cleartext = fixture.cleartext_commands();
    assert!(
        cleartext
            .iter()
            .all(|line| line.to_ascii_uppercase().starts_with("EHLO")
                || line.eq_ignore_ascii_case("STARTTLS")),
        "only EHLO/STARTTLS may precede TLS: {cleartext:?}"
    );
    assert!(fixture.saw("AUTH"), "AUTH must be attempted");
    assert!(fixture.saw("MAIL FROM"), "envelope must be sent");
    assert!(fixture.saw("RCPT TO"));
    assert!(fixture.saw("DATA"));

    // A second EHLO is mandatory after the upgrade (RFC 3207 §4.2).
    let ehlo_after_tls = fixture
        .received()
        .iter()
        .filter(|(tls, line)| *tls && line.to_ascii_uppercase().starts_with("EHLO"))
        .count();
    assert_eq!(ehlo_after_tls, 1, "must re-EHLO inside TLS");

    let body = fixture.body.lock().expect("body lock").clone();
    assert!(body.contains("Subject: [high]"), "{body}");
    fixture.handle.abort();
}

#[tokio::test]
async fn implicit_tls_delivery_succeeds_with_auth_login() {
    let mut script = SmtpScript::implicit_default();
    script.ehlo_plain = vec!["250-fixture".to_string(), "250 AUTH LOGIN".to_string()];
    script.ehlo_tls = script.ehlo_plain.clone();
    let fixture = spawn_smtp_fixture(script, true, "localhost").await;

    let channel = parse_email(fixture.channel_def(json!({
        "tls_mode": "implicit_tls",
        "username": SMTP_USERNAME,
        "password": SMTP_PASSWORD
    })));

    channel
        .dispatch(
            &notification(EventAction::Trigger),
            &client_with_ca(fixture.ca_path()),
        )
        .await
        .expect("implicit TLS delivery succeeds");

    assert!(
        fixture.cleartext_commands().is_empty(),
        "SMTPS carries nothing in the clear"
    );
    assert!(fixture.saw("AUTH LOGIN"));
    assert!(fixture.saw("DATA"));
    fixture.handle.abort();
}

#[tokio::test]
async fn trigger_and_resolve_both_dispatch_through_the_channel_enum() {
    for action in [EventAction::Trigger, EventAction::Resolve] {
        let fixture = spawn_smtp_fixture(SmtpScript::starttls_default(), false, "localhost").await;
        let channel =
            NotificationChannel::Email(Box::new(parse_email(fixture.channel_def(json!({})))));
        let mut extras = HashMap::new();
        extras.insert("rule_name".to_string(), "proxy_5xx".to_string());

        channel
            .dispatch_with_vars(
                &notification(action),
                &extras,
                &client_with_ca(fixture.ca_path()),
            )
            .await
            .unwrap_or_else(|e| panic!("{action:?} dispatch failed: {e}"));

        let body = fixture.body.lock().expect("body lock").clone();
        assert!(
            body.contains(&format!(
                "X-Ferrum-Notification-Event-Action: {}",
                match action {
                    EventAction::Trigger => "trigger",
                    EventAction::Resolve => "resolve",
                    EventAction::Info => "info",
                }
            )),
            "{body}"
        );
        assert!(!fixture.saw("AUTH"), "no credentials configured");
        fixture.handle.abort();
    }
}

#[tokio::test]
async fn missing_starttls_advertisement_fails_closed() {
    let mut script = SmtpScript::starttls_default();
    script.ehlo_plain = vec!["250-fixture".to_string(), "250 AUTH PLAIN".to_string()];
    let fixture = spawn_smtp_fixture(script, false, "localhost").await;

    let channel = parse_email(fixture.channel_def(json!({
        "username": SMTP_USERNAME,
        "password": SMTP_PASSWORD
    })));
    let error = channel
        .dispatch(
            &notification(EventAction::Trigger),
            &client_with_ca(fixture.ca_path()),
        )
        .await
        .expect_err("must refuse to continue in cleartext");

    assert!(error.contains("did not advertise STARTTLS"), "{error}");
    assert!(
        !fixture.saw("AUTH"),
        "credentials must not leave the process"
    );
    assert!(!fixture.saw("MAIL FROM"), "no cleartext envelope");
    fixture.handle.abort();
}

#[tokio::test]
async fn tls_handshake_failure_is_reported_without_downgrading() {
    // Leaf certificate is issued for a name the channel does not expect.
    let fixture = spawn_smtp_fixture(SmtpScript::starttls_default(), false, "other.test").await;
    let channel = parse_email(fixture.channel_def(json!({
        "username": SMTP_USERNAME,
        "password": SMTP_PASSWORD
    })));

    let error = channel
        .dispatch(
            &notification(EventAction::Trigger),
            &client_with_ca(fixture.ca_path()),
        )
        .await
        .expect_err("verification must fail");

    assert!(error.contains("TLS handshake failed"), "{error}");
    assert!(!fixture.saw("AUTH"));
    fixture.handle.abort();
}

#[tokio::test]
async fn untrusted_certificate_is_rejected_even_though_the_host_answers() {
    // A CA bundle that does not contain the fixture's issuer.
    let (unrelated_ca, _acceptor) = tls_materials("localhost");
    let fixture = spawn_smtp_fixture(SmtpScript::starttls_default(), false, "localhost").await;
    let channel = parse_email(fixture.channel_def(json!({})));

    let error = channel
        .dispatch(
            &notification(EventAction::Trigger),
            &client_with_ca(unrelated_ca.path().to_str().expect("ca path")),
        )
        .await
        .expect_err("unknown issuer must fail");
    assert!(error.contains("TLS handshake failed"), "{error}");
    fixture.handle.abort();
}

#[tokio::test]
async fn authentication_failure_is_sanitized() {
    let mut script = SmtpScript::starttls_default();
    script.auth = vec!["535 5.7.8 authentication credentials invalid".to_string()];
    let fixture = spawn_smtp_fixture(script, false, "localhost").await;

    let channel = parse_email(fixture.channel_def(json!({
        "username": SMTP_USERNAME,
        "password": SMTP_PASSWORD
    })));
    let error = channel
        .dispatch(
            &notification(EventAction::Trigger),
            &client_with_ca(fixture.ca_path()),
        )
        .await
        .expect_err("auth failure must surface");

    assert!(error.contains("535"), "{error}");
    assert!(error.contains("authentication"), "{error}");
    assert!(error.contains("reply text withheld"), "{error}");
    assert!(!error.contains(SMTP_PASSWORD), "password leaked: {error}");
    assert!(!error.contains(SMTP_USERNAME), "username leaked: {error}");
    assert!(
        !error.contains("credentials invalid"),
        "server text leaked: {error}"
    );
    assert!(
        !fixture.saw("MAIL FROM"),
        "envelope must not follow a failed AUTH"
    );
    fixture.handle.abort();
}

#[tokio::test]
async fn missing_auth_mechanism_fails_closed_when_credentials_are_configured() {
    let mut script = SmtpScript::starttls_default();
    script.ehlo_tls = vec!["250-fixture".to_string(), "250 SIZE 1000".to_string()];
    let fixture = spawn_smtp_fixture(script, false, "localhost").await;

    let channel = parse_email(fixture.channel_def(json!({
        "username": SMTP_USERNAME,
        "password": SMTP_PASSWORD
    })));
    let error = channel
        .dispatch(
            &notification(EventAction::Trigger),
            &client_with_ca(fixture.ca_path()),
        )
        .await
        .expect_err("no mechanism must fail");

    assert!(error.contains("no supported AUTH mechanism"), "{error}");
    assert!(!fixture.saw("MAIL FROM"));
    fixture.handle.abort();
}

#[tokio::test]
async fn rejected_recipient_and_rejected_message_are_reported_by_code_only() {
    let mut script = SmtpScript::starttls_default();
    script.rcpt_to = vec!["550 5.1.1 no such user <oncall@example.com>".to_string()];
    let fixture = spawn_smtp_fixture(script, false, "localhost").await;
    let channel = parse_email(fixture.channel_def(json!({})));

    let error = channel
        .dispatch(
            &notification(EventAction::Trigger),
            &client_with_ca(fixture.ca_path()),
        )
        .await
        .expect_err("rejected recipient must fail the send");
    assert!(error.contains("550"), "{error}");
    assert!(error.contains("RCPT TO"), "{error}");
    assert!(
        !error.contains("no such user"),
        "server text leaked: {error}"
    );
    fixture.handle.abort();

    let mut script = SmtpScript::starttls_default();
    script.data_end = vec!["554 5.3.0 message content rejected".to_string()];
    let fixture = spawn_smtp_fixture(script, false, "localhost").await;
    let channel = parse_email(fixture.channel_def(json!({})));
    let error = channel
        .dispatch(
            &notification(EventAction::Trigger),
            &client_with_ca(fixture.ca_path()),
        )
        .await
        .expect_err("rejected message must fail the send");
    assert!(error.contains("554"), "{error}");
    assert!(!error.contains("content rejected"), "{error}");
    fixture.handle.abort();
}

#[tokio::test]
async fn oversized_and_malformed_replies_fail_closed() {
    // Oversized single reply line.
    let mut script = SmtpScript::starttls_default();
    script.greeting = vec![format!("220 {}", "A".repeat(4096))];
    let fixture = spawn_smtp_fixture(script, false, "localhost").await;
    let channel = parse_email(fixture.channel_def(json!({})));
    let error = channel
        .dispatch(
            &notification(EventAction::Trigger),
            &client_with_ca(fixture.ca_path()),
        )
        .await
        .expect_err("oversized reply must fail");
    assert!(error.contains("response bounds"), "{error}");
    fixture.handle.abort();

    // Too many continuation lines.
    let mut script = SmtpScript::starttls_default();
    let mut flood: Vec<String> = (0..80).map(|i| format!("250-EXT{i}")).collect();
    flood.push("250 STARTTLS".to_string());
    script.ehlo_plain = flood;
    let fixture = spawn_smtp_fixture(script, false, "localhost").await;
    let channel = parse_email(fixture.channel_def(json!({})));
    let error = channel
        .dispatch(
            &notification(EventAction::Trigger),
            &client_with_ca(fixture.ca_path()),
        )
        .await
        .expect_err("reply-line flood must fail");
    assert!(error.contains("response bounds"), "{error}");
    fixture.handle.abort();

    // Non-numeric reply code.
    let mut script = SmtpScript::starttls_default();
    script.greeting = vec!["OK fixture ready".to_string()];
    let fixture = spawn_smtp_fixture(script, false, "localhost").await;
    let channel = parse_email(fixture.channel_def(json!({})));
    let error = channel
        .dispatch(
            &notification(EventAction::Trigger),
            &client_with_ca(fixture.ca_path()),
        )
        .await
        .expect_err("malformed reply must fail");
    assert!(error.contains("malformed SMTP reply"), "{error}");
    fixture.handle.abort();

    // Continuation lines that change the reply code mid-reply.
    let mut script = SmtpScript::starttls_default();
    script.ehlo_plain = vec![
        "250-fixture".to_string(),
        "500-STARTTLS".to_string(),
        "250 8BITMIME".to_string(),
    ];
    let fixture = spawn_smtp_fixture(script, false, "localhost").await;
    let channel = parse_email(fixture.channel_def(json!({})));
    let error = channel
        .dispatch(
            &notification(EventAction::Trigger),
            &client_with_ca(fixture.ca_path()),
        )
        .await
        .expect_err("inconsistent codes must fail");
    assert!(error.contains("malformed SMTP reply"), "{error}");
    fixture.handle.abort();
}

#[tokio::test]
async fn multiline_greeting_and_ehlo_are_accepted() {
    let mut script = SmtpScript::starttls_default();
    script.greeting = vec![
        "220-fixture ESMTP ready".to_string(),
        "220-this relay is monitored".to_string(),
        "220 proceed".to_string(),
    ];
    let fixture = spawn_smtp_fixture(script, false, "localhost").await;
    let channel = parse_email(fixture.channel_def(json!({})));

    channel
        .dispatch(
            &notification(EventAction::Trigger),
            &client_with_ca(fixture.ca_path()),
        )
        .await
        .expect("multiline replies are legal SMTP");
    assert!(fixture.saw("DATA"));
    fixture.handle.abort();
}

#[tokio::test]
async fn a_reply_that_echoes_credential_material_aborts_the_session() {
    let mut script = SmtpScript::starttls_default();
    script.auth = vec![format!("535 5.7.8 rejected password {SMTP_PASSWORD}")];
    let fixture = spawn_smtp_fixture(script, false, "localhost").await;

    let channel = parse_email(fixture.channel_def(json!({
        "username": SMTP_USERNAME,
        "password": SMTP_PASSWORD
    })));
    let error = channel
        .dispatch(
            &notification(EventAction::Trigger),
            &client_with_ca(fixture.ca_path()),
        )
        .await
        .expect_err("credential-reflecting reply must abort");

    assert!(
        error.contains("echoed configured credential material"),
        "{error}"
    );
    assert!(!error.contains(SMTP_PASSWORD), "{error}");
    fixture.handle.abort();
}

#[tokio::test]
async fn a_reply_that_echoes_the_auth_username_is_not_a_credential_leak() {
    let mut script = SmtpScript::starttls_default();
    // SMTP AUTH usernames are normally the mailbox address, and relays routinely
    // echo addresses back (sendmail's classic `250 2.1.0 <sender>... Sender ok`,
    // and the `550 ... <rcpt>` shape used elsewhere in this file). That must not
    // be mistaken for the relay reflecting credential material, or every send
    // from a `username == from` configuration would abort at MAIL FROM.
    script.mail_from = vec![format!("250 2.1.0 <{SMTP_USERNAME}>... Sender ok")];
    let fixture = spawn_smtp_fixture(script, false, "localhost").await;

    let channel = parse_email(fixture.channel_def(json!({
        "username": SMTP_USERNAME,
        "password": SMTP_PASSWORD
    })));
    channel
        .dispatch(
            &notification(EventAction::Trigger),
            &client_with_ca(fixture.ca_path()),
        )
        .await
        .expect("an echoed address is not a credential reflection");

    assert!(fixture.saw("DATA"), "delivery must reach the DATA phase");
    fixture.handle.abort();
}

#[tokio::test]
async fn command_timeout_bounds_a_silent_relay() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let handle = tokio::spawn(async move {
        // Accept and then never speak: the greeting read must time out.
        let _accepted = listener.accept().await;
        std::future::pending::<()>().await;
    });
    let (ca_file, _acceptor) = tls_materials("localhost");

    let mut def = minimal_def(addr.port());
    def["command_timeout_ms"] = json!(200);
    let channel = parse_email(def);
    let error = channel
        .dispatch(
            &notification(EventAction::Trigger),
            &client_with_ca(ca_file.path().to_str().expect("ca path")),
        )
        .await
        .expect_err("a silent relay must time out");
    assert!(
        error.contains("timed out during server greeting"),
        "{error}"
    );
    handle.abort();
}

#[tokio::test]
async fn a_relay_that_hangs_up_early_is_reported() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let handle = tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            drop(stream);
        }
    });
    let (ca_file, _acceptor) = tls_materials("localhost");

    let channel = parse_email(minimal_def(addr.port()));
    let error = channel
        .dispatch(
            &notification(EventAction::Trigger),
            &client_with_ca(ca_file.path().to_str().expect("ca path")),
        )
        .await
        .expect_err("an early close must fail the send");
    assert!(error.contains("closed the connection"), "{error}");
    handle.abort();
}

#[test]
fn startup_diagnostics_withhold_email_names_and_numeric_scalars() {
    let secret = "'diagnostic-secret-5594`\"\\\n";
    for (field, value, hidden) in [
        ("tls_mode", json!(secret), "diagnostic-secret-5594"),
        ("tls_server_name", json!(secret), "diagnostic-secret-5594"),
        ("smtp_port", json!(987654321), "987654321"),
        ("connect_timeout_ms", json!(987654321), "987654321"),
        ("command_timeout_ms", json!(987654321), "987654321"),
        ("smtp_port", json!(true), "true"),
    ] {
        let mut config = minimal_def(587);
        config[field] = value;
        let error = parse_error(config);
        let rendered = ferrum_edge::startup::render_startup_error(anyhow::Error::msg(error), &[]);
        assert!(rendered.contains(&format!("`{field}`")), "{rendered}");
        assert!(!rendered.contains(hidden), "{rendered}");
        assert!(
            !rendered.contains("diagnostic_secret_5594"),
            "normalized TLS-mode operand must also be withheld: {rendered}"
        );
        if field == "tls_mode" {
            assert!(rendered.contains("unknown `tls_mode`"), "{rendered}");
        }
        assert!(!rendered.contains("ops_email"), "{rendered}");
    }

    let mut config = minimal_def(587);
    config["subject_template"] = json!("'diagnostic-secret-5594${unclosed");
    let error = parse_error(config);
    let rendered = ferrum_edge::startup::render_startup_error(anyhow::Error::msg(error), &[]);
    assert!(rendered.contains("`subject_template`"), "{rendered}");
    assert!(
        rendered.contains("unbalanced `${` starting at byte offset"),
        "{rendered}"
    );
    assert!(!rendered.contains("diagnostic-secret-5594"), "{rendered}");
}

#[test]
fn startup_diagnostics_preserve_empty_credential_env_field() {
    let channel = "'ChannelName5594`\"\\\n";
    let env_name = "'EnvName5594`\"\\\n";
    for (key, env_key) in [("username", "username_env"), ("password", "password_env")] {
        let mut config = minimal_def(587);
        config["username"] = json!(SMTP_USERNAME);
        config["password"] = json!(SMTP_PASSWORD);
        config.as_object_mut().unwrap().remove(key);
        config[env_key] = json!(env_name);
        let mut env = HashMap::from([(env_name.to_string(), "ResolvedValue5594".to_string())]);
        ferrum_edge::_test_support::email_channel_new_with_env_for_test(channel, &config, &env)
            .expect("non-empty injected credentials must still be admitted");
        env.insert(env_name.to_string(), String::new());
        let error =
            ferrum_edge::_test_support::email_channel_new_with_env_for_test(channel, &config, &env)
                .expect_err("empty injected credentials must still be rejected");
        let rendered = ferrum_edge::startup::render_startup_error(anyhow::Error::msg(error), &[]);
        assert!(
            rendered.contains(&format!("referenced by `{env_key}`")),
            "{rendered}"
        );
        assert!(rendered.contains("resolved to empty string"), "{rendered}");
        for hidden in ["ChannelName5594", "EnvName5594", "ResolvedValue5594"] {
            assert!(!rendered.contains(hidden), "{rendered}");
        }
    }
}

#[test]
fn smtp_host_diagnostics_keep_channel_schema_without_supplied_names() {
    let name = "UNREGISTERED_EMAIL_NAME";
    let config = json!({
        name: {
            "type": "email",
            "smtp_host": "https://UNREGISTERED_SMTP_HOST.invalid",
            "from": "ferrum@example.com",
            "to": ["oncall@example.com"]
        }
    });
    let error = parse_channels(&config).expect_err("URL host must be rejected");
    let rendered = ferrum_edge::startup::render_startup_error(anyhow::Error::msg(error), &[]);
    for expected in ["`channels`", "email", "`smtp_host`", "scheme"] {
        assert!(rendered.contains(expected), "{rendered}");
    }
    for withheld in ["UNREGISTERED_EMAIL_NAME", "UNREGISTERED_SMTP_HOST"] {
        assert!(!rendered.contains(withheld), "{rendered}");
    }
}
