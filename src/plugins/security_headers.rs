//! Security Headers Plugin
//!
//! Hardens responses by injecting common security headers and stripping
//! fingerprinting headers the backend may have set. Runs in the response band
//! (`after_proxy`) so it applies to every proxied response regardless of the
//! backend's own header hygiene.
//!
//! Secure-by-default: simply enabling the plugin adds `X-Content-Type-Options`,
//! `X-Frame-Options`, and `Referrer-Policy`, and removes `Server` /
//! `X-Powered-By`. HSTS, CSP, and Permissions-Policy are opt-in because they
//! are deployment- or app-specific (HSTS requires HTTPS; CSP must match the
//! app). Operators can add or remove arbitrary headers via `set` / `remove`.

use async_trait::async_trait;
use http::header::{HeaderName, HeaderValue};
use serde_json::Value;
use std::collections::{HashMap, HashSet};

use crate::util::http_headers::{cache_control_has_directive, etag_value_is_strong};

use super::{HTTP_FAMILY_PROTOCOLS, Plugin, PluginResult, ProxyProtocol, RequestContext};

/// Most `set` entries one instance accepts.
pub const MAX_SET_ENTRIES: usize = 64;
/// Most `remove` names one instance accepts.
pub const MAX_REMOVE_ENTRIES: usize = 64;
/// Longest configured header value, in bytes. Every value is emitted on every
/// response the policy covers, so an oversized one is a permanent
/// per-response cost and can exceed a peer's response-header limit.
pub const MAX_HEADER_VALUE_BYTES: usize = 8192;

/// Representation metadata the gateway's response pipeline decides from.
///
/// Content-type-selective body inspection (`waf`, `body_validator`, AI
/// response guards), compression, and range handling read these fields before
/// `after_proxy` runs, and this plugin does not declare
/// `may_modify_response_content_type`. A `set` or `remove` here would relabel
/// (or unlabel, inviting browser sniffing) a body those decisions already
/// classified under the backend's value, so the names are refused at
/// admission instead. Values are canonical lowercase `HeaderName`s.
const REPRESENTATION_MANAGED_DESTINATIONS: [&str; 3] =
    ["content-type", "content-encoding", "content-range"];

/// Built-in security headers whose backend value a browser either acts on or
/// ignores entirely. With `override_existing: false` only a backend copy that
/// a browser would ignore entirely fails to satisfy the policy; any value a
/// browser acts on — even a different or weaker-looking one than the
/// configured default — is kept.
#[derive(Debug, Clone, Copy)]
enum ManagedHeader {
    ContentTypeOptions,
    FrameOptions,
    ReferrerPolicy,
    StrictTransportSecurity,
    ContentSecurityPolicy,
    PermissionsPolicy,
}

impl ManagedHeader {
    /// `name` is a canonical lowercase `HeaderName`.
    fn for_name(name: &str) -> Option<Self> {
        match name {
            "x-content-type-options" => Some(Self::ContentTypeOptions),
            "x-frame-options" => Some(Self::FrameOptions),
            "referrer-policy" => Some(Self::ReferrerPolicy),
            "strict-transport-security" => Some(Self::StrictTransportSecurity),
            "content-security-policy" => Some(Self::ContentSecurityPolicy),
            "permissions-policy" => Some(Self::PermissionsPolicy),
            _ => None,
        }
    }

    /// Whether a browser acts on a backend `value` for this header.
    ///
    /// These follow the browser processing algorithms, NOT the strict
    /// configuration-admission checks: admission refuses anything a browser
    /// might not honor, while this keeps anything a browser might honor, so an
    /// effective backend protection is never replaced by a weaker default.
    fn browser_honors(self, value: &str) -> bool {
        match self {
            Self::ContentTypeOptions => backend_nosniff_is_effective(value),
            Self::FrameOptions => backend_frame_options_is_effective(std::iter::once(value)),
            Self::ReferrerPolicy => backend_referrer_policy_is_effective(value),
            Self::StrictTransportSecurity => backend_hsts_is_effective(value),
            Self::ContentSecurityPolicy | Self::PermissionsPolicy => !trim_ows(value).is_empty(),
        }
    }
}

fn trim_ows(text: &str) -> &str {
    text.trim_matches([' ', '\t'])
}

/// Fetch "determine nosniff": the first comma-separated value is an ASCII
/// case-insensitive `nosniff`.
fn backend_nosniff_is_effective(value: &str) -> bool {
    value
        .split(',')
        .next()
        .is_some_and(|first| trim_ows(first).eq_ignore_ascii_case("nosniff"))
}

/// HTML X-Frame-Options processing: the comma-separated values form an ASCII
/// case-insensitive set. A set of several distinct values blocks framing when
/// it contains `deny`, `sameorigin`, or `allowall` (a conflict is treated as
/// a denial); otherwise it is ignored. A single value is enforced only when it
/// is `deny` or `sameorigin`. Repeated `DENY, DENY` and conflicting
/// `DENY, SAMEORIGIN` therefore both still protect.
fn backend_frame_options_is_effective<'a>(values: impl Iterator<Item = &'a str>) -> bool {
    fn is_framing_directive(token: &str) -> bool {
        token.eq_ignore_ascii_case("deny") || token.eq_ignore_ascii_case("sameorigin")
    }
    let mut first: Option<&str> = None;
    let mut distinct = false;
    let mut recognized = false;
    for token in values.flat_map(|value| value.split(',')).map(trim_ows) {
        recognized |= is_framing_directive(token) || token.eq_ignore_ascii_case("allowall");
        match first {
            None => first = Some(token),
            Some(seen) => distinct |= !seen.eq_ignore_ascii_case(token),
        }
    }
    if distinct {
        recognized
    } else {
        first.is_some_and(is_framing_directive)
    }
}

/// Referrer Policy "parse a referrer policy from a header": the last
/// recognized non-empty token wins and unknown or empty tokens are skipped, so
/// the field is effective when any token is a known policy.
fn backend_referrer_policy_is_effective(value: &str) -> bool {
    value.split(',').map(trim_ows).any(|token| {
        REFERRER_POLICY_TOKENS
            .iter()
            .any(|known| token.eq_ignore_ascii_case(known))
    })
}

/// A user agent ignores a Strict-Transport-Security field without exactly one
/// `max-age` carrying `delta-seconds` (RFC 6797 §6.1). Other directive syntax
/// is deliberately not judged here: when in doubt the backend value is kept.
fn backend_hsts_is_effective(value: &str) -> bool {
    let mut max_age: Option<bool> = None;
    for directive in backend_hsts_directives(value) {
        let (name, argument) = match directive.split_once('=') {
            Some((name, argument)) => (trim_ows(name), Some(trim_ows(argument))),
            None => (trim_ows(directive), None),
        };
        if !name.eq_ignore_ascii_case("max-age") {
            continue;
        }
        if max_age.is_some() {
            return false;
        }
        max_age = Some(argument.is_some_and(is_delta_seconds));
    }
    max_age == Some(true)
}

/// Split only at unquoted semicolons. A quoted-pair consumes the next
/// character, so an escaped quote cannot expose extension text as directives.
/// Backend extensions are deliberately more permissive than config admission.
fn backend_hsts_directives(value: &str) -> impl Iterator<Item = &str> {
    let mut quoted = false;
    let mut escaped = false;
    value.split(move |character| {
        if escaped {
            escaped = false;
            return false;
        }
        match character {
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            ';' if !quoted => return true,
            _ => {}
        }
        false
    })
}

/// `1*DIGIT`, optionally as a quoted string.
fn is_delta_seconds(argument: &str) -> bool {
    let seconds = argument
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .unwrap_or(argument);
    !seconds.is_empty() && seconds.bytes().all(|b| b.is_ascii_digit())
}

#[derive(Debug)]
struct SetEntry {
    /// Canonical lowercase header name.
    name: String,
    value: String,
    /// Browser-recognition check for a built-in header name; `None` for an
    /// arbitrary header, which keeps pure presence semantics.
    managed: Option<ManagedHeader>,
}

impl SetEntry {
    fn new(name: String, value: String) -> Self {
        let managed = ManagedHeader::for_name(&name);
        Self {
            name,
            value,
            managed,
        }
    }
}

/// What a response already carries for one `set` name.
enum ExistingValue {
    Absent,
    /// The backend field is effective (any copy, for an arbitrary header).
    Satisfies,
    /// Several spellings of an order-sensitive field must collapse to this
    /// effective backend copy, identified by its exact map key.
    Collapse(String),
    /// The backend field is ignored entirely under this header's processing
    /// rules (empty, or syntactically ineffective).
    Ignored,
}

#[derive(Debug)]
pub struct SecurityHeaders {
    /// Headers applied to every response, names unique.
    set: Vec<SetEntry>,
    /// Header names (lowercase) to strip from the response.
    remove: Vec<String>,
    /// Unique canonical names touched by `set` or `remove`, precomputed for
    /// buffered initial-header provenance tracking.
    policy_header_names: Vec<String>,
    /// When false, only add a header if the backend did not already set an
    /// acceptable value for it.
    override_existing: bool,
}

impl SecurityHeaders {
    pub fn new(config: &Value) -> Result<Self, String> {
        let object = config
            .as_object()
            .ok_or_else(|| "security_headers: config must be an object".to_string())?;
        reject_unknown_keys(
            object,
            "security_headers",
            &[
                "content_type_options",
                "frame_options",
                "referrer_policy",
                "hsts",
                "content_security_policy",
                "permissions_policy",
                "set",
                "remove",
                "override_existing",
            ],
        )?;

        let override_existing = parse_bool(object, "override_existing", true)?;

        // Built-in headers with secure defaults. Each can be disabled with
        // `false`/`null` or customized with an explicit value.
        let mut set: Vec<SetEntry> = Vec::new();

        if let Some(value) = header_value(object, "content_type_options", "nosniff", true)? {
            set.push(SetEntry::new("x-content-type-options".to_string(), value));
        }
        if let Some(value) = header_value(object, "frame_options", "SAMEORIGIN", true)? {
            set.push(SetEntry::new("x-frame-options".to_string(), value));
        }
        if let Some(value) = header_value(
            object,
            "referrer_policy",
            "strict-origin-when-cross-origin",
            true,
        )? {
            set.push(SetEntry::new("referrer-policy".to_string(), value));
        }
        // Opt-in headers: default disabled (no value unless configured).
        if let Some(value) = parse_hsts(object)? {
            set.push(SetEntry::new(
                "strict-transport-security".to_string(),
                value,
            ));
        }
        if let Some(value) = optional_header(object, "content_security_policy")? {
            set.push(SetEntry::new("content-security-policy".to_string(), value));
        }
        if let Some(value) = optional_header(object, "permissions_policy")? {
            set.push(SetEntry::new("permissions-policy".to_string(), value));
        }

        // Arbitrary operator-defined headers. A later `set` entry overrides an
        // earlier built-in (or an earlier case variant) of the same canonical
        // name; the index keeps construction linear in the entry count.
        let mut positions: HashMap<String, usize> = set
            .iter()
            .enumerate()
            .map(|(position, entry)| (entry.name.clone(), position))
            .collect();
        for (name, value) in parse_set_map(object)? {
            if let Some(&position) = positions.get(&name) {
                set[position].value = value;
            } else {
                positions.insert(name.clone(), set.len());
                set.push(SetEntry::new(name, value));
            }
        }

        let remove = parse_remove(object)?;

        if set.is_empty() && remove.is_empty() {
            return Err(
                "security_headers: no headers to set or remove — configure at least one, or remove the plugin".to_string(),
            );
        }

        let policy_header_names = unique_policy_header_names(&remove, &set);

        Ok(Self {
            set,
            remove,
            policy_header_names,
            override_existing,
        })
    }

    fn apply(&self, headers: &mut HashMap<String, String>) {
        // One pass over the response map drops every case-insensitive copy of
        // a removed name and, when overriding, of every set name. `set` names
        // are unique, and `policy_header_names` is exactly `remove` ∪ `set`.
        let dropped: &[String] = if self.override_existing {
            &self.policy_header_names
        } else {
            &self.remove
        };
        if !dropped.is_empty() {
            headers.retain(|key, _| !dropped.iter().any(|name| key.eq_ignore_ascii_case(name)));
        }
        for entry in &self.set {
            if self.override_existing {
                headers.insert(entry.name.clone(), entry.value.clone());
                continue;
            }
            match existing_value(headers, entry) {
                ExistingValue::Satisfies => {}
                ExistingValue::Collapse(key) => {
                    // The classifier selected a key from this unchanged map.
                    // Move its value rather than cloning a backend field.
                    if let Some(value) = headers.remove(&key) {
                        headers.retain(|key, _| !key.eq_ignore_ascii_case(&entry.name));
                        headers.insert(entry.name.clone(), value);
                    }
                }
                ExistingValue::Absent => {
                    headers.insert(entry.name.clone(), entry.value.clone());
                }
                ExistingValue::Ignored => {
                    // A value the browser drops protects nothing: replace every
                    // case variant with the configured one.
                    headers.retain(|key, _| !key.eq_ignore_ascii_case(&entry.name));
                    headers.insert(entry.name.clone(), entry.value.clone());
                }
            }
        }
    }
}

#[async_trait]
impl Plugin for SecurityHeaders {
    fn name(&self) -> &str {
        "security_headers"
    }

    fn priority(&self) -> u16 {
        super::priority::SECURITY_HEADERS
    }

    fn lifecycle_hooks(&self) -> crate::plugins::PluginHooks {
        crate::plugins::PluginHooks::AFTER_PROXY
    }

    fn supported_protocols(&self) -> &'static [ProxyProtocol] {
        HTTP_FAMILY_PROTOCOLS
    }

    async fn after_proxy(
        &self,
        _ctx: &mut RequestContext,
        _response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        self.apply(response_headers);
        PluginResult::Continue
    }

    fn is_initial_response_header_policy(&self) -> bool {
        true
    }

    fn apply_initial_response_header_policy(&self, response_headers: &mut HashMap<String, String>) {
        self.apply(response_headers);
    }

    fn initial_response_header_policy_names(&self) -> &[String] {
        &self.policy_header_names
    }

    /// A configured `remove` is a policy decision about the FIELD, not about
    /// the header section that happened to carry it: a backend that sends the
    /// same name as a trailer would otherwise reintroduce exactly what the
    /// policy suppressed, and the removal is a no-op on the initial map in that
    /// case, so no observed-mutation diff can catch it. `set` names are
    /// declared for the same reason — a trailer copy would leave the client
    /// holding two conflicting values for a header the gateway owns.
    fn response_trailer_policy(&self) -> super::ResponseTrailerPolicy<'_> {
        super::ResponseTrailerPolicy::Names(&self.policy_header_names)
    }

    fn may_add_response_cache_control_no_transform(
        &self,
        _ctx: &RequestContext,
        _response_headers: &HashMap<String, String>,
    ) -> bool {
        self.set.iter().any(|entry| {
            entry.name == "cache-control"
                && cache_control_has_directive(&entry.value, "no-transform")
        })
    }

    fn may_add_response_strong_etag(
        &self,
        _ctx: &RequestContext,
        _response_headers: &HashMap<String, String>,
    ) -> bool {
        self.set
            .iter()
            .any(|entry| entry.name == "etag" && etag_value_is_strong(&entry.value))
    }

    fn simulate_after_proxy_response_headers(
        &self,
        _ctx: &mut RequestContext,
        response_headers: &mut HashMap<String, String>,
    ) {
        self.apply(response_headers);
    }

    fn applies_after_proxy_on_reject(&self) -> bool {
        true
    }
}

/// Classify every case-insensitive copy of `entry.name` already in the map.
///
/// X-Frame-Options is evaluated across the combined field, since individually
/// ignored copies can jointly block framing. STS and nosniff instead need one
/// effective copy: retaining ignored siblings makes their first/combined wire
/// value depend on unordered map iteration. Other headers retain presence or
/// per-copy recognition semantics.
fn existing_value(headers: &HashMap<String, String>, entry: &SetEntry) -> ExistingValue {
    let mut copies = headers
        .iter()
        .filter(|(key, _)| key.eq_ignore_ascii_case(&entry.name))
        .peekable();
    if copies.peek().is_none() {
        return ExistingValue::Absent;
    }
    let Some(managed) = entry.managed else {
        return ExistingValue::Satisfies;
    };
    if matches!(managed, ManagedHeader::FrameOptions) {
        return if backend_frame_options_is_effective(copies.map(|(_, value)| value.as_str())) {
            ExistingValue::Satisfies
        } else {
            ExistingValue::Ignored
        };
    }
    if matches!(
        managed,
        ManagedHeader::ContentTypeOptions | ManagedHeader::StrictTransportSecurity
    ) && copies.clone().nth(1).is_some()
    {
        // The map has no backend wire order. Choose the bytewise first
        // effective spelling so normalization is deterministic, and allocate
        // only the small key on this duplicate-field path.
        return match copies
            .filter(|(_, value)| managed.browser_honors(value))
            .min_by(|(left, _), (right, _)| left.cmp(right))
        {
            Some((key, _)) => ExistingValue::Collapse(key.clone()),
            None => ExistingValue::Ignored,
        };
    }
    if copies.any(|(_, value)| managed.browser_honors(value)) {
        return ExistingValue::Satisfies;
    }
    ExistingValue::Ignored
}

/// `remove` ∪ `set` names in first-seen order, deduplicated in one pass.
fn unique_policy_header_names(remove: &[String], set: &[SetEntry]) -> Vec<String> {
    let mut seen: HashSet<&str> = HashSet::with_capacity(remove.len() + set.len());
    let mut names = Vec::with_capacity(remove.len() + set.len());
    for name in remove.iter().chain(set.iter().map(|entry| &entry.name)) {
        if seen.insert(name.as_str()) {
            names.push(name.clone());
        }
    }
    names
}

/// Gateway-owned response destinations `set` and `remove` may not name:
/// protocol-managed hop-by-hop / framing fields, and representation metadata.
/// `name` is a canonical lowercase `HeaderName`.
fn gateway_owned_destination_reason(name: &str) -> Option<&'static str> {
    if crate::proxy::headers::is_protocol_managed_plugin_response_destination(name) {
        // Framing and connection-control destinations belong to the gateway's
        // final client-wire boundary, not to a static response-header policy.
        // This plugin runs in `after_proxy`, i.e. AFTER the backend hop-by-hop
        // strip and before that boundary, so a `Content-Length` written here
        // is a syntactically valid length the gateway cannot verify against
        // the bytes it will actually write — on an HTTP/1.1 chain that is a
        // request/response desync primitive. Removing one is at best a no-op
        // the boundary re-derives, so it is refused too rather than accepted
        // as a policy that does nothing.
        return Some(
            "is protocol-managed (hop-by-hop or framing) and cannot be configured; the gateway \
             derives Content-Length from the final response body and strips \
             Connection/Transfer-Encoding/Trailer/Upgrade at the final response boundary",
        );
    }
    if REPRESENTATION_MANAGED_DESTINATIONS.contains(&name) {
        return Some(
            "is representation metadata and cannot be configured; content-type-selective body \
             inspection, compression, and range handling decide from the backend's value \
             before this plugin runs, so relabeling or removing it would bypass those decisions",
        );
    }
    None
}

/// Resolve a built-in security header. `key` is the config field; when present
/// and `true` (or absent and `default_on`) the `default_value` is used; an
/// explicit string overrides it; `false`/`null`/`""` disables it.
fn header_value(
    object: &serde_json::Map<String, Value>,
    key: &str,
    default_value: &str,
    default_on: bool,
) -> Result<Option<String>, String> {
    match object.get(key) {
        None => Ok(default_on.then(|| default_value.to_string())),
        Some(Value::Null) => Ok(None),
        Some(Value::Bool(true)) => Ok(Some(default_value.to_string())),
        Some(Value::Bool(false)) => Ok(None),
        Some(Value::String(value)) => {
            if value.is_empty() {
                return Ok(None);
            }
            validate_header_value(key, value)?;
            validate_builtin_tokens(key, value)?;
            Ok(Some(value.clone()))
        }
        Some(other) => Err(format!(
            "security_headers: `{key}` must be a boolean or string, got {other:?}",
            other = other.to_string()
        )),
    }
}

/// `Referrer-Policy` tokens from the W3C Referrer Policy specification.
const REFERRER_POLICY_TOKENS: [&str; 8] = [
    "no-referrer",
    "no-referrer-when-downgrade",
    "origin",
    "origin-when-cross-origin",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
    "unsafe-url",
];

/// Reject a custom value for a built-in header that browsers would ignore.
///
/// A browser drops an unrecognized `X-Content-Type-Options`, `X-Frame-Options`
/// or `Referrer-Policy` value, so a typo such as `SAMEORGIN` would silently
/// remove the protection the operator configured. Tokens compare ASCII
/// case-insensitively and may carry surrounding spaces or tabs, as browsers
/// parse them. `Referrer-Policy` accepts a comma-separated list of known tokens.
fn validate_builtin_tokens(key: &str, value: &str) -> Result<(), String> {
    match builtin_token_expectation(key, value) {
        None => Ok(()),
        Some(expected) => Err(format!(
            "security_headers: `{key}` must be {expected}; browsers ignore any other value"
        )),
    }
}

/// The same check for a `set` entry that names one of those three headers or
/// `Strict-Transport-Security`, so `set` cannot reintroduce a value the
/// built-in option would refuse. `name` is the lowercased `HeaderName`.
fn validate_set_builtin_tokens(name: &str, value: &str) -> Result<(), String> {
    let expected = match name {
        "x-content-type-options" => builtin_token_expectation("content_type_options", value),
        "x-frame-options" => builtin_token_expectation("frame_options", value),
        "referrer-policy" => builtin_token_expectation("referrer_policy", value),
        "strict-transport-security" => (!hsts_value_is_valid(value)).then_some(HSTS_EXPECTATION),
        _ => None,
    };
    match expected {
        None => Ok(()),
        Some(expected) => Err(format!(
            "security_headers: `set` entry {name:?} must be {expected}; browsers ignore any other value"
        )),
    }
}

/// `None` when `value` is acceptable for the built-in `key`, otherwise a
/// description of the accepted values.
fn builtin_token_expectation(key: &str, value: &str) -> Option<&'static str> {
    fn trim(token: &str) -> &str {
        token.trim_matches([' ', '\t'])
    }
    let (valid, expected) = match key {
        "content_type_options" => (trim(value).eq_ignore_ascii_case("nosniff"), "`nosniff`"),
        "frame_options" => {
            let token = trim(value);
            (
                token.eq_ignore_ascii_case("DENY") || token.eq_ignore_ascii_case("SAMEORIGIN"),
                "`DENY` or `SAMEORIGIN`",
            )
        }
        "referrer_policy" => (
            value.split(',').all(|token| {
                let token = trim(token);
                REFERRER_POLICY_TOKENS
                    .iter()
                    .any(|known| token.eq_ignore_ascii_case(known))
            }),
            "a comma-separated list of Referrer-Policy tokens (for example `no-referrer` or `strict-origin-when-cross-origin`)",
        ),
        _ => return None,
    };
    (!valid).then_some(expected)
}

const HSTS_EXPECTATION: &str = "a Strict-Transport-Security value with exactly one \
     `max-age=<seconds>` directive (for example `max-age=31536000; includeSubDomains`), at most \
     one valueless `includeSubDomains`, and `;`-separated token or quoted extension directives";

/// Whether a browser honors `value` as a `Strict-Transport-Security` field
/// (RFC 6797 §6.1).
///
/// A user agent ignores the whole field unless it carries exactly one
/// `max-age` whose value is `delta-seconds` (optionally quoted), so an STS
/// value without one — `includeSubDomains; preload`, `maxage=1`, a bare
/// space — silently provides no downgrade protection. Directive names are
/// ASCII case-insensitive tokens separated by `;` with optional whitespace;
/// `includeSubDomains` is valueless and may appear once; any other directive
/// (`preload`, extensions) is a token with an optional token or quoted value.
/// Quoted values may not contain `"`, `\`, or `;`.
fn hsts_value_is_valid(value: &str) -> bool {
    fn ows(text: &str) -> &str {
        text.trim_matches([' ', '\t'])
    }
    let mut max_age_seen = false;
    let mut include_subdomains_seen = false;
    for directive in value.split(';') {
        let directive = ows(directive);
        if directive.is_empty() {
            continue;
        }
        let (name, argument) = match directive.split_once('=') {
            Some((name, argument)) => (ows(name), Some(ows(argument))),
            None => (directive, None),
        };
        if !is_http_token(name) {
            return false;
        }
        if name.eq_ignore_ascii_case("max-age") {
            let Some(argument) = argument else {
                return false;
            };
            if max_age_seen || !is_delta_seconds(argument) {
                return false;
            }
            max_age_seen = true;
        } else if name.eq_ignore_ascii_case("includesubdomains") {
            if include_subdomains_seen || argument.is_some() {
                return false;
            }
            include_subdomains_seen = true;
        } else if let Some(argument) = argument
            && !(is_http_token(argument) || is_simple_quoted_string(argument))
        {
            return false;
        }
    }
    max_age_seen
}

/// RFC 9110 `token`: one or more `tchar`.
fn is_http_token(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

/// A `"`-delimited value whose content carries no `"` or `\` (the caller has
/// already split on `;` and validated the field-value character set).
fn is_simple_quoted_string(text: &str) -> bool {
    text.len() >= 2
        && text.starts_with('"')
        && text.ends_with('"')
        && !text[1..text.len() - 1]
            .bytes()
            .any(|b| b == b'"' || b == b'\\')
}

fn optional_header(
    object: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<Option<String>, String> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if value.is_empty() => Ok(None),
        Some(Value::String(value)) => {
            validate_header_value(key, value)?;
            Ok(Some(value.clone()))
        }
        Some(other) => Err(format!(
            "security_headers: `{key}` must be a string, got {other:?}",
            other = other.to_string()
        )),
    }
}

/// HSTS accepts `true` (defaults), `false`/absent (disabled), a string (a
/// complete Strict-Transport-Security value; see [`hsts_value_is_valid`]), or
/// an object `{max_age, include_subdomains, preload}`.
fn parse_hsts(object: &serde_json::Map<String, Value>) -> Result<Option<String>, String> {
    match object.get("hsts") {
        None | Some(Value::Null) | Some(Value::Bool(false)) => Ok(None),
        Some(Value::Bool(true)) => Ok(Some("max-age=31536000; includeSubDomains".to_string())),
        Some(Value::String(value)) => {
            if value.is_empty() {
                return Ok(None);
            }
            validate_header_value("hsts", value)?;
            if !hsts_value_is_valid(value) {
                return Err(format!(
                    "security_headers: `hsts` must be {HSTS_EXPECTATION}; browsers ignore any other value"
                ));
            }
            Ok(Some(value.clone()))
        }
        Some(Value::Object(map)) => {
            reject_unknown_keys(
                map,
                "security_headers.hsts",
                &["max_age", "include_subdomains", "preload"],
            )?;
            let max_age = match map.get("max_age") {
                None | Some(Value::Null) => 31_536_000u64,
                Some(Value::Number(n)) => n.as_u64().ok_or_else(|| {
                    "security_headers: `hsts.max_age` must be a non-negative integer".to_string()
                })?,
                Some(_) => {
                    return Err("security_headers: `hsts.max_age` must be an integer".to_string());
                }
            };
            let mut value = format!("max-age={max_age}");
            if parse_bool(map, "include_subdomains", true)? {
                value.push_str("; includeSubDomains");
            }
            if parse_bool(map, "preload", false)? {
                value.push_str("; preload");
            }
            Ok(Some(value))
        }
        Some(other) => Err(format!(
            "security_headers: `hsts` must be a boolean, string, or object, got {other:?}",
            other = other.to_string()
        )),
    }
}

fn parse_set_map(object: &serde_json::Map<String, Value>) -> Result<Vec<(String, String)>, String> {
    match object.get("set") {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Object(map)) => {
            if map.len() > MAX_SET_ENTRIES {
                return Err(format!(
                    "security_headers: `set` accepts at most {MAX_SET_ENTRIES} entries"
                ));
            }
            let mut out = Vec::with_capacity(map.len());
            for (name, value) in map {
                let name = parse_header_name("set", name)?;
                // The check is a case-insensitive predicate over shared closed
                // sets, so `Content-Length`, `CONTENT-LENGTH`, and
                // `content-length` all fail closed identically and this plugin
                // cannot drift from `response_transformer` / `response_mock` /
                // `mesh_route_dispatch` on the protocol-managed names.
                //
                // `name` is already a validated `HeaderName` (lowercased by
                // `HeaderName::as_str`) and, to reach this branch, a member of
                // a compiled-in closed set — so echoing it names the offending
                // setting without reflecting hostile config bytes.
                if let Some(reason) = gateway_owned_destination_reason(&name) {
                    return Err(format!("security_headers: `set` entry {name:?} {reason}"));
                }
                let value = value.as_str().ok_or_else(|| {
                    format!("security_headers: `set` entry {name:?} value must be a string")
                })?;
                validate_header_value("set", value)?;
                validate_set_builtin_tokens(&name, value)?;
                out.push((name, value.to_string()));
            }
            Ok(out)
        }
        Some(other) => Err(format!(
            "security_headers: `set` must be an object, got {other:?}",
            other = other.to_string()
        )),
    }
}

fn parse_remove(object: &serde_json::Map<String, Value>) -> Result<Vec<String>, String> {
    match object.get("remove") {
        None => Ok(vec!["server".to_string(), "x-powered-by".to_string()]),
        Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(values)) => {
            if values.len() > MAX_REMOVE_ENTRIES {
                return Err(format!(
                    "security_headers: `remove` accepts at most {MAX_REMOVE_ENTRIES} entries"
                ));
            }
            let mut out = Vec::with_capacity(values.len());
            for value in values {
                let name = value.as_str().ok_or_else(|| {
                    "security_headers: `remove` entries must be strings".to_string()
                })?;
                let name = parse_header_name("remove", name)?;
                // Same closed sets and same safe echo as `set`.
                if let Some(reason) = gateway_owned_destination_reason(&name) {
                    return Err(format!(
                        "security_headers: `remove` entry {name:?} {reason}"
                    ));
                }
                out.push(name);
            }
            Ok(out)
        }
        Some(other) => Err(format!(
            "security_headers: `remove` must be an array, got {other:?}",
            other = other.to_string()
        )),
    }
}

fn parse_header_name(field: &str, name: &str) -> Result<String, String> {
    HeaderName::from_bytes(name.as_bytes())
        .map(|name| name.as_str().to_string())
        .map_err(|_| {
            format!(
                "security_headers: `{field}` contains invalid HTTP field name {:?}",
                render_invalid_header_name(name)
            )
        })
}

/// Render an untrusted invalid field name without allowing hostile config to
/// inject control characters or create an unbounded validation error.
fn render_invalid_header_name(name: &str) -> String {
    const MAX_RENDERED_BYTES: usize = 96;

    let mut rendered = String::with_capacity(MAX_RENDERED_BYTES + 3);
    let mut chars = name.chars().peekable();
    while let Some(character) = chars.next() {
        let escaped = character.escape_default();
        let escaped_len = escaped.clone().count();
        if rendered.len() + escaped_len > MAX_RENDERED_BYTES {
            rendered.push_str("...");
            break;
        }
        rendered.extend(escaped);
        if rendered.len() == MAX_RENDERED_BYTES && chars.peek().is_some() {
            rendered.push_str("...");
            break;
        }
    }
    rendered
}

fn validate_header_value(key: &str, value: &str) -> Result<(), String> {
    if value.len() > MAX_HEADER_VALUE_BYTES {
        return Err(format!(
            "security_headers: `{key}` value must be at most {MAX_HEADER_VALUE_BYTES} bytes"
        ));
    }
    let invalid_value = || format!("security_headers: `{key}` must be a valid HTTP field value");
    if !value
        .bytes()
        .all(|byte| byte == b'\t' || byte == b' ' || byte.is_ascii_graphic())
    {
        return Err(invalid_value());
    }
    HeaderValue::from_str(value)
        .map(|_| ())
        .map_err(|_| invalid_value())
}

fn reject_unknown_keys(
    object: &serde_json::Map<String, Value>,
    path: &str,
    allowed: &[&str],
) -> Result<(), String> {
    let mut unknown: Vec<&str> = object
        .keys()
        .map(String::as_str)
        .filter(|key| !allowed.contains(key))
        .collect();
    if unknown.is_empty() {
        return Ok(());
    }
    unknown.sort_unstable();
    Err(format!(
        "security_headers: unknown configuration key(s) under `{path}`: {:?}",
        unknown.join(", ")
    ))
}

fn parse_bool(
    object: &serde_json::Map<String, Value>,
    key: &str,
    default: bool,
) -> Result<bool, String> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(default),
        Some(Value::Bool(value)) => Ok(*value),
        Some(other) => Err(format!(
            "security_headers: `{key}` must be a boolean, got {other:?}",
            other = other.to_string()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn apply_to(config: Value, mut headers: HashMap<String, String>) -> HashMap<String, String> {
        let plugin = SecurityHeaders::new(&config).unwrap();
        plugin.apply(&mut headers);
        headers
    }

    #[test]
    fn secure_defaults_add_and_strip() {
        let headers = apply_to(
            json!({}),
            HashMap::from([
                ("Server".to_string(), "nginx/1.0".to_string()),
                ("X-Powered-By".to_string(), "PHP/8".to_string()),
            ]),
        );
        assert_eq!(
            headers.get("x-content-type-options").map(String::as_str),
            Some("nosniff")
        );
        assert_eq!(
            headers.get("x-frame-options").map(String::as_str),
            Some("SAMEORIGIN")
        );
        assert_eq!(
            headers.get("referrer-policy").map(String::as_str),
            Some("strict-origin-when-cross-origin")
        );
        // Fingerprinting headers stripped case-insensitively.
        assert!(headers.keys().all(|k| !k.eq_ignore_ascii_case("server")));
        assert!(
            headers
                .keys()
                .all(|k| !k.eq_ignore_ascii_case("x-powered-by"))
        );
    }

    #[test]
    fn hsts_csp_and_custom_headers_opt_in() {
        let headers = apply_to(
            json!({
                "hsts": { "max_age": 63072000, "preload": true },
                "content_security_policy": "default-src 'self'",
                "set": { "X-Custom": "1" }
            }),
            HashMap::new(),
        );
        assert_eq!(
            headers.get("strict-transport-security").map(String::as_str),
            Some("max-age=63072000; includeSubDomains; preload")
        );
        assert_eq!(
            headers.get("content-security-policy").map(String::as_str),
            Some("default-src 'self'")
        );
        assert_eq!(headers.get("x-custom").map(String::as_str), Some("1"));
    }

    #[test]
    fn override_existing_false_preserves_backend_header() {
        let headers = apply_to(
            json!({ "override_existing": false, "frame_options": "DENY" }),
            HashMap::from([("X-Frame-Options".to_string(), "SAMEORIGIN".to_string())]),
        );
        // A recognized backend value is preserved (case-insensitively) when
        // not overriding.
        assert_eq!(
            headers.get("X-Frame-Options").map(String::as_str),
            Some("SAMEORIGIN")
        );
        assert!(!headers.contains_key("x-frame-options"));
    }

    #[test]
    fn override_existing_true_replaces_backend_header() {
        let headers = apply_to(
            json!({ "frame_options": "DENY" }),
            HashMap::from([("X-Frame-Options".to_string(), "ALLOW-FROM x".to_string())]),
        );
        assert_eq!(
            headers.get("x-frame-options").map(String::as_str),
            Some("DENY")
        );
        // No duplicate case-variant left behind.
        let count = headers
            .keys()
            .filter(|k| k.eq_ignore_ascii_case("x-frame-options"))
            .count();
        assert_eq!(count, 1);
    }

    #[test]
    fn removed_and_set_name_without_override_takes_the_set_value() {
        let headers = apply_to(
            json!({
                "override_existing": false,
                "remove": ["X-Policy"],
                "set": { "X-Policy": "gateway" }
            }),
            HashMap::from([
                ("X-Policy".to_string(), "backend".to_string()),
                ("x-POLICY".to_string(), "backend-2".to_string()),
            ]),
        );
        let copies: Vec<&str> = headers
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case("x-policy"))
            .map(|(_, value)| value.as_str())
            .collect();
        assert_eq!(copies, vec!["gateway"]);
    }

    #[test]
    fn disabling_a_default_header() {
        let headers = apply_to(json!({ "frame_options": false }), HashMap::new());
        assert!(!headers.contains_key("x-frame-options"));
        assert_eq!(
            headers.get("x-content-type-options").map(String::as_str),
            Some("nosniff")
        );
    }

    #[test]
    fn header_value_with_crlf_is_rejected() {
        let err =
            SecurityHeaders::new(&json!({ "set": { "X-Bad": "a\r\nInjected: 1" } })).unwrap_err();
        assert!(err.contains("valid HTTP field value"));
    }

    #[test]
    fn no_op_config_is_rejected() {
        // Everything disabled and nothing to remove → no-op, rejected.
        let err = SecurityHeaders::new(&json!({
            "content_type_options": false,
            "frame_options": false,
            "referrer_policy": false,
            "remove": []
        }))
        .unwrap_err();
        assert!(err.contains("no headers"));
    }
}
