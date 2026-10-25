//! Request transformer plugin — modifies headers, query params, and body
//! before proxying.
//!
//! Header/query rules execute in `before_proxy` before the backend request is
//! built. Body rules execute in `transform_request_body`, which needs the
//! request body buffered — but only for the representations it can actually
//! rewrite: `RequestTransformer::should_buffer_request_body` releases a
//! DECLARED non-JSON upload to the streaming path, while an absent
//! `Content-Type` (which the transform still parses as JSON) stays buffered.
//!
//! Rules are validated and partitioned at construction time:
//!
//! - Unknown top-level and per-rule properties are rejected (no silent typos).
//! - Unknown `operation` / `target` values are rejected (no silent no-ops).
//! - Header/query operation fields are exact: only `add`/`update` accept
//!   `value`; only `rename` accepts `new_key`; `remove` accepts neither.
//! - Every configured header `value` must parse as an HTTP `HeaderValue`
//!   (same complete syntax accepted at H1/H2/H3 emission). CR/LF keep a
//!   dedicated diagnostic; other forbidden control bytes fail the same gate.
//! - Gateway-owned header destinations (primary egress strip inventory,
//!   generated forwarding headers, Host, the `x-consumer-*` assertion
//!   namespace, and the `x-path-param-*` route-capture namespace) reject
//!   add/update and rename. Matching folds ASCII case AND treats `_` as `-`,
//!   because CGI-style backends (Rack, WSGI, PHP-FPM) map `X_Forwarded_For`
//!   onto the same variable as `X-Forwarded-For`. Removal and rename sources
//!   remain allowed.
//! - Header/query `value` strings may reference a bounded set of request
//!   variables — `$(consumer.username)`, `$(client_ip)`, `$(request_id)`,
//!   `$(header.<name>)`, `$(query.<name>)` — compiled at construction (an
//!   unknown variable or an unterminated `$(` is rejected; `$$(` is a literal
//!   `$(`). A rule whose variable is unavailable for a request, or whose
//!   resolved header value is not a valid `HeaderValue`, is skipped for that
//!   request rather than authoring a partial value. Sources resolve from the
//!   ORIGINAL client headers and query, so a rename cannot relabel a
//!   credential into an innocuous source name; credential-class names (any
//!   spelling), chain credential locations, and authentication-owned query
//!   credentials are never template sources.
//! - Query `value` / `new_key` / `key` strings must not contain CR or LF
//!   (injection into the request-target). Names and values are otherwise
//!   percent-encoded when authored onto the outbound query.
//! - Rules are split into `header_rules` and `query_rules` so the hot path
//!   does not dispatch on target strings per request, and so
//!   [`modifies_request_headers`] returns an accurate answer (which lets the
//!   handler skip cloning `ctx.headers` for query-only and body-only configs).
//!
//! ## Query mutation contract
//!
//! Query rules mutate an ordered, duplicate-aware representation derived from
//! the retained raw wire query (not the single-value `query_params` map).
//! Authentication-owned credential pairs marked under
//! `auth.strip_query_param.*` are removed from that representation **before**
//! any query rules run, so a rename/update/duplicate cannot relocate or
//! re-encode an authenticated secret onto a new outbound name. The serialized
//! result is published on [`RequestContext::publish_transformed_query`] so
//! every primary dispatch surface and `request_mirror` share the same
//! canonical outbound query; the proxy still applies a final strip pass as
//! defense in depth. Unmodified pairs keep their original encoding; the
//! ordinary no-query-rule path allocates nothing and leaves the raw query
//! untouched.
//!
//! Duplicate-name semantics (decoded names):
//! - `add`: append only when the name is absent; existing duplicates stay.
//! - `update`: rewrite every matching pair's value; append when absent.
//! - `remove`: drop every matching pair.
//! - `rename`: rename every matching pair, preserving value encoding and
//!   key-without-equals shape; existing destination names are left in place.
//!
//! ## Protocols
//!
//! The plugin runs on HTTP, gRPC, and WebSocket handshakes. A WebSocket
//! handshake carries no request body (the proxy never buffers one), so only
//! header and query rules — and route-level header finalization — apply
//! there; post-upgrade frames are never touched.
//!
//! ## Body rewrites and content integrity
//!
//! Body rules can replace the request bytes after the backend header map has
//! already been fixed on some dispatch ladders, so a client
//! `Content-Digest` / `Repr-Digest` / `Digest` / `Content-MD5` computed over
//! the original bytes cannot be repaired afterwards. `before_proxy` enrols the
//! request (a plain bool); core then inspects the FINAL outbound headers
//! (after every `before_proxy` hook and the route-header finalizer) and, when
//! such a field is present and the body rules may rewrite the request (the
//! body is not proven empty by `Content-Length: 0` and the effective
//! `Content-Type` is absent or JSON), removes the fields clone-on-write (`proxy::
//! retire_stale_request_integrity_headers`). Client JSON number lexemes are
//! preserved exactly across a rewrite (see
//! `body_transform::apply_request_body_rules`).
//!
//! ## Non-application signal
//!
//! A rule or body pass that did not apply publishes a fixed, value-free
//! reason under [`RULE_SKIPPED_METADATA_KEY`] / [`BODY_SKIPPED_METADATA_KEY`]
//! so transaction logs can show that a transform silently stopped firing.
//!
//! ## Per-rule overrides from `mesh_route_dispatch`
//!
//! When `mesh_route_dispatch` matches a rule that carries
//! `request_transform`, it publishes a pre-compiled `Arc` onto
//! [`RequestContext::route_override_request_transform`]. Each enabled
//! instance of this plugin applies only its **static** header/query rules in
//! `before_proxy`. Proxy core then applies the matched route list **exactly
//! once** after the last eligible (enabled) `request_transformer` in the
//! ordered chain — i.e. **all static rules run first, then route-level
//! writes**. That ordering is structural under multiple same-type instances
//! and priority overrides: a later static add/update/remove/rename cannot
//! recreate or overwrite a header the matched route removed or set.
//!
//! ## `apply_route_overrides` opt-in
//!
//! Setting `apply_route_overrides: true` on the plugin config lets the
//! instance carry zero static `rules`. The K8s VirtualService translator
//! uses this to auto-emit a `request_transformer` on proxies that do not
//! already have one, so per-rule route-level transforms still find an
//! eligible consumer for the chain-level final phase. Direct operator
//! configs without static rules and without this flag continue to be
//! rejected.
//!
//! ## RTDS overlay
//!
//! When `runtime_overlay_scope: "<scope>"` is set, the effective value of
//! `ferrum.request_transformer.<scope>.enabled` is bound into this instance's
//! configuration by mesh preparation and resolved ONCE, immutably, at
//! construction. A `false` value short-circuits the plugin (static rules
//! become no-ops) and the instance is **not** eligible for route-header
//! finalization, so it cannot consume or suppress route overrides needed by
//! a later enabled consumer. A scope the accepted overlay does not name
//! falls back to `default_enabled` (defaults to `true` so the gate is
//! fail-open).
//!
//! The gate is deliberately NOT read at request time (GHSA-83rc-23c9-3g9x).
//! Because it is resolved from configuration, the gate and the rules it gates
//! are one indivisible generation: they are validated together, built into one
//! plugin cache, and published in one `RequestEpoch`. A request that pinned an
//! epoch therefore observes a single complete accepted generation for its whole
//! lifetime — it is wholly enabled or wholly disabled across `before_proxy`,
//! query rules, and body transformation, no matter how long it is in flight or
//! how many overlay updates land meanwhile. That holds identically on H1, H2,
//! and H3, across retries and synthetic responses, and for every instance in a
//! multi-instance chain.

use async_trait::async_trait;
use http::header::{HeaderName, HeaderValue};
use serde_json::{Map, Value};
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use tracing::debug;

use super::utils::body_transform::{self, BodyRule, RequestBodyRulesOutcome};
use super::utils::query::OrderedQuery;
use super::utils::transformer_gate;
use super::{Plugin, PluginResult, RequestContext};

pub mod runtime_overlay;

/// Top-level config keys accepted by [`RequestTransformer::new`].
const CONFIG_KEYS: &[&str] = &[
    "rules",
    "apply_route_overrides",
    "runtime_overlay_scope",
    "default_enabled",
    // Reserved: written by mesh preparation from the accepted RTDS overlay so
    // the gate rides the same generation as the rules. See
    // `crate::plugins::utils::transformer_gate::RESOLVED_ENABLED_KEY`.
    transformer_gate::RESOLVED_ENABLED_KEY,
];

/// Per-rule keys accepted for header, query, and body rules.
const RULE_KEYS: &[&str] = &["operation", "target", "key", "value", "new_key"];

/// Transaction-metadata key set when a header or query rule was skipped for a
/// request. The value is a fixed reason literal (`template_unresolved` or
/// `template_invalid_header_value`) and never carries request data.
pub const RULE_SKIPPED_METADATA_KEY: &str = "request_transformer.rule_skipped";

/// Transaction-metadata key set when configured body rules did not rewrite a
/// request body. The value is a fixed reason literal
/// (`non_json_content_type`, `parse_error`, or `no_rule_applied`) and never
/// carries body bytes.
pub const BODY_SKIPPED_METADATA_KEY: &str = "request_transformer.body_skipped";

const RULE_SKIPPED_TEMPLATE_UNRESOLVED: &str = "template_unresolved";
const RULE_SKIPPED_TEMPLATE_INVALID_HEADER_VALUE: &str = "template_invalid_header_value";
const BODY_SKIPPED_NON_JSON_CONTENT_TYPE: &str = "non_json_content_type";

/// Request fields whose value is computed over the request content. A body
/// rewrite invalidates every one of them, and on several dispatch ladders the
/// outbound header map is fixed before the body transform runs, so they are
/// removed whenever this instance's body rules may rewrite the request.
const BODY_BOUND_REQUEST_INTEGRITY_HEADERS: &[&str] =
    &["content-digest", "repr-digest", "digest", "content-md5"];

/// Upper bound on template variables in one configured value.
const MAX_TEMPLATE_VARIABLES: usize = 8;

/// One request variable a configured value may reference.
#[derive(Debug, Clone)]
enum TemplateVariable {
    /// `$(consumer.username)`: the gateway Consumer asserted to the backend.
    ConsumerUsername,
    /// `$(client_ip)`: the resolved client IP.
    ClientIp,
    /// `$(request_id)`: the canonical request ID (`correlation_id`).
    RequestId,
    /// `$(header.<name>)`: a pre-lowercased header of the ORIGINAL client
    /// request (`ctx.headers`), never the outbound map, so an earlier rename
    /// cannot launder a credential into an innocuous source name.
    Header(String),
    /// `$(query.<name>)`: a percent-decoded parameter of the ORIGINAL client
    /// query (the retained raw wire query), for the same reason.
    Query(String),
}

#[derive(Debug, Clone)]
enum TemplatePart {
    Literal(String),
    Variable(TemplateVariable),
}

/// A configured value compiled at construction into literal and variable
/// parts, resolved per request without re-parsing.
#[derive(Debug, Clone)]
struct ValueTemplate {
    parts: Vec<TemplatePart>,
}

enum ParsedValue {
    /// No variables; `$$(` escapes already reduced to `$(`.
    Literal(String),
    Template(ValueTemplate),
}

impl TemplateVariable {
    fn resolve<'a>(
        &self,
        ctx: &'a RequestContext,
        original_query: &'a HashMap<String, String>,
    ) -> Option<&'a str> {
        match self {
            Self::ConsumerUsername => ctx.backend_consumer_username(),
            Self::ClientIp => Some(ctx.client_ip.as_str()).filter(|ip| !ip.is_empty()),
            Self::RequestId => ctx
                .metadata
                .get(super::REQUEST_ID_METADATA_KEY)
                .map(String::as_str),
            Self::Header(name) => {
                // A custom credential location (for example a `key_auth`
                // header) is only known per chain; never copy it elsewhere,
                // in any `_` / `-` spelling.
                if header_source_is_chain_credential(ctx, name) {
                    return None;
                }
                ctx.headers.get(name.as_str()).map(String::as_str)
            }
            Self::Query(name) => {
                if query_name_is_auth_credential(ctx, name) {
                    return None;
                }
                original_query.get(name.as_str()).map(String::as_str)
            }
        }
    }
}

impl ValueTemplate {
    /// Resolve every part, or `None` when any variable is unavailable.
    fn resolve(
        &self,
        ctx: &RequestContext,
        original_query: &HashMap<String, String>,
    ) -> Option<String> {
        let mut resolved = String::new();
        for part in &self.parts {
            match part {
                TemplatePart::Literal(text) => resolved.push_str(text),
                TemplatePart::Variable(variable) => {
                    resolved.push_str(variable.resolve(ctx, original_query)?);
                }
            }
        }
        Some(resolved)
    }

    fn reads_query(&self) -> bool {
        self.parts
            .iter()
            .any(|part| matches!(part, TemplatePart::Variable(TemplateVariable::Query(_))))
    }

    fn reads_headers(&self) -> bool {
        self.parts
            .iter()
            .any(|part| matches!(part, TemplatePart::Variable(TemplateVariable::Header(_))))
    }
}

/// Whether a header or query NAME can never be a template source: the
/// built-in credential header inventory (`_` / `-` folded) or any name the
/// shared sensitive-name classifier flags (`authorization`, `*_token`,
/// `api_key`, `session`, `password`, …, in any delimiter spelling).
fn template_source_name_is_sensitive(name: &str) -> bool {
    use crate::proxy::headers::field_names_equivalent_for_backends;
    super::utils::replay_partition::CREDENTIAL_CONTEXT_HEADERS
        .iter()
        .any(|credential| field_names_equivalent_for_backends(name, credential))
        || super::utils::metadata_redaction::is_sensitive_header_name(name)
}

/// Whether this request's chain declared `name` (folded) a credential header
/// location, beyond the built-in inventory checked at construction.
fn header_source_is_chain_credential(ctx: &RequestContext, name: &str) -> bool {
    use crate::proxy::headers::field_names_equivalent_for_backends;
    ctx.request_headers_requiring_redaction()
        .iter()
        .any(|credential| field_names_equivalent_for_backends(name, credential))
}

/// The percent-decoded ORIGINAL client query (last occurrence wins), decoded
/// exactly as `RequestContext::materialize_query_params` does. Built once per
/// request, only when a template reads `$(query.<name>)`.
fn original_query_params(ctx: &RequestContext) -> HashMap<String, String> {
    use percent_encoding::percent_decode_str;
    let mut params = HashMap::new();
    let Some(raw) = ctx.raw_query_string() else {
        return params;
    };
    for pair in raw.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        params.insert(
            percent_decode_str(name).decode_utf8_lossy().into_owned(),
            percent_decode_str(value).decode_utf8_lossy().into_owned(),
        );
    }
    params
}

/// Whether an authentication plugin marked `name` as a query credential
/// location (stripped or not) for this request.
fn query_name_is_auth_credential(ctx: &RequestContext, name: &str) -> bool {
    use super::utils::token_extract::{
        QUERY_CREDENTIAL_METADATA_PREFIX, STRIP_QUERY_PARAM_METADATA_PREFIX,
    };
    ctx.query_credential_partition_digests()
        .iter()
        .any(|(marked, _)| marked == name)
        || ctx.metadata.keys().any(|key| {
            key.strip_prefix(STRIP_QUERY_PARAM_METADATA_PREFIX)
                .or_else(|| key.strip_prefix(QUERY_CREDENTIAL_METADATA_PREFIX))
                == Some(name)
        })
}

fn parse_template_variable(name: &str, idx: usize) -> Result<TemplateVariable, String> {
    match name {
        "consumer.username" => return Ok(TemplateVariable::ConsumerUsername),
        "client_ip" => return Ok(TemplateVariable::ClientIp),
        "request_id" => return Ok(TemplateVariable::RequestId),
        _ => {}
    }
    if let Some(header) = name.strip_prefix("header.") {
        let header = HeaderName::from_bytes(header.as_bytes())
            .map_err(|_| {
                format!(
                    "request_transformer: `rule[{idx}]`: template variable `$(header.<name>)` must name a valid HTTP header"
                )
            })?
            .to_string();
        if template_source_name_is_sensitive(&header) {
            return Err(format!(
                "request_transformer: `rule[{idx}]`: template variable `$(header.<name>)` names a credential-bearing header; credentials cannot be copied into another request field"
            ));
        }
        return Ok(TemplateVariable::Header(header));
    }
    if let Some(query) = name.strip_prefix("query.") {
        if query.is_empty() {
            return Err(format!(
                "request_transformer: `rule[{idx}]`: template variable `$(query.<name>)` must name a query parameter"
            ));
        }
        if template_source_name_is_sensitive(query) {
            return Err(format!(
                "request_transformer: `rule[{idx}]`: template variable `$(query.<name>)` names a credential-bearing query parameter; credentials cannot be copied into another request field"
            ));
        }
        return Ok(TemplateVariable::Query(query.to_string()));
    }
    Err(format!(
        "request_transformer: `rule[{idx}]`: unknown template variable in `value` (expected `$(consumer.username)`, `$(client_ip)`, `$(request_id)`, `$(header.<name>)`, or `$(query.<name>)`; write `$$(` for a literal `$(`)"
    ))
}

/// Compile a configured header/query `value`. `$(...)` references a request
/// variable; `$$(` is a literal `$(`; any other `$` is literal.
fn parse_value_template(raw: &str, idx: usize) -> Result<ParsedValue, String> {
    if !raw.contains("$(") {
        return Ok(ParsedValue::Literal(raw.to_string()));
    }
    let mut parts = Vec::new();
    let mut literal = String::new();
    let mut variables = 0usize;
    let mut rest = raw;
    while let Some(position) = rest.find("$(") {
        let (before, marker_and_after) = rest.split_at(position);
        let after = marker_and_after.get(2..).unwrap_or_default();
        if let Some(escaped_prefix) = before.strip_suffix('$') {
            literal.push_str(escaped_prefix);
            literal.push_str("$(");
            rest = after;
            continue;
        }
        literal.push_str(before);
        let Some(end) = after.find(')') else {
            return Err(format!(
                "request_transformer: `rule[{idx}]`: unterminated `$(` template variable in `value`; write `$$(` for a literal `$(`"
            ));
        };
        let (name, closing_and_rest) = after.split_at(end);
        let variable = parse_template_variable(name, idx)?;
        variables += 1;
        if variables > MAX_TEMPLATE_VARIABLES {
            return Err(format!(
                "request_transformer: `rule[{idx}]`: `value` references more than {MAX_TEMPLATE_VARIABLES} template variables"
            ));
        }
        if !literal.is_empty() {
            parts.push(TemplatePart::Literal(std::mem::take(&mut literal)));
        }
        parts.push(TemplatePart::Variable(variable));
        rest = closing_and_rest.get(1..).unwrap_or_default();
    }
    literal.push_str(rest);
    if variables == 0 {
        return Ok(ParsedValue::Literal(literal));
    }
    if !literal.is_empty() {
        parts.push(TemplatePart::Literal(literal));
    }
    Ok(ParsedValue::Template(ValueTemplate { parts }))
}

/// Split a configured value into the stored literal and optional template.
fn compile_configured_value(
    value: Option<String>,
    idx: usize,
) -> Result<(Option<String>, Option<ValueTemplate>), String> {
    match value {
        None => Ok((None, None)),
        Some(raw) => match parse_value_template(&raw, idx)? {
            ParsedValue::Literal(literal) => Ok((Some(literal), None)),
            ParsedValue::Template(template) => Ok((Some(raw), Some(template))),
        },
    }
}

/// Whether `dest` is a gateway-owned header destination from the primary
/// egress strip inventory, the generated forwarding family, or Host, under
/// the backend folding (`_` ≡ `-`, ASCII case-insensitive).
fn is_gateway_owned_header_destination(dest: &str) -> bool {
    use crate::proxy::headers::{
        BACKEND_REQUEST_STRIP_HEADER_NAMES, PROXY_GENERATED_FORWARDING_HEADER_NAMES,
        field_names_equivalent_for_backends,
    };
    BACKEND_REQUEST_STRIP_HEADER_NAMES
        .iter()
        .chain(PROXY_GENERATED_FORWARDING_HEADER_NAMES)
        .chain(std::iter::once(&"host"))
        .any(|owned| field_names_equivalent_for_backends(dest, owned))
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum HeaderOp {
    Add,
    Update,
    Remove,
    Rename,
}

#[derive(Debug, Clone)]
struct HeaderRule {
    operation: HeaderOp,
    /// Pre-lowercased header key.
    key: String,
    /// Required for add/update. The literal to author when `value_template`
    /// is `None`.
    value: Option<String>,
    /// Compiled `$(...)` template for add/update, when the value has one.
    value_template: Option<ValueTemplate>,
    /// Pre-lowercased new key, required for rename.
    new_key: Option<String>,
}

impl HeaderRule {
    /// The value an add/update authors for this request, or the fixed skip
    /// reason when a template cannot produce a valid header value.
    fn authored_value<'r>(
        &'r self,
        ctx: &RequestContext,
        original_query: &HashMap<String, String>,
    ) -> Result<Cow<'r, str>, &'static str> {
        let Some(template) = &self.value_template else {
            return self
                .value
                .as_deref()
                .map(Cow::Borrowed)
                .ok_or(RULE_SKIPPED_TEMPLATE_UNRESOLVED);
        };
        let resolved = template
            .resolve(ctx, original_query)
            .ok_or(RULE_SKIPPED_TEMPLATE_UNRESOLVED)?;
        // A resolved request value (a decoded query parameter, a consumer
        // name) can carry CR/LF or other bytes no protocol may emit.
        if HeaderValue::from_str(&resolved).is_err() {
            return Err(RULE_SKIPPED_TEMPLATE_INVALID_HEADER_VALUE);
        }
        Ok(Cow::Owned(resolved))
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum QueryOp {
    Add,
    Update,
    Remove,
    Rename,
}

#[derive(Debug, Clone)]
struct QueryRule {
    operation: QueryOp,
    key: String,
    /// Required for add/update. The literal to author when `value_template`
    /// is `None`.
    value: Option<String>,
    /// Compiled `$(...)` template for add/update, when the value has one.
    value_template: Option<ValueTemplate>,
    /// Required for rename.
    new_key: Option<String>,
}

impl QueryRule {
    /// The value an add/update authors for this request. Query values are
    /// percent-encoded when authored, so any resolved text is safe in the
    /// request-target.
    fn authored_value<'r>(
        &'r self,
        ctx: &RequestContext,
        original_query: &HashMap<String, String>,
    ) -> Result<Cow<'r, str>, &'static str> {
        match &self.value_template {
            Some(template) => template
                .resolve(ctx, original_query)
                .map(Cow::Owned)
                .ok_or(RULE_SKIPPED_TEMPLATE_UNRESOLVED),
            None => self
                .value
                .as_deref()
                .map(Cow::Borrowed)
                .ok_or(RULE_SKIPPED_TEMPLATE_UNRESOLVED),
        }
    }
}

pub struct RequestTransformer {
    header_rules: Vec<HeaderRule>,
    query_rules: Vec<QueryRule>,
    body_rules: Vec<BodyRule>,
    /// Set by config field `apply_route_overrides`. When `true` the plugin
    /// instance accepts a zero-rule config and declares
    /// `modifies_request_headers() == true` so the dispatcher clones request
    /// headers for it. The K8s VirtualService translator uses this opt-in
    /// when auto-emitting a `request_transformer` whose sole purpose is to
    /// apply per-rule `mesh_route_dispatch` route-level transforms.
    apply_route_overrides: bool,
    /// The one immutable effective gate decision for this instance, resolved at
    /// construction from `runtime_overlay_scope`, the mesh-materialized
    /// `runtime_overlay_resolved_enabled`, and `default_enabled`.
    ///
    /// `true` for every instance that did not opt into an RTDS scope. Every
    /// request phase reads this field, so a request can never see the gate
    /// change underneath it and paired header/query/body rules can never be
    /// applied under different gate states (GHSA-83rc-23c9-3g9x). A gate change
    /// arrives as a new plugin instance in a new `RequestEpoch`; in-flight
    /// requests keep the generation they pinned.
    rules_enabled: bool,
    /// Whether any header/query template reads `$(query.<name>)`, so
    /// `before_proxy` decodes the original client query once up front.
    templates_read_query: bool,
    /// Whether any template reads `$(header.<name>)` from the original client
    /// headers, which the dispatcher keeps intact only while it hands this
    /// instance a separate outbound copy.
    templates_read_headers: bool,
}

fn parse_op(op: &str) -> Option<(HeaderOp, QueryOp)> {
    match op {
        "add" => Some((HeaderOp::Add, QueryOp::Add)),
        "update" => Some((HeaderOp::Update, QueryOp::Update)),
        "remove" => Some((HeaderOp::Remove, QueryOp::Remove)),
        "rename" => Some((HeaderOp::Rename, QueryOp::Rename)),
        _ => None,
    }
}

fn contains_crlf(s: &str) -> bool {
    s.bytes().any(|b| b == b'\r' || b == b'\n')
}

fn reject_unknown_keys(
    object: &Map<String, Value>,
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
        "request_transformer: unknown config key(s) under `{path}`: {:?}; allowed keys: `{}`",
        unknown.join(", "),
        allowed.join("`, `")
    ))
}

/// Validate a configured header value the same way outbound Hyper / H3 /
/// reqwest adapters do (`HeaderValue::from_str`), while keeping the
/// historical CR/LF-specific diagnostic for injection typos.
fn validate_configured_header_value(value: &str, idx: usize) -> Result<(), String> {
    if contains_crlf(value) {
        return Err(format!(
            "request_transformer: `rule[{idx}]`: header `value` must not contain CR or LF"
        ));
    }
    HeaderValue::from_str(value).map_err(|_| {
        format!(
            "request_transformer: `rule[{idx}]`: header `value` must be a valid HTTP HeaderValue"
        )
    })?;
    Ok(())
}

fn validate_configured_query_string_field(
    field: &str,
    value: &str,
    idx: usize,
) -> Result<(), String> {
    if contains_crlf(value) {
        return Err(format!(
            "request_transformer: `rule[{idx}]`: query `{field}` must not contain CR or LF"
        ));
    }
    Ok(())
}

impl RequestTransformer {
    pub fn new(config: &Value) -> Result<Self, String> {
        let config_obj = config.as_object().ok_or_else(|| {
            format!(
                "request_transformer: config must be an object; allowed keys: `{}`",
                CONFIG_KEYS.join("`, `")
            )
        })?;
        reject_unknown_keys(config_obj, "config", CONFIG_KEYS)?;

        let mut header_rules: Vec<HeaderRule> = Vec::new();
        let mut query_rules: Vec<QueryRule> = Vec::new();

        if let Some(rules) = config.get("rules") {
            let arr = rules
                .as_array()
                .ok_or("request_transformer: `rules` must be an array")?;
            for (idx, r) in arr.iter().enumerate() {
                let rule_obj = r.as_object().ok_or_else(|| {
                    format!("request_transformer: `rule[{idx}]`: rule must be an object")
                })?;
                let rule_path = format!("config.rules[{idx}]");
                reject_unknown_keys(rule_obj, &rule_path, RULE_KEYS)?;

                let target = match r.get("target") {
                    Some(Value::String(s)) => s.as_str(),
                    None => {
                        return Err(format!(
                            "request_transformer: `rule[{idx}]`: `target` is required (expected `header`/`query`/`body`)"
                        ));
                    }
                    Some(_) => {
                        return Err(format!(
                            "request_transformer: `rule[{idx}]`: `target` must be a string (expected `header`/`query`/`body`)"
                        ));
                    }
                };

                // Body rules are validated and collected by `parse_body_rules`
                // (required / incompatible fields). Unknown keys are already
                // rejected above.
                if target == "body" {
                    continue;
                }

                if target != "header" && target != "query" {
                    return Err(format!(
                        "request_transformer: `rule[{idx}]`: unknown `target` {target:?} (expected `header`/`query`/`body`)"
                    ));
                }

                let op_str = match r.get("operation") {
                    Some(Value::String(s)) => s.as_str(),
                    None => {
                        return Err(format!(
                            "request_transformer: `rule[{idx}]`: `operation` is required"
                        ));
                    }
                    Some(_) => {
                        return Err(format!(
                            "request_transformer: `rule[{idx}]`: `operation` must be a string"
                        ));
                    }
                };
                let (hop, qop) = parse_op(op_str).ok_or_else(|| {
                    format!(
                        "request_transformer: `rule[{idx}]`: unknown `operation` {op_str:?} (expected `add`/`update`/`remove`/`rename`)"
                    )
                })?;

                let raw_key = match r.get("key") {
                    Some(Value::String(s)) => s.clone(),
                    None => {
                        return Err(format!(
                            "request_transformer: `rule[{idx}]`: `key` is required"
                        ));
                    }
                    Some(_) => {
                        return Err(format!(
                            "request_transformer: `rule[{idx}]`: `key` must be a string"
                        ));
                    }
                };
                let value_present = rule_obj.contains_key("value");
                let value = match r.get("value") {
                    Some(Value::String(s)) => Some(s.clone()),
                    Some(Value::Null) | None => None,
                    Some(_) => {
                        return Err(format!(
                            "request_transformer: `rule[{idx}]`: `value` must be a string for header/query rules"
                        ));
                    }
                };
                let new_key_present = rule_obj.contains_key("new_key");
                let raw_new_key = match r.get("new_key") {
                    Some(Value::String(s)) => Some(s.clone()),
                    Some(Value::Null) | None => None,
                    Some(_) => {
                        return Err(format!(
                            "request_transformer: `rule[{idx}]`: `new_key` must be a string"
                        ));
                    }
                };

                // Per-operation required- and forbidden-field validation.
                // Incompatible extras are rejected rather than silently ignored
                // so typos cannot produce a different transform than intended.
                // Matches body-rule constraints in `body_transform`.
                match op_str {
                    "add" | "update" => {
                        if value.is_none() {
                            return Err(format!(
                                "request_transformer: `rule[{idx}]`: {op_str:?} operation requires a `value`"
                            ));
                        }
                        if new_key_present {
                            return Err(format!(
                                "request_transformer: `rule[{idx}]`: `new_key` must not be set for {target:?} {op_str:?} operation"
                            ));
                        }
                    }
                    "rename" => {
                        if value_present {
                            return Err(format!(
                                "request_transformer: `rule[{idx}]`: `value` must not be set for {target:?} `rename` operation"
                            ));
                        }
                        if raw_new_key.is_none() {
                            return Err(format!(
                                "request_transformer: `rule[{idx}]`: `rename` operation requires a `new_key`"
                            ));
                        }
                    }
                    "remove" => {
                        if value_present {
                            return Err(format!(
                                "request_transformer: `rule[{idx}]`: `value` must not be set for {target:?} `remove` operation"
                            ));
                        }
                        if new_key_present {
                            return Err(format!(
                                "request_transformer: `rule[{idx}]`: `new_key` must not be set for {target:?} `remove` operation"
                            ));
                        }
                    }
                    _ => {}
                }

                if target == "header" {
                    let key = HeaderName::from_bytes(raw_key.as_bytes())
                        .map_err(|_| {
                            format!(
                                "request_transformer: `rule[{idx}]`: `key` must be a valid HTTP header name"
                            )
                        })?
                        .to_string();
                    let new_key = raw_new_key
                        .as_deref()
                        .map(|key| {
                            HeaderName::from_bytes(key.as_bytes())
                                .map_err(|_| {
                                    format!(
                                        "request_transformer: `rule[{idx}]`: `new_key` must be a valid HTTP header name"
                                    )
                                })
                                .map(|name| name.to_string())
                        })
                        .transpose()?;

                    if let Some(ref v) = value {
                        validate_configured_header_value(v, idx)?;
                    }
                    let (value, value_template) = compile_configured_value(value, idx)?;
                    // Match the primary egress ownership inventory. Removal and
                    // rename sources stay available, as in response_transformer.
                    let destination = match hop {
                        HeaderOp::Add | HeaderOp::Update => Some(key.as_str()),
                        HeaderOp::Rename => new_key.as_deref(),
                        HeaderOp::Remove => None,
                    };
                    // Folded comparison: `x_forwarded_for` or `content_length`
                    // is a legal token that survives every exact-name egress
                    // strip and lands on the gateway-owned variable at a
                    // CGI-style backend.
                    if let Some(dest) = destination
                        && is_gateway_owned_header_destination(dest)
                    {
                        return Err(format!(
                            "request_transformer: `rule[{idx}]`: header destination {dest:?} is \
                             gateway-owned and cannot be configured; use `preserve_host_header` \
                             for Host or trusted-proxy configuration for forwarding identity"
                        ));
                    }
                    // `x-path-param-*` carries the router's trusted path
                    // captures, and nothing re-asserts them after
                    // `before_proxy`, so a rule must not overwrite or mint one.
                    if let Some(dest) = destination
                        && crate::proxy::headers::is_path_param_assertion_header(dest)
                    {
                        return Err(format!(
                            "request_transformer: `rule[{idx}]`: header destination {dest:?} is \
                             in the gateway-owned `x-path-param-*` route-capture namespace and \
                             cannot be configured; only the router asserts path captures to \
                             backends"
                        ));
                    }
                    // The whole `x-consumer-*` namespace is gateway-owned
                    // consumer assertion metadata. Removing or renaming away
                    // from it stays legal (the client value is already gone).
                    if let Some(dest) = destination
                        && crate::proxy::headers::is_consumer_assertion_header(dest)
                    {
                        return Err(format!(
                            "request_transformer: `rule[{idx}]`: header destination {dest:?} is \
                             in the gateway-owned `x-consumer-*` consumer assertion namespace \
                             and cannot be configured; only the gateway asserts consumer \
                             identity to backends"
                        ));
                    }
                    // `X-Ferrum-Hops` is the gateway's loop-guard count. Unlike
                    // the consumer namespace, removing or renaming it away is
                    // refused too: that would reset the count a later gateway
                    // hop reads and let a request loop run unbounded.
                    if crate::proxy::hop_limit::is_proxy_hops_header(&key)
                        || new_key
                            .as_deref()
                            .is_some_and(crate::proxy::hop_limit::is_proxy_hops_header)
                    {
                        return Err(format!(
                            "request_transformer: `rule[{idx}]`: header `x-ferrum-hops` is the \
                             gateway-owned proxy hop count and cannot be added, updated, \
                             renamed, or removed"
                        ));
                    }
                    header_rules.push(HeaderRule {
                        operation: hop,
                        key,
                        value,
                        value_template,
                        new_key,
                    });
                } else {
                    validate_configured_query_string_field("key", &raw_key, idx)?;
                    if let Some(ref v) = value {
                        validate_configured_query_string_field("value", v, idx)?;
                    }
                    if let Some(ref nk) = raw_new_key {
                        validate_configured_query_string_field("new_key", nk, idx)?;
                    }
                    let (value, value_template) = compile_configured_value(value, idx)?;
                    query_rules.push(QueryRule {
                        operation: qop,
                        key: raw_key,
                        value,
                        value_template,
                        new_key: raw_new_key,
                    });
                }
            }
        }

        let body_rules = body_transform::parse_body_rules(config)
            .map_err(|e| format!("request_transformer: {e}"))?;

        let apply_route_overrides = match config.get("apply_route_overrides") {
            Some(Value::Bool(b)) => *b,
            Some(Value::Null) | None => false,
            Some(_) => {
                return Err(
                    "request_transformer: `apply_route_overrides` must be a boolean".to_string(),
                );
            }
        };

        if header_rules.is_empty()
            && query_rules.is_empty()
            && body_rules.is_empty()
            && !apply_route_overrides
        {
            return Err(
                "request_transformer: no `rules` configured — plugin will have no effect"
                    .to_string(),
            );
        }

        let runtime_overlay_scope = match config.get("runtime_overlay_scope") {
            Some(Value::String(s)) => {
                let trimmed = s.trim();
                if trimmed.is_empty() {
                    return Err(
                        "request_transformer: `runtime_overlay_scope` must be a non-empty string"
                            .to_string(),
                    );
                }
                Some(trimmed.to_string())
            }
            Some(Value::Null) | None => None,
            Some(_) => {
                return Err(
                    "request_transformer: `runtime_overlay_scope` must be a string".to_string(),
                );
            }
        };

        let default_enabled = match config.get("default_enabled") {
            Some(Value::Bool(b)) => *b,
            Some(Value::Null) | None => true,
            Some(_) => {
                return Err("request_transformer: `default_enabled` must be a boolean".to_string());
            }
        };

        let resolved_enabled = match config.get(transformer_gate::RESOLVED_ENABLED_KEY) {
            Some(Value::Bool(b)) => Some(*b),
            Some(Value::Null) | None => None,
            Some(_) => {
                return Err(format!(
                    "request_transformer: `{}` must be a boolean",
                    transformer_gate::RESOLVED_ENABLED_KEY
                ));
            }
        };

        // Resolve the gate exactly once, here. An instance without a scope is
        // unconditionally enabled; otherwise the accepted overlay's value for
        // this generation wins, falling back to the operator's `default_enabled`
        // when the overlay named no gate for the scope.
        let rules_enabled = if runtime_overlay_scope.is_some() {
            resolved_enabled.unwrap_or(default_enabled)
        } else {
            true
        };

        let templates_read_query = header_rules
            .iter()
            .filter_map(|rule| rule.value_template.as_ref())
            .chain(
                query_rules
                    .iter()
                    .filter_map(|rule| rule.value_template.as_ref()),
            )
            .any(ValueTemplate::reads_query);
        let templates_read_headers = header_rules
            .iter()
            .filter_map(|rule| rule.value_template.as_ref())
            .chain(
                query_rules
                    .iter()
                    .filter_map(|rule| rule.value_template.as_ref()),
            )
            .any(ValueTemplate::reads_headers);

        Ok(Self {
            header_rules,
            query_rules,
            body_rules,
            apply_route_overrides,
            rules_enabled,
            templates_read_query,
            templates_read_headers,
        })
    }

    /// Whether this instance's body rules decline this request outright for
    /// a declared non-JSON `Content-Type` that may carry a body.
    fn body_rules_decline_declared_non_json(
        &self,
        ctx: &RequestContext,
        headers: &HashMap<String, String>,
    ) -> bool {
        !self.body_rules.is_empty()
            && crate::proxy::request_may_have_body(&ctx.method, headers)
            && headers
                .get("content-type")
                .is_some_and(|content_type| !body_transform::is_json_content_type(content_type))
    }

    /// Shared body pass for the context-free and context-aware hooks.
    fn transform_body(&self, body: &[u8], content_type: Option<&str>) -> BodyPass {
        // The same immutable decision `before_proxy` used. A marker header and
        // its paired body removal therefore cannot straddle a gate flip.
        if !self.rules_enabled {
            return BodyPass::Unchanged;
        }
        // Only transform JSON bodies. When Content-Type is absent, attempt
        // JSON parse anyway — the body_transform helper short-circuits on
        // parse failure, so the cost is one failed parse per non-JSON request.
        if let Some(ct) = content_type
            && !body_transform::is_json_content_type(ct)
        {
            return BodyPass::Skipped(BODY_SKIPPED_NON_JSON_CONTENT_TYPE);
        }
        match body_transform::apply_request_body_rules(body, &self.body_rules) {
            RequestBodyRulesOutcome::Replaced(bytes) => BodyPass::Replaced(bytes),
            RequestBodyRulesOutcome::Skipped(reason) => BodyPass::Skipped(reason.as_str()),
            RequestBodyRulesOutcome::Unchanged => BodyPass::Unchanged,
        }
    }
}

enum BodyPass {
    Replaced(Vec<u8>),
    Skipped(&'static str),
    Unchanged,
}

/// Whether `name` is a request field computed over the request content,
/// under the backend folding (`_` ≡ `-`, ASCII case-insensitive): a
/// `Content_Digest` reaches a CGI-style backend as the same variable.
pub(crate) fn is_body_bound_request_integrity_header(name: &str) -> bool {
    BODY_BOUND_REQUEST_INTEGRITY_HEADERS
        .iter()
        .any(|bound| crate::proxy::headers::field_names_equivalent_for_backends(name, bound))
}

/// Whether request-transformer body rules may replace the bytes of a request
/// with these FINAL outbound headers: the body is not proven empty and the
/// effective `Content-Type` is absent or a JSON document type (framed gRPC
/// `+json` can never parse as one document).
///
/// The method is deliberately NOT consulted: an HTTP/2 or HTTP/3 `GET` may
/// carry DATA without `Content-Length`, and the body pass buffers and rewrites
/// it all the same. Only an explicit `Content-Length: 0` proves emptiness here.
pub(crate) fn request_body_rules_may_rewrite(
    _method: &str,
    headers: &HashMap<String, String>,
) -> bool {
    !headers
        .get("content-length")
        .is_some_and(|length| length.trim() == "0")
        && headers
            .get("content-type")
            .map(String::as_str)
            .is_none_or(|content_type| {
                body_transform::is_json_content_type(content_type)
                    && !body_transform::is_framed_grpc_content_type(content_type)
            })
}

/// Remove request integrity fields computed over the client's bytes.
pub(crate) fn strip_body_bound_integrity_headers(headers: &mut HashMap<String, String>) {
    headers.retain(|name, _| !is_body_bound_request_integrity_header(name));
}

#[async_trait]
impl Plugin for RequestTransformer {
    fn name(&self) -> &str {
        "request_transformer"
    }

    fn priority(&self) -> u16 {
        super::priority::REQUEST_TRANSFORMER
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        // WebSocket handshakes carry headers and a query like any request;
        // the proxy never buffers a handshake body, so body rules stay inert
        // there and post-upgrade frames are never touched.
        super::HTTP_FAMILY_PROTOCOLS
    }

    fn modifies_request_headers(&self) -> bool {
        // Per-rule overrides (`apply_route_overrides=true`) can mutate
        // headers even when this instance has no static `header_rules`, so
        // the dispatcher must clone request headers for it. Returning
        // `false` here would let the dispatcher hand `ctx.headers` itself
        // to plugins via `mem::take`, which both breaks the gateway-wide
        // "ctx.headers is the original inbound headers" invariant and (on
        // some paths) silently drops route-level header writes.
        //
        // A `$(header.<name>)` template reads the ORIGINAL client headers in
        // `ctx.headers`, which stay intact during `before_proxy` only when the
        // dispatcher hands plugins a separate outbound copy. Body rules do NOT
        // force the copy: stale integrity fields are retired by proxy core
        // over the final outbound headers, copying only when a request
        // actually carries one (`retire_stale_request_integrity_headers`).
        self.rules_enabled
            && (!self.header_rules.is_empty()
                || self.apply_route_overrides
                || self.templates_read_headers)
    }

    fn needs_final_request_body_context(&self) -> bool {
        // The context-aware body hook publishes the value-free skip reason;
        // without this the ordinary H1/H2 dispatcher would select the
        // context-free hook and drop it.
        self.rules_enabled && !self.body_rules.is_empty()
    }

    fn modifies_request_query(&self) -> bool {
        // Same immutable gate as the header and body capabilities: a disabled
        // generation must not advertise a query mutation it can never make.
        self.rules_enabled && !self.query_rules.is_empty()
    }

    fn participates_in_route_request_header_finalization(&self) -> bool {
        self.rules_enabled
    }

    fn modifies_request_body(&self) -> bool {
        // The gate is immutable for this plugin generation, so a disabled
        // instance can safely drop the config-time buffering capability too.
        // Otherwise the kill-switch would still retain every request body even
        // though no phase can consume or transform it.
        self.rules_enabled && !self.body_rules.is_empty()
    }

    fn should_buffer_request_body(&self, ctx: &RequestContext) -> bool {
        // `modifies_request_body` is only the config-time upper bound. Refine it
        // per request so an ordinary binary or form upload is not collected in
        // full for a JSON-only body rule that `transform_request_body` will
        // decline anyway — which otherwise added the whole upload duration to
        // upstream time-to-first-byte and retained a needless full-body buffer.
        //
        // The condition is the EXACT negation of what `transform_request_body`
        // declines on media type: a DECLARED non-JSON type is released; an
        // ABSENT `Content-Type` keeps the buffered path because the transform
        // still attempts a JSON parse for it. Framed gRPC `+json` satisfies
        // `is_json_content_type` and so also stays buffered, matching the
        // transform, which declines it only after a failed document parse.
        //
        // Safe against a header rewrite that changes eligibility: proxy core
        // (and the H3 path) re-evaluates `final_request_body_requirements`
        // against the effective outbound headers after `before_proxy`, so a
        // `text/plain` -> `application/json` rewrite still selects buffering
        // before the body is read. Route-level request transforms are
        // header-only and never reach the body.
        if !self.rules_enabled || self.body_rules.is_empty() {
            return false;
        }
        ctx.headers
            .get("content-type")
            .is_none_or(|ct| body_transform::is_json_content_type(ct))
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        if !self.rules_enabled {
            return PluginResult::Continue;
        }
        let original_query = if self.templates_read_query {
            original_query_params(ctx)
        } else {
            HashMap::new()
        };
        let mut rule_skipped: Option<&'static str> = None;
        for rule in &self.header_rules {
            match rule.operation {
                HeaderOp::Add => {
                    // Add-if-absent: an existing header wins before any
                    // template is resolved.
                    if headers.contains_key(&rule.key) {
                        continue;
                    }
                    match rule.authored_value(ctx, &original_query) {
                        Ok(val) => {
                            let val = val.into_owned();
                            headers.insert(rule.key.clone(), val);
                            debug!("request_transformer: added header {}", rule.key);
                        }
                        Err(reason) => rule_skipped = Some(reason),
                    }
                }
                HeaderOp::Update => match rule.authored_value(ctx, &original_query) {
                    Ok(val) => {
                        let val = val.into_owned();
                        headers.insert(rule.key.clone(), val);
                        debug!("request_transformer: set header {}", rule.key);
                    }
                    Err(reason) => rule_skipped = Some(reason),
                },
                HeaderOp::Remove => {
                    headers.remove(&rule.key);
                    debug!("request_transformer: removed header {}", rule.key);
                }
                HeaderOp::Rename => {
                    if let Some(ref new_key) = rule.new_key
                        && let Some(val) = headers.remove(&rule.key)
                    {
                        debug!(
                            "request_transformer: renamed header {} -> {}",
                            rule.key, new_key
                        );
                        headers.insert(new_key.clone(), val);
                        // Record the rename so secondary egress
                        // (request_mirror) can carry credential provenance to
                        // the new name under its own classifiers.
                        ctx.plugin_state_mut()
                            .request_header_rename_lineage
                            .push((rule.key.clone(), new_key.clone()));
                    }
                }
            }
        }
        if !self.query_rules.is_empty() {
            apply_query_rules(self, ctx, &original_query, &mut rule_skipped);
        }
        if self.body_rules_decline_declared_non_json(ctx, headers) {
            ctx.metadata.insert(
                BODY_SKIPPED_METADATA_KEY.to_string(),
                BODY_SKIPPED_NON_JSON_CONTENT_TYPE.to_string(),
            );
        }
        // Body rules may rewrite the bytes a client digest describes. Whether
        // they can — and whether a digest is even present — is decided by
        // proxy core over the FINAL outbound headers: a later header rule, a
        // rename into `Content-Digest`, or the route-header finalizer can still
        // change either. Enrolment is a plain bool, so it never allocates.
        if !self.body_rules.is_empty() {
            ctx.request_body_integrity_retirement = true;
        }
        if let Some(reason) = rule_skipped {
            ctx.metadata
                .insert(RULE_SKIPPED_METADATA_KEY.to_string(), reason.to_string());
        }
        // Route-level header transforms are applied exactly once by proxy core
        // after the last eligible request_transformer in the chain — see
        // `finalize_route_override_request_headers`. Do not take or apply them
        // here: a later same-type instance must still be able to run static
        // rules before that authoritative final phase.
        PluginResult::Continue
    }

    async fn transform_request_body(
        &self,
        body: &[u8],
        content_type: Option<&str>,
        _request_headers: &std::collections::HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        match self.transform_body(body, content_type) {
            BodyPass::Replaced(bytes) => Some(bytes),
            BodyPass::Skipped(_) | BodyPass::Unchanged => None,
        }
    }

    async fn transform_request_body_with_context(
        &self,
        ctx: &mut RequestContext,
        body: &[u8],
        content_type: Option<&str>,
        _request_headers: &std::collections::HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        match self.transform_body(body, content_type) {
            BodyPass::Replaced(bytes) => {
                // A `before_proxy` non-JSON verdict is superseded when a later
                // header change made the body rewritable after all.
                ctx.metadata.remove(BODY_SKIPPED_METADATA_KEY);
                Some(bytes)
            }
            BodyPass::Skipped(reason) => {
                ctx.metadata
                    .insert(BODY_SKIPPED_METADATA_KEY.to_string(), reason.to_string());
                None
            }
            BodyPass::Unchanged => None,
        }
    }
}

fn apply_query_rules(
    plugin: &RequestTransformer,
    ctx: &mut RequestContext,
    original_query: &HashMap<String, String>,
    rule_skipped: &mut Option<&'static str>,
) {
    // Prefer an earlier transformer's published outbound query, then the
    // retained raw wire query, then the decoded map for synthetic contexts.
    // Starting from raw after a prior instance already mutated would undo
    // earlier ordered rules when multiple request_transformer instances run.
    let mut ordered = if let Some(outbound) = ctx.outbound_query_string() {
        OrderedQuery::parse(outbound)
    } else if let Some(raw) = ctx.raw_query_string() {
        OrderedQuery::parse(raw)
    } else if !ctx.query_params.is_empty() {
        OrderedQuery::from_map(&ctx.query_params)
    } else {
        OrderedQuery::new()
    };

    // Fail-closed: strip authentication-owned credentials from the transform
    // input before any query rules run. A rename/update of a marked name must
    // not relocate or re-encode the authenticated secret onto the outbound
    // query or the plugin-visible map. The proxy still applies a final strip
    // pass as defense in depth.
    let strip_names: HashSet<&str> = ctx
        .metadata
        .keys()
        .filter_map(|key| {
            key.strip_prefix(
                crate::plugins::utils::token_extract::STRIP_QUERY_PARAM_METADATA_PREFIX,
            )
        })
        .collect();
    let mut query_mutated = ordered.remove_matching_names(&strip_names);

    for rule in &plugin.query_rules {
        match rule.operation {
            QueryOp::Add => {
                // Add-if-absent: an existing name wins before any template
                // is resolved.
                if rule.value_template.is_some() && ordered.contains_decoded_name(&rule.key) {
                    continue;
                }
                match rule.authored_value(ctx, original_query) {
                    Ok(val) => {
                        let changed = ordered.add(&rule.key, &val);
                        if changed {
                            // Log only the parameter name — never the value (may be secret).
                            debug!("request_transformer: added query param {}", rule.key);
                        }
                        query_mutated |= changed;
                    }
                    Err(reason) => *rule_skipped = Some(reason),
                }
            }
            QueryOp::Update => match rule.authored_value(ctx, original_query) {
                Ok(val) => {
                    query_mutated |= ordered.update(&rule.key, &val);
                    debug!("request_transformer: updated query param {}", rule.key);
                }
                Err(reason) => *rule_skipped = Some(reason),
            },
            QueryOp::Remove => {
                let changed = ordered.remove(&rule.key);
                if changed {
                    debug!("request_transformer: removed query param {}", rule.key);
                }
                query_mutated |= changed;
            }
            QueryOp::Rename => {
                if let Some(ref new_key) = rule.new_key {
                    let changed = ordered.rename(&rule.key, new_key);
                    if changed {
                        debug!(
                            "request_transformer: renamed query param {} -> {}",
                            rule.key, new_key
                        );
                        // Record the rename for credential provenance.
                        ctx.plugin_state_mut()
                            .request_query_rename_lineage
                            .push((rule.key.clone(), new_key.clone()));
                    }
                    query_mutated |= changed;
                }
            }
        }
    }

    if !query_mutated {
        return;
    }

    // Keep the plugin-visible map coherent with the ordered outbound query
    // (last occurrence wins), without forcing later consumers to re-parse.
    ctx.publish_transformed_query(ordered.serialize(), ordered.to_single_value_map());
    ctx.metadata.insert(
        crate::proxy::QUERY_PARAMS_TRANSFORMED_METADATA_KEY.to_string(),
        "true".to_string(),
    );
}
