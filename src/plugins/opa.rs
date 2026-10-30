//! Open Policy Agent (OPA) authorization plugin.
//!
//! Delegates HTTP-family request authorization to OPA's Data API by POSTing an
//! `input` document to `/v1/data/{policy_path}` during the `authorize` phase.
//! The plugin fails closed by default, bounds policy responses, and redacts
//! sensitive client headers and query credentials before forwarding request
//! context to OPA. External identities carry their verified realm, repeated
//! non-list headers are classified like ambiguous queries, opt-in decision
//! obligations can set allowed upstream headers or shape a denial, and every
//! decision records a fixed-cardinality `opa.decision` / `opa.reason` pair.

use crate::plugins::utils::log_sampling::warn_sampled;

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine;
use http::header::{CONTENT_TYPE, HeaderName, HeaderValue};
use serde::Serialize;
use serde::ser::SerializeMap;
use serde_json::{Map, Value};
use tokio::sync::Semaphore;
use tracing::info;
use url::{Host, Url};

use crate::proxy::headers::field_names_equivalent_for_backends;
use crate::retry::classify_reqwest_error;

use super::utils::auth_flow::ExternalIdentityRealm;
use super::utils::claim_header_fanout::is_output_claim_reserved_header;
use super::utils::metadata_redaction::is_sensitive_header_name;
use super::utils::query::{CanonicalQuery, CanonicalQueryParam, canonical_query_for_policy};
use super::utils::response_body::{
    BoundedReadError, parse_max_response_body_bytes, read_response_body_bounded,
};
use super::utils::socket_host::is_loopback_ip_literal_endpoint;
use super::{HTTP_FAMILY_PROTOCOLS, Plugin, PluginHttpClient, PluginResult, RequestContext};

const DEFAULT_TIMEOUT_MS: u64 = 1000;
const MAX_TIMEOUT_MS: u64 = 30_000;
const DEFAULT_MAX_RESPONSE_BYTES: usize = 256 * 1024;
const DEFAULT_MAX_BODY_BYTES: usize = 1024 * 1024;
const DEFAULT_DENY_STATUS: u16 = 403;
const DEFAULT_DENY_BODY: &str = r#"{"error":"forbidden by policy"}"#;
const DEFAULT_FAIL_CLOSED_STATUS: u16 = 503;
const DEFAULT_FAIL_CLOSED_BODY: &str = r#"{"error":"authorization service unavailable"}"#;
const OPA_DATA_PREFIX: &str = "/v1/data/";
/// Upper bound for `max_concurrent_decisions`.
const MAX_CONCURRENT_DECISIONS_LIMIT: u64 = 1_000_000;
/// Upper bound on how many names `decision_request_headers` may list.
const MAX_DECISION_REQUEST_HEADERS: usize = 32;
/// Upper bound on one header value a decision obligation may carry.
const MAX_OBLIGATION_HEADER_VALUE_BYTES: usize = 8 * 1024;
/// Upper bound on how many response headers a policy-authored denial may add.
const MAX_DENY_OBLIGATION_HEADERS: usize = 16;
/// Upper bound on a policy-authored denial body.
const MAX_DENY_OBLIGATION_BODY_BYTES: usize = 64 * 1024;
/// `input.header_ambiguity` token for a non-list header that arrived as more
/// than one field line.
const HEADER_AMBIGUITY_DUPLICATE_FIELD_LINES: &str = "duplicate_field_lines";

/// Transaction-log metadata key carrying this request's OPA outcome:
/// `allow`, `deny`, `error_fail_open`, or `error_fail_closed`.
pub const OPA_DECISION_METADATA_KEY: &str = "opa.decision";
/// Transaction-log metadata key carrying the fixed-cardinality reason for
/// [`OPA_DECISION_METADATA_KEY`]. Never request or decision-document content.
pub const OPA_REASON_METADATA_KEY: &str = "opa.reason";

/// Request headers that carry credentials and are never sent to OPA. The
/// shared sensitive-name classifier ([`is_sensitive_header_name`]) is applied
/// on top of this list.
const DEFAULT_REDACT_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "api-key",
    "x-api-key",
    "x-goog-api-key",
    "x-auth-token",
    "x-csrf-token",
    "x-xsrf-token",
    "x-forwarded-authorization",
    "x-loadtesting-key",
    "x-loadtesting-fanout",
];

const OPA_CONFIG_KEYS: &[&str] = &[
    "opa_host",
    "policy_path",
    "headers",
    "timeout_ms",
    "max_response_bytes",
    "fail_open",
    "fail_closed",
    "deny_status",
    "deny_body",
    "deny_headers",
    "fail_closed_status",
    "fail_closed_body",
    "fail_closed_headers",
    "decision_pointer",
    "include_method",
    "include_path",
    "include_query",
    "include_query_credentials",
    "include_headers",
    "include_body",
    "max_body_bytes",
    "include_consumer",
    "include_client_ip",
    "include_service",
    "query_ambiguity_policy",
    "header_ambiguity_policy",
    "redact_headers",
    "redact_query_keys",
    "allow_plaintext",
    "max_concurrent_decisions",
    "decision_request_headers",
    "decision_deny_response",
];

#[derive(Serialize)]
struct OpaDecisionPayload<'a> {
    input: OpaInputPayload<'a>,
}

struct OpaInputPayload<'a> {
    fields: Map<String, Value>,
    body: Option<OpaBody<'a>>,
}

enum OpaBody<'a> {
    Text(&'a str),
    Base64(String),
    Null,
}

impl Serialize for OpaInputPayload<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let body_field_count = if self.body.is_some() { 1 } else { 0 };
        let mut map = serializer.serialize_map(Some(self.fields.len() + body_field_count))?;
        for (key, value) in &self.fields {
            map.serialize_entry(key, value)?;
        }
        match self.body.as_ref() {
            Some(OpaBody::Text(body)) => map.serialize_entry("body", body)?,
            Some(OpaBody::Base64(body)) => map.serialize_entry("body_base64", body)?,
            Some(OpaBody::Null) => map.serialize_entry("body", &Value::Null)?,
            None => {}
        }
        map.end()
    }
}

pub struct Opa {
    http_client: PluginHttpClient,
    /// The admitted, already-normalized decision URL. Requests are built from
    /// this parsed value rather than re-parsing a string, so the URL sent on
    /// the wire is exactly the one whose path was proven to stay under the
    /// `/v1/data/` Data API prefix at config admission.
    decision_url: Url,
    /// Structural `scheme://host[:port]/redacted` rendering of `decision_url`,
    /// precomputed once so the shared client's slow-call and egress-denial
    /// diagnostics never print the configured base path. `opa_host` rejects
    /// userinfo, query, and fragment, but it does accept a base PATH, and a
    /// deployment may put a reusable credential there
    /// (GHSA-4ghp-v85j-5hvq).
    redacted_decision_url: String,
    decision_hostname: String,
    custom_headers: Vec<(HeaderName, HeaderValue)>,
    timeout: Duration,
    max_response_bytes: usize,
    fail_open: bool,
    deny_status: u16,
    deny_body: String,
    deny_headers: HashMap<String, String>,
    fail_closed_status: u16,
    fail_closed_body: String,
    fail_closed_headers: HashMap<String, String>,
    decision_pointer: Vec<String>,
    include_method: bool,
    include_path: bool,
    include_query: bool,
    include_query_credentials: bool,
    include_headers: bool,
    include_body: bool,
    max_body_bytes: usize,
    include_consumer: bool,
    include_client_ip: bool,
    include_service: bool,
    query_ambiguity_policy: AmbiguityPolicy,
    header_ambiguity_policy: AmbiguityPolicy,
    redact_headers: HashSet<String>,
    redact_query_keys: HashSet<String>,
    /// Per-instance bulkhead on in-flight decision calls. `None` is unbounded.
    /// Over the limit a request takes the configured failure posture at once
    /// instead of queueing behind a slow policy service.
    decision_concurrency: Option<Semaphore>,
    /// Lowercase upstream request headers an allow decision may set. Empty
    /// disables allow obligations. Every listed name is gateway-owned while
    /// this instance governs the request: client copies (any case, `_` or
    /// `-`) are removed and only a policy-supplied value is forwarded.
    decision_request_headers: Vec<String>,
    /// Whether a deny decision object may supply its own `status`, `body`,
    /// and `headers`.
    decision_deny_response: bool,
}

/// The request-header view sent to OPA.
struct HeaderInput {
    /// `input.headers`: one folded value per lowercase name. A name whose
    /// repeated field lines are ambiguous is omitted.
    flat: Map<String, Value>,
    /// `input.header_pairs`: every field line the backend may receive, grouped
    /// by lowercase name in sorted order, repeated lines in wire order.
    pairs: Vec<Value>,
    /// Whether some non-list header arrived as more than one field line.
    ambiguous: bool,
}

/// Outcome of the network half of one decision call: everything decided while
/// the shared HTTP client is still measuring external I/O.
///
/// JSON parsing and policy evaluation deliberately happen after the measured
/// span closes, so CPU time is never attributed to network I/O.
enum OpaDecisionFetch {
    /// The complete decision document, within the configured byte ceiling.
    Body(bytes::Bytes),
    /// `Content-Length` already exceeded the configured ceiling.
    DeclaredTooLarge,
    /// The streamed body crossed the ceiling before it finished.
    StreamedTooLarge,
    /// The body read failed mid-stream; carries only the error CLASS.
    ReadFailed(String),
    /// OPA answered with a non-2xx status.
    NonSuccess(u16),
}

/// What to do when the request query (`query_ambiguity_policy`) or the
/// request headers (`header_ambiguity_policy`) cannot be reduced to one view
/// that OPA and the backend are guaranteed to read identically.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AmbiguityPolicy {
    /// Deny the request before calling OPA. Default: a policy decision must
    /// never be made on a value different from the one the backend executes.
    Reject,
    /// Call OPA anyway and let Rego decide, using the ordered occurrence list
    /// (`input.query_pairs` / `input.header_pairs`) plus the classifications
    /// (`input.query_ambiguity` / `input.header_ambiguity`). The flat view of
    /// the ambiguous part (all of `input.query`, or the ambiguous names in
    /// `input.headers`) is omitted so no rule can read a flat value the
    /// backend may not execute.
    ///
    /// Omission is not itself a denial, and this mode moves that decision to
    /// the operator by design: an `allow` rule that reads the omitted value
    /// becomes undefined and denies, but the deny-list idiom
    /// (`deny { input.query.x == "bad" }` with `allow { not deny }`) leaves
    /// `deny` undefined and therefore allows. A `delegate` policy must deny
    /// on a non-empty classification it does not handle.
    Delegate,
}

impl AmbiguityPolicy {
    fn parse(object: &Map<String, Value>, field: &'static str) -> Result<Self, String> {
        match parse_optional_string(object, field)?.as_deref() {
            None | Some("reject") => Ok(Self::Reject),
            Some("delegate") => Ok(Self::Delegate),
            Some(_) => Err(format!(
                "opa: `{field}` must be one of `reject` or `delegate`"
            )),
        }
    }
}

impl Opa {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        let object = config
            .as_object()
            .ok_or_else(|| "opa: config must be a JSON object".to_string())?;
        reject_unknown_keys(object)?;

        let (decision_url, redacted_decision_url, decision_hostname) =
            parse_decision_endpoint(object)?;
        if decision_url.scheme() == "https" {
            info!(
                plugin = "opa",
                scheme = "https",
                "OPA HTTPS decision endpoint uses global TLS trust configuration"
            );
        }
        let custom_headers = parse_header_map(object, "headers", "opa")?;
        let timeout_ms = parse_optional_u64(object, "timeout_ms")?.unwrap_or(DEFAULT_TIMEOUT_MS);
        if timeout_ms == 0 {
            return Err("opa: `timeout_ms` must be greater than zero".to_string());
        }
        let timeout_ms = timeout_ms.min(MAX_TIMEOUT_MS);
        let max_response_bytes = parse_max_response_body_bytes(
            config,
            "opa",
            "max_response_bytes",
            DEFAULT_MAX_RESPONSE_BYTES,
        )?;
        let max_body_bytes =
            parse_max_response_body_bytes(config, "opa", "max_body_bytes", DEFAULT_MAX_BODY_BYTES)?;
        let fail_open = parse_fail_open(object)?;
        let deny_status = parse_response_status(object, "deny_status", DEFAULT_DENY_STATUS)?;
        let deny_body = parse_optional_string(object, "deny_body")?
            .unwrap_or_else(|| DEFAULT_DENY_BODY.to_string());
        let deny_headers = parse_string_header_map(object, "deny_headers", "opa")?;
        let fail_closed_status =
            parse_response_status(object, "fail_closed_status", DEFAULT_FAIL_CLOSED_STATUS)?;
        let fail_closed_body = parse_optional_string(object, "fail_closed_body")?
            .unwrap_or_else(|| DEFAULT_FAIL_CLOSED_BODY.to_string());
        let fail_closed_headers = parse_string_header_map(object, "fail_closed_headers", "opa")?;
        let decision_pointer = parse_decision_pointer(object)?;
        let redact_headers = parse_redact_headers(object)?;
        let redact_query_keys = parse_redact_query_keys(object)?;
        let decision_concurrency = parse_max_concurrent_decisions(object)?;
        let decision_request_headers = parse_decision_request_headers(object)?;
        let decision_deny_response =
            parse_optional_bool(object, "decision_deny_response")?.unwrap_or(false);

        Ok(Self {
            http_client,
            decision_url,
            redacted_decision_url,
            decision_hostname,
            custom_headers,
            timeout: Duration::from_millis(timeout_ms),
            max_response_bytes,
            fail_open,
            deny_status,
            deny_body,
            deny_headers,
            fail_closed_status,
            fail_closed_body,
            fail_closed_headers,
            decision_pointer,
            include_method: parse_optional_bool(object, "include_method")?.unwrap_or(true),
            include_path: parse_optional_bool(object, "include_path")?.unwrap_or(true),
            include_query: parse_optional_bool(object, "include_query")?.unwrap_or(true),
            include_query_credentials: parse_optional_bool(object, "include_query_credentials")?
                .unwrap_or(false),
            include_headers: parse_optional_bool(object, "include_headers")?.unwrap_or(true),
            include_body: parse_optional_bool(object, "include_body")?.unwrap_or(false),
            max_body_bytes,
            include_consumer: parse_optional_bool(object, "include_consumer")?.unwrap_or(true),
            include_client_ip: parse_optional_bool(object, "include_client_ip")?.unwrap_or(true),
            include_service: parse_optional_bool(object, "include_service")?.unwrap_or(true),
            query_ambiguity_policy: AmbiguityPolicy::parse(object, "query_ambiguity_policy")?,
            header_ambiguity_policy: AmbiguityPolicy::parse(object, "header_ambiguity_policy")?,
            redact_headers,
            redact_query_keys,
            decision_concurrency,
            decision_request_headers,
            decision_deny_response,
        })
    }

    /// The upstream request headers allow obligations may set (lowercase).
    /// Plugin-cache composition admission compares them against the credential
    /// locations all plugins on the same chain publish.
    pub(crate) fn decision_request_header_destinations(&self) -> &[String] {
        &self.decision_request_headers
    }

    /// Whether an obligation destination is one of this route's active
    /// credential locations (any plugin's `request_headers_to_redact`, built
    /// with the plugin cache), compared as backends read names. Admission
    /// refuses these overlaps; this is the per-request fail-closed backstop.
    fn obligation_destination_owns_a_credential(&self, ctx: &RequestContext) -> bool {
        if self.decision_request_headers.is_empty() {
            return false;
        }
        ctx.request_headers_requiring_redaction()
            .iter()
            .any(|credential| {
                self.decision_request_headers
                    .iter()
                    .any(|destination| field_names_equivalent_for_backends(destination, credential))
            })
    }

    fn build_input(
        &self,
        ctx: &RequestContext,
        query: Option<&CanonicalQuery>,
        headers: Option<HeaderInput>,
    ) -> Map<String, Value> {
        let mut input = Map::new();

        if self.include_method {
            input.insert("method".to_string(), Value::String(ctx.method.clone()));
        }
        if self.include_path {
            input.insert("path".to_string(), Value::String(ctx.path.clone()));
        }
        if let Some(query) = query {
            // Authentication-marked query credential names are request
            // invariant, so they are collected once here rather than by
            // rescanning `ctx.metadata` for every parameter.
            let marked_credentials = if self.include_query_credentials {
                HashSet::new()
            } else {
                query_credential_keys(ctx)
            };
            // `input.query` is the convenient flat view and is emitted only
            // when the canonical decoding is the one the backend must also
            // read. For an ambiguous query it is omitted entirely, so a Rego
            // rule can never read from it a value the backend does not
            // execute — the whole of both advisories. Under `delegate` the
            // policy itself must still deny on a non-empty
            // `input.query_ambiguity`; see `AmbiguityPolicy::Delegate`.
            if query.is_unambiguous() {
                input.insert(
                    "query".to_string(),
                    self.query_map_input(&marked_credentials, query),
                );
            }
            // The ordered occurrence-complete representation and the ambiguity
            // classifications are always present, so a policy that opts into
            // `query_ambiguity_policy: delegate` can validate the query
            // against its own backend's duplicate/plus contract.
            input.insert(
                "query_pairs".to_string(),
                self.query_pairs_input(&marked_credentials, query),
            );
            input.insert(
                "query_ambiguity".to_string(),
                Value::Array(
                    query
                        .ambiguities()
                        .iter()
                        .map(|ambiguity| Value::String(ambiguity.reason().to_string()))
                        .collect(),
                ),
            );
        }
        if let Some(headers) = headers {
            input.insert("headers".to_string(), Value::Object(headers.flat));
            input.insert("header_pairs".to_string(), Value::Array(headers.pairs));
            let ambiguity = if headers.ambiguous {
                vec![Value::String(
                    HEADER_AMBIGUITY_DUPLICATE_FIELD_LINES.to_string(),
                )]
            } else {
                Vec::new()
            };
            input.insert("header_ambiguity".to_string(), Value::Array(ambiguity));
        }
        if self.include_client_ip {
            input.insert(
                "client_ip".to_string(),
                Value::String(ctx.client_ip.clone()),
            );
        }
        if self.include_service {
            input.insert("service".to_string(), self.service_input(ctx));
        }
        if self.include_consumer {
            input.insert("consumer".to_string(), self.consumer_input(ctx));
        }
        input
    }

    /// Flat decoded `name -> value` view. Only built for an unambiguous
    /// canonical query, where each name occurs exactly once.
    fn query_map_input(
        &self,
        marked_credentials: &HashSet<String>,
        query: &CanonicalQuery,
    ) -> Value {
        let mut map = Map::with_capacity(query.len());
        for param in query.params() {
            if self.query_param_is_redacted(marked_credentials, param) {
                continue;
            }
            map.insert(param.name.clone(), Value::String(param.value.clone()));
        }
        Value::Object(map)
    }

    /// Ordered occurrence view: every pair in wire order, with the
    /// bare-parameter bit that distinguishes `?flag` from `?flag=`. Credential
    /// redaction applies here exactly as it does to the flat map, so opting
    /// into `delegate` never widens what OPA is told. Non-UTF-8 components are
    /// lossy-decoded and carry an explicit ambiguity classification; Rego must
    /// reject that class when it needs exact bytes.
    fn query_pairs_input(
        &self,
        marked_credentials: &HashSet<String>,
        query: &CanonicalQuery,
    ) -> Value {
        let mut pairs = Vec::with_capacity(query.len());
        for param in query.params() {
            if self.query_param_is_redacted(marked_credentials, param) {
                continue;
            }
            let mut entry = Map::with_capacity(3);
            entry.insert("name".to_string(), Value::String(param.name.clone()));
            entry.insert("value".to_string(), Value::String(param.value.clone()));
            entry.insert("bare".to_string(), Value::Bool(param.bare));
            pairs.push(Value::Object(entry));
        }
        Value::Array(pairs)
    }

    /// Whether a pair must be withheld from OPA. Beyond its own name, a pair
    /// is withheld when a `;`-separated sub-pair of it names a redacted key
    /// (issue #6579): `carrier=;api_key=secret` is one `carrier` pair here but
    /// an `api_key` credential to a backend that also splits on `;`, and under
    /// `query_ambiguity_policy: delegate` its value would otherwise reach the
    /// policy service. Sub-pairs come from the still-encoded bytes, so an
    /// encoded name (`;api%5Fkey=`, `;private%3Dkey=`) is matched decoded while
    /// a `%3B` stays ordinary content and never hides a parameter.
    fn query_param_is_redacted(
        &self,
        marked_credentials: &HashSet<String>,
        param: &CanonicalQueryParam,
    ) -> bool {
        self.query_key_is_redacted(marked_credentials, &param.name)
            || param
                .form_name
                .as_deref()
                .is_some_and(|name| self.query_key_is_redacted(marked_credentials, name))
            || param
                .semicolon_sub_names
                .iter()
                .any(|name| self.query_key_is_redacted(marked_credentials, name))
    }

    /// Hashed, case-insensitive lookups only: both configured and
    /// authentication-marked names are stored lowercase, so one lowercase
    /// rendering of `key` (borrowed when it is already lowercase) serves both.
    /// Built-in credential names, the shared sensitive-name classifier, and
    /// authentication-marked locations are withheld unless
    /// `include_query_credentials` is set; `redact_query_keys` always are.
    fn query_key_is_redacted(&self, marked_credentials: &HashSet<String>, key: &str) -> bool {
        let lower = ascii_lowercase(key);
        self.redact_query_keys.contains(&*lower)
            || (!self.include_query_credentials
                && (is_default_sensitive_query_key(&lower)
                    || marked_credentials.contains(&*lower)
                    || is_sensitive_header_name(key)))
    }

    /// Whether a request header must be withheld from OPA: the built-in list
    /// plus `redact_headers`, the active authentication credential headers,
    /// and the shared sensitive-name classifier also used by log redaction,
    /// so an unlisted credential spelling (`x-vault-token`,
    /// `x-amz-security-token`) does not reach the policy service.
    fn header_is_redacted(&self, ctx: &RequestContext, lower: &str) -> bool {
        self.redact_headers.contains(lower)
            || ctx.request_header_requires_redaction(lower)
            || is_sensitive_header_name(lower)
    }

    /// Build the header view from the materialized (plugin-effective) map,
    /// reporting every field line the backend may receive for each name.
    ///
    /// A name the backend may receive as more than one field line is only
    /// unambiguous for list-valued fields, where repetition and comma folding
    /// mean the same thing. For any other field a backend may read the first
    /// line, the last, or the fold, while the folded `input.headers` value
    /// matches none of them — so such a name is classified and, under
    /// `delegate`, omitted from `input.headers`.
    fn header_input(&self, ctx: &RequestContext) -> HeaderInput {
        let mut entries: Vec<(&String, &String)> = ctx.headers.iter().collect();
        entries.sort_unstable_by(|left, right| left.0.cmp(right.0));

        let mut flat = Map::new();
        let mut pairs = Vec::with_capacity(entries.len());
        let mut ambiguous_names: Vec<String> = Vec::new();
        for (name, folded) in entries {
            let lower = ascii_lowercase(name);
            if self.header_is_redacted(ctx, &lower) {
                continue;
            }
            let occurrences = header_field_line_occurrences(ctx, name, folded);
            // Two map keys that differ only in case also reach the backend as
            // two field lines of one name.
            let repeated = occurrences.len() > 1
                || flat.contains_key(&*lower)
                || ambiguous_names.iter().any(|seen| seen == &*lower);
            let duplicated = repeated && !is_list_valued_request_header(&lower);
            for value in &occurrences {
                let mut entry = Map::with_capacity(2);
                entry.insert("name".to_string(), Value::String(lower.to_string()));
                entry.insert("value".to_string(), Value::String((*value).to_string()));
                pairs.push(Value::Object(entry));
            }
            if duplicated {
                flat.remove(&*lower);
                if !ambiguous_names.iter().any(|seen| seen == &*lower) {
                    ambiguous_names.push(lower.into_owned());
                }
            } else {
                flat.insert(lower.into_owned(), Value::String(folded.clone()));
            }
        }
        HeaderInput {
            flat,
            pairs,
            ambiguous: !ambiguous_names.is_empty(),
        }
    }

    fn service_input(&self, ctx: &RequestContext) -> Value {
        let Some(proxy) = ctx.matched_proxy.as_ref() else {
            return Value::Null;
        };

        let mut service = Map::new();
        service.insert("id".to_string(), Value::String(proxy.id.clone()));
        if let Some(name) = proxy.name.as_ref() {
            service.insert("name".to_string(), Value::String(name.clone()));
        }
        service.insert(
            "backend_host".to_string(),
            Value::String(proxy.backend_host.clone()),
        );
        service.insert(
            "backend_port".to_string(),
            Value::Number(serde_json::Number::from(proxy.backend_port)),
        );
        if let Some(listen_path) = proxy.listen_path.as_ref() {
            service.insert(
                "listen_path".to_string(),
                Value::String(listen_path.clone()),
            );
        }
        Value::Object(service)
    }

    fn consumer_input(&self, ctx: &RequestContext) -> Value {
        if let Some(consumer) = ctx.identified_consumer.as_ref() {
            let mut value = Map::new();
            value.insert("id".to_string(), Value::String(consumer.id.clone()));
            value.insert(
                "username".to_string(),
                Value::String(consumer.username.clone()),
            );
            value.insert(
                "acl_groups".to_string(),
                Value::Array(
                    consumer
                        .acl_groups
                        .iter()
                        .cloned()
                        .map(Value::String)
                        .collect(),
                ),
            );
            if let Some(custom_id) = consumer.custom_id.as_ref() {
                value.insert("custom_id".to_string(), Value::String(custom_id.clone()));
            }
            return Value::Object(value);
        }

        if let Some(identity) = ctx.authenticated_identity.as_ref() {
            let mut value = Map::new();
            value.insert("identity".to_string(), Value::String(identity.clone()));
            if let Some(auth_method) = ctx.auth_method {
                value.insert(
                    "auth_method".to_string(),
                    Value::String(auth_method.to_string()),
                );
            }
            // An external subject only names a principal inside the authority
            // that verified it: two accepted issuers may both vouch for
            // `alice`. The realm is committed by the authentication boundary
            // together with the identity and cannot be written by a plugin or
            // a client header, so a policy keys external principals on
            // `identity` + `realm`. `null` means the identity was not
            // committed through that boundary.
            value.insert(
                "realm".to_string(),
                realm_input(ctx.authenticated_identity_realm()),
            );
            return Value::Object(value);
        }

        Value::Null
    }

    /// The request body for `include_body`.
    ///
    /// Sourced only from the gateway-owned byte view, never from the
    /// plugin-writable `request_body` metadata. A transport-proven empty body
    /// is published by every frontend as an empty byte view and serializes as
    /// `body: ""`; `body: null` means no body representation was collected
    /// (a WebSocket handshake or tunnel request, for example).
    fn body_input<'a>(&self, ctx: &'a RequestContext) -> Option<OpaBody<'a>> {
        if !self.include_body {
            return None;
        }

        let Some(bytes) = ctx.request_body_bytes.as_ref() else {
            return Some(OpaBody::Null);
        };
        match std::str::from_utf8(bytes) {
            Ok(body) => Some(OpaBody::Text(body)),
            Err(_) => Some(OpaBody::Base64(
                base64::engine::general_purpose::STANDARD.encode(bytes),
            )),
        }
    }

    fn evaluate(&self, ctx: &mut RequestContext, body: &Value) -> PluginResult {
        let Some(decision) = self.decision_value(body) else {
            return self.deny(ctx, "decision_undefined");
        };

        if decision.as_bool() == Some(true) {
            return self.allow(ctx, None);
        }

        let Some(object) = decision.as_object() else {
            return self.deny(ctx, "policy_denied");
        };
        if object.get("allow").and_then(Value::as_bool) == Some(true) {
            return self.allow(ctx, Some(object));
        }
        self.deny_with_decision(ctx, object)
    }

    fn decision_value<'a>(&self, body: &'a Value) -> Option<&'a Value> {
        let mut current = body;
        for segment in &self.decision_pointer {
            current = current.get(segment)?;
        }
        Some(current)
    }

    /// Continue an allowed request, applying any allow obligations.
    ///
    /// With `decision_request_headers` configured, an allow decision object
    /// may carry `headers`: every name must be one of the configured
    /// destinations and every value a bounded, valid field value. A decision
    /// the gateway cannot honor exactly is refused as a policy denial rather
    /// than forwarded with its obligations dropped.
    fn allow(
        &self,
        ctx: &mut RequestContext,
        decision: Option<&Map<String, Value>>,
    ) -> PluginResult {
        if !self.decision_request_headers.is_empty() {
            let staged = match decision {
                Some(decision) => match self.upstream_header_obligations(decision) {
                    Some(staged) => staged,
                    None => return self.deny(ctx, "invalid_obligation"),
                },
                None => Vec::new(),
            };
            self.install_upstream_headers(ctx, staged);
        }
        record_outcome(ctx, "allow", "policy_allowed");
        PluginResult::Continue
    }

    fn upstream_header_obligations(
        &self,
        decision: &Map<String, Value>,
    ) -> Option<Vec<(String, String)>> {
        let Some(headers) = decision.get("headers") else {
            return Some(Vec::new());
        };
        let headers = headers.as_object()?;
        if headers.len() > self.decision_request_headers.len() {
            return None;
        }
        let mut staged: Vec<(String, String)> = Vec::with_capacity(headers.len());
        for (name, value) in headers {
            let destination = self
                .decision_request_headers
                .iter()
                .find(|allowed| allowed.eq_ignore_ascii_case(name))?;
            let value = value.as_str()?;
            if value.len() > MAX_OBLIGATION_HEADER_VALUE_BYTES
                || HeaderValue::from_str(value).is_err()
                || staged.iter().any(|(existing, _)| existing == destination)
            {
                return None;
            }
            staged.push((destination.clone(), value.to_string()));
        }
        Some(staged)
    }

    /// Remove every client copy of the configured destinations (ASCII case
    /// and `_`/`-` folded, as CGI-style backends read them) and install the
    /// policy-supplied values. Runs on every request this instance lets
    /// through, including a bare `true` decision and a fail-open error, so a
    /// backend never receives a client-authored value under a name the policy
    /// owns. The map is materialized first so a later materialization can
    /// never fold a raw client value onto an installed one.
    fn install_upstream_headers(&self, ctx: &mut RequestContext, staged: Vec<(String, String)>) {
        if self.decision_request_headers.is_empty() {
            return;
        }
        ctx.materialize_headers();
        let destinations = &self.decision_request_headers;
        ctx.headers.retain(|name, _| {
            !destinations
                .iter()
                .any(|destination| field_names_equivalent_for_backends(destination, name))
        });
        for (name, value) in staged {
            ctx.headers.insert(name, value);
        }
    }

    /// Deny, using the decision object's own response when
    /// `decision_deny_response` is enabled. A malformed response obligation
    /// still denies, with the configured static response.
    fn deny_with_decision(
        &self,
        ctx: &mut RequestContext,
        decision: &Map<String, Value>,
    ) -> PluginResult {
        if !self.decision_deny_response {
            return self.deny(ctx, "policy_denied");
        }
        match self.deny_response_obligation(decision) {
            Some(result) => {
                record_outcome(ctx, "deny", "policy_denied");
                result
            }
            None => self.deny(ctx, "invalid_obligation"),
        }
    }

    fn deny_response_obligation(&self, decision: &Map<String, Value>) -> Option<PluginResult> {
        let status_code = match decision.get("status") {
            None => self.deny_status,
            Some(value) => {
                let status = u16::try_from(value.as_u64()?).ok()?;
                if !(400..=599).contains(&status) {
                    return None;
                }
                status
            }
        };
        let body = match decision.get("body") {
            None => self.deny_body.clone(),
            Some(value) => {
                let body = value.as_str()?;
                if body.len() > MAX_DENY_OBLIGATION_BODY_BYTES {
                    return None;
                }
                body.to_string()
            }
        };
        let mut headers = self.deny_headers.clone();
        if let Some(value) = decision.get("headers") {
            let map = value.as_object()?;
            if map.len() > MAX_DENY_OBLIGATION_HEADERS {
                return None;
            }
            for (name, value) in map {
                let value = value.as_str()?;
                let header_name = HeaderName::from_bytes(name.as_bytes()).ok()?;
                if crate::proxy::headers::is_protocol_managed_plugin_response_destination(
                    header_name.as_str(),
                ) || crate::proxy::headers::is_gateway_owned_diagnostic_response_header(
                    header_name.as_str(),
                ) || value.len() > MAX_OBLIGATION_HEADER_VALUE_BYTES
                    || HeaderValue::from_str(value).is_err()
                {
                    return None;
                }
                headers.insert(header_name.as_str().to_string(), value.to_string());
            }
        }
        Some(PluginResult::Reject {
            status_code,
            body,
            headers,
        })
    }

    fn on_error(
        &self,
        ctx: &mut RequestContext,
        reason: &'static str,
        detail: String,
    ) -> PluginResult {
        warn_sampled!(
            plugin = "opa",
            reason = reason,
            detail = %detail,
            "OPA authorization decision failed"
        );
        if self.fail_open {
            self.install_upstream_headers(ctx, Vec::new());
            record_outcome(ctx, "error_fail_open", reason);
            PluginResult::Continue
        } else {
            record_outcome(ctx, "error_fail_closed", reason);
            self.reject_fail_closed()
        }
    }

    fn deny(&self, ctx: &mut RequestContext, reason: &'static str) -> PluginResult {
        record_outcome(ctx, "deny", reason);
        self.reject_policy_denial()
    }

    fn reject_policy_denial(&self) -> PluginResult {
        PluginResult::Reject {
            status_code: self.deny_status,
            body: self.deny_body.clone(),
            headers: self.deny_headers.clone(),
        }
    }

    fn reject_fail_closed(&self) -> PluginResult {
        PluginResult::Reject {
            status_code: self.fail_closed_status,
            body: self.fail_closed_body.clone(),
            headers: self.fail_closed_headers.clone(),
        }
    }
}

#[async_trait]
impl Plugin for Opa {
    fn name(&self) -> &str {
        "opa"
    }

    fn priority(&self) -> u16 {
        super::priority::OPA
    }

    fn lifecycle_hooks(&self) -> crate::plugins::PluginHooks {
        crate::plugins::PluginHooks::NONE
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        HTTP_FAMILY_PROTOCOLS
    }

    async fn authorize(&self, ctx: &mut RequestContext) -> PluginResult {
        // Decode the backend-bound query representation at the OPA hook,
        // including authentication-owned strips, instead of the lossy shared
        // map. A deliberately later request_transformer remains a separate
        // ordered operation (advisories GHSA-j2j6-f9c7-hh85,
        // GHSA-gr4p-3qw3-87r5).
        // A destination that is also an active credential location would let
        // the policy replace the client's credential, or be stripped after an
        // allow by the owner's credential hiding. Refuse it fail closed before
        // the decision call, independent of `fail_open`: this is an
        // ownership conflict, not an availability failure.
        if self.obligation_destination_owns_a_credential(ctx) {
            warn_sampled!(
                plugin = "opa",
                reason = "obligation_credential_conflict",
                "Refusing request: a decision_request_headers destination is an active credential location on this route"
            );
            record_outcome(ctx, "error_fail_closed", "obligation_credential_conflict");
            return self.reject_fail_closed();
        }

        let query = self.include_query.then(|| canonical_query_for_policy(ctx));

        if let Some(query) = query.as_ref()
            && let Some(ambiguity) = query.first_ambiguity()
            && self.query_ambiguity_policy == AmbiguityPolicy::Reject
        {
            // The reason is a fixed-cardinality token; query bytes are
            // attacker-controlled and may carry credentials, so they are never
            // logged here.
            warn_sampled!(
                plugin = "opa",
                reason = "ambiguous_query",
                ambiguity = ambiguity.reason(),
                "Rejecting request whose query cannot be decoded to one value OPA and the backend both read"
            );
            return self.deny(ctx, "ambiguous_query");
        }

        let headers = if self.include_headers {
            ctx.materialize_headers();
            Some(self.header_input(ctx))
        } else {
            None
        };
        if headers.as_ref().is_some_and(|headers| headers.ambiguous)
            && self.header_ambiguity_policy == AmbiguityPolicy::Reject
        {
            // Header names and values are client-controlled; only the fixed
            // reason token is logged.
            warn_sampled!(
                plugin = "opa",
                reason = "ambiguous_header",
                "Rejecting request with a repeated non-list header OPA and the backend could read differently"
            );
            return self.deny(ctx, "ambiguous_header");
        }

        let Ok(client) = self.http_client.get() else {
            return self.on_error(
                ctx,
                "opa_call_failed",
                "plugin HTTP client unavailable".to_string(),
            );
        };
        // Bulkhead: never queue behind a saturated policy service. The permit
        // is held until the decision document has been read.
        let _decision_permit = match self.decision_concurrency.as_ref() {
            Some(semaphore) => match semaphore.try_acquire() {
                Ok(permit) => Some(permit),
                Err(_) => {
                    return self.on_error(
                        ctx,
                        "opa_concurrency_limit",
                        "max_concurrent_decisions reached".to_string(),
                    );
                }
            },
            None => None,
        };

        let input = self.build_input(ctx, query.as_ref(), headers);
        let payload = OpaDecisionPayload {
            input: OpaInputPayload {
                fields: input,
                body: self.body_input(ctx),
            },
        };
        let mut request = client
            .post(self.decision_url.clone())
            .timeout(self.timeout)
            .json(&payload);
        drop(payload);
        for (name, value) in &self.custom_headers {
            request = request.header(name.clone(), value.clone());
        }
        // A decision URL that resolves back to the gateway is refused at the
        // proxy hop limit like a looping route (issue #6128).
        request = crate::proxy::hop_limit::stamp_plugin_call_proxy_hops(
            request,
            crate::proxy::hop_limit::plugin_call_proxy_hops(ctx),
        );

        // The decision is not made until the complete response document has
        // arrived, so the body wait is part of the external I/O this plugin
        // performs. Measuring it inside the shared call keeps
        // `latency_plugin_external_io_ms` and the slow-call threshold on the
        // same boundary the decision actually waits for; a policy service that
        // flushes headers immediately and its decision 180 ms later is
        // otherwise invisible in both (issue #5059). Only the read runs inside
        // the closure — JSON parsing and evaluation stay outside so CPU time is
        // never reported as network time.
        let max_response_bytes = self.max_response_bytes;
        let fetched = self
            .http_client
            .execute_redacted_tracked_through_body(
                request,
                "opa",
                &self.redacted_decision_url,
                &ctx.plugin_http_call_ns,
                move |response| async move {
                    if !response.status().is_success() {
                        return OpaDecisionFetch::NonSuccess(response.status().as_u16());
                    }
                    if response
                        .content_length()
                        .is_some_and(|length| length > max_response_bytes as u64)
                    {
                        return OpaDecisionFetch::DeclaredTooLarge;
                    }
                    match read_response_body_bounded(response, max_response_bytes).await {
                        Ok(bytes) => OpaDecisionFetch::Body(bytes),
                        Err(BoundedReadError::LimitExceeded { .. }) => {
                            OpaDecisionFetch::StreamedTooLarge
                        }
                        Err(BoundedReadError::Stream(error)) => {
                            OpaDecisionFetch::ReadFailed(classify_reqwest_error(&error).to_string())
                        }
                    }
                },
            )
            .await;

        match fetched {
            Ok(OpaDecisionFetch::Body(bytes)) => match serde_json::from_slice::<Value>(&bytes) {
                Ok(body) => self.evaluate(ctx, &body),
                Err(error) => self.on_error(ctx, "opa_response_parse_failed", error.to_string()),
            },
            Ok(OpaDecisionFetch::DeclaredTooLarge) => self.on_error(
                ctx,
                "opa_response_too_large",
                format!("declared response length exceeds {max_response_bytes} bytes"),
            ),
            Ok(OpaDecisionFetch::StreamedTooLarge) => self.on_error(
                ctx,
                "opa_response_too_large",
                format!("response exceeded configured {max_response_bytes} byte limit"),
            ),
            Ok(OpaDecisionFetch::ReadFailed(error_class)) => {
                self.on_error(ctx, "opa_response_read_failed", error_class)
            }
            Ok(OpaDecisionFetch::NonSuccess(status)) => {
                self.on_error(ctx, "opa_non_success_status", status.to_string())
            }
            Err(error) => self.on_error(ctx, "opa_call_failed", error),
        }
    }

    fn requires_request_body_before_authorize(&self) -> bool {
        self.include_body
    }

    fn requires_request_body_buffering(&self) -> bool {
        self.include_body
    }

    fn needs_request_body_bytes(&self) -> bool {
        self.include_body
    }

    fn needs_request_body_text(&self) -> bool {
        false
    }

    fn request_body_buffer_limit(&self) -> Option<usize> {
        self.include_body.then_some(self.max_body_bytes)
    }

    /// OPA's decision does not read `ctx.query_params` — it decodes the
    /// forwarded query itself, identically on H1/H2/H3. Declared when the
    /// query is part of the policy input.
    fn requires_decoded_query_params(&self) -> bool {
        self.include_query
    }

    /// Allow obligations (`decision_request_headers`) rewrite backend-visible
    /// request headers from `authorize`. Removal folds `_` and `-`, so the
    /// changed set is not a fixed list of spellings and
    /// `modified_request_header_names` keeps its conservative default.
    fn modifies_request_headers(&self) -> bool {
        !self.decision_request_headers.is_empty()
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        vec![self.decision_hostname.clone()]
    }
}

/// Record this request's fixed-cardinality OPA outcome for transaction logs.
fn record_outcome(ctx: &mut RequestContext, decision: &'static str, reason: &'static str) {
    ctx.metadata
        .insert(OPA_DECISION_METADATA_KEY.to_string(), decision.to_string());
    ctx.metadata
        .insert(OPA_REASON_METADATA_KEY.to_string(), reason.to_string());
}

/// `input.consumer.realm`: the verifying mechanism and the opaque, stable
/// authority digest (lowercase hex, `null` for a single-authority mechanism).
/// Carries no token, claim, issuer URL, or credential material.
fn realm_input(realm: Option<ExternalIdentityRealm>) -> Value {
    let Some(realm) = realm else {
        return Value::Null;
    };
    let mut value = Map::with_capacity(2);
    value.insert(
        "mechanism".to_string(),
        Value::String(realm.mechanism().to_string()),
    );
    value.insert(
        "authority".to_string(),
        realm.authority().map_or(Value::Null, |authority| {
            Value::String(hex::encode(authority))
        }),
    );
    Value::Object(value)
}

/// Lowercase without allocating when `value` already is.
fn ascii_lowercase(value: &str) -> Cow<'_, str> {
    if value.bytes().any(|byte| byte.is_ascii_uppercase()) {
        Cow::Owned(value.to_ascii_lowercase())
    } else {
        Cow::Borrowed(value)
    }
}

/// Lowercase query names that authentication plugins marked as credential
/// locations for this request.
fn query_credential_keys(ctx: &RequestContext) -> HashSet<String> {
    ctx.metadata
        .keys()
        .filter_map(|metadata_key| {
            metadata_key
                .strip_prefix(super::utils::token_extract::QUERY_CREDENTIAL_METADATA_PREFIX)
                .or_else(|| {
                    metadata_key.strip_prefix(
                        super::utils::token_extract::STRIP_QUERY_PARAM_METADATA_PREFIX,
                    )
                })
        })
        .map(str::to_ascii_lowercase)
        .collect()
}

/// The field lines the backend may receive for one materialized header.
///
/// While the materialized value still equals the pristine field lines joined
/// with the materialization separator, the paths that forward repeated lines
/// (native gRPC, secured mesh replay) send those lines unchanged, so each one
/// is reported. A plugin rewrite, a non-UTF-8 line, or a single line means
/// exactly the folded value is forwarded.
fn header_field_line_occurrences<'a>(
    ctx: &'a RequestContext,
    name: &'a str,
    folded: &'a str,
) -> Vec<&'a str> {
    let mut lines: Vec<&'a str> = Vec::new();
    for raw in ctx.raw_header_value_bytes(name) {
        match std::str::from_utf8(raw) {
            Ok(line) => lines.push(line),
            Err(_) => return vec![folded],
        }
    }
    if lines.len() < 2
        || !folded_value_matches_field_lines(
            &lines,
            folded,
            super::repeated_request_header_separator(name),
        )
    {
        return vec![folded];
    }
    lines
}

fn folded_value_matches_field_lines(lines: &[&str], folded: &str, separator: &str) -> bool {
    let mut remaining = folded;
    for (index, line) in lines.iter().enumerate() {
        if index > 0 {
            let Some(rest) = remaining.strip_prefix(separator) else {
                return false;
            };
            remaining = rest;
        }
        let Some(rest) = remaining.strip_prefix(*line) else {
            return false;
        };
        remaining = rest;
    }
    remaining.is_empty()
}

/// Request fields whose RFC 9110 grammar is a comma-separated list (or, for
/// `cookie`, a `; `-joined crumb list), so separate field lines and their fold
/// mean the same thing. Repetition of any other field is ambiguous.
fn is_list_valued_request_header(lower: &str) -> bool {
    matches!(
        lower,
        "accept"
            | "accept-charset"
            | "accept-encoding"
            | "accept-language"
            | "access-control-request-headers"
            | "baggage"
            | "cache-control"
            | "connection"
            | "content-encoding"
            | "content-language"
            | "cookie"
            | "expect"
            | "forwarded"
            | "if-match"
            | "if-none-match"
            | "link"
            | "pragma"
            | "prefer"
            | "sec-websocket-extensions"
            | "sec-websocket-protocol"
            | "te"
            | "trailer"
            | "tracestate"
            | "transfer-encoding"
            | "upgrade"
            | "via"
            | "warning"
            | "x-forwarded-for"
            | "x-forwarded-host"
            | "x-forwarded-proto"
    )
}

/// Parse `opa_host` + `policy_path` into the wire decision URL, its
/// diagnostic-safe rendering, and the hostname used for DNS warmup.
fn parse_decision_endpoint(object: &Map<String, Value>) -> Result<(Url, String, String), String> {
    // Typed whenever supplied, even for an https host it does not affect.
    let allow_plaintext = parse_optional_bool(object, "allow_plaintext")?.unwrap_or(false);
    let opa_host = required_string(object, "opa_host")?;
    let parsed =
        Url::parse(opa_host).map_err(|error| format!("opa: invalid `opa_host`: {error}"))?;

    match parsed.scheme() {
        "http" | "https" => {}
        scheme => {
            return Err(format!(
                "opa: `opa_host` must use http:// or https:// (got {scheme:?})"
            ));
        }
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(
            "opa: `opa_host` must not include credentials; configure OPA auth with `headers`"
                .to_string(),
        );
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err("opa: `opa_host` must not include query or fragment components".to_string());
    }

    let host = parsed
        .host()
        .ok_or_else(|| "opa: `opa_host` must include a hostname or IP address".to_string())?;
    let hostname = match host {
        Host::Domain(hostname) => hostname.to_string(),
        Host::Ipv4(address) => address.to_string(),
        Host::Ipv6(address) => address.to_string(),
    };

    let policy_path = required_string(object, "policy_path")?;
    validate_policy_path(policy_path)?;

    // Join onto the parsed (already normalized) base so the raw `opa_host`
    // text can never contribute a separator or dot segment of its own.
    let decision_url = format!(
        "{}{}{}",
        parsed.as_str().trim_end_matches('/'),
        OPA_DATA_PREFIX,
        policy_path
    );
    let parsed_decision_url = Url::parse(&decision_url)
        .map_err(|error| format!("opa: invalid decision URL from opa_host/policy_path: {error}"))?;
    let data_prefix = format!("{}{}", parsed.path().trim_end_matches('/'), OPA_DATA_PREFIX);
    ensure_decision_path_under_data_prefix(&parsed_decision_url, &data_prefix, policy_path)?;
    let redacted_decision_url = crate::plugins::utils::redacted_endpoint_url(&parsed_decision_url);

    // Authorization decisions and any `headers` credential travel on this
    // call. Cleartext is admitted without an opt-in only to a loopback IP
    // literal (a co-located OPA sidecar).
    if parsed.scheme() == "http"
        && !allow_plaintext
        && !is_loopback_ip_literal_endpoint(opa_host, parsed.host())
    {
        return Err(
            "opa: `opa_host` uses `http://` to a host that is not a loopback IP literal, which is rejected by default; use `https://` or set `allow_plaintext: true`"
                .to_string(),
        );
    }

    Ok((parsed_decision_url, redacted_decision_url, hostname))
}

/// Prove the NORMALIZED decision URL still addresses `policy_path` beneath the
/// Data API prefix (issue #6368).
///
/// The WHATWG URL parser rewrites paths: for `http`/`https` it treats `\` as a
/// separator, strips tab/CR/LF, trims trailing spaces and C0 controls from the
/// whole input, and then removes `.`/`..` segments. A raw string check alone
/// cannot see any of that, so admission re-checks the parsed result: the path
/// must begin with `{base}/v1/data/` and carry exactly as many segments after
/// it as `policy_path` has. Anything the parser collapsed or redirected fails
/// closed here instead of reaching OPA.
fn ensure_decision_path_under_data_prefix(
    decision_url: &Url,
    data_prefix: &str,
    policy_path: &str,
) -> Result<(), String> {
    let escapes = match decision_url.path().strip_prefix(data_prefix) {
        Some(rest) => rest.split('/').count() != policy_path.split('/').count(),
        None => true,
    };
    if escapes {
        return Err(
            "opa: `policy_path` must stay under `/v1/data/` after URL normalization".to_string(),
        );
    }
    Ok(())
}

fn validate_policy_path(policy_path: &str) -> Result<(), String> {
    if policy_path.is_empty() {
        return Err("opa: `policy_path` must not be empty".to_string());
    }
    if policy_path.starts_with('/') {
        return Err("opa: `policy_path` must not start with `/`".to_string());
    }
    if policy_path.contains('?') || policy_path.contains('#') {
        return Err("opa: `policy_path` must not contain `?` or `#`".to_string());
    }
    if policy_path.contains('%') {
        return Err("opa: `policy_path` must not contain percent-encoding".to_string());
    }
    // `\` is a path separator for http/https URLs, and the URL parser strips
    // tab/CR/LF and trailing spaces/controls, so any of these could turn an
    // admitted segment into a separator or a dot segment after normalization.
    if policy_path
        .chars()
        .any(|c| c == '\\' || c == ' ' || c.is_ascii_control())
    {
        return Err(
            "opa: `policy_path` must not contain `\\`, spaces, or ASCII control characters"
                .to_string(),
        );
    }
    if policy_path
        .split('/')
        .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return Err(
            "opa: `policy_path` must not contain empty, `.`, or `..` path segments".to_string(),
        );
    }
    Ok(())
}

fn parse_fail_open(object: &Map<String, Value>) -> Result<bool, String> {
    let fail_open = parse_optional_bool(object, "fail_open")?;
    let fail_closed = parse_optional_bool(object, "fail_closed")?;
    match (fail_open, fail_closed) {
        (Some(_), Some(_)) => {
            Err("opa: configure only one of `fail_open` or `fail_closed`".to_string())
        }
        (Some(value), None) => Ok(value),
        (None, Some(value)) => Ok(!value),
        (None, None) => Ok(false),
    }
}

fn reject_unknown_keys(object: &Map<String, Value>) -> Result<(), String> {
    for key in object.keys() {
        if !OPA_CONFIG_KEYS.contains(&key.as_str()) {
            return Err(format!("opa: unknown config key {key:?}"));
        }
    }
    Ok(())
}

fn parse_decision_pointer(object: &Map<String, Value>) -> Result<Vec<String>, String> {
    let Some(value) = object.get("decision_pointer") else {
        return Ok(vec!["result".to_string()]);
    };
    let array = value
        .as_array()
        .ok_or_else(|| "opa: `decision_pointer` must be an array of strings".to_string())?;
    let mut pointer = Vec::with_capacity(array.len());
    for (idx, value) in array.iter().enumerate() {
        let segment = value
            .as_str()
            .ok_or_else(|| format!("opa: `decision_pointer[{idx}]` must be a string"))?;
        pointer.push(segment.to_string());
    }
    Ok(pointer)
}

fn parse_redact_headers(object: &Map<String, Value>) -> Result<HashSet<String>, String> {
    let mut headers = default_redact_headers();
    let Some(value) = object.get("redact_headers") else {
        return Ok(headers);
    };
    let array = value
        .as_array()
        .ok_or_else(|| "opa: `redact_headers` must be an array of strings".to_string())?;
    for (idx, value) in array.iter().enumerate() {
        let header = value
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("opa: `redact_headers[{idx}]` must be a non-empty string"))?;
        let header_name = HeaderName::from_bytes(header.as_bytes()).map_err(|error| {
            format!("opa: invalid `redact_headers[{idx}]` header name {header:?}: {error}")
        })?;
        headers.insert(header_name.as_str().to_string());
    }
    Ok(headers)
}

fn parse_redact_query_keys(object: &Map<String, Value>) -> Result<HashSet<String>, String> {
    let Some(value) = object.get("redact_query_keys") else {
        return Ok(HashSet::new());
    };
    let array = value
        .as_array()
        .ok_or_else(|| "opa: `redact_query_keys` must be an array of strings".to_string())?;
    let mut keys = HashSet::with_capacity(array.len());
    for (idx, value) in array.iter().enumerate() {
        let key = value
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("opa: `redact_query_keys[{idx}]` must be a non-empty string"))?;
        keys.insert(key.to_ascii_lowercase());
    }
    Ok(keys)
}

fn is_default_sensitive_query_key(key: &str) -> bool {
    [
        "access_token",
        "api_key",
        "apikey",
        "auth",
        "authorization",
        "bearer_token",
        "id_token",
        "jwt",
        "key",
        "token",
    ]
    .iter()
    .any(|sensitive| sensitive.eq_ignore_ascii_case(key))
}

fn default_redact_headers() -> HashSet<String> {
    DEFAULT_REDACT_HEADERS
        .iter()
        .map(|header| (*header).to_string())
        .collect()
}

/// `max_concurrent_decisions`: optional per-instance bound on in-flight
/// decision calls.
fn parse_max_concurrent_decisions(
    object: &Map<String, Value>,
) -> Result<Option<Semaphore>, String> {
    let Some(limit) = parse_optional_u64(object, "max_concurrent_decisions")? else {
        return Ok(None);
    };
    if limit == 0 || limit > MAX_CONCURRENT_DECISIONS_LIMIT {
        return Err(format!(
            "opa: `max_concurrent_decisions` must be between 1 and {MAX_CONCURRENT_DECISIONS_LIMIT}"
        ));
    }
    let permits = usize::try_from(limit).map_err(|_| {
        format!(
            "opa: `max_concurrent_decisions` must be between 1 and {MAX_CONCURRENT_DECISIONS_LIMIT}"
        )
    })?;
    Ok(Some(Semaphore::new(permits)))
}

/// `decision_request_headers`: the upstream request headers an allow decision
/// may set. Names a policy must never author are refused at admission:
/// gateway-owned assertions (`x-consumer-*`, `x-geo-country`, path-param
/// captures, `x-ferrum-*`, forwarding identity), hop-by-hop and framing
/// fields, representation fields the body was read under, and
/// credential-bearing names (the built-in redaction list and the shared
/// sensitive-name classifier). Diagnostics name the index, never the value.
fn parse_decision_request_headers(object: &Map<String, Value>) -> Result<Vec<String>, String> {
    let Some(value) = object.get("decision_request_headers") else {
        return Ok(Vec::new());
    };
    let array = value
        .as_array()
        .ok_or_else(|| "opa: `decision_request_headers` must be an array of strings".to_string())?;
    if array.len() > MAX_DECISION_REQUEST_HEADERS {
        return Err(format!(
            "opa: `decision_request_headers` must list at most {MAX_DECISION_REQUEST_HEADERS} names"
        ));
    }
    let mut names: Vec<String> = Vec::with_capacity(array.len());
    for (idx, value) in array.iter().enumerate() {
        let raw = value
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                format!("opa: `decision_request_headers[{idx}]` must be a non-empty string")
            })?;
        let header_name = HeaderName::from_bytes(raw.as_bytes()).map_err(|_| {
            format!("opa: `decision_request_headers[{idx}]` must be a valid HTTP header name")
        })?;
        let name = header_name.as_str();
        if decision_request_header_is_reserved(name) {
            return Err(format!(
                "opa: `decision_request_headers[{idx}]` names a gateway-owned, hop-by-hop, \
                 framing, representation, or credential-bearing header that a policy decision \
                 cannot set"
            ));
        }
        if names
            .iter()
            .any(|existing| field_names_equivalent_for_backends(existing, name))
        {
            return Err(format!(
                "opa: `decision_request_headers[{idx}]` repeats an earlier name (ASCII case and \
                 `_`/`-` are equivalent)"
            ));
        }
        names.push(name.to_string());
    }
    Ok(names)
}

fn decision_request_header_is_reserved(name: &str) -> bool {
    is_output_claim_reserved_header(name)
        || RequestContext::is_reserved_gateway_assertion_header(name)
        || is_sensitive_header_name(name)
        || DEFAULT_REDACT_HEADERS
            .iter()
            .chain(&["content-type", "content-encoding", "content-range"])
            .any(|reserved| field_names_equivalent_for_backends(reserved, name))
}

fn parse_header_map(
    object: &Map<String, Value>,
    field: &'static str,
    plugin_name: &'static str,
) -> Result<Vec<(HeaderName, HeaderValue)>, String> {
    let Some(value) = object.get(field) else {
        return Ok(Vec::new());
    };
    let map = value
        .as_object()
        .ok_or_else(|| format!("{plugin_name}: `{field}` must be an object"))?;
    let mut headers = Vec::with_capacity(map.len());
    for (key, value) in map {
        let value = value
            .as_str()
            .ok_or_else(|| format!("{plugin_name}: `{field}` entry {key:?} must be a string"))?;
        let header_name = HeaderName::from_bytes(key.as_bytes())
            .map_err(|error| format!("{plugin_name}: invalid `{field}` name {key:?}: {error}"))?;
        if field == "headers" && header_name == CONTENT_TYPE {
            return Err(format!(
                "{plugin_name}: `{field}` must not include `content-type`; OPA decision requests are always sent as JSON"
            ));
        }
        // The decision call carries the gateway's hop count as exactly one
        // field line (issue #6128); a configured copy (any case, `_` or `-`)
        // would sit beside it and reset or duplicate the count.
        if field == "headers" && crate::proxy::hop_limit::is_proxy_hops_header(key) {
            return Err(format!(
                "{plugin_name}: `{field}` must not include `X-Ferrum-Hops`; the gateway owns the proxy hop count"
            ));
        }
        let header_value = HeaderValue::from_str(value).map_err(|error| {
            format!("{plugin_name}: invalid `{field}` value for {key:?}: {error}")
        })?;
        headers.retain(|(existing, _)| *existing != header_name);
        headers.push((header_name, header_value));
    }
    Ok(headers)
}

/// Parse an operator-configured CLIENT RESPONSE header map (`deny_headers`,
/// `fail_closed_headers`).
///
/// Both maps are installed verbatim onto a `PluginResult::Reject`, so their
/// names are arbitrary response-header destinations. Protocol-managed framing /
/// connection-control names are rejected at construction with the shared
/// case-insensitive predicate: the gateway's final wire boundary owns
/// `Content-Length` and the hop-by-hop set, and a configured value there is an
/// unverifiable framing claim rather than a policy header. Names are validated
/// `HeaderName`s from the compiled-in closed set by the time they are echoed, so
/// the diagnostic identifies the setting without reflecting hostile input.
fn parse_string_header_map(
    object: &Map<String, Value>,
    field: &'static str,
    plugin_name: &'static str,
) -> Result<HashMap<String, String>, String> {
    let mut parsed = HashMap::new();
    let Some(value) = object.get(field) else {
        return Ok(parsed);
    };
    let map = value
        .as_object()
        .ok_or_else(|| format!("{plugin_name}: `{field}` must be an object"))?;
    parsed.reserve(map.len());
    for (key, value) in map {
        let value = value
            .as_str()
            .ok_or_else(|| format!("{plugin_name}: `{field}` entry {key:?} must be a string"))?;
        let header_name = HeaderName::from_bytes(key.as_bytes())
            .map_err(|error| format!("{plugin_name}: invalid `{field}` name {key:?}: {error}"))?;
        if crate::proxy::headers::is_protocol_managed_plugin_response_destination(
            header_name.as_str(),
        ) {
            return Err(format!(
                "{plugin_name}: `{field}` name {:?} is protocol-managed (hop-by-hop or framing) and \
                 cannot be configured; the gateway derives Content-Length from the reject body and \
                 strips Connection/Transfer-Encoding/Trailer/Upgrade at the final response \
                 boundary",
                header_name.as_str()
            ));
        }
        HeaderValue::from_str(value).map_err(|error| {
            format!("{plugin_name}: invalid `{field}` value for {key:?}: {error}")
        })?;
        parsed.insert(header_name.as_str().to_string(), value.to_string());
    }
    Ok(parsed)
}

fn parse_response_status(
    object: &Map<String, Value>,
    field: &'static str,
    default_status: u16,
) -> Result<u16, String> {
    let status = parse_optional_u16(object, field)?.unwrap_or(default_status);
    if !(400..=599).contains(&status) {
        return Err(format!("opa: `{field}` must be in the 4xx or 5xx range"));
    }
    Ok(status)
}

fn required_string<'a>(
    object: &'a Map<String, Value>,
    field: &'static str,
) -> Result<&'a str, String> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("opa: `{field}` is required and must be a non-empty string"))
}

fn parse_optional_string(
    object: &Map<String, Value>,
    field: &'static str,
) -> Result<Option<String>, String> {
    object
        .get(field)
        .map(|value| {
            value
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| format!("opa: `{field}` must be a string"))
        })
        .transpose()
}

fn parse_optional_bool(
    object: &Map<String, Value>,
    field: &'static str,
) -> Result<Option<bool>, String> {
    object
        .get(field)
        .map(|value| {
            value
                .as_bool()
                .ok_or_else(|| format!("opa: `{field}` must be a boolean"))
        })
        .transpose()
}

fn parse_optional_u64(
    object: &Map<String, Value>,
    field: &'static str,
) -> Result<Option<u64>, String> {
    object
        .get(field)
        .map(|value| {
            value
                .as_u64()
                .ok_or_else(|| format!("opa: `{field}` must be an unsigned integer"))
        })
        .transpose()
}

fn parse_optional_u16(
    object: &Map<String, Value>,
    field: &'static str,
) -> Result<Option<u16>, String> {
    object
        .get(field)
        .map(|value| {
            let raw = value
                .as_u64()
                .ok_or_else(|| format!("opa: `{field}` must be an unsigned integer"))?;
            u16::try_from(raw).map_err(|_| format!("opa: `{field}` is too large"))
        })
        .transpose()
}
