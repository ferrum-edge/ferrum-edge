use std::collections::HashMap;

use http::header::{HeaderName, HeaderValue};
use serde_json::{Map, Value};

use crate::plugins::RequestContext;

use super::auth_attempt::AuthenticationAttempt;
use super::claim_resolver::{parse_claim_path_value, resolve_claim_path};

/// Keep direct plugin configuration on the same bounded surface as Istio
/// `outputClaimToHeaders` translation.
pub const MAX_OUTPUT_CLAIM_HEADERS: usize = 16;
pub const MAX_OUTPUT_CLAIM_HEADER_NAME_LEN: usize = 128;
pub const MAX_OUTPUT_CLAIM_PATH_LEN: usize = 256;
pub const MAX_OUTPUT_CLAIM_VALUE_LEN: usize = 8 * 1024;

#[derive(Clone, Debug)]
pub struct ClaimHeaderMapping {
    pub claim_path: String,
    pub metadata_key: String,
    /// Normalized (lowercase) request-header name this mapping owns. Retained
    /// alongside `metadata_key` so the request path never has to strip the
    /// metadata prefix to learn which destination is gateway-owned.
    pub destination_header: String,
}

/// The complete set of request-header destinations one plugin instance owns
/// through `claim_headers`, including every provider override.
///
/// `claim_headers` destinations are **gateway-owned**: after a successful
/// authentication the gateway is the only party allowed to assert them. The set
/// is precomputed at plugin construction so the request path performs no
/// configuration walk and no per-request name normalization.
#[derive(Clone, Debug, Default)]
pub struct ClaimHeaderDestinations {
    /// Deduplicated, sorted owned destinations as
    /// `(pending-claim metadata key, lowercase destination header name)`. The
    /// metadata key is precomputed so the request path can look a destination's
    /// staged value up directly, with no per-request formatting.
    entries: Vec<(String, String)>,
}

impl ClaimHeaderDestinations {
    /// Union every destination reachable from one plugin instance. Callers pass
    /// the plugin-level mappings plus each provider's override mappings, so a
    /// provider that only overrides some destinations still contributes to the
    /// owned set and cannot leave a stale client value behind.
    pub fn from_mapping_groups<'a, I>(mapping_groups: I) -> Self
    where
        I: IntoIterator<Item = &'a [ClaimHeaderMapping]>,
    {
        let mut entries: Vec<(String, String)> = mapping_groups
            .into_iter()
            .flatten()
            .map(|mapping| {
                (
                    mapping.metadata_key.clone(),
                    mapping.destination_header.clone(),
                )
            })
            .collect();
        entries.sort_unstable();
        entries.dedup();
        Self { entries }
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Lowercase destination header names this instance owns.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|(_, name)| name.as_str())
    }

    /// Owned destinations as `(metadata key, destination header name)` pairs.
    fn entries(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries
            .iter()
            .map(|(key, name)| (key.as_str(), name.as_str()))
    }
}

pub fn parse_claim_headers(
    config: &Map<String, Value>,
    field: &str,
    plugin: &str,
    metadata_prefix: &str,
) -> Result<Vec<ClaimHeaderMapping>, String> {
    let Some(value) = config.get(field) else {
        return Ok(Vec::new());
    };
    let object = value.as_object().ok_or_else(|| {
        format!(
            "{plugin}: `{field}` must be an object, got: {value:?}",
            value = value.to_string()
        )
    })?;
    let mut mappings = Vec::with_capacity(object.len());
    for (index, (claim_path, header_value)) in object.iter().enumerate() {
        let parsed_claim_path = parse_claim_path_value(
            &format!("{field}[{index}].claim"),
            &Value::String(claim_path.clone()),
            plugin,
        )?;
        let raw_header = header_value.as_str().ok_or_else(|| {
            format!(
                "{plugin}: `{field}[{index}].header` must be a header name string, got: {header_value:?}",
                header_value = header_value.to_string()
            )
        })?;
        let header_name =
            normalize_allowed_header(raw_header, plugin, &format!("{field}[{index}].header"))?;
        let metadata_key = format!("{metadata_prefix}{header_name}");
        mappings.push(ClaimHeaderMapping {
            claim_path: parsed_claim_path,
            metadata_key,
            destination_header: header_name,
        });
    }
    Ok(mappings)
}

/// Parse the ARRAY form of a claim → header mapping list.
///
/// Istio `RequestAuthentication.jwtRules[].outputClaimToHeaders` is an ordered
/// LIST of `{header, claim}` pairs, not a claim-keyed map: the same claim may
/// legitimately be published to two different headers. An object shape
/// (`parse_claim_headers`) cannot express that, so the mesh projection carries
/// the list shape and this parser resolves it into the same
/// [`ClaimHeaderMapping`] the object form produces.
///
/// Two entries naming the SAME destination header are rejected rather than
/// resolved by declaration order: both would derive the same metadata key, so
/// whichever claim happened to resolve last would decide the gateway-asserted
/// value. A configuration whose meaning depends on that is refused at load.
pub fn parse_claim_header_list(
    config: &Map<String, Value>,
    field: &str,
    plugin: &str,
    metadata_prefix: &str,
) -> Result<Vec<ClaimHeaderMapping>, String> {
    let Some(value) = config.get(field) else {
        return Ok(Vec::new());
    };
    let entries = value.as_array().ok_or_else(|| {
        format!(
            "{plugin}: `{field}` must be an array, got: {value:?}",
            value = value.to_string()
        )
    })?;
    if entries.len() > MAX_OUTPUT_CLAIM_HEADERS {
        return Err(format!(
            "{plugin}: `{field}` supports at most {MAX_OUTPUT_CLAIM_HEADERS} entries"
        ));
    }
    let mut mappings: Vec<ClaimHeaderMapping> = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        let object = entry
            .as_object()
            .ok_or_else(|| format!("{plugin}: `{field}[{index}]` must be an object"))?;
        for key in object.keys() {
            if key != "claim" && key != "header" {
                return Err(format!(
                    "{plugin}: `{field}[{index}]` does not support field {key:?}"
                ));
            }
        }
        let claim_value = object
            .get("claim")
            .ok_or_else(|| format!("{plugin}: `{field}[{index}].claim` is required"))?;
        let claim_path =
            parse_claim_path_value(&format!("{field}[{index}].claim"), claim_value, plugin)?;
        if claim_path.len() > MAX_OUTPUT_CLAIM_PATH_LEN
            || claim_path
                .chars()
                .any(|character| character.is_control() || character.is_whitespace())
        {
            return Err(format!(
                "{plugin}: `{field}[{index}].claim` must be at most \
                 {MAX_OUTPUT_CLAIM_PATH_LEN} bytes and contain no whitespace or control characters"
            ));
        }
        let raw_header = object
            .get("header")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("{plugin}: `{field}[{index}].header` must be a string"))?;
        let header_name =
            normalize_allowed_header(raw_header, plugin, &format!("{field}[{index}].header"))?;
        if header_name.len() > MAX_OUTPUT_CLAIM_HEADER_NAME_LEN {
            return Err(format!(
                "{plugin}: `{field}[{index}].header` must be at most \
                 {MAX_OUTPUT_CLAIM_HEADER_NAME_LEN} bytes"
            ));
        }
        if is_output_claim_reserved_header(&header_name) {
            return Err(format!(
                "{plugin}: `{field}` cannot target framing, provenance, credential-bearing, \
                 or gateway-reserved header {header_name:?}"
            ));
        }
        if mappings
            .iter()
            .any(|mapping| mapping.destination_header == header_name)
        {
            return Err(format!(
                "{plugin}: `{field}` declares header {header_name:?} more than once; \
                 a destination may be asserted from exactly one claim"
            ));
        }
        mappings.push(ClaimHeaderMapping {
            metadata_key: format!("{metadata_prefix}{header_name}"),
            claim_path,
            destination_header: header_name,
        });
    }
    Ok(mappings)
}

/// Stage the values for an `outputClaimToHeaders`-style mapping list.
///
/// Differs from [`emit_claim_headers_to_attempt`] only in the value
/// conversion: Istio `ClaimToHeader` publishes nonblank string, integer, and
/// boolean claims only. Arrays, objects, null, floating-point / non-integer
/// numbers, blank strings, and header-illegal values leave the destination
/// absent. The destination was already stripped of any client-supplied value by
/// [`apply_claim_headers_from_context`].
pub fn emit_output_claim_headers_to_attempt(
    attempt: &mut AuthenticationAttempt,
    claims: &Value,
    mappings: &[ClaimHeaderMapping],
    _separator: &str,
) {
    for mapping in mappings {
        let Some(value) = output_claim_value_for_header(claims, &mapping.claim_path) else {
            continue;
        };
        attempt.stage_claim_header(mapping.metadata_key.clone(), value);
    }
}

/// Render one claim as an output-header value, or `None` when it cannot be
/// represented under Istio `ClaimToHeader` semantics. Never logs or returns
/// the claim value on refusal.
fn output_claim_value_for_header(claims: &Value, claim_path: &str) -> Option<String> {
    let rendered = render_istio_output_claim(resolve_claim_path(claims, claim_path)?)?;
    if rendered.trim().is_empty() {
        return None;
    }
    // One validated token may fan a claim out to every configured destination.
    // Bound each published value before staging clones it up to 16 times.
    if rendered.len() > MAX_OUTPUT_CLAIM_VALUE_LEN {
        return None;
    }
    // The same complete `HeaderValue` gate the outbound adapters apply, so a
    // claim carrying CR/LF or other control bytes can never be spliced into
    // the backend-bound request.
    HeaderValue::from_str(&rendered).ok()?;
    Some(rendered)
}

fn render_istio_output_claim(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => (!value.trim().is_empty()).then(|| value.clone()),
        Value::Number(number) => number
            .as_i64()
            .map(|value| value.to_string())
            .or_else(|| number.as_u64().map(|value| value.to_string())),
        Value::Bool(flag) => Some(flag.to_string()),
        Value::Null | Value::Array(_) | Value::Object(_) => None,
    }
}

pub fn emit_claim_headers_to_attempt(
    attempt: &mut AuthenticationAttempt,
    claims: &Value,
    mappings: &[ClaimHeaderMapping],
    separator: &str,
) {
    for mapping in mappings {
        let Some(value) = claim_value_for_header(claims, &mapping.claim_path, separator) else {
            continue;
        };
        attempt.stage_claim_header(mapping.metadata_key.clone(), value);
    }
}

/// Resolve configured mappings once for a cacheable normalized authorization
/// result. The returned index refers to the immutable provider mapping table,
/// so cache entries retain only provider-controlled header values rather than
/// duplicating configuration-owned metadata keys and destination names.
pub fn normalized_claim_header_values(
    claims: &Value,
    mappings: &[ClaimHeaderMapping],
    separator: &str,
) -> Vec<(usize, String)> {
    mappings
        .iter()
        .enumerate()
        .filter_map(|(mapping_index, mapping)| {
            claim_value_for_header(claims, &mapping.claim_path, separator)
                .map(|value| (mapping_index, value))
        })
        .collect()
}

/// Install verified claim values into the backend request headers.
///
/// `claim_headers` destinations are gateway-owned and always sanitized: every
/// destination this plugin instance owns is removed case-insensitively (covering
/// duplicate and case-variant client headers) *before* any verified value is
/// installed. A claim that is missing, null, empty, of an unusable type, or that
/// belongs to a principal this instance did not authenticate therefore leaves the
/// destination **absent** rather than preserving attacker-controlled client
/// input.
///
/// Sanitization is claimed once per destination per request. The first instance
/// that owns a destination strips the client value; a later instance that shares
/// the same destination will not erase a value an earlier instance already
/// installed, and no instance ever touches a destination it does not own.
///
/// Both sanitization *and* installation are scoped to the owned destination set.
/// Instances of the same plugin type share a `claim_headers` metadata prefix, so
/// consuming every pending key under that prefix would let an instance that runs
/// earlier install — and thereby drain — a value staged by the instance that
/// actually owns and authenticated that destination; the true owner would then
/// sanitize the value away with nothing left to reinstall.
pub fn apply_claim_headers_from_context(
    ctx: &mut RequestContext,
    headers: &mut HashMap<String, String>,
    destinations: &ClaimHeaderDestinations,
) {
    if destinations.is_empty() {
        return;
    }
    sanitize_owned_claim_header_destinations(ctx, headers, destinations);
    for (metadata_key, header_name) in destinations.entries() {
        if let Some(value) = ctx
            .plugin_state_opt_mut()
            .and_then(|state| state.pending_claim_headers.remove(metadata_key))
        {
            headers.insert(header_name.to_string(), value);
        }
    }
}

/// Remove every gateway-owned destination this instance still has to claim.
///
/// Runs before installation so an absent, wrong-type, or unusable claim can
/// never leave a client-supplied value in place. Removal is case-insensitive
/// because the effective `before_proxy` map is not guaranteed to be all
/// lowercase: hyper normalizes wire field names, but plugins and transformers
/// insert operator-cased names, so a lowercase insert alone could leave an
/// `X-Authenticated-Email` variant beside the gateway's value. It also treats
/// `_` as `-` ([`crate::proxy::headers::field_names_equivalent_for_backends`]):
/// a client `X_Authenticated_Email` reaches a CGI-style backend as the same
/// variable as the gateway's `x-authenticated-email`.
fn sanitize_owned_claim_header_destinations(
    ctx: &mut RequestContext,
    headers: &mut HashMap<String, String>,
    destinations: &ClaimHeaderDestinations,
) {
    if destinations.is_empty() {
        return;
    }
    let sanitized = ctx.plugin_state_mut();
    headers.retain(|name, _| {
        !destinations.names().any(|destination| {
            !sanitized
                .sanitized_claim_header_destinations
                .contains(destination)
                && crate::proxy::headers::field_names_equivalent_for_backends(name, destination)
        })
    });
    for destination in destinations.names() {
        if !sanitized
            .sanitized_claim_header_destinations
            .contains(destination)
        {
            sanitized
                .sanitized_claim_header_destinations
                .insert(destination.to_string());
        }
    }
}

pub fn parse_separator(
    config: &Map<String, Value>,
    field: &str,
    plugin: &str,
    default_value: &str,
) -> Result<String, String> {
    let Some(value) = config.get(field) else {
        return Ok(default_value.to_string());
    };
    let raw = value.as_str().ok_or_else(|| {
        format!(
            "{plugin}: `{field}` must be a string, got: {value:?}",
            value = value.to_string()
        )
    })?;
    if raw.is_empty() {
        return Err(format!("{plugin}: `{field}` must not be empty"));
    }
    Ok(raw.to_string())
}

/// Resolve one mapped claim into a header value, or `None` when the claim is
/// absent, null, of an unusable type, or carries no non-whitespace content.
///
/// Returning `None` is what makes the destination absent after sanitization, so
/// an empty or blank claim must never yield `Some("")` — a backend that trusts
/// the destination would otherwise see a gateway-asserted empty identity.
fn claim_value_for_header(claims: &Value, claim_path: &str, separator: &str) -> Option<String> {
    let value = match resolve_claim_path(claims, claim_path)? {
        Value::String(value) => value.clone(),
        Value::Array(values) => {
            let parts: Vec<&str> = values
                .iter()
                .filter_map(Value::as_str)
                .filter(|part| !part.trim().is_empty())
                .collect();
            if parts.is_empty() {
                return None;
            }
            parts.join(separator)
        }
        _ => return None,
    };
    (!value.trim().is_empty()).then_some(value)
}

fn normalize_allowed_header(raw_header: &str, plugin: &str, field: &str) -> Result<String, String> {
    let trimmed = raw_header.trim();
    if trimmed.is_empty() {
        return Err(format!("{plugin}: `{field}` header name must not be empty"));
    }
    let header = HeaderName::from_bytes(trimmed.as_bytes())
        .map_err(|e| format!("{plugin}: `{field}` header name is invalid: {e}"))?
        .as_str()
        .to_string();
    if crate::proxy::headers::is_consumer_assertion_header(&header) {
        return Err(format!(
            "{plugin}: `{field}` cannot target {header:?}: the `x-consumer-*` namespace is \
             gateway-owned consumer assertion metadata"
        ));
    }
    if is_reserved_header(&header) {
        return Err(format!(
            "{plugin}: `{field}` cannot target reserved header {header:?}"
        ));
    }
    Ok(header)
}

/// Headers a claim mapping may never write. The whole gateway-owned
/// `x-consumer-*` namespace is reserved
/// ([`crate::proxy::headers::is_consumer_assertion_header`]), not only the
/// two identity fields the gateway itself asserts, and so is the gateway's
/// `X-Ferrum-Hops` loop-guard count
/// ([`crate::proxy::hop_limit::is_proxy_hops_header`]).
pub fn is_reserved_header(name: &str) -> bool {
    crate::proxy::headers::is_consumer_assertion_header(name)
        || crate::proxy::hop_limit::is_proxy_hops_header(name)
        || matches!(
            name.to_ascii_lowercase().as_str(),
            "host"
                | "connection"
                | "te"
                | "keep-alive"
                | "transfer-encoding"
                | "upgrade"
                | "proxy-authorization"
                | "authorization"
        )
}

/// Headers that a validated JWT claim must never be allowed to synthesize.
///
/// This is intentionally stricter than the legacy `claim_headers` predicate:
/// `outputClaimToHeaders` is a new Istio-facing surface, so direct plugin
/// configuration and mesh translation can share one fail-closed contract
/// without changing established `claim_headers` configurations.
pub fn is_output_claim_reserved_header(name: &str) -> bool {
    let lowercase = name.to_ascii_lowercase();
    is_reserved_header(&lowercase)
        || matches!(
            lowercase.as_str(),
            "baggage"
                | "content-length"
                | "cookie"
                | "expect"
                | "forwarded"
                | "proxy-authenticate"
                | "proxy-connection"
                | "trailer"
                | "via"
                | "x-real-ip"
        )
        || lowercase.starts_with("x-ferrum-")
        || lowercase.starts_with("x-forwarded-")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rejects_reserved_header_target() {
        let config = json!({"claim_headers": {"sub": "Authorization"}});
        let err = parse_claim_headers(
            config.as_object().expect("object"),
            "claim_headers",
            "test",
            "test.",
        )
        .expect_err("reserved header should reject");
        assert!(err.contains("reserved"));
    }

    #[test]
    fn emits_string_and_array_claims() {
        let mapping = vec![
            ClaimHeaderMapping {
                claim_path: "email".to_string(),
                metadata_key: "p.x-user-email".to_string(),
                destination_header: "x-user-email".to_string(),
            },
            ClaimHeaderMapping {
                claim_path: "roles".to_string(),
                metadata_key: "p.x-user-roles".to_string(),
                destination_header: "x-user-roles".to_string(),
            },
        ];
        let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/".into());
        let mut attempt = AuthenticationAttempt::new();
        emit_claim_headers_to_attempt(
            &mut attempt,
            &json!({"email": "a@example.com", "roles": ["admin", "editor"]}),
            &mapping,
            ",",
        );
        crate::plugins::utils::auth_flow::commit_authentication_attempt(
            &mut ctx,
            attempt,
            crate::plugins::utils::auth_flow::VerifyOutcome::success(
                None,
                Some("accepted-principal".to_string()),
                None,
            ),
            "test_auth",
            true,
        )
        .expect("attempt commits");
        assert_eq!(
            ctx.plugin_state()
                .and_then(|state| state.pending_claim_headers.get("p.x-user-email"))
                .map(String::as_str),
            Some("a@example.com")
        );
        assert_eq!(
            ctx.plugin_state()
                .and_then(|state| state.pending_claim_headers.get("p.x-user-roles"))
                .map(String::as_str),
            Some("admin,editor")
        );
    }
}
