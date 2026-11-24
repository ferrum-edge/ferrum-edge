use crate::fips::approved::Sha256;
use crate::plugins::RequestContext;

use super::auth_attempt::AuthenticationAttempt;
use super::auth_flow::ExtractedCredential;
use super::header_extract::{ConfiguredHeaderLookup, lookup_configured_header};
use super::query::query_has_semicolon_credential_alias;

/// Metadata-key prefix marking a query parameter that carried the auth token and
/// must be stripped from the URL forwarded upstream. It is shared by every auth
/// plugin that supports query-param token locations and is consumed by
/// `request_transformer` (pre-rule input strip) and the proxy
/// (`effective_backend_query_string` / `query_string_after_plugin_strips`),
/// which compose authentication strips onto the transformer outbound query or
/// retained raw wire query. Per-plugin prefixes would be silently ignored
/// there, leaking the token to the backend.
pub(crate) const STRIP_QUERY_PARAM_METADATA_PREFIX: &str = "auth.strip_query_param.";

/// Metadata-key prefix identifying a present query parameter configured as an
/// authentication credential location. Authorization plugins such as OPA use
/// this marker to keep credentials out of secondary policy-service payloads,
/// including invalid credentials alongside another successful auth mechanism.
/// Unlike [`STRIP_QUERY_PARAM_METADATA_PREFIX`], this marker does not change
/// the query forwarded to the primary backend.
pub(crate) const QUERY_CREDENTIAL_METADATA_PREFIX: &str = "auth.query_credential_param.";

pub(crate) fn mark_query_credential_metadata(ctx: &mut RequestContext, name: &str) {
    if let Some(value) = ctx.query_params.get(name) {
        let digest: [u8; 32] = Sha256::digest(value.as_bytes());
        ctx.mark_query_credential_partition_digest(name, digest);
    }
    let mut key = String::with_capacity(QUERY_CREDENTIAL_METADATA_PREFIX.len() + name.len());
    key.push_str(QUERY_CREDENTIAL_METADATA_PREFIX);
    key.push_str(name);
    ctx.metadata.insert(key, String::from("true"));
}

/// Rejection body for a query token location whose name also rides behind a
/// `;` sub-parameter (issue #6579, GHSA-c259-vchc-3vgr): Ferrum's `&`-only
/// parser and a `;`-splitting backend disagree about which value is the token.
pub(crate) const AMBIGUOUS_QUERY_TOKEN_BODY: &str =
    r#"{"error":"Ambiguous token query parameter"}"#;

/// Mark every configured query token location present in the request — in the
/// decoded map or behind a `;` sub-parameter — for policy redaction
/// (`auth.query_credential_param.<name>`). Never changes the forwarded query.
pub fn mark_present_query_credential_locations(
    ctx: &mut RequestContext,
    token_locations: &[TokenLocation],
) {
    mark_provider_query_credential_locations(ctx, token_locations, true);
}

/// [`mark_present_query_credential_locations`] for one provider, which also
/// marks a `;`-aliased query token (issue #6579, GHSA-c259-vchc-3vgr) for
/// removal from the forwarded query when the provider does not forward the
/// original token. Extraction refuses the alias, so it is never a token this
/// provider accepted; the discovery hook runs for every auth instance before
/// multi-auth can stop at another mechanism's success, so the alias is hidden
/// whichever mechanism authenticates — the same contract `key_auth` and
/// `jwt_auth` apply under `hide_credentials`.
pub fn mark_provider_query_credential_locations(
    ctx: &mut RequestContext,
    token_locations: &[TokenLocation],
    forward_original_token: bool,
) {
    for location in token_locations {
        let TokenLocation::QueryParam(name) = location else {
            continue;
        };
        let sub_pair_alias = query_has_semicolon_credential_alias(ctx.raw_query_string(), name);
        if !sub_pair_alias && !ctx.query_params.contains_key(name) {
            continue;
        }
        mark_query_credential_metadata(ctx, name);
        if sub_pair_alias && !forward_original_token {
            let mut key =
                String::with_capacity(STRIP_QUERY_PARAM_METADATA_PREFIX.len() + name.len());
            key.push_str(STRIP_QUERY_PARAM_METADATA_PREFIX);
            key.push_str(name);
            ctx.metadata.insert(key, String::from("true"));
        }
    }
}

/// Whether any configured query token location in `token_locations` also
/// rides behind a `;` sub-parameter (issue #6579, GHSA-c259-vchc-3vgr).
///
/// Multi-location plugins (`jwks_auth`, `oauth2_introspection`) treat such an
/// alias as terminal for the whole instance — checked before any header,
/// `Authorization`, or fallback extraction, across every provider — exactly
/// as `key_auth` refuses a request whose query key is ambiguous whatever its
/// other locations carry. Free unless the raw query holds a `;`.
pub fn query_locations_have_semicolon_alias<'a>(
    ctx: &RequestContext,
    token_locations: impl IntoIterator<Item = &'a TokenLocation>,
) -> bool {
    let Some(raw_query) = ctx.raw_query_string().filter(|raw| raw.contains(';')) else {
        return false;
    };
    token_locations.into_iter().any(|location| {
        matches!(
            location,
            TokenLocation::QueryParam(name)
                if query_has_semicolon_credential_alias(Some(raw_query), name)
        )
    })
}

#[derive(Clone)]
pub struct TokenHeaderLocation {
    pub name: String,
    pub prefix: Option<String>,
}

#[derive(Clone)]
pub enum TokenLocation {
    Header(TokenHeaderLocation),
    QueryParam(String),
}

pub enum TokenLocationExtract {
    Missing,
    Credential(ExtractedCredential),
}

pub fn extract_authorization_bearer(ctx: &RequestContext) -> ExtractedCredential {
    // `Authorization: Bearer` conveys a base64url token (RFC 6750 §2.1), i.e.
    // visible ASCII. A present field line that is not visible ASCII is malformed
    // credential material, not an absent header.
    match lookup_configured_header(ctx, "authorization", None) {
        ConfiguredHeaderLookup::Absent => ExtractedCredential::Missing,
        ConfiguredHeaderLookup::PresentNonMaterialized => ExtractedCredential::InvalidFormat(
            r#"{"error":"Invalid Authorization header"}"#.to_string(),
        ),
        ConfiguredHeaderLookup::Value(value) => bearer_credential_from_authorization_value(&value),
    }
}

/// Classify an `Authorization` header value against the `Bearer` scheme. A
/// foreign scheme is `Missing` (not applicable, so multi-auth may continue),
/// while an applicable `Bearer` value with an empty token is `InvalidFormat`
/// so single mode rejects it instead of skipping to a later mechanism.
pub fn bearer_credential_from_authorization_value(value: &str) -> ExtractedCredential {
    let scheme = value
        .split(|c: char| c.is_ascii_whitespace())
        .next()
        .unwrap_or_default();
    if !scheme.eq_ignore_ascii_case("bearer") {
        return ExtractedCredential::Missing;
    }
    match crate::plugins::strip_auth_scheme(value, "Bearer") {
        Some(token) => ExtractedCredential::BearerToken(token.to_string()),
        None => ExtractedCredential::InvalidFormat(r#"{"error":"Empty bearer token"}"#.to_string()),
    }
}

/// Read an access token presented under the RFC 9449 `DPoP` authorization
/// scheme (§7.1).
///
/// Separate from [`extract_authorization_bearer`] on purpose: a `DPoP`-scheme
/// presentation asserts a key-bound token, so only a caller that actually
/// validates the accompanying proof may accept one. A plugin without a DPoP
/// contract must keep treating the scheme as foreign, which is what the bearer
/// extractor does.
pub fn extract_authorization_dpop(ctx: &RequestContext) -> ExtractedCredential {
    match lookup_configured_header(ctx, "authorization", None) {
        ConfiguredHeaderLookup::Absent => ExtractedCredential::Missing,
        ConfiguredHeaderLookup::PresentNonMaterialized => ExtractedCredential::InvalidFormat(
            r#"{"error":"Invalid Authorization header"}"#.to_string(),
        ),
        ConfiguredHeaderLookup::Value(value) => dpop_credential_from_authorization_value(&value),
    }
}

/// Classify an `Authorization` header value against the RFC 9449 `DPoP`
/// scheme. Mirrors [`bearer_credential_from_authorization_value`]: a foreign
/// scheme is `Missing` (not applicable), while an applicable `DPoP` value with
/// an empty token is `InvalidFormat` so a malformed applicable credential is
/// refused rather than skipped.
pub fn dpop_credential_from_authorization_value(value: &str) -> ExtractedCredential {
    let scheme = value
        .split(|c: char| c.is_ascii_whitespace())
        .next()
        .unwrap_or_default();
    if !scheme.eq_ignore_ascii_case("dpop") {
        return ExtractedCredential::Missing;
    }
    match crate::plugins::strip_auth_scheme(value, "DPoP") {
        Some(token) => ExtractedCredential::BearerToken(token.to_string()),
        None => ExtractedCredential::InvalidFormat(r#"{"error":"Empty DPoP token"}"#.to_string()),
    }
}

pub fn extract_from_location(
    location: &TokenLocation,
    ctx: &RequestContext,
) -> TokenLocationExtract {
    match location {
        TokenLocation::Header(header) => match lookup_configured_header(ctx, &header.name, None) {
            ConfiguredHeaderLookup::Absent => TokenLocationExtract::Missing,
            // Bearer/JWT/opaque tokens are ASCII by grammar (RFC 6750 §2.1
            // base64url, JWS compact serialisation, RFC 6749 opaque tokens). A
            // present field line that is not visible ASCII is malformed
            // credential material, not an absent header.
            ConfiguredHeaderLookup::PresentNonMaterialized => TokenLocationExtract::Credential(
                ExtractedCredential::InvalidFormat(r#"{"error":"Invalid token"}"#.to_string()),
            ),
            ConfiguredHeaderLookup::Value(value) => {
                if header.name.eq_ignore_ascii_case("authorization") && header.prefix.is_none() {
                    return match bearer_credential_from_authorization_value(&value) {
                        ExtractedCredential::Missing => TokenLocationExtract::Missing,
                        credential => TokenLocationExtract::Credential(credential),
                    };
                }
                extract_location_value(&value, header.prefix.as_deref())
            }
        },
        TokenLocation::QueryParam(name) => {
            if query_has_semicolon_credential_alias(ctx.raw_query_string(), name) {
                return TokenLocationExtract::Credential(ExtractedCredential::InvalidFormat(
                    AMBIGUOUS_QUERY_TOKEN_BODY.to_string(),
                ));
            }
            match ctx.query_params.get(name) {
                Some(value) => extract_location_value(value, None),
                None => TokenLocationExtract::Missing,
            }
        }
    }
}

pub fn provider_locations_extract_token(
    token_locations: &[TokenLocation],
    ctx: &RequestContext,
    expected_token: &str,
) -> bool {
    token_locations
        .iter()
        .any(|location| match extract_from_location(location, ctx) {
            TokenLocationExtract::Credential(ExtractedCredential::BearerToken(token)) => {
                token == expected_token
            }
            _ => false,
        })
}

pub fn stage_original_token_stripping(
    attempt: &mut AuthenticationAttempt,
    token_locations: &[TokenLocation],
    strip_authorization_metadata_key: &str,
    strip_header_metadata_prefix: &str,
    strip_query_param_metadata_prefix: &str,
) {
    if token_locations.is_empty() {
        attempt.stage_stripping_metadata(strip_authorization_metadata_key.to_string());
        return;
    }

    for location in token_locations {
        match location {
            TokenLocation::Header(header) => {
                attempt.stage_stripping_metadata(format!(
                    "{strip_header_metadata_prefix}{}",
                    header.name
                ));
            }
            TokenLocation::QueryParam(name) => {
                attempt.stage_query_param_strip(
                    format!("{strip_query_param_metadata_prefix}{name}"),
                    name.clone(),
                );
            }
        }
    }
}

/// Append the request headers credential stripping may remove for
/// `token_locations`: `Authorization` and every configured header location.
/// Feeds [`crate::plugins::Plugin::modified_request_header_names`] on the cold
/// path (issue #6022).
pub fn push_stripped_credential_header_names<'a>(
    names: &mut Vec<String>,
    token_locations: impl IntoIterator<Item = &'a TokenLocation>,
) {
    names.push("authorization".to_string());
    for location in token_locations {
        if let TokenLocation::Header(header) = location {
            names.push(header.name.to_ascii_lowercase());
        }
    }
}

fn extract_location_value(value: &str, prefix: Option<&str>) -> TokenLocationExtract {
    let token = match prefix {
        Some(prefix) => match value.strip_prefix(prefix) {
            Some(token) => token,
            None => return TokenLocationExtract::Missing,
        },
        None => value,
    };

    if token.is_empty() {
        return TokenLocationExtract::Credential(ExtractedCredential::InvalidFormat(
            r#"{"error":"Empty token"}"#.to_string(),
        ));
    }

    TokenLocationExtract::Credential(ExtractedCredential::BearerToken(token.to_string()))
}
