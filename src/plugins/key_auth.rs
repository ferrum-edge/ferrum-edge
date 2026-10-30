//! API key authentication plugin.
//!
//! Extracts an API key from configurable locations (headers or query parameters)
//! and looks up the corresponding consumer via the `ConsumerIndex` for O(1)
//! credential matching. Provides transport-level authentication only — the key
//! reaches the gateway in plaintext, so TLS is required in production.
//! Configured credential locations are removed before backend forwarding by
//! default after the request authenticates, including when another mechanism
//! wins a multi-auth chain.
//!
//! Default key location: `header:X-API-Key`. Configurable via `key_location`
//! in the plugin config (a string or an ordered array of up to eight locations).
//! Location values are whitespace-sensitive and are never trimmed.
//! Credentials in two different configured locations are ambiguous, even when
//! their values match, and are refused with 401.
//!
//! A `query:<name>` credential that also appears as a `;`-separated
//! sub-parameter (`?carrier=;api_key=k`) is ambiguous: Ferrum's `&`-only query
//! parser and a `;`-splitting backend disagree about which value is the key.
//! Such a request is refused (`401`, never authenticated), and the sub-pair is
//! still marked for removal and policy redaction so a chain won by another
//! mechanism cannot forward it.
//!
//! The authenticate hook borrows the key straight from the request (the
//! single-field-line header case and the decoded query map), so a successful
//! lookup allocates nothing for the credential itself.

use std::borrow::Cow;

use async_trait::async_trait;
use http::header::HeaderName;
use serde_json::Value;
use tracing::debug;

use crate::consumer_index::ConsumerIndex;

use super::utils::auth_flow::{
    self, AuthMechanism, CredentialRejection, ExtractedCredential, VerifyOutcome,
};
use super::utils::header_extract::{ConfiguredUtf8HeaderLookup, lookup_configured_header_utf8};
use super::utils::token_extract::STRIP_QUERY_PARAM_METADATA_PREFIX;
use super::{PluginResult, RequestContext};

const INVALID_API_KEY_FORMAT_BODY: &str = r#"{"error":"Invalid API key format"}"#;
const AMBIGUOUS_QUERY_API_KEY_BODY: &str = r#"{"error":"Ambiguous API key query parameter"}"#;
const AMBIGUOUS_API_KEY_LOCATIONS_BODY: &str = r#"{"error":"Ambiguous API key locations"}"#;
const MAX_KEY_LOCATIONS: usize = 8;

/// One extraction of the configured key location, borrowing from the request
/// whenever the representation allows it.
enum KeyLookup<'a> {
    Missing,
    Present(Cow<'a, str>),
    InvalidFormat(&'static str),
}

enum KeyLocation {
    Header {
        /// Pre-lowercased to avoid allocating during extraction.
        lower: String,
        original: String,
    },
    Query {
        name: String,
        /// Precomputed key for the shared outbound-query strip funnel.
        strip_metadata_key: String,
    },
}

impl KeyLocation {
    fn parse(key_location: &str) -> Result<Self, String> {
        if key_location.is_empty() {
            return Err("key_auth: `key_location` must not be empty".to_string());
        }
        if key_location.trim() != key_location {
            return Err(
                "key_auth: `key_location` must not have leading or trailing whitespace".to_string(),
            );
        }
        if let Some(name) = key_location.strip_prefix("header:") {
            if name.is_empty() {
                return Err("key_auth: `key_location` header name must not be empty".to_string());
            }
            let normalized_name = name.to_ascii_lowercase();
            let header_name = HeaderName::from_bytes(normalized_name.as_bytes()).map_err(|_| {
                "key_auth: `key_location` header name is not a valid HTTP header name".to_string()
            })?;
            Ok(Self::Header {
                lower: header_name.as_str().to_string(),
                original: name.to_string(),
            })
        } else if let Some(name) = key_location.strip_prefix("query:") {
            if name.is_empty() {
                return Err("key_auth: `key_location` query name must not be empty".to_string());
            }
            if name.chars().any(char::is_whitespace) {
                return Err(
                    "key_auth: `key_location` query name must not contain whitespace".to_string(),
                );
            }
            let mut strip_metadata_key =
                String::with_capacity(STRIP_QUERY_PARAM_METADATA_PREFIX.len() + name.len());
            strip_metadata_key.push_str(STRIP_QUERY_PARAM_METADATA_PREFIX);
            strip_metadata_key.push_str(name);
            Ok(Self::Query {
                name: name.to_string(),
                strip_metadata_key,
            })
        } else {
            Err("key_auth: `key_location` must use `header:<name>` or `query:<name>`".to_string())
        }
    }

    fn same_location(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Header { lower: a, .. }, Self::Header { lower: b, .. }) => a == b,
            (Self::Query { name: a, .. }, Self::Query { name: b, .. }) => a == b,
            _ => false,
        }
    }

    /// Borrow a single field line or decoded query value; only folded,
    /// repeated header field lines allocate.
    fn lookup<'a>(&'a self, ctx: &'a RequestContext) -> KeyLookup<'a> {
        match self {
            Self::Header { lower, original } => {
                utf8_header_lookup_to_key(lookup_configured_header_utf8(ctx, lower, Some(original)))
            }
            Self::Query { name, .. } => {
                if query_has_semicolon_credential_alias(ctx.raw_query_string(), name) {
                    return KeyLookup::InvalidFormat(AMBIGUOUS_QUERY_API_KEY_BODY);
                }
                match ctx.query_params.get(name) {
                    Some(key) => KeyLookup::Present(Cow::Borrowed(key.as_str())),
                    None => KeyLookup::Missing,
                }
            }
        }
    }
}

pub struct KeyAuth {
    /// Validated, distinct locations in configured order.
    locations: Vec<KeyLocation>,
    /// Configured request headers that diagnostics and policy calls must omit.
    request_headers_to_redact: Vec<String>,
    /// Remove every configured credential location before the backend request.
    hide_credentials: bool,
}

impl KeyAuth {
    pub fn new(config: &Value) -> Result<Self, String> {
        let config_obj = config.as_object().ok_or_else(|| {
            format!(
                "key_auth: config must be an object, got: {config:?}",
                config = config.to_string()
            )
        })?;
        let mut unknown_fields: Vec<&str> = config_obj
            .keys()
            .map(String::as_str)
            .filter(|key| !matches!(*key, "key_location" | "hide_credentials"))
            .collect();
        unknown_fields.sort_unstable();
        if !unknown_fields.is_empty() {
            return Err(format!(
                "key_auth: unknown configuration field(s): {:?}; allowed fields are `key_location` and `hide_credentials`",
                unknown_fields.join(", ")
            ));
        }

        let hide_credentials = match config_obj.get("hide_credentials") {
            Some(value) => value
                .as_bool()
                .ok_or_else(|| "key_auth: `hide_credentials` must be a boolean".to_string())?,
            None => true,
        };
        let locations = match config_obj.get("key_location") {
            None => vec![KeyLocation::parse("header:X-API-Key")?],
            Some(Value::String(location)) => vec![KeyLocation::parse(location)?],
            Some(Value::Array(values)) => {
                if values.is_empty() || values.len() > MAX_KEY_LOCATIONS {
                    return Err(
                        "key_auth: `key_location` array must contain 1 to 8 locations".to_string(),
                    );
                }
                let mut locations = Vec::with_capacity(values.len());
                for (index, value) in values.iter().enumerate() {
                    let location = value.as_str().ok_or_else(|| {
                        format!(
                            "key_auth: `key_location` array element {index} must be a string, got: {value:?}",
                            value = value.to_string()
                        )
                    })?;
                    let location = KeyLocation::parse(location)?;
                    // Header names are case-insensitive. Repeating the same
                    // location cannot create a second credential source.
                    if !locations
                        .iter()
                        .any(|known: &KeyLocation| known.same_location(&location))
                    {
                        locations.push(location);
                    }
                }
                locations
            }
            Some(value) => {
                return Err(format!(
                    "key_auth: `key_location` must be a string or an array of strings, got: {value:?}",
                    value = value.to_string()
                ));
            }
        };
        let request_headers_to_redact = locations
            .iter()
            .filter_map(|location| match location {
                KeyLocation::Header { lower, .. } => Some(lower.clone()),
                KeyLocation::Query { .. } => None,
            })
            .collect();

        Ok(Self {
            locations,
            request_headers_to_redact,
            hide_credentials,
        })
    }

    /// Scan in configured order, but never let a valid key mask another
    /// configured source (including a blank or malformed credential).
    fn lookup_key<'a>(&'a self, ctx: &'a RequestContext) -> KeyLookup<'a> {
        let mut found = None;
        for location in &self.locations {
            let candidate = location.lookup(ctx);
            if matches!(candidate, KeyLookup::Missing) {
                continue;
            }
            if found.is_some() {
                return KeyLookup::InvalidFormat(AMBIGUOUS_API_KEY_LOCATIONS_BODY);
            }
            found = Some(candidate);
        }
        found.unwrap_or(KeyLookup::Missing)
    }
}

fn utf8_header_lookup_to_key(lookup: ConfiguredUtf8HeaderLookup<'_>) -> KeyLookup<'_> {
    match lookup {
        ConfiguredUtf8HeaderLookup::Value(key) => KeyLookup::Present(key),
        ConfiguredUtf8HeaderLookup::Absent => KeyLookup::Missing,
        ConfiguredUtf8HeaderLookup::InvalidUtf8 => {
            KeyLookup::InvalidFormat(INVALID_API_KEY_FORMAT_BODY)
        }
    }
}

/// Whether `raw_query` carries `name` as a `;`-separated sub-parameter that
/// Ferrum's `&`-only parser does not see as that name (issue #6579 shape):
/// `carrier=;api_key=k`, or `api_key;x=1` whose Ferrum name is `api_key;x`.
///
/// A sub-pair name matches by its raw spelling or by any decoding
/// [`crate::plugins::utils::query::query_name_decodings`] reports, the same
/// raw-or-decoded contract the outbound strip uses. The leading sub-pair of a
/// segment is the segment's own parameter, already represented in the decoded
/// map, unless the segment's NAME itself holds the `;`. Allocation-free unless
/// the query contains a raw `;`.
fn query_has_semicolon_credential_alias(raw_query: Option<&str>, name: &str) -> bool {
    let Some(raw_query) = raw_query else {
        return false;
    };
    if !raw_query.contains(';') {
        return false;
    }
    raw_query.split('&').any(|segment| {
        if !segment.contains(';') {
            return false;
        }
        let ferrum_name = segment
            .split_once('=')
            .map_or(segment, |(pair_name, _)| pair_name);
        let skip_leading = usize::from(!ferrum_name.contains(';'));
        segment.split(';').skip(skip_leading).any(|sub_pair| {
            let sub_name = sub_pair
                .split_once('=')
                .map_or(sub_pair, |(sub_name, _)| sub_name);
            sub_name == name
                || crate::plugins::utils::query::query_name_decodings(sub_name)
                    .iter()
                    .any(|decoded| decoded == name)
        })
    })
}

/// The shared key verification: blank keys never reach the index.
fn verify_api_key(api_key: &str, consumer_index: &ConsumerIndex) -> VerifyOutcome {
    // Reject empty / whitespace-only keys before hitting the index. This
    // prevents a misconfigured consumer (with an empty `key` value) from
    // accidentally matching every request that sends a blank header, and
    // gives clients a clearer error than a generic "Invalid API key".
    if api_key.trim().is_empty() {
        return VerifyOutcome::Invalid(r#"{"error":"Missing API key"}"#.into());
    }

    match consumer_index.find_by_api_key(api_key) {
        Some(consumer) => VerifyOutcome::consumer(consumer),
        None => VerifyOutcome::ConsumerNotFound(r#"{"error":"Invalid API key"}"#.into()),
    }
}

/// `key_auth`'s authenticate hook: the shared [`auth_flow::run_auth`]
/// contract, with the key borrowed from the request instead of copied into an
/// owned [`ExtractedCredential::ApiKey`]. Commit and rejection mapping are the
/// shared [`auth_flow::finish_verified_auth_attempt`], so outcomes, bodies,
/// and challenges are identical to the generic flow.
async fn run_key_auth(
    mechanism: &KeyAuth,
    ctx: &mut RequestContext,
    consumer_index: &ConsumerIndex,
) -> PluginResult {
    let outcome = match mechanism.lookup_key(ctx) {
        KeyLookup::Missing => {
            debug!("{}: no credential present", mechanism.mechanism_name());
            return PluginResult::Continue;
        }
        KeyLookup::InvalidFormat(body) => {
            return auth_flow::auth_rejection(
                401,
                body.to_string(),
                mechanism.rejection_challenge(CredentialRejection::InvalidFormat),
            );
        }
        KeyLookup::Present(key) => verify_api_key(&key, consumer_index),
    };
    auth_flow::finish_verified_auth_attempt(mechanism, ctx, outcome, false)
}

#[async_trait]
impl AuthMechanism for KeyAuth {
    fn mechanism_name(&self) -> &'static str {
        "key_auth"
    }

    fn authentication_challenge(&self) -> &'static str {
        auth_flow::API_KEY_AUTHENTICATION_CHALLENGE
    }

    fn extract(&self, ctx: &RequestContext) -> ExtractedCredential {
        match self.lookup_key(ctx) {
            KeyLookup::Present(key) => ExtractedCredential::ApiKey(key.into_owned()),
            KeyLookup::Missing => ExtractedCredential::Missing,
            KeyLookup::InvalidFormat(body) => ExtractedCredential::InvalidFormat(body.into()),
        }
    }

    async fn verify(
        &self,
        credential: ExtractedCredential,
        consumer_index: &ConsumerIndex,
    ) -> VerifyOutcome {
        let ExtractedCredential::ApiKey(api_key) = credential else {
            return VerifyOutcome::NotApplicable;
        };
        verify_api_key(&api_key, consumer_index)
    }
}

auth_flow::impl_auth_plugin!(
    KeyAuth,
    "key_auth",
    super::priority::KEY_AUTH,
    crate::plugins::HTTP_FAMILY_PROTOCOLS,
    run_key_auth;

    /// Mark every configured query credential — in the decoded map or behind a
    /// `;` — for policy redaction and, with `hide_credentials`, for removal
    /// from the forwarded query. Runs for every auth instance before the
    /// chain can short-circuit, so a sub-pair spelling is hidden even when
    /// another mechanism authenticates the request.
    fn mark_query_credentials_for_redaction(&self, ctx: &mut crate::plugins::RequestContext) {
        for location in &self.locations {
            if let KeyLocation::Query {
                name,
                strip_metadata_key,
            } = location
                && (ctx.query_params.contains_key(name)
                    || query_has_semicolon_credential_alias(ctx.raw_query_string(), name))
            {
                crate::plugins::utils::token_extract::mark_query_credential_metadata(ctx, name);
                if self.hide_credentials {
                    ctx.metadata
                        .insert(strip_metadata_key.clone(), "true".to_string());
                }
            }
        }
    }

    fn request_headers_to_redact(&self) -> &[String] {
        &self.request_headers_to_redact
    }

    fn modifies_request_headers(&self) -> bool {
        self.hide_credentials && !self.request_headers_to_redact.is_empty()
    }

    /// `hide_credentials` removes every configured key header.
    fn modified_request_header_names(&self) -> Option<Vec<String>> {
        Some(self.request_headers_to_redact.clone())
    }

    /// Query discovery marks every present query credential for stripping;
    /// `before_proxy` also removes it from the decoded query map.
    fn modifies_request_query(&self) -> bool {
        self.hide_credentials && self.requires_decoded_query_params()
    }

    async fn before_proxy(
        &self,
        ctx: &mut crate::plugins::RequestContext,
        headers: &mut std::collections::HashMap<String, String>,
    ) -> crate::plugins::PluginResult {
        if !self.hide_credentials {
            return crate::plugins::PluginResult::Continue;
        }

        for location in &self.locations {
            match location {
                KeyLocation::Header { lower, original } => {
                    headers.remove(lower);
                    if original != lower {
                        headers.remove(original);
                    }
                }
                KeyLocation::Query {
                    name,
                    strip_metadata_key,
                } => {
                    let sub_pair_alias =
                        query_has_semicolon_credential_alias(ctx.raw_query_string(), name);
                    if ctx.query_params.remove(name).is_some() || sub_pair_alias {
                        ctx.metadata
                            .insert(strip_metadata_key.clone(), "true".to_string());
                    }
                }
            }
        }
        crate::plugins::PluginResult::Continue
    }

    fn requires_decoded_query_params(&self) -> bool {
        self.locations
            .iter()
            .any(|location| matches!(location, KeyLocation::Query { .. }))
    }

    fn lifecycle_hooks(&self) -> crate::plugins::PluginHooks {
        crate::plugins::PluginHooks::BEFORE_PROXY
    }
);
