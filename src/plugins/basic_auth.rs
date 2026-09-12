//! HTTP Basic Authentication plugin with HMAC-SHA256 password verification.
//!
//! Supports `hmac_sha256:<hex>` password hashes using a server secret.
//! This keeps verification fast and avoids variable-time password-hash
//! work on the request path.
//!
//! The server secret (`FERRUM_BASIC_AUTH_HMAC_SECRET`) MUST be set to a
//! unique, random value of at least 32 bytes. The plugin rejects construction
//! if that requirement is not met — there is no insecure default.
//!
//! RFC 7617 encodes the reusable username/password in reversible Base64, so the
//! verified `Authorization: Basic` field is removed before backend forwarding by
//! default — including when another mechanism wins a multi-auth chain and the
//! losing Basic credential would otherwise still ride along. Only the `Basic`
//! scheme is removed; a `Bearer` or other scheme another policy needs is left
//! untouched. `hide_credentials: false` is the explicit legacy opt-out and
//! mirrors `key_auth`'s convention.

use crate::fips::approved::HmacSha256;
use async_trait::async_trait;
use base64::Engine;
use serde_json::Value;
use tracing::{debug, warn};

use crate::consumer_index::ConsumerIndex;

use super::utils::auth_flow::{
    self, AuthMechanism, ExtractedCredential, VerifyOutcome, constant_time_eq,
};
use super::utils::header_extract::{ConfiguredHeaderLookup, lookup_configured_header};
use super::{RequestContext, strip_auth_scheme};

// A canonical stored Basic hash alone consumes this many serialized bytes,
// before its JSON field/object/array overhead. Capping dummy work by the total
// credential JSON limit therefore cannot omit any valid stored Basic hash, but
// prevents a mistaken enormous FERRUM_MAX_CREDENTIALS_PER_TYPE value from
// turning an unknown-user request into unbounded HMAC work.
const MIN_STORED_BASIC_AUTH_HASH_BYTES: usize = "hmac_sha256:".len() + 64;
const MAX_BASIC_AUTH_VERIFICATION_ROUNDS: usize =
    crate::config::types::MAX_CREDENTIALS_SIZE / MIN_STORED_BASIC_AUTH_HASH_BYTES;

pub(crate) fn bounded_verification_rounds(configured_limit: usize) -> usize {
    configured_limit.clamp(1, MAX_BASIC_AUTH_VERIFICATION_ROUNDS)
}

/// The only configuration key this plugin accepts.
const BASIC_AUTH_CONFIG_KEYS: &[&str] = &["hide_credentials"];

pub struct BasicAuth {
    /// Pre-computed HMAC key from FERRUM_BASIC_AUTH_HMAC_SECRET.
    hmac_secret: Vec<u8>,
    /// A valid process-local hash used to equalize missing credential rounds.
    dummy_password_hash: String,
    /// Fixed verification work, independent of consumer rotation state.
    verification_rounds: usize,
    /// Remove a `Basic` `Authorization` field before the backend request.
    hide_credentials: bool,
}

impl BasicAuth {
    pub fn new(config: &Value) -> Result<Self, String> {
        use crate::config::conf_file::resolve_ferrum_var;

        let hmac_secret = resolve_ferrum_var("FERRUM_BASIC_AUTH_HMAC_SECRET");
        Self::new_with_hmac_secret(config, hmac_secret.as_deref())
    }

    pub(crate) fn new_with_hmac_secret(
        config: &Value,
        hmac_secret: Option<&str>,
    ) -> Result<Self, String> {
        let hide_credentials = match config {
            Value::Null => true,
            Value::Object(obj) => {
                crate::util::unknown_keys::reject_unknown_keys(
                    obj,
                    "config",
                    BASIC_AUTH_CONFIG_KEYS,
                    "basic_auth: ",
                )?;
                match obj.get("hide_credentials") {
                    Some(value) => value.as_bool().ok_or_else(|| {
                        "basic_auth: 'hide_credentials' must be a boolean".to_string()
                    })?,
                    None => true,
                }
            }
            other => {
                return Err(format!(
                    "basic_auth: config must be an object, got: {other}"
                ));
            }
        };

        let hmac_secret = hmac_secret.ok_or_else(|| {
            "basic_auth: FERRUM_BASIC_AUTH_HMAC_SECRET must be set to a unique, random value of \
             at least 32 bytes. The plugin cannot operate without a strong secret."
                .to_string()
        })?;
        crate::config::types::validate_basic_auth_hmac_secret(hmac_secret)
            .map_err(|error| format!("basic_auth: {error}"))?;

        let mut dummy_mac = HmacSha256::new_from_slice(hmac_secret.as_bytes())
            .map_err(|_| "basic_auth: failed to initialize HMAC verification".to_string())?;
        dummy_mac.update(uuid::Uuid::new_v4().as_bytes());
        let dummy_password_hash = format!(
            "hmac_sha256:{}",
            hex::encode(dummy_mac.finalize().into_bytes())
        );

        debug!("basic_auth: HMAC-SHA256 configured with operator-provided secret");

        Ok(Self {
            hmac_secret: hmac_secret.as_bytes().to_vec(),
            dummy_password_hash,
            verification_rounds: bounded_verification_rounds(
                crate::config::types::max_credentials_per_type(),
            ),
            hide_credentials,
        })
    }

    /// Verify a password against a stored hash.
    ///
    /// Supports `hmac_sha256:<hex>` — HMAC-SHA256 with the server secret.
    fn verify_password(&self, password: &str, stored_hash: &str) -> bool {
        let Ok(mut mac) = HmacSha256::new_from_slice(&self.hmac_secret) else {
            warn!("basic_auth: failed to create HMAC instance");
            return false;
        };
        mac.update(password.as_bytes());
        let computed = mac.finalize().into_bytes();
        let Some(hex_hash) = stored_hash.strip_prefix("hmac_sha256:") else {
            return false;
        };
        let mut expected = [0u8; 32];
        if hex::decode_to_slice(hex_hash, &mut expected).is_err() {
            return false;
        }

        constant_time_eq(&computed, &expected)
    }

    fn verify_credential_with_round_observer<F>(
        &self,
        credential: ExtractedCredential,
        consumer_index: &ConsumerIndex,
        mut observe_round: F,
    ) -> VerifyOutcome
    where
        F: FnMut(),
    {
        let ExtractedCredential::BasicAuth { username, password } = credential else {
            return VerifyOutcome::NotApplicable;
        };

        let consumer = consumer_index.find_by_username(&username);
        let mut password_matched = false;

        for round in 0..self.verification_rounds {
            observe_round();
            // Fixed indexed access avoids collecting a username-dependent
            // number of entries before the padded verification work begins.
            let configured_hash = consumer
                .as_ref()
                .and_then(|consumer| consumer.credentials.get("basicauth"))
                .and_then(Value::as_array)
                .and_then(|entries| entries.get(round))
                .and_then(|entry| entry.get("password_hash"))
                .and_then(Value::as_str);
            let round_matched = self.verify_password(
                &password,
                configured_hash.unwrap_or(&self.dummy_password_hash),
            );
            // Always execute the padded HMAC round, but only a configured
            // credential is allowed to establish identity. The random dummy
            // material is timing padding, never a process-local master password.
            password_matched |= configured_hash.is_some() & round_matched;
        }

        if password_matched && let Some(consumer) = consumer {
            return VerifyOutcome::consumer(consumer);
        }

        VerifyOutcome::VerificationFailed(r#"{"error":"Invalid credentials"}"#.into())
    }

    // The library target exposes this through `_test_support` to external unit
    // tests. The binary test target compiles this module separately without
    // that bridge, so the helper is intentionally unused there.
    #[allow(dead_code)]
    pub(crate) fn verify_with_test_material(
        dummy_password_hash: String,
        verification_rounds: usize,
        username: &str,
        password: &str,
        consumer_index: &ConsumerIndex,
    ) -> (VerifyOutcome, usize) {
        let plugin = Self {
            hmac_secret: vec![b'x'; 32],
            dummy_password_hash,
            verification_rounds,
            hide_credentials: true,
        };
        let mut verification_count = 0;
        let outcome = plugin.verify_credential_with_round_observer(
            ExtractedCredential::BasicAuth {
                username: username.to_string(),
                password: password.to_string(),
            },
            consumer_index,
            || verification_count += 1,
        );
        (outcome, verification_count)
    }
}

#[async_trait]
impl AuthMechanism for BasicAuth {
    fn mechanism_name(&self) -> &'static str {
        "basic_auth"
    }

    fn authentication_challenge(&self) -> Option<&'static str> {
        Some(r#"Basic realm="ferrum-edge", charset="UTF-8""#)
    }

    fn extract(&self, ctx: &RequestContext) -> ExtractedCredential {
        // RFC 7617 `Authorization: Basic` credentials are base64 (visible ASCII).
        // A present field line that is not visible ASCII is malformed, not absent
        // — report invalid so operators are not pointed at a missing credential.
        let auth_header = match lookup_configured_header(ctx, "authorization", None) {
            ConfiguredHeaderLookup::Absent => return ExtractedCredential::Missing,
            ConfiguredHeaderLookup::PresentNonMaterialized => {
                return ExtractedCredential::InvalidFormat(
                    r#"{"error":"Invalid Authorization header"}"#.into(),
                );
            }
            ConfiguredHeaderLookup::Value(header) => header,
        };

        if !authorization_value_is_basic(&auth_header) {
            return ExtractedCredential::Missing;
        }

        let Some(encoded) = strip_auth_scheme(&auth_header, "Basic") else {
            return ExtractedCredential::InvalidFormat(
                r#"{"error":"Invalid Basic auth format"}"#.into(),
            );
        };

        let decoded = match base64::engine::general_purpose::STANDARD.decode(encoded) {
            Ok(decoded) => decoded,
            Err(_) => {
                return ExtractedCredential::InvalidFormat(
                    r#"{"error":"Invalid base64 in Basic auth"}"#.into(),
                );
            }
        };

        let credential_str = match String::from_utf8(decoded) {
            Ok(credential_str) => credential_str,
            Err(_) => {
                return ExtractedCredential::InvalidFormat(
                    r#"{"error":"Invalid UTF-8 in Basic auth"}"#.into(),
                );
            }
        };

        let Some((username, password)) = credential_str.split_once(':') else {
            return ExtractedCredential::InvalidFormat(
                r#"{"error":"Invalid Basic auth format"}"#.into(),
            );
        };

        ExtractedCredential::BasicAuth {
            username: username.to_string(),
            password: password.to_string(),
        }
    }

    async fn verify(
        &self,
        credential: ExtractedCredential,
        consumer_index: &ConsumerIndex,
    ) -> VerifyOutcome {
        self.verify_credential_with_round_observer(credential, consumer_index, || {})
    }
}

/// Whether a materialized `Authorization` value presents the RFC 7617 `Basic`
/// scheme.
///
/// Scheme comparison is ASCII case-insensitive (RFC 9110 §11.1) and only the
/// FIRST token is inspected — that is the credential
/// [`BasicAuth::extract`] parses, so it is exactly the one this plugin is
/// responsible for keeping off the backend. Any other scheme belongs to another
/// policy and is left in place.
fn authorization_value_is_basic(value: &str) -> bool {
    value
        .split(|c: char| c.is_ascii_whitespace())
        .next()
        .unwrap_or_default()
        .eq_ignore_ascii_case("Basic")
}

/// Whether one backend-bound header entry is an `Authorization` field carrying
/// the `Basic` scheme.
///
/// The materialized map is lowercase, but a plugin can insert a mixed-case key,
/// so the name is matched ASCII case-insensitively. The decision is keyed on the
/// VALUE as well: a `Bearer` (or any other) scheme is not this plugin's.
fn is_basic_authorization_field(name: &str, value: &str) -> bool {
    name.eq_ignore_ascii_case("authorization") && authorization_value_is_basic(value)
}

/// Remove every `Authorization` field carrying the `Basic` scheme from a
/// backend-bound header map.
fn strip_basic_authorization(headers: &mut std::collections::HashMap<String, String>) {
    headers.retain(|name, value| !is_basic_authorization_field(name, value));
}

auth_flow::impl_auth_plugin!(
    BasicAuth,
    "basic_auth",
    super::priority::BASIC_AUTH,
    crate::plugins::HTTP_FAMILY_PROTOCOLS,
    auth_flow::run_auth;

    fn modifies_request_headers(&self) -> bool {
        self.hide_credentials
    }

    /// Remove the verified Basic credential from the backend request.
    ///
    /// `before_proxy` runs for EVERY configured plugin, not only the mechanism
    /// that won the chain, so a Basic credential is stripped even when
    /// `key_auth` (or any other mechanism) authenticated the request for a
    /// different consumer. That mixed-chain case is the one that leaked a
    /// consumer password to an upstream asserting a different principal.
    async fn before_proxy(
        &self,
        _ctx: &mut crate::plugins::RequestContext,
        headers: &mut std::collections::HashMap<String, String>,
    ) -> crate::plugins::PluginResult {
        if self.hide_credentials {
            strip_basic_authorization(headers);
        }
        crate::plugins::PluginResult::Continue
    }
);
