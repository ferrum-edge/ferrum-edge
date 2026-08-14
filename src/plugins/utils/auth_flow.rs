use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::debug;

use crate::config::types::Consumer;
use crate::consumer_index::ConsumerIndex;
use crate::plugins::{PluginResult, RequestContext};

use super::auth_attempt::AuthenticationAttempt;

/// What an auth plugin extracted from the request.
#[derive(Debug, Clone)]
pub enum ExtractedCredential {
    BearerToken(String),
    ApiKey(String),
    BasicAuth {
        username: String,
        password: String,
    },
    /// Boxed because this variant is much larger than the others; an
    /// `ExtractedCredential` is also wrapped by other enums (e.g.
    /// `TokenLocationExtract`), so keeping it small avoids inflating them.
    HmacAuth(Box<HmacAuthCredential>),
    MtlsCert {
        der_bytes: Arc<Vec<u8>>,
        chain_der: Option<Arc<Vec<Vec<u8>>>>,
        connection_cache: Option<Arc<crate::plugins::mtls_auth::MtlsAuthConnectionCache>>,
    },
    /// Extract failed before verification could run (bad header scheme,
    /// malformed base64, missing required companion header, etc.).
    InvalidFormat(String),
    /// No credential present — multi-auth can continue with the next plugin.
    Missing,
}

/// HMAC credential fields extracted from a request, used to reconstruct the
/// signing string and verify the body digest. Boxed inside
/// [`ExtractedCredential::HmacAuth`].
#[derive(Debug, Clone)]
pub struct HmacAuthCredential {
    /// Namespace of the matched proxy. HMAC identity resolution is scoped to
    /// this namespace and the value is bound into the signing base.
    pub namespace: String,
    pub username: String,
    /// Canonical client-request authority bound into the versioned signature
    /// base so a captured request cannot cross virtual-host boundaries.
    pub authority: String,
    pub algorithm: String,
    pub signature: String,
    pub date: String,
    pub method: String,
    pub path: String,
    /// Raw request query string (verbatim, percent-encoded as received), bound
    /// into the signing string so query parameters cannot be altered without
    /// invalidating the HMAC. Empty when the request had no query.
    pub query: String,
    /// Value of legacy `Digest:` or RFC 9530 `Content-Digest:`
    /// header.
    pub digest_header: String,
    /// Hashes of the sole forwarding buffer used to verify `digest_header`
    /// without retaining another full request-body copy.
    pub request_body_sha256: [u8; 32],
    pub request_body_sha512: [u8; 64],
}

/// Canonical maximum size, in UTF-8 bytes, of an authenticated principal.
///
/// A verified external identity claim is attacker- or issuer-selectable: JWT,
/// OIDC, and introspection paths accept a claim value as the request principal
/// even when no configured Consumer matches. Every downstream consumer of that
/// principal (billing, rate-limit keys, cache keys, log summaries, backend
/// identity headers) needs a bounded value, and any component that bounds it
/// itself by truncation would merge two distinct principals that share a
/// prefix. Ferrum therefore rejects an oversized principal at the one place it
/// becomes authoritative — [`commit_authentication_attempt`] — instead of
/// letting a later stage silently shorten it.
///
/// 512 bytes is far above any realistic `sub`/`email`/SPIFFE-style identifier
/// while keeping every per-principal key, index entry, and exported column
/// bounded.
pub const MAX_AUTHENTICATED_IDENTITY_BYTES: usize = 512;

/// Reject an authenticated principal whose identity exceeds
/// [`MAX_AUTHENTICATED_IDENTITY_BYTES`].
///
/// The error body carries the limit and the observed length only. The identity
/// itself is credential-derived and is never echoed to the client or logged.
fn identity_within_limit(identity: &str, field: &'static str) -> Result<(), VerifyOutcome> {
    if identity.len() <= MAX_AUTHENTICATED_IDENTITY_BYTES {
        return Ok(());
    }
    Err(VerifyOutcome::Forbidden(format!(
        "Authenticated identity rejected: {field} is {} bytes, which exceeds the \
         {MAX_AUTHENTICATED_IDENTITY_BYTES}-byte limit for an authenticated principal",
        identity.len()
    )))
}

/// Shared auth verification result, mapped to PluginResult by the dispatcher.
#[derive(Debug, Clone)]
pub enum VerifyOutcome {
    Success {
        consumer: Option<Arc<Consumer>>,
        external_identity: Option<String>,
        external_identity_header: Option<String>,
        /// Monotonic end of the credential's validated temporal validity.
        /// Raw tokens and claims deliberately never cross this boundary.
        credential_deadline: Option<tokio::time::Instant>,
    },
    NotApplicable,
    /// Credential was malformed, but the issue was only discovered during
    /// provider-specific verification rather than initial extraction.
    InvalidFormat(String),
    /// Credential was well-formed enough to verify, but failed semantic or
    /// cryptographic validation.
    Invalid(String),
    ConsumerNotFound(String),
    VerificationFailed(String),
    Forbidden(String),
    Internal(String),
}

impl VerifyOutcome {
    pub fn success(
        consumer: Option<Arc<Consumer>>,
        external_identity: Option<String>,
        external_identity_header: Option<String>,
    ) -> Self {
        let external_identity = external_identity.filter(|identity| !identity.trim().is_empty());
        let external_identity_header =
            external_identity_header.filter(|identity_header| !identity_header.trim().is_empty());
        Self::Success {
            consumer,
            external_identity,
            external_identity_header,
            credential_deadline: None,
        }
    }

    pub fn consumer(consumer: Arc<Consumer>) -> Self {
        Self::success(Some(consumer), None, None)
    }

    /// Attach the authoritative credential deadline after provider validation.
    pub fn with_credential_deadline(mut self, deadline: Option<tokio::time::Instant>) -> Self {
        if let Self::Success {
            credential_deadline,
            ..
        } = &mut self
        {
            *credential_deadline = deadline;
        }
        self
    }
}

/// Convert a validated Unix expiry plus its validation leeway to a monotonic
/// deadline. A wall-clock step after authentication cannot extend the result.
pub fn credential_deadline_from_unix_seconds(
    expires_at_unix: i64,
    leeway_seconds: u64,
) -> tokio::time::Instant {
    let now_mono = tokio::time::Instant::now();
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(u64::MAX);
    credential_deadline_from_unix_seconds_at(expires_at_unix, leeway_seconds, now_unix, now_mono)
}

fn credential_deadline_from_unix_seconds_at(
    expires_at_unix: i64,
    leeway_seconds: u64,
    now_unix: u64,
    now_mono: tokio::time::Instant,
) -> tokio::time::Instant {
    try_credential_deadline_from_unix_seconds_at(
        expires_at_unix,
        leeway_seconds,
        now_unix,
        now_mono,
    )
    .unwrap_or(now_mono)
}

/// Fallible conversion used by providers that must fail closed when the
/// expiry cannot be represented as a monotonic instant (issue #3816).
///
/// `None` covers a clock before the Unix epoch, a negative expiry, arithmetic
/// overflow, and an `Instant` that cannot hold the remaining duration. Callers
/// must treat `None` as rejection, never as "no deadline".
pub fn try_credential_deadline_from_unix_seconds(
    expires_at_unix: i64,
    leeway_seconds: u64,
) -> Option<tokio::time::Instant> {
    let now_mono = tokio::time::Instant::now();
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .ok()?;
    try_credential_deadline_from_unix_seconds_at(
        expires_at_unix,
        leeway_seconds,
        now_unix,
        now_mono,
    )
}

pub(crate) fn try_credential_deadline_from_unix_seconds_at(
    expires_at_unix: i64,
    leeway_seconds: u64,
    now_unix: u64,
    now_mono: tokio::time::Instant,
) -> Option<tokio::time::Instant> {
    let valid_until = expires_at_unix.checked_add(i64::try_from(leeway_seconds).ok()?)?;
    let valid_until = u64::try_from(valid_until).ok()?;
    let remaining = valid_until.saturating_sub(now_unix);
    now_mono.checked_add(Duration::from_secs(remaining))
}

/// Extract an authoritative numeric `exp` from already-validated claims.
pub fn credential_deadline_from_claims(
    claims: &serde_json::Value,
    leeway_seconds: u64,
) -> Option<tokio::time::Instant> {
    let exp = claims
        .get("exp")
        .and_then(|value| value.as_i64().or_else(|| value.as_u64()?.try_into().ok()))?;
    Some(credential_deadline_from_unix_seconds(exp, leeway_seconds))
}

macro_rules! impl_auth_plugin {
    (
        $ty:ty,
        $name:literal,
        $priority:expr,
        $protocols:expr,
        $runner:path
        $(; $($extra:tt)*)?
    ) => {
        #[async_trait::async_trait]
        impl crate::plugins::Plugin for $ty {
            fn name(&self) -> &str {
                $name
            }

            fn is_auth_plugin(&self) -> bool {
                true
            }

            fn priority(&self) -> u16 {
                $priority
            }

            fn supported_protocols(&self) -> &'static [crate::plugins::ProxyProtocol] {
                $protocols
            }

            fn authentication_challenge(&self) -> Option<&'static str> {
                <$ty as crate::plugins::utils::auth_flow::AuthMechanism>::authentication_challenge(
                    self,
                )
            }

            async fn authenticate(
                &self,
                ctx: &mut crate::plugins::RequestContext,
                consumer_index: &crate::consumer_index::ConsumerIndex,
            ) -> crate::plugins::PluginResult {
                $runner(self, ctx, consumer_index).await
            }

            $($($extra)*)?
        }
    };
}

pub(crate) use impl_auth_plugin;

#[async_trait]
pub trait AuthMechanism: Send + Sync {
    fn mechanism_name(&self) -> &'static str;

    fn authentication_challenge(&self) -> Option<&'static str> {
        None
    }

    fn extract(&self, ctx: &RequestContext) -> ExtractedCredential;

    async fn verify(
        &self,
        credential: ExtractedCredential,
        consumer_index: &ConsumerIndex,
    ) -> VerifyOutcome;
}

pub async fn run_auth<M: AuthMechanism>(
    mechanism: &M,
    ctx: &mut RequestContext,
    consumer_index: &ConsumerIndex,
) -> PluginResult {
    run_auth_impl(mechanism, ctx, consumer_index, false).await
}

pub async fn run_auth_external_identity<M: AuthMechanism>(
    mechanism: &M,
    ctx: &mut RequestContext,
    consumer_index: &ConsumerIndex,
) -> PluginResult {
    run_auth_impl(mechanism, ctx, consumer_index, true).await
}

async fn run_auth_impl<M: AuthMechanism>(
    mechanism: &M,
    ctx: &mut RequestContext,
    consumer_index: &ConsumerIndex,
    allow_external_identity: bool,
) -> PluginResult {
    let credential = mechanism.extract(ctx);

    match credential {
        ExtractedCredential::Missing => {
            debug!("{}: no credential present", mechanism.mechanism_name());
            PluginResult::Continue
        }
        ExtractedCredential::InvalidFormat(body) => {
            reject(401, body, mechanism.authentication_challenge())
        }
        credential => match commit_authentication_attempt(
            ctx,
            AuthenticationAttempt::new(),
            mechanism.verify(credential, consumer_index).await,
            mechanism.mechanism_name(),
            allow_external_identity,
        ) {
            Ok(_) => PluginResult::Continue,
            Err(VerifyOutcome::InvalidFormat(body))
            | Err(VerifyOutcome::Invalid(body))
            | Err(VerifyOutcome::ConsumerNotFound(body))
            | Err(VerifyOutcome::VerificationFailed(body)) => {
                reject(401, body, mechanism.authentication_challenge())
            }
            Err(VerifyOutcome::Forbidden(body)) => reject(403, body, None),
            Err(VerifyOutcome::Internal(body)) => reject(500, body, None),
            Err(VerifyOutcome::Success { .. }) | Err(VerifyOutcome::NotApplicable) => {
                PluginResult::Continue
            }
        },
    }
}

/// Commit one authentication attempt transactionally.
///
/// `Ok(true)` means the attempt established a nonblank Consumer or a permitted
/// nonblank external principal. `Ok(false)` means it was not applicable or
/// produced no usable principal, so every staged mutation was discarded.
/// Verification errors are returned unchanged for the caller's protocol-
/// specific rejection mapping.
pub fn commit_authentication_attempt(
    ctx: &mut RequestContext,
    attempt: AuthenticationAttempt,
    outcome: VerifyOutcome,
    auth_method: &'static str,
    allow_external_identity: bool,
) -> Result<bool, VerifyOutcome> {
    let VerifyOutcome::Success {
        consumer,
        external_identity,
        external_identity_header,
        credential_deadline,
    } = outcome
    else {
        return match outcome {
            VerifyOutcome::NotApplicable => Ok(false),
            rejection => Err(rejection),
        };
    };

    let consumer = consumer.filter(|consumer| !consumer.username.trim().is_empty());
    let external_identity = if allow_external_identity {
        nonblank_identity(external_identity)
    } else {
        None
    };
    // A display/header claim is meaningful only when the same attempt supplied
    // a usable external principal. A blank header simply falls back to the
    // external identity through RequestContext::backend_consumer_username().
    let external_identity_header = external_identity
        .as_ref()
        .and_then(|_| external_identity_header.filter(|header| !header.trim().is_empty()));

    if consumer.is_none() && external_identity.is_none() {
        return Ok(false);
    }

    // Fail closed on an oversized verified principal BEFORE any staged
    // mutation is committed, so no credential cleanup, principal state, or
    // identity value is applied for a request that is about to be rejected.
    // Truncating here instead would let two distinct principals sharing a
    // prefix collapse into one downstream billing identity.
    if let Some(identity) = external_identity.as_deref() {
        identity_within_limit(identity, "external identity claim")?;
    }
    if let Some(identity_header) = external_identity_header.as_deref() {
        identity_within_limit(identity_header, "external identity display claim")?;
    }

    let principal_already_committed = request_principal_is_committed(ctx);

    // Cleanup is additive for every accepted credential that reaches this
    // boundary. The dispatcher normally stops after its first success; direct
    // or custom callers still cannot erase cleanup already requested. Failed
    // and principal-less attempts never reach this boundary.
    attempt.commit_credential_cleanup(ctx);

    if !principal_already_committed {
        if let Some(consumer) = consumer {
            debug!(
                "{}: identified consumer '{}'",
                auth_method, consumer.username
            );
            ctx.identified_consumer = Some(consumer);
        }
        ctx.authenticated_identity = external_identity;
        ctx.authenticated_identity_header = external_identity_header;
        if ctx.auth_method.is_none() {
            ctx.auth_method = Some(auth_method);
        }
        ctx.credential_deadline_at = credential_deadline;
        attempt.commit_principal_state(ctx);
    }

    Ok(true)
}

/// Whether this attempt could become the first accepted request principal.
/// Callers with irreversible side effects can use this as a non-mutating
/// preflight before performing them; the final commit still revalidates the
/// outcome at the transaction boundary.
pub fn authentication_attempt_can_commit(
    ctx: &RequestContext,
    outcome: &VerifyOutcome,
    allow_external_identity: bool,
) -> bool {
    if request_principal_is_committed(ctx) {
        return false;
    }
    let VerifyOutcome::Success {
        consumer,
        external_identity,
        external_identity_header,
        ..
    } = outcome
    else {
        return false;
    };

    // Mirror commit_authentication_attempt's principal filtering exactly: a
    // display/header claim is meaningful only when the same attempt supplies a
    // permitted nonblank external principal, and either principal-bearing field
    // that would fail the size bound there must fail preflight here too.
    let has_consumer = consumer
        .as_ref()
        .is_some_and(|consumer| !consumer.username.trim().is_empty());
    let external_identity = if allow_external_identity {
        external_identity
            .as_deref()
            .filter(|identity| !identity.trim().is_empty())
    } else {
        None
    };
    let external_identity_header = external_identity.and_then(|_| {
        external_identity_header
            .as_deref()
            .filter(|header| !header.trim().is_empty())
    });

    if !has_consumer && external_identity.is_none() {
        return false;
    }
    if external_identity.is_some_and(|identity| identity.len() > MAX_AUTHENTICATED_IDENTITY_BYTES) {
        return false;
    }
    if external_identity_header
        .is_some_and(|header| header.len() > MAX_AUTHENTICATED_IDENTITY_BYTES)
    {
        return false;
    }

    true
}

fn request_principal_is_committed(ctx: &RequestContext) -> bool {
    ctx.identified_consumer
        .as_ref()
        .is_some_and(|consumer| !consumer.username.trim().is_empty())
        || ctx
            .authenticated_identity
            .as_deref()
            .is_some_and(|identity| !identity.trim().is_empty())
}

/// Retain an identity claim byte-for-byte when it contains a non-whitespace
/// principal, otherwise treat it as missing before Consumer lookup.
pub fn nonblank_identity(identity: Option<String>) -> Option<String> {
    identity.filter(|value| !value.trim().is_empty())
}

fn reject(status_code: u16, body: String, challenge: Option<&'static str>) -> PluginResult {
    let mut headers = HashMap::new();
    if status_code == 401
        && let Some(challenge) = challenge
    {
        headers.insert("WWW-Authenticate".to_string(), challenge.to_string());
    }
    PluginResult::Reject {
        status_code,
        body,
        headers,
    }
}

/// Constant-time byte comparison to prevent timing attacks on secret material.
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }

    diff == 0
}

#[cfg(test)]
mod tests {
    use super::{
        AuthMechanism, AuthenticationAttempt, ExtractedCredential, VerifyOutcome,
        commit_authentication_attempt, constant_time_eq, credential_deadline_from_unix_seconds_at,
        run_auth, run_auth_external_identity,
    };
    use crate::config::types::{Consumer, default_namespace};
    use crate::consumer_index::ConsumerIndex;
    use crate::plugins::{PluginResult, RequestContext};
    use async_trait::async_trait;
    use chrono::Utc;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Duration;

    #[derive(Clone)]
    struct FakeMechanism {
        extracted: ExtractedCredential,
        outcome: VerifyOutcome,
    }

    #[async_trait]
    impl AuthMechanism for FakeMechanism {
        fn mechanism_name(&self) -> &'static str {
            "fake_auth"
        }

        fn extract(&self, _ctx: &RequestContext) -> ExtractedCredential {
            self.extracted.clone()
        }

        async fn verify(
            &self,
            _credential: ExtractedCredential,
            _consumer_index: &ConsumerIndex,
        ) -> VerifyOutcome {
            self.outcome.clone()
        }
    }

    #[tokio::test]
    async fn missing_credential_continues_without_identity() {
        let mechanism = FakeMechanism {
            extracted: ExtractedCredential::Missing,
            outcome: VerifyOutcome::NotApplicable,
        };
        let mut ctx = test_ctx();
        let index = ConsumerIndex::new(&[]);

        let result = run_auth(&mechanism, &mut ctx, &index).await;

        assert!(matches!(result, PluginResult::Continue));
        assert!(ctx.identified_consumer.is_none());
        assert!(ctx.authenticated_identity.is_none());
        assert!(ctx.authenticated_identity_header.is_none());
    }

    #[tokio::test]
    async fn invalid_outcome_maps_to_401() {
        let mechanism = FakeMechanism {
            extracted: ExtractedCredential::ApiKey("bad-key".to_string()),
            outcome: VerifyOutcome::Invalid(r#"{"error":"Invalid API key"}"#.to_string()),
        };
        let mut ctx = test_ctx();
        let index = ConsumerIndex::new(&[]);

        let result = run_auth(&mechanism, &mut ctx, &index).await;

        assert_reject(result, 401);
    }

    #[tokio::test]
    async fn forbidden_outcome_maps_to_403() {
        let mechanism = FakeMechanism {
            extracted: ExtractedCredential::BearerToken("token".to_string()),
            outcome: VerifyOutcome::Forbidden(r#"{"error":"Insufficient scope"}"#.to_string()),
        };
        let mut ctx = test_ctx();
        let index = ConsumerIndex::new(&[]);

        let result = run_auth(&mechanism, &mut ctx, &index).await;

        assert_reject(result, 403);
    }

    #[tokio::test]
    async fn success_sets_identified_consumer() {
        let consumer = Arc::new(test_consumer());
        let mechanism = FakeMechanism {
            extracted: ExtractedCredential::ApiKey("test-key".to_string()),
            outcome: VerifyOutcome::Success {
                consumer: Some(Arc::clone(&consumer)),
                external_identity: None,
                external_identity_header: None,
                credential_deadline: None,
            },
        };
        let mut ctx = test_ctx();
        let index = ConsumerIndex::new(&[]);

        let result = run_auth(&mechanism, &mut ctx, &index).await;

        assert!(matches!(result, PluginResult::Continue));
        assert_eq!(
            ctx.identified_consumer
                .as_ref()
                .map(|c| c.username.as_str()),
            Some("phase3-user")
        );
        assert!(ctx.authenticated_identity.is_none());
    }

    #[tokio::test]
    async fn external_identity_sets_authenticated_identity() {
        let mechanism = FakeMechanism {
            extracted: ExtractedCredential::BearerToken("token".to_string()),
            outcome: VerifyOutcome::Success {
                consumer: None,
                external_identity: Some("alice@example.com".to_string()),
                external_identity_header: None,
                credential_deadline: None,
            },
        };
        let mut ctx = test_ctx();
        let index = ConsumerIndex::new(&[]);

        let result = run_auth_external_identity(&mechanism, &mut ctx, &index).await;

        assert!(matches!(result, PluginResult::Continue));
        assert!(ctx.identified_consumer.is_none());
        assert_eq!(
            ctx.authenticated_identity.as_deref(),
            Some("alice@example.com")
        );
        assert!(ctx.authenticated_identity_header.is_none());
    }

    #[tokio::test]
    async fn external_identity_flow_sets_both_consumer_and_identity() {
        let consumer = Arc::new(test_consumer());
        let mechanism = FakeMechanism {
            extracted: ExtractedCredential::BasicAuth {
                username: "phase3-user".to_string(),
                password: "secret".to_string(),
            },
            outcome: VerifyOutcome::Success {
                consumer: Some(Arc::clone(&consumer)),
                external_identity: Some("alice@example.com".to_string()),
                external_identity_header: Some("Alice Example".to_string()),
                credential_deadline: None,
            },
        };
        let mut ctx = test_ctx();
        let index = ConsumerIndex::new(&[]);

        let result = run_auth_external_identity(&mechanism, &mut ctx, &index).await;

        assert!(matches!(result, PluginResult::Continue));
        assert_eq!(
            ctx.identified_consumer
                .as_ref()
                .map(|c| c.username.as_str()),
            Some("phase3-user")
        );
        assert_eq!(
            ctx.authenticated_identity.as_deref(),
            Some("alice@example.com")
        );
        assert_eq!(
            ctx.authenticated_identity_header.as_deref(),
            Some("Alice Example")
        );
    }

    #[tokio::test]
    async fn auth_method_set_on_consumer_success() {
        let consumer = Arc::new(test_consumer());
        let mechanism = FakeMechanism {
            extracted: ExtractedCredential::ApiKey("key".to_string()),
            outcome: VerifyOutcome::Success {
                consumer: Some(Arc::clone(&consumer)),
                external_identity: None,
                external_identity_header: None,
                credential_deadline: None,
            },
        };
        let mut ctx = test_ctx();
        let index = ConsumerIndex::new(&[]);

        run_auth(&mechanism, &mut ctx, &index).await;

        assert_eq!(ctx.auth_method, Some("fake_auth"));
    }

    #[tokio::test]
    async fn auth_method_set_on_external_identity_success() {
        let mechanism = FakeMechanism {
            extracted: ExtractedCredential::BearerToken("token".to_string()),
            outcome: VerifyOutcome::Success {
                consumer: None,
                external_identity: Some("alice@example.com".to_string()),
                external_identity_header: None,
                credential_deadline: None,
            },
        };
        let mut ctx = test_ctx();
        let index = ConsumerIndex::new(&[]);

        run_auth_external_identity(&mechanism, &mut ctx, &index).await;

        assert_eq!(ctx.auth_method, Some("fake_auth"));
    }

    #[tokio::test]
    async fn auth_method_none_on_missing_credential() {
        let mechanism = FakeMechanism {
            extracted: ExtractedCredential::Missing,
            outcome: VerifyOutcome::NotApplicable,
        };
        let mut ctx = test_ctx();
        let index = ConsumerIndex::new(&[]);

        run_auth(&mechanism, &mut ctx, &index).await;

        assert!(ctx.auth_method.is_none());
    }

    #[tokio::test]
    async fn auth_method_none_on_rejection() {
        let mechanism = FakeMechanism {
            extracted: ExtractedCredential::ApiKey("bad".to_string()),
            outcome: VerifyOutcome::Invalid(r#"{"error":"bad"}"#.to_string()),
        };
        let mut ctx = test_ctx();
        let index = ConsumerIndex::new(&[]);

        run_auth(&mechanism, &mut ctx, &index).await;

        assert!(ctx.auth_method.is_none());
    }

    #[tokio::test]
    async fn auth_method_none_when_success_establishes_no_identity() {
        let mechanism = FakeMechanism {
            extracted: ExtractedCredential::BearerToken("token".to_string()),
            outcome: VerifyOutcome::Success {
                consumer: None,
                external_identity: None,
                external_identity_header: None,
                credential_deadline: None,
            },
        };
        let mut ctx = test_ctx();
        let index = ConsumerIndex::new(&[]);

        run_auth_external_identity(&mechanism, &mut ctx, &index).await;

        assert!(ctx.effective_identity().is_none());
        assert!(ctx.auth_method.is_none());
    }

    #[tokio::test]
    async fn blank_external_identity_does_not_authenticate() {
        let mechanism = FakeMechanism {
            extracted: ExtractedCredential::BearerToken("token".to_string()),
            outcome: VerifyOutcome::Success {
                consumer: None,
                external_identity: Some("   \t".to_string()),
                external_identity_header: Some(" \n".to_string()),
                credential_deadline: None,
            },
        };
        let mut ctx = test_ctx();
        let index = ConsumerIndex::new(&[]);

        let result = run_auth_external_identity(&mechanism, &mut ctx, &index).await;

        assert!(matches!(result, PluginResult::Continue));
        assert!(ctx.authenticated_identity.is_none());
        assert!(ctx.authenticated_identity_header.is_none());
        assert!(ctx.effective_identity().is_none());
        assert!(ctx.auth_method.is_none());
    }

    #[tokio::test]
    async fn not_applicable_continues() {
        let mechanism = FakeMechanism {
            extracted: ExtractedCredential::BearerToken("token".to_string()),
            outcome: VerifyOutcome::NotApplicable,
        };
        let mut ctx = test_ctx();
        let index = ConsumerIndex::new(&[]);

        let result = run_auth(&mechanism, &mut ctx, &index).await;

        assert!(matches!(result, PluginResult::Continue));
        assert!(ctx.identified_consumer.is_none());
        assert!(ctx.authenticated_identity.is_none());
    }

    #[tokio::test]
    async fn consumer_not_found_maps_to_401() {
        let mechanism = FakeMechanism {
            extracted: ExtractedCredential::BearerToken("token".to_string()),
            outcome: VerifyOutcome::ConsumerNotFound(
                r#"{"error":"Consumer not found"}"#.to_string(),
            ),
        };
        let mut ctx = test_ctx();
        let index = ConsumerIndex::new(&[]);

        let result = run_auth(&mechanism, &mut ctx, &index).await;

        assert_reject(result, 401);
    }

    #[test]
    fn constant_time_eq_matches_equal_and_unequal_inputs() {
        assert!(constant_time_eq(b"abc123", b"abc123"));
        assert!(!constant_time_eq(b"abc123", b"abc124"));
        assert!(!constant_time_eq(b"short", b"longer"));
    }

    #[test]
    fn credential_deadline_uses_exact_validated_expiry_and_leeway_boundary() {
        let now = tokio::time::Instant::now();
        assert_eq!(
            credential_deadline_from_unix_seconds_at(1_000, 0, 1_000, now),
            now
        );
        assert_eq!(
            credential_deadline_from_unix_seconds_at(995, 5, 1_000, now),
            now
        );
        assert_eq!(
            credential_deadline_from_unix_seconds_at(1_000, 5, 1_000, now),
            now + Duration::from_secs(5)
        );
    }

    #[test]
    fn accepted_authentication_commits_only_the_monotonic_deadline() {
        let mut ctx = test_ctx();
        let consumer = Arc::new(test_consumer());
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        let committed = commit_authentication_attempt(
            &mut ctx,
            AuthenticationAttempt::new(),
            VerifyOutcome::consumer(consumer).with_credential_deadline(Some(deadline)),
            "jwt_auth",
            false,
        )
        .expect("validated success should commit");
        assert!(committed);
        assert_eq!(ctx.credential_deadline_at, Some(deadline));
        assert!(ctx.metadata.values().all(|value| !value.contains("token")));
    }

    fn test_ctx() -> RequestContext {
        RequestContext::new(
            "127.0.0.1".to_string(),
            "GET".to_string(),
            "/phase3".to_string(),
        )
    }

    fn test_consumer() -> Consumer {
        Consumer {
            id: "phase3-consumer".to_string(),
            username: "phase3-user".to_string(),
            namespace: default_namespace(),
            custom_id: Some("phase3-custom".to_string()),
            credentials: HashMap::new(),
            acl_groups: Vec::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn assert_reject(result: PluginResult, expected_status_code: u16) {
        match result {
            PluginResult::Reject { status_code, .. } => {
                assert_eq!(status_code, expected_status_code);
            }
            other => panic!("expected reject result, got {other:?}"),
        }
    }
}
