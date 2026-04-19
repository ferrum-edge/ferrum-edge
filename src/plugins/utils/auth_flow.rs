use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::debug;

use crate::config::types::Consumer;
use crate::consumer_index::ConsumerIndex;
use crate::plugins::{PluginResult, RequestContext};

/// What an auth plugin extracted from the request.
#[derive(Debug, Clone)]
pub enum ExtractedCredential {
    BearerToken(String),
    ApiKey(String),
    BasicAuth {
        username: String,
        password: String,
    },
    HmacAuth {
        username: String,
        algorithm: String,
        signature: String,
        date: String,
        method: String,
        path: String,
    },
    MtlsCert {
        der_bytes: Arc<Vec<u8>>,
        chain_der: Option<Arc<Vec<Vec<u8>>>>,
    },
    /// Extract failed before verification could run (bad header scheme,
    /// malformed base64, missing required companion header, etc.).
    InvalidFormat(String),
    /// No credential present — multi-auth can continue with the next plugin.
    Missing,
}

/// Shared auth verification result, mapped to PluginResult by the dispatcher.
#[derive(Debug, Clone)]
pub enum VerifyOutcome {
    Success {
        consumer: Option<Arc<Consumer>>,
        external_identity: Option<String>,
        external_identity_header: Option<String>,
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
        Self::Success {
            consumer,
            external_identity,
            external_identity_header,
        }
    }

    pub fn consumer(consumer: Arc<Consumer>) -> Self {
        Self::success(Some(consumer), None, None)
    }
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
    fn mechanism_name(&self) -> &str;

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
        ExtractedCredential::InvalidFormat(body) => reject(401, body),
        credential => match mechanism.verify(credential, consumer_index).await {
            VerifyOutcome::Success {
                consumer,
                external_identity,
                external_identity_header,
            } => {
                if let Some(consumer) = consumer
                    && ctx.identified_consumer.is_none()
                {
                    debug!(
                        "{}: identified consumer '{}'",
                        mechanism.mechanism_name(),
                        consumer.username
                    );
                    ctx.identified_consumer = Some(consumer);
                }

                if allow_external_identity {
                    if let Some(external_identity) = external_identity {
                        ctx.authenticated_identity = Some(external_identity);
                    }
                    if let Some(external_identity_header) = external_identity_header {
                        ctx.authenticated_identity_header = Some(external_identity_header);
                    }
                }

                PluginResult::Continue
            }
            VerifyOutcome::NotApplicable => PluginResult::Continue,
            VerifyOutcome::InvalidFormat(body)
            | VerifyOutcome::Invalid(body)
            | VerifyOutcome::ConsumerNotFound(body)
            | VerifyOutcome::VerificationFailed(body) => reject(401, body),
            VerifyOutcome::Forbidden(body) => reject(403, body),
            VerifyOutcome::Internal(body) => reject(500, body),
        },
    }
}

fn reject(status_code: u16, body: String) -> PluginResult {
    PluginResult::Reject {
        status_code,
        body,
        headers: HashMap::new(),
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
        AuthMechanism, ExtractedCredential, VerifyOutcome, constant_time_eq, run_auth,
        run_auth_external_identity,
    };
    use crate::config::types::{Consumer, default_namespace};
    use crate::consumer_index::ConsumerIndex;
    use crate::plugins::{PluginResult, RequestContext};
    use async_trait::async_trait;
    use chrono::Utc;
    use std::collections::HashMap;
    use std::sync::Arc;

    #[derive(Clone)]
    struct FakeMechanism {
        extracted: ExtractedCredential,
        outcome: VerifyOutcome,
    }

    #[async_trait]
    impl AuthMechanism for FakeMechanism {
        fn mechanism_name(&self) -> &str {
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
