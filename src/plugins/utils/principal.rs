//! The caller principal behind Consumer-scoped policy and per-caller limiter
//! state (GHSA-rxwj-x6c6-f4j5).
//!
//! A gateway **Consumer** and an unmapped **external principal** (a
//! `jwks_auth` / `oidc_relying_party` / `oauth2_introspection` / `ldap_auth` /
//! `soap_ws_security` identity) live in different namespaces (issue #6082).
//! `RequestContext::effective_identity()` collapses both into one display
//! string, so anything that grants something by Consumer username, or keys
//! shared state by caller, must not use it as a key:
//!
//! - A list configured as **Consumer usernames** (WAF `consumers`,
//!   `openapi_validator` `bypass.consumers`, `rate_limiting` `scope: consumers`,
//!   `ai_rate_limiter` `consumer_limits`, the trigger `consumer` predicate)
//!   matches only a mapped Consumer: use [`consumer_username`]. An external
//!   principal whose identity string equals a privileged Consumer's username
//!   gains nothing, exactly as `access_control` already guarantees.
//! - Per-caller limiter state is keyed by [`Principal::push_key`], which keeps
//!   the two namespaces disjoint (`consumer:<username>` versus
//!   `external:<mechanism>:<authority>:<identity>`) and binds an external
//!   identity to the realm that verified it, so two authorities that issue the
//!   same subject never share a bucket.

use crate::plugins::utils::auth_flow::ExternalIdentityRealm;
use crate::plugins::{RequestContext, StreamConnectionContext, meaningful_identity};

/// Prefix of a mapped Consumer's limiter key.
pub const CONSUMER_KEY_PREFIX: &str = "consumer:";
/// Prefix of an unmapped external principal's limiter key.
pub const EXTERNAL_KEY_PREFIX: &str = "external:";
/// Placeholder for an absent realm component in an external key. Neither a
/// compiled-in mechanism name nor a lowercase-hex authority digest can equal
/// it.
const ABSENT_REALM_COMPONENT: &str = "-";

/// The mapped gateway Consumer's username, never an unmapped external identity.
pub fn consumer_username(ctx: &RequestContext) -> Option<&str> {
    ctx.identified_consumer
        .as_ref()
        .map(|consumer| consumer.username.as_str())
}

/// [`consumer_username`] for a stream connection.
pub fn stream_consumer_username(ctx: &StreamConnectionContext) -> Option<&str> {
    ctx.identified_consumer
        .as_ref()
        .map(|consumer| consumer.username.as_str())
}

/// The unmapped external identity, only when no Consumer is mapped.
pub fn external_identity(ctx: &RequestContext) -> Option<&str> {
    if ctx.identified_consumer.is_some() {
        return None;
    }
    meaningful_identity(ctx.authenticated_identity.as_deref())
}

/// [`external_identity`] for a stream connection.
pub fn stream_external_identity(ctx: &StreamConnectionContext) -> Option<&str> {
    if ctx.identified_consumer.is_some() {
        return None;
    }
    meaningful_identity(ctx.authenticated_identity.as_deref())
}

/// The authenticated caller, with the namespace it belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Principal<'a> {
    /// A mapped gateway Consumer, by username.
    Consumer(&'a str),
    /// An unmapped external principal and the realm that verified it. The
    /// realm is `None` only when the identity was not committed through the
    /// authentication boundary (for example a custom plugin writing
    /// `authenticated_identity` directly, or a stream connection, which
    /// carries no realm).
    External {
        identity: &'a str,
        realm: Option<ExternalIdentityRealm>,
    },
}

impl<'a> Principal<'a> {
    /// The principal of an HTTP-family request: its mapped Consumer, else its
    /// external identity with the committed realm.
    pub fn of_request(ctx: &'a RequestContext) -> Option<Self> {
        if let Some(username) = consumer_username(ctx) {
            return Some(Self::Consumer(username));
        }
        external_identity(ctx).map(|identity| Self::External {
            identity,
            realm: ctx.authenticated_identity_realm(),
        })
    }

    /// The principal of a stream connection.
    pub fn of_stream(ctx: &'a StreamConnectionContext) -> Option<Self> {
        if let Some(username) = stream_consumer_username(ctx) {
            return Some(Self::Consumer(username));
        }
        stream_external_identity(ctx).map(|identity| Self::External {
            identity,
            realm: None,
        })
    }

    /// Append this principal's namespaced limiter key to `out`:
    /// `consumer:<username>` for a Consumer and
    /// `external:<mechanism|->:<authority-hex|->:<identity>` for an external
    /// principal. The mechanism is a compiled-in name and the authority is
    /// fixed-width hex, so neither contains `:` and the identity, which comes
    /// last, cannot forge another realm's key.
    pub fn push_key(&self, out: &mut String) {
        match self {
            Self::Consumer(username) => {
                out.reserve(CONSUMER_KEY_PREFIX.len() + username.len());
                out.push_str(CONSUMER_KEY_PREFIX);
                out.push_str(username);
            }
            Self::External { identity, realm } => {
                let mechanism = realm
                    .map(|realm| realm.mechanism())
                    .unwrap_or(ABSENT_REALM_COMPONENT);
                let authority = realm.and_then(|realm| realm.authority().map(hex::encode));
                let authority = authority.as_deref().unwrap_or(ABSENT_REALM_COMPONENT);
                out.reserve(
                    EXTERNAL_KEY_PREFIX.len()
                        + mechanism.len()
                        + authority.len()
                        + 2
                        + identity.len(),
                );
                out.push_str(EXTERNAL_KEY_PREFIX);
                out.push_str(mechanism);
                out.push(':');
                out.push_str(authority);
                out.push(':');
                out.push_str(identity);
            }
        }
    }

    /// [`Self::push_key`] into a new `String`.
    pub fn key(&self) -> String {
        let mut key = String::new();
        self.push_key(&mut key);
        key
    }
}
