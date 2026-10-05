//! Pure, generation-pinned route selection for early retained uploads.
//!
//! No hook runs here. The private collector witness is never a routing override
//! and never arms a gRPC attempt. Unknown dependencies are explicit; see the
//! DRAFT supported-profile proposal in docs/early_upload_policy.md.

use std::collections::HashMap;
use std::sync::Arc;

use super::utils::query::canonical_query_for_policy;
use super::{Plugin, RequestContext};

/// Facts available at this collector boundary. Authorization is a distinct
/// phase from authentication; waypoint stamps may still be pending afterward.
#[doc(hidden)]
#[derive(Clone, Copy)]
pub struct EarlyRouteTotalFacts {
    pub identity_ready: bool,
    pub authorization_ready: bool,
    pub waypoint_authorization_pending: bool,
}

/// Pure projection supplied by an instance in the compiled effective chain.
#[doc(hidden)]
pub enum EarlyRouteTotalStep<'a> {
    NoMatch,
    Matched {
        timeout_ms: Option<u64>,
        host: Option<&'a str>,
    },
    /// A redirect, fault, query refusal or waypoint veto precedes publication.
    Terminal,
    Unresolved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EarlyRouteTotalSelection {
    NoMatch,
    Untimed,
    Timed(u64),
    Terminal,
    Unresolved,
}

/// Compiled once at reload from the effective scoped, priority-sorted,
/// protocol-filtered chain. Selectors, possible intervening mutations and
/// destination publishers survive; requests do no topology scan or locking.
#[derive(Default)]
pub(crate) struct EarlyRouteTotalPlan {
    steps: Vec<Arc<dyn Plugin>>,
    needs_query: bool,
    authorization_publishers: Vec<Arc<dyn Plugin>>,
}

impl EarlyRouteTotalPlan {
    pub(crate) fn compile(plugins: &[Arc<dyn Plugin>]) -> Self {
        let Some(last) = plugins
            .iter()
            .rposition(|p| p.name() == "mesh_route_dispatch")
        else {
            return Self::default();
        };
        let steps: Vec<_> = plugins
            .iter()
            .enumerate()
            .filter(|(index, p)| {
                p.early_route_total_participant()
                    && (*index <= last || p.modifies_request_destination())
            })
            .map(|(_, p)| Arc::clone(p))
            .collect();
        let needs_query = steps.iter().any(|p| p.requires_decoded_query_params());
        let authorization_publishers = plugins
            .iter()
            .filter(|p| p.may_publish_route_authorization())
            .map(Arc::clone)
            .collect();
        Self {
            steps,
            needs_query,
            authorization_publishers,
        }
    }

    pub(crate) fn select(
        &self,
        ctx: &RequestContext,
        headers: &HashMap<String, String>,
        identity_ready: bool,
        authorization_ready: bool,
    ) -> EarlyRouteTotalSelection {
        // This typed claim outranks mesh dispatch in the normal hook too.
        if ctx.has_ai_stream_router_claim() {
            return EarlyRouteTotalSelection::NoMatch;
        }
        let facts = EarlyRouteTotalFacts {
            identity_ready,
            authorization_ready,
            waypoint_authorization_pending: !authorization_ready
                && self
                    .authorization_publishers
                    .iter()
                    .any(|p| p.route_authorization_may_be_pending(ctx, identity_ready)),
        };
        let query = self.needs_query.then(|| canonical_query_for_policy(ctx));
        let mut host = headers.get("host").map(String::as_str);
        let mut selected = EarlyRouteTotalSelection::NoMatch;
        for plugin in &self.steps {
            match plugin.early_route_total(ctx, headers, host, query.as_ref(), facts) {
                EarlyRouteTotalStep::NoMatch => {}
                EarlyRouteTotalStep::Matched {
                    timeout_ms,
                    host: next,
                } => {
                    selected = match timeout_ms.filter(|ms| *ms > 0) {
                        Some(ms) => EarlyRouteTotalSelection::Timed(ms),
                        None => EarlyRouteTotalSelection::Untimed,
                    };
                    host = next;
                }
                EarlyRouteTotalStep::Terminal => return EarlyRouteTotalSelection::Terminal,
                EarlyRouteTotalStep::Unresolved => return EarlyRouteTotalSelection::Unresolved,
            }
        }
        selected
    }
}
