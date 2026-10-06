//! Pure, generation-pinned preview of the route total deadline a request will
//! arm once `before_proxy` selects its `mesh_route_dispatch` rule (issue
//! #6008).
//!
//! Body-before-auth plugins (SOAP WS-Security, `hmac_auth`, `waf`) collect the
//! upload before `before_proxy` runs, so without a preview that collect is
//! bounded only by the read/RPC timeouts. The preview runs the compiled rule
//! matchers of the request's pinned plugin-cache generation. It never runs a
//! hook, publishes an override, or starts a gRPC attempt clock.
//!
//! When a rule cannot be decided yet (an earlier plugin may still rewrite an
//! input it matches on, or its trigger reads an identity that is not
//! established), the preview takes the MAXIMUM total among the rules that
//! could still be selected. If any of them would arm no total, there is no
//! early route bound and the read/RPC bounds apply as before. A request
//! answered before a total is published (a redirect, an unmatched `404`) arms
//! no total either, so it adds no candidate.

use std::sync::Arc;

use super::utils::query::{CanonicalQuery, canonical_query_for_policy};
use super::{Plugin, RequestContext};

/// What can still change before one `mesh_route_dispatch` instance evaluates
/// its rules. A rule that matches on a changing input cannot be decided early.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, Default)]
pub struct EarlyRouteTotalFacts {
    /// Authentication has run, so an identity-reading trigger is decidable.
    pub identity_ready: bool,
    /// An earlier plugin may rewrite request headers, Host included.
    pub headers_may_change: bool,
    /// An earlier plugin may rewrite the forwarded query.
    pub query_may_change: bool,
    /// An earlier plugin may rewrite the path or destination, or claim the
    /// request so this instance publishes nothing.
    pub destination_may_change: bool,
    /// An earlier undecided instance may have rewritten the forwarded Host.
    pub host_unknown: bool,
}

impl EarlyRouteTotalFacts {
    /// Whether any request input this instance reads may still change.
    pub fn inputs_may_change(self) -> bool {
        self.headers_may_change
            || self.query_may_change
            || self.destination_may_change
            || self.host_unknown
    }
}

/// The totals a set of possible rule selections would arm.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EarlyRouteCandidates {
    max_timeout_ms: u64,
    untimed: bool,
}

impl EarlyRouteCandidates {
    /// Record one possible selection; `None` or `Some(0)` arms no total.
    pub fn add(&mut self, timeout_ms: Option<u64>) {
        match timeout_ms.filter(|ms| *ms > 0) {
            Some(ms) => self.max_timeout_ms = self.max_timeout_ms.max(ms),
            None => self.untimed = true,
        }
    }

    fn merge(&mut self, other: Self) {
        self.max_timeout_ms = self.max_timeout_ms.max(other.max_timeout_ms);
        self.untimed |= other.untimed;
    }

    /// The candidate-max total, or `None` when a candidate arms no total (or
    /// every candidate answers before a total is published).
    pub fn bound_ms(self) -> Option<u64> {
        (!self.untimed && self.max_timeout_ms > 0).then_some(self.max_timeout_ms)
    }
}

/// One instance's preview.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EarlyRouteTotalStep<'a> {
    /// The instance publishes nothing; an earlier selection stays in force.
    NoMatch,
    /// A deterministic first match. `host` is the forwarded Host after it.
    Matched {
        timeout_ms: Option<u64>,
        host: Option<&'a str>,
    },
    /// The request is answered before any total is published.
    Terminal,
    /// The selection is undetermined: the totals of every rule that could
    /// still be selected, and whether the instance may publish nothing.
    Candidates {
        candidates: EarlyRouteCandidates,
        may_fall_through: bool,
    },
}

impl EarlyRouteTotalStep<'_> {
    /// The same preview for an instance that may not run at all (an
    /// undecided trigger, or a routing claim by an earlier plugin).
    pub fn or_skipped(self) -> Self {
        match self {
            Self::NoMatch => Self::NoMatch,
            Self::Matched { timeout_ms, .. } => {
                let mut candidates = EarlyRouteCandidates::default();
                candidates.add(timeout_ms);
                Self::Candidates {
                    candidates,
                    may_fall_through: true,
                }
            }
            Self::Terminal => Self::Candidates {
                candidates: EarlyRouteCandidates::default(),
                may_fall_through: true,
            },
            Self::Candidates { candidates, .. } => Self::Candidates {
                candidates,
                may_fall_through: true,
            },
        }
    }
}

struct PlanStep {
    plugin: Arc<dyn Plugin>,
    headers_may_change: bool,
    query_may_change: bool,
    destination_may_change: bool,
}

/// Compiled once per plugin-cache generation from the priority-ordered,
/// protocol-filtered chain. Requests scan no topology and take no lock.
#[derive(Default)]
pub(crate) struct EarlyRouteTotalPlan {
    steps: Vec<PlanStep>,
    needs_query: bool,
}

impl EarlyRouteTotalPlan {
    pub(crate) fn compile(plugins: &[Arc<dyn Plugin>]) -> Self {
        let mut steps = Vec::new();
        let (mut headers, mut query, mut destination) = (false, false, false);
        for plugin in plugins {
            if plugin.name() == "mesh_route_dispatch" {
                steps.push(PlanStep {
                    plugin: Arc::clone(plugin),
                    headers_may_change: headers,
                    query_may_change: query,
                    destination_may_change: destination,
                });
                continue;
            }
            let moves_destination = plugin.modifies_request_destination();
            headers |= plugin.modifies_request_headers() || moves_destination;
            query |= plugin.modifies_request_query() || moves_destination;
            destination |= moves_destination;
        }
        let needs_query = steps
            .iter()
            .any(|step| step.plugin.requires_decoded_query_params());
        Self { steps, needs_query }
    }

    /// The route total, in milliseconds from receipt, this request will arm
    /// (or, when undetermined, the maximum it could arm). `None` keeps the
    /// read/RPC bounds alone.
    pub(crate) fn select_ms(&self, ctx: &RequestContext, identity_ready: bool) -> Option<u64> {
        if self.steps.is_empty() {
            return None;
        }
        let query: Option<CanonicalQuery> =
            self.needs_query.then(|| canonical_query_for_policy(ctx));
        let mut host = ctx.headers.get("host").map(String::as_str);
        let mut selected: Option<u64> = None;
        let mut undetermined: Option<EarlyRouteCandidates> = None;
        for step in &self.steps {
            let facts = EarlyRouteTotalFacts {
                identity_ready,
                headers_may_change: step.headers_may_change,
                query_may_change: step.query_may_change,
                destination_may_change: step.destination_may_change,
                host_unknown: undetermined.is_some(),
            };
            let plugin = &step.plugin;
            // A selector this preview cannot model keeps today's bounds.
            match plugin.early_route_total(ctx, host, query.as_ref(), facts)? {
                EarlyRouteTotalStep::NoMatch => {}
                EarlyRouteTotalStep::Matched {
                    timeout_ms,
                    host: next,
                } => {
                    // A definite match replaces every earlier possibility,
                    // including a later untimed rule clearing an earlier total.
                    selected = timeout_ms.filter(|ms| *ms > 0);
                    host = next;
                    undetermined = None;
                }
                EarlyRouteTotalStep::Terminal => return None,
                EarlyRouteTotalStep::Candidates {
                    mut candidates,
                    may_fall_through,
                } => {
                    if may_fall_through {
                        match undetermined {
                            Some(prior) => candidates.merge(prior),
                            None => candidates.add(selected),
                        }
                    }
                    undetermined = Some(candidates);
                }
            }
        }
        match undetermined {
            Some(candidates) => candidates.bound_ms(),
            None => selected,
        }
    }
}
