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
//! A rule cannot be decided yet when a plugin may still rewrite an input it
//! matches on, or when its trigger reads an identity that is not established.
//! Plugins that can rewrite inputs before `before_proxy` (authentication,
//! authorization, body normalization, and every custom plugin) count whatever
//! their priority; other plugins count only when they run ahead of the
//! instance. For an undecided selection the preview takes the MAXIMUM total
//! among the rules that could still be selected. If any of them would arm no
//! total, there is no early route bound and the read/RPC bounds apply as
//! before. A request answered before a total is published arms no total, so
//! it adds no candidate: a redirect, a certain fault abort, a decided
//! waypoint veto, or the unmatched `404`.

use std::sync::Arc;

use super::utils::query::{CanonicalQuery, canonical_query_for_policy};
use super::{Plugin, RequestContext, is_builtin_plugin};

const MESH_ROUTE_DISPATCH: &str = "mesh_route_dispatch";
const FAULT_INJECTION: &str = "fault_injection";

/// Whether `plugin` is the built-in plugin `name`. The type decides trust, so
/// a custom plugin reporting `name` is not taken for the built-in (issue
/// #6022).
fn is_builtin(plugin: &(dyn Plugin + 'static), name: &str) -> bool {
    plugin.name() == name && is_builtin_plugin(plugin)
}

/// The request headers a plugin may still rewrite before one
/// `mesh_route_dispatch` instance evaluates its rules.
#[doc(hidden)]
#[derive(Debug, Clone, Default)]
pub struct EarlyHeaderChanges {
    /// Any header may change.
    any: bool,
    /// Otherwise, the lower-case names that may change.
    names: Vec<String>,
}

impl EarlyHeaderChanges {
    /// Whether the header `name` may still change.
    pub fn may_change(&self, name: &str) -> bool {
        let named = |known: &String| known.eq_ignore_ascii_case(name);
        self.any || self.names.iter().any(named)
    }

    /// Whether no header may change.
    pub fn is_empty(&self) -> bool {
        !self.any && self.names.is_empty()
    }

    fn record_any(&mut self) {
        self.any = true;
        self.names = Vec::new();
    }

    fn record(&mut self, names: Option<Vec<String>>) {
        if self.any {
            return;
        }
        let Some(names) = names else {
            self.record_any();
            return;
        };
        for name in names {
            let name = name.to_ascii_lowercase();
            if !self.names.contains(&name) {
                self.names.push(name);
            }
        }
    }
}

/// What can still change before one `mesh_route_dispatch` instance evaluates
/// its rules. A rule that matches on a changing input cannot be decided early.
#[doc(hidden)]
#[derive(Debug, Clone, Copy)]
pub struct EarlyRouteTotalFacts<'a> {
    /// Authentication has run, so an identity-reading trigger is decidable.
    pub identity_ready: bool,
    /// The request headers, Host included, a plugin may still rewrite.
    pub headers: &'a EarlyHeaderChanges,
    /// A plugin may still rewrite the forwarded query.
    pub query_may_change: bool,
    /// A plugin may still rewrite the path or destination, or claim the
    /// request so this instance publishes nothing.
    pub destination_may_change: bool,
    /// An earlier undecided instance may have rewritten the forwarded Host.
    pub host_unknown: bool,
    /// A `fault_injection` instance, or an earlier instance with a rule
    /// fault, runs ahead of this one. When it injects, a route rule's own
    /// fault stands down, so no rule's abort is certain.
    pub route_faults_may_be_preempted: bool,
}

impl EarlyRouteTotalFacts<'_> {
    /// Whether any request input this instance reads may still change.
    pub fn inputs_may_change(self) -> bool {
        !self.headers.is_empty()
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
    /// no candidate reaches a backend at all).
    pub fn bound_ms(self) -> Option<u64> {
        (!self.untimed && self.max_timeout_ms > 0).then_some(self.max_timeout_ms)
    }
}

/// One instance's preview.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EarlyRouteTotalStep<'a> {
    /// The instance publishes nothing; an earlier selection stays in force.
    /// `stages_unmatched`: it definitely ran, matched no rule, and staged the
    /// deferred unmatched `404` for the cache's finalizer.
    NoMatch { stages_unmatched: bool },
    /// A deterministic first match. `host` is the forwarded Host after it.
    Matched {
        timeout_ms: Option<u64>,
        host: Option<&'a str>,
    },
    /// The request is answered here before any total is published.
    Terminal,
    /// The selection is undetermined: the totals of every rule that could
    /// still be selected, whether the instance may publish nothing, and
    /// whether that fall-through definitely stages the unmatched `404`.
    Candidates {
        candidates: EarlyRouteCandidates,
        may_fall_through: bool,
        stages_unmatched: bool,
    },
}

impl EarlyRouteTotalStep<'_> {
    /// The same preview for an instance that may not run at all (an
    /// undecided trigger, or a routing claim by another plugin). A skipped
    /// instance stages nothing.
    pub fn or_skipped(self) -> Self {
        let candidates = match self {
            Self::NoMatch { .. } => {
                return Self::NoMatch {
                    stages_unmatched: false,
                };
            }
            Self::Matched { timeout_ms, .. } => {
                let mut candidates = EarlyRouteCandidates::default();
                candidates.add(timeout_ms);
                candidates
            }
            Self::Terminal => EarlyRouteCandidates::default(),
            Self::Candidates { candidates, .. } => candidates,
        };
        Self::Candidates {
            candidates,
            may_fall_through: true,
            stages_unmatched: false,
        }
    }
}

/// The request inputs plugins may rewrite before an instance runs.
#[derive(Debug, Clone, Default)]
struct InputChanges {
    headers: EarlyHeaderChanges,
    query: bool,
    destination: bool,
}

impl InputChanges {
    fn record(&mut self, plugin: &(dyn Plugin + 'static)) {
        let declared = is_builtin_plugin(plugin) || plugin.declares_request_input_mutations();
        if !declared {
            // A custom plugin that has not declared its request mutations
            // may rewrite any input in any phase.
            self.headers.record_any();
            self.query = true;
            self.destination = true;
            return;
        }
        let moves_destination = plugin.modifies_request_destination();
        if moves_destination {
            self.headers.record_any();
        } else if plugin.modifies_request_headers() {
            self.headers.record(plugin.modified_request_header_names());
        }
        self.query |= moves_destination || plugin.modifies_request_query();
        self.destination |= moves_destination;
    }
}

/// Whether `plugin` can rewrite request inputs from a hook that runs before
/// `before_proxy` (`authenticate`, `authorize`, or the pre-`before_proxy` body
/// normalization), and so ahead of every instance whatever its priority. Every
/// custom plugin can, including one that reports a built-in name.
fn rewrites_inputs_before_before_proxy(plugin: &(dyn Plugin + 'static)) -> bool {
    !is_builtin_plugin(plugin)
        || plugin.is_auth_plugin()
        || plugin.normalizes_buffered_request_body_before_before_proxy()
}

/// The first custom plugin in `plugins` that has not declared its request
/// input mutations, when the chain also runs a `mesh_route_dispatch` instance
/// and collects a body before `before_proxy`. Such a plugin may rewrite any
/// routing input, so that body gets no early route bound.
pub(crate) fn undeclared_plugin_disabling_early_route_bound(
    plugins: &[Arc<dyn Plugin>],
) -> Option<&str> {
    let dispatches = plugins
        .iter()
        .any(|plugin| is_builtin(plugin.as_ref(), MESH_ROUTE_DISPATCH));
    let collects_early = plugins.iter().any(|plugin| {
        plugin.requires_request_body_before_before_proxy()
            || plugin.requires_request_body_before_authenticate()
            || plugin.requires_request_body_before_authorize()
    });
    if !dispatches || !collects_early {
        return None;
    }
    plugins
        .iter()
        .find(|plugin| {
            !is_builtin_plugin(plugin.as_ref()) && !plugin.declares_request_input_mutations()
        })
        .map(|plugin| plugin.name())
}

/// Whether the request may still be unmatched by every instance so far.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Unmatched {
    /// Some instance definitely matched or answered.
    Impossible,
    /// Unmatched so far, and nothing staged the deferred `404`.
    Open,
    /// Unmatched so far, and an instance definitely staged the `404`.
    Staged,
}

impl Unmatched {
    fn staged(self) -> Self {
        match self {
            Self::Open => Self::Staged,
            other => other,
        }
    }
}

struct PlanStep {
    plugin: Arc<dyn Plugin>,
    changes: InputChanges,
    route_faults_may_be_preempted: bool,
}

/// Compiled once per plugin-cache generation from the priority-ordered,
/// protocol-filtered chain. Requests scan no topology and take no lock.
#[derive(Default)]
pub(crate) struct EarlyRouteTotalPlan {
    steps: Vec<PlanStep>,
    needs_query: bool,
    /// A plugin may publish a route override before the unmatched finalizer
    /// runs, and the finalizer then lets an unmatched request through.
    unmatched_may_be_overridden: bool,
}

impl EarlyRouteTotalPlan {
    pub(crate) fn compile(plugins: &[Arc<dyn Plugin>]) -> Self {
        // Rewrites before `before_proxy` reach every instance.
        let mut changes = InputChanges::default();
        for plugin in plugins {
            if rewrites_inputs_before_before_proxy(plugin.as_ref()) {
                changes.record(plugin.as_ref());
            }
        }
        // `before_proxy` rewrites reach only the instances after them.
        let mut steps = Vec::new();
        let mut route_faults_may_be_preempted = false;
        for plugin in plugins {
            if is_builtin(plugin.as_ref(), MESH_ROUTE_DISPATCH) {
                steps.push(PlanStep {
                    plugin: Arc::clone(plugin),
                    changes: changes.clone(),
                    route_faults_may_be_preempted,
                });
                // A fault this instance's matched rule injects (a delay, or a
                // partial abort) marks the request, so a later instance's
                // rule fault stands down.
                route_faults_may_be_preempted |= plugin.may_inject_route_fault();
                continue;
            }
            changes.record(plugin.as_ref());
            // A custom plugin, whatever name it reports, may mark the request
            // `fault_injected` like the built-in `fault_injection` does.
            let custom = !is_builtin_plugin(plugin.as_ref());
            route_faults_may_be_preempted |= custom || plugin.name() == FAULT_INJECTION;
        }
        let needs_query = steps
            .iter()
            .any(|step| step.plugin.requires_decoded_query_params());
        // The unmatched finalizer runs right after the last instance.
        let overridable = steps.last().is_some_and(|step| step.changes.destination);
        Self {
            steps,
            needs_query,
            unmatched_may_be_overridden: overridable,
        }
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
        // The totals of the selections that may be in force so far.
        let mut selected = EarlyRouteCandidates::default();
        let mut unmatched = Unmatched::Open;
        // Exactly one outcome is possible so far, so `host` is known.
        let mut decided = true;
        for step in &self.steps {
            let facts = EarlyRouteTotalFacts {
                identity_ready,
                headers: &step.changes.headers,
                query_may_change: step.changes.query,
                destination_may_change: step.changes.destination,
                host_unknown: !decided,
                route_faults_may_be_preempted: step.route_faults_may_be_preempted,
            };
            let plugin = &step.plugin;
            // A selector this preview cannot model keeps today's bounds.
            match plugin.early_route_total(ctx, host, query.as_ref(), facts)? {
                EarlyRouteTotalStep::NoMatch { stages_unmatched } => {
                    if stages_unmatched {
                        unmatched = unmatched.staged();
                    }
                }
                EarlyRouteTotalStep::Matched {
                    timeout_ms,
                    host: next,
                } => {
                    // A definite match replaces every earlier possibility,
                    // including a later untimed rule clearing an earlier total.
                    selected = EarlyRouteCandidates::default();
                    selected.add(timeout_ms);
                    unmatched = Unmatched::Impossible;
                    host = next;
                    decided = true;
                }
                EarlyRouteTotalStep::Terminal => return None,
                EarlyRouteTotalStep::Candidates {
                    mut candidates,
                    may_fall_through,
                    stages_unmatched,
                } => {
                    if may_fall_through {
                        candidates.merge(selected);
                        if stages_unmatched {
                            unmatched = unmatched.staged();
                        }
                    } else {
                        unmatched = Unmatched::Impossible;
                    }
                    selected = candidates;
                    decided = false;
                }
            }
        }
        // A request no instance matched reaches the proxy's own backend with
        // no total, unless the finalizer answers it with the staged `404`.
        let unmatched_dispatches = match unmatched {
            Unmatched::Impossible => false,
            Unmatched::Open => true,
            Unmatched::Staged => self.unmatched_may_be_overridden || ctx.has_route_overrides(),
        };
        if unmatched_dispatches {
            selected.add(None);
        }
        selected.bound_ms()
    }
}
