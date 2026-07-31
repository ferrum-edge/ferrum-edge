//! Cooldown gate + recovery state machine for proxy_alerts.
//!
//! - [`CooldownGate`] suppresses repeated dispatches per `(rule_id,
//!   proxy_id, ownership_generation, channel_id)`. Atomic CAS on a single
//!   `AtomicU64` per ownership key.
//! - [`RecoveryGate`] tracks per-`(rule_id, proxy_id, ownership_generation)`
//!   lifecycle so a rule that breaches and then recovers can dispatch a
//!   single resolve event.
//!
//! Both surfaces are infallible by design — they only return whether to
//! proceed; the caller's `tokio::spawn` does the actual dispatch.
//!
//! Rows are keyed by admission ownership generation so a stale write that
//! races past retain cannot populate or poison the replacement incarnation.
//! Per-proxy entries are retired when a proxy leaves a preserved global or
//! proxy-group instance, or when its published generation advances
//! ([`CooldownGate::retain_proxies`] / [`RecoveryGate::retain_proxies`]).
//! Expired cooldown / resolved recovery rows are swept by the plugin's
//! background eviction task.
//!
//! All timestamps here are process-monotonic milliseconds. Zero is reserved
//! for an unarmed cooldown. Defensive backward-discontinuity handling rebases
//! injected/test clocks instead of freezing elapsed-time state.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use dashmap::DashMap;

use super::generation_map::GenerationMap;
use crate::util::sharding::pool_shard_amount;

type CooldownKey = (u32, u32);
type CooldownGenerationMap = GenerationMap<Arc<AtomicU64>>;
type SharedCooldownGenerationMap = Arc<CooldownGenerationMap>;
type CooldownProxyMap = DashMap<String, SharedCooldownGenerationMap>;
type SharedCooldownProxyMap = Arc<CooldownProxyMap>;
type RecoveryGenerationMap = GenerationMap<RuleState>;
type SharedRecoveryGenerationMap = Arc<RecoveryGenerationMap>;
type RecoveryRuleMap = DashMap<String, SharedRecoveryGenerationMap>;
type SharedRecoveryRuleMap = Arc<RecoveryRuleMap>;

#[derive(Debug)]
pub struct CooldownGate {
    last_sent: DashMap<CooldownKey, SharedCooldownProxyMap>,
    inner_shard_amount: usize,
}

impl Default for CooldownGate {
    fn default() -> Self {
        Self::new()
    }
}

impl CooldownGate {
    pub fn new() -> Self {
        let shard_amount = pool_shard_amount(0);
        Self {
            last_sent: DashMap::with_shard_amount(shard_amount),
            inner_shard_amount: shard_amount,
        }
    }

    /// Returns `true` if the cooldown window has elapsed and the dispatch
    /// should proceed. On success the gate is rearmed atomically with the
    /// `now_ms` value.
    ///
    /// `ownership_generation` is the admission-time lifecycle generation
    /// (or [`super::UNARMED_PROXY_LIFECYCLE_GENERATION`] for offline tests).
    pub fn try_acquire(
        &self,
        rule_id: u32,
        proxy_id: &str,
        channel_id: u32,
        cooldown_ms: u64,
        now_ms: u64,
        ownership_generation: u64,
    ) -> bool {
        let per_proxy = if let Some(existing) = self.last_sent.get(&(rule_id, channel_id)) {
            Arc::clone(existing.value())
        } else {
            Arc::clone(
                self.last_sent
                    .entry((rule_id, channel_id))
                    .or_insert_with(|| {
                        Arc::new(DashMap::with_shard_amount(self.inner_shard_amount))
                    })
                    .value(),
            )
        };
        let per_generation = if let Some(existing) = per_proxy.get(proxy_id) {
            Arc::clone(existing.value())
        } else {
            Arc::clone(
                per_proxy
                    .entry(proxy_id.to_string())
                    .or_insert_with(|| Arc::new(GenerationMap::new()))
                    .value(),
            )
        };
        // Brief map lock for lookup/insert only; CAS below is lock-free.
        let atomic =
            per_generation.get_or_insert_with(ownership_generation, || Arc::new(AtomicU64::new(0)));
        let mut prev = atomic.load(Ordering::Acquire);
        loop {
            if prev != 0 {
                match now_ms.checked_sub(prev) {
                    Some(elapsed) if elapsed < cooldown_ms => return false,
                    Some(_) => {}
                    None => {
                        // A real monotonic clock never reaches this branch, but
                        // injected clocks must rebase instead of suppressing
                        // alerts until the old timestamp is reached again.
                    }
                }
            }
            match atomic.compare_exchange_weak(prev, now_ms, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return true,
                Err(p) => prev = p,
            }
        }
    }

    /// Clear a previously acquired cooldown so a failed delivery does not
    /// silently consume the window.
    ///
    /// The compare-and-swap is load-bearing: a slow delivery may settle after
    /// its cooldown elapsed and a newer dispatch rearmed the same slot. That
    /// stale settle must not clear the newer dispatch's reservation.
    pub fn release(
        &self,
        rule_id: u32,
        proxy_id: &str,
        channel_id: u32,
        ownership_generation: u64,
        reserved_at_ms: u64,
    ) {
        let Some(per_proxy) = self.last_sent.get(&(rule_id, channel_id)) else {
            return;
        };
        let Some(per_generation) = per_proxy.get(proxy_id) else {
            return;
        };
        if let Some(atomic) = per_generation.get_cloned(&ownership_generation) {
            let _ = atomic.compare_exchange(reserved_at_ms, 0, Ordering::AcqRel, Ordering::Acquire);
        }
    }

    /// Drop cooldown rows for proxies absent from `active_proxy_generations`
    /// or whose stored generation does not match the published incarnation.
    ///
    /// Cold-path only: called after incremental plugin-cache commit when a
    /// preserved global/proxy-group instance outlives individual proxies.
    pub fn retain_proxies(&self, active_proxy_generations: &HashMap<&str, u64>) {
        self.last_sent.retain(|_, per_proxy| {
            per_proxy.retain(|proxy_id, generations| {
                match active_proxy_generations.get(proxy_id.as_str()).copied() {
                    Some(active_gen) => {
                        generations.retain(|&generation, _| generation == active_gen);
                        !generations.is_empty()
                    }
                    None => false,
                }
            });
            !per_proxy.is_empty()
        });
    }

    /// Drop cooldown timestamps older than `keep_ms`.
    ///
    /// Entries whose last dispatch is still inside the keep window are
    /// retained so an in-flight cooldown continues to suppress duplicates.
    pub fn evict_stale(&self, now_ms: u64, keep_ms: u64) {
        let cutoff = now_ms.saturating_sub(keep_ms);
        self.last_sent.retain(|_, per_proxy| {
            per_proxy.retain(|_, generations| {
                generations.retain(|_, atomic| {
                    let ts = atomic.load(Ordering::Acquire);
                    ts == 0 || (ts <= now_ms && ts > cutoff)
                });
                !generations.is_empty()
            });
            !per_proxy.is_empty()
        });
    }

    /// Whether any `(rule, channel)` map currently holds a row for `proxy_id`
    /// under any ownership generation.
    #[allow(dead_code)] // Used by external test crate and admin/debug helpers.
    pub fn contains_proxy(&self, proxy_id: &str) -> bool {
        self.last_sent.iter().any(|entry| {
            entry
                .value()
                .get(proxy_id)
                .is_some_and(|generations| !generations.is_empty())
        })
    }

    /// Whether any `(rule, channel)` map holds a row for `(proxy_id, generation)`.
    #[allow(dead_code)] // Used by external test crate.
    pub fn contains_proxy_generation(&self, proxy_id: &str, ownership_generation: u64) -> bool {
        self.last_sent.iter().any(|entry| {
            entry
                .value()
                .get(proxy_id)
                .is_some_and(|generations| generations.contains_key(&ownership_generation))
        })
    }
}

/// Per-`(rule, proxy, generation)` lifecycle for recovery notifications.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleState {
    Healthy,
    /// Trigger accepted for dispatch but delivery has not settled yet.
    /// Suppresses duplicate Trigger admissions until success (→ Active) or
    /// failure/abandon (→ Healthy, cooldown released).
    PendingTrigger {
        reserved_at_ms: u64,
    },
    Active {
        fired_at_ms: u64,
    },
    Recovering {
        left_threshold_at_ms: u64,
    },
    /// Resolve accepted for dispatch but delivery has not settled yet.
    /// Suppresses duplicate Resolve admissions until success (→ Healthy) or
    /// failure/abandon (→ Recovering, so the next healthy sample can retry).
    PendingResolve {
        left_threshold_at_ms: u64,
        reserved_at_ms: u64,
    },
    /// The rule breached again while its Resolve was **already externally in
    /// flight** — the uncertain delivery boundary.
    ///
    /// The Resolve cannot be unsent, and cancelling or retiring its local
    /// future is not a rollback: the endpoint may have received it and marked
    /// the incident resolved. Returning straight to `Active` here (the previous
    /// behaviour) permanently suppressed the Trigger for a genuinely breached
    /// incident, because `Active` + `StillActive` never re-enters the
    /// `Trigger` transition.
    ///
    /// So the breach is *retained* instead: no notification is emitted yet (a
    /// Trigger dispatched now could overtake the in-flight Resolve and leave
    /// "resolved" as the operator's last view), and when the Resolve settles —
    /// success, failure, or abandonment alike — the state converges to
    /// [`RuleState::CompensatingTrigger`].
    ResolveInFlightRebreached {
        /// Reservation token of the Resolve that is still externally in flight.
        resolve_reserved_at_ms: u64,
        /// When the re-breach was observed.
        rebreached_at_ms: u64,
    },
    /// A Resolve that may have been delivered is now known to be stale: the
    /// incident is breached and owes the operator a Trigger.
    ///
    /// The next breaching observation emits that compensating Trigger (subject
    /// to the ordinary cooldown gate, so it stays bounded and never queues). If
    /// the rule is no longer breaching by then, the possibly-delivered Resolve
    /// already matches reality and the state falls back to `Healthy` with no
    /// phantom alert.
    CompensatingTrigger {
        rebreached_at_ms: u64,
    },
}

/// Outcome of evaluating a single observation against the recovery state
/// machine. The dispatch loop translates this into zero or one notification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleOutcome {
    /// Healthy → PendingTrigger. Caller should dispatch a `Trigger` notification
    /// (subject to cooldown).
    Trigger,
    /// Active → Active. Caller MAY dispatch a re-trigger if its cooldown
    /// allows; this is informational so the cooldown gate stays the source
    /// of truth.
    StillActive,
    /// Active → Recovering. No notification.
    EnteringRecovery,
    /// Recovering → PendingResolve. Caller should dispatch a `Resolve`
    /// notification (no cooldown applies — recovery events are always one-shot).
    Resolve,
    /// Re-breach while the incident was recovering or while its Resolve was
    /// externally in flight. No notification is emitted on this transition
    /// itself — either the rule is still considered alerting (`Recovering` →
    /// `Active`), or a compensating Trigger is being retained until the
    /// in-flight Resolve settles (`PendingResolve` →
    /// [`RuleState::ResolveInFlightRebreached`]).
    Reactivate,
    /// No transition; the rule remains in its prior state.
    Quiet,
}

#[derive(Debug)]
pub struct RecoveryGate {
    state: DashMap<u32, SharedRecoveryRuleMap>,
    inner_shard_amount: usize,
}

impl Default for RecoveryGate {
    fn default() -> Self {
        Self::new()
    }
}

impl RecoveryGate {
    pub fn new() -> Self {
        let shard_amount = pool_shard_amount(0);
        Self {
            state: DashMap::with_shard_amount(shard_amount),
            inner_shard_amount: shard_amount,
        }
    }

    /// Advance the state machine for `(rule_id, proxy_id, ownership_generation)`
    /// based on whether the current observation is above threshold (`breach`).
    /// `recovery_ms` is the configured `resolved_window_seconds * 1000`; pass
    /// `0` for rules that opt out of recovery (in which case `Resolve` will
    /// never be returned).
    pub fn observe(
        &self,
        rule_id: u32,
        proxy_id: &str,
        breach: bool,
        recovery_ms: u64,
        now_ms: u64,
        ownership_generation: u64,
    ) -> LifecycleOutcome {
        let per_generation = self.per_proxy_generations(rule_id, proxy_id);
        per_generation.with_mut(
            ownership_generation,
            || RuleState::Healthy,
            |state| Self::transition(state, breach, recovery_ms, now_ms),
        )
    }

    /// Evaluate the next lifecycle outcome without committing a transition.
    ///
    /// Used by the dispatch path so Trigger/Resolve transitions can be
    /// committed only after at least one notification channel accepts the
    /// event. Non-notifying outcomes still use [`Self::observe`] directly.
    ///
    /// # Concurrency: deliberate TOCTOU + commit-or-drop
    ///
    /// `evaluate()` snapshots state and `observe()` commits the transition
    /// later, after dispatch permits + cooldowns are reserved. The dispatch
    /// loop in `mod.rs` gates the commit on the freshly-observed outcome
    /// still matching the originally-evaluated `event_action`; if the state
    /// shifted between evaluate and observe (high-frequency breach/recover
    /// oscillation, or a sibling worker racing the same rule/proxy), the
    /// dispatch is dropped rather than fired against stale reasoning.
    ///
    /// This is by design: under concurrent oscillation a missed alert is
    /// preferable to a phantom alert. Holding evaluate+commit across the
    /// dispatch reservation would extend generation-map contention into
    /// channel/permit work and is intentionally avoided.
    pub fn evaluate(
        &self,
        rule_id: u32,
        proxy_id: &str,
        breach: bool,
        recovery_ms: u64,
        now_ms: u64,
        ownership_generation: u64,
    ) -> LifecycleOutcome {
        let state = self
            .state
            .get(&rule_id)
            .and_then(|per_rule| {
                per_rule
                    .get(proxy_id)
                    .and_then(|generations| generations.get_copied(&ownership_generation))
            })
            .unwrap_or(RuleState::Healthy);
        let mut state = state;
        Self::transition(&mut state, breach, recovery_ms, now_ms)
    }

    fn per_proxy_generations(&self, rule_id: u32, proxy_id: &str) -> SharedRecoveryGenerationMap {
        let per_rule = self.per_rule(rule_id);
        if let Some(existing) = per_rule.get(proxy_id) {
            Arc::clone(existing.value())
        } else {
            Arc::clone(
                per_rule
                    .entry(proxy_id.to_string())
                    .or_insert_with(|| Arc::new(GenerationMap::new()))
                    .value(),
            )
        }
    }

    fn per_rule(&self, rule_id: u32) -> SharedRecoveryRuleMap {
        if let Some(existing) = self.state.get(&rule_id) {
            Arc::clone(existing.value())
        } else {
            Arc::clone(
                self.state
                    .entry(rule_id)
                    .or_insert_with(|| {
                        Arc::new(DashMap::with_shard_amount(self.inner_shard_amount))
                    })
                    .value(),
            )
        }
    }

    fn transition(
        state: &mut RuleState,
        breach: bool,
        recovery_ms: u64,
        now_ms: u64,
    ) -> LifecycleOutcome {
        match (*state, breach) {
            (RuleState::Healthy, true) => {
                *state = RuleState::PendingTrigger {
                    reserved_at_ms: now_ms,
                };
                LifecycleOutcome::Trigger
            }
            (RuleState::Healthy, false) => LifecycleOutcome::Quiet,
            // PendingTrigger holds the seat until delivery settles. A continued
            // breach stays quiet (no duplicate dispatch); a clear while pending
            // stays pending so a late success still lands on Active, and a late
            // failure rolls back to Healthy via [`Self::settle_trigger`].
            (RuleState::PendingTrigger { .. }, _) => LifecycleOutcome::Quiet,
            (RuleState::Active { .. }, true) => LifecycleOutcome::StillActive,
            (RuleState::Active { .. }, false) if recovery_ms == 0 => {
                *state = RuleState::Healthy;
                LifecycleOutcome::Quiet
            }
            (RuleState::Active { .. }, false) => {
                *state = RuleState::Recovering {
                    left_threshold_at_ms: now_ms,
                };
                LifecycleOutcome::EnteringRecovery
            }
            (
                RuleState::Recovering {
                    left_threshold_at_ms,
                },
                false,
            ) => {
                if recovery_ms == 0 {
                    *state = RuleState::Healthy;
                    LifecycleOutcome::Quiet
                } else if let Some(elapsed) = now_ms.checked_sub(left_threshold_at_ms) {
                    if elapsed >= recovery_ms {
                        *state = RuleState::PendingResolve {
                            left_threshold_at_ms,
                            reserved_at_ms: now_ms,
                        };
                        LifecycleOutcome::Resolve
                    } else {
                        LifecycleOutcome::Quiet
                    }
                } else {
                    // Rebase a defensive/injected backward discontinuity so
                    // recovery accrues from the new monotonic epoch.
                    *state = RuleState::Recovering {
                        left_threshold_at_ms: now_ms,
                    };
                    LifecycleOutcome::Quiet
                }
            }
            (RuleState::Recovering { .. }, true) if recovery_ms == 0 => {
                *state = RuleState::PendingTrigger {
                    reserved_at_ms: now_ms,
                };
                LifecycleOutcome::Trigger
            }
            (RuleState::Recovering { .. }, true) => {
                *state = RuleState::Active {
                    fired_at_ms: now_ms,
                };
                LifecycleOutcome::Reactivate
            }
            // PendingResolve holds the seat until delivery settles.
            (RuleState::PendingResolve { reserved_at_ms, .. }, true) => {
                // Re-breach while the Resolve is externally in flight. The
                // Resolve may already have been delivered, so this is NOT a
                // rollback to Active: retain the re-breach against the
                // outstanding reservation token and let the settle converge to
                // a compensating Trigger. Emitting a Trigger right now could
                // overtake the in-flight Resolve on the wire and leave the
                // operator's last view as "resolved".
                *state = RuleState::ResolveInFlightRebreached {
                    resolve_reserved_at_ms: reserved_at_ms,
                    rebreached_at_ms: now_ms,
                };
                LifecycleOutcome::Reactivate
            }
            (RuleState::PendingResolve { .. }, false) => LifecycleOutcome::Quiet,
            // Waiting for the in-flight Resolve to settle. Further samples in
            // either direction change nothing: the compensating decision is
            // owned by the settle, which cannot be lost (a retired generation
            // still settles exactly once, as Abandoned).
            (RuleState::ResolveInFlightRebreached { .. }, _) => LifecycleOutcome::Quiet,
            // The compensating Trigger the possibly-delivered Resolve owes the
            // operator. Cooldown still applies, so this cannot storm; if the
            // gate suppresses it the state is left in place and the next
            // sample retries.
            (RuleState::CompensatingTrigger { .. }, true) => {
                *state = RuleState::PendingTrigger {
                    reserved_at_ms: now_ms,
                };
                LifecycleOutcome::Trigger
            }
            // No longer breaching: the possibly-delivered Resolve is now an
            // accurate description of reality, so no compensating Trigger is
            // owed and no phantom alert is emitted.
            (RuleState::CompensatingTrigger { .. }, false) => {
                *state = RuleState::Healthy;
                LifecycleOutcome::Quiet
            }
        }
    }

    /// Commit a successful Trigger delivery: PendingTrigger → Active.
    ///
    /// No-op when the state is no longer PendingTrigger (e.g. retired
    /// generation or a concurrent Reactivate path).
    pub fn settle_trigger_success(
        &self,
        rule_id: u32,
        proxy_id: &str,
        ownership_generation: u64,
        reserved_at_ms: u64,
        fired_at_ms: u64,
    ) {
        let per_generation = self.per_proxy_generations(rule_id, proxy_id);
        let _ = per_generation.with_mut(
            ownership_generation,
            || RuleState::Healthy,
            |state| {
                if matches!(
                    state,
                    RuleState::PendingTrigger {
                        reserved_at_ms: current,
                    } if *current == reserved_at_ms
                ) {
                    *state = RuleState::Active { fired_at_ms };
                }
                LifecycleOutcome::Quiet
            },
        );
    }

    /// Roll back a failed/abandoned Trigger: PendingTrigger → Healthy.
    pub fn settle_trigger_failure(
        &self,
        rule_id: u32,
        proxy_id: &str,
        ownership_generation: u64,
        reserved_at_ms: u64,
    ) {
        let per_generation = self.per_proxy_generations(rule_id, proxy_id);
        let _ = per_generation.with_mut(
            ownership_generation,
            || RuleState::Healthy,
            |state| {
                if matches!(
                    state,
                    RuleState::PendingTrigger {
                        reserved_at_ms: current,
                    } if *current == reserved_at_ms
                ) {
                    *state = RuleState::Healthy;
                }
                LifecycleOutcome::Quiet
            },
        );
    }

    /// Roll back a Trigger/Resolve reservation that `observe` committed on a
    /// path that never admitted delivery (non-event evaluate → commit).
    ///
    /// The evaluate/permit/observe split can race: a non-event snapshot (e.g.
    /// `PendingResolve` + breach → [`LifecycleOutcome::Reactivate`]) may see
    /// its outstanding resolve settle to `Healthy` before the matching
    /// `observe` runs, so the commit installs `PendingTrigger`/`PendingResolve`
    /// instead. Leaving that seat without a dispatch permit orphans it forever.
    ///
    /// `reserved_at_ms` must be the `now_ms` passed to the `observe` that
    /// produced `committed`. Only event-reserving outcomes are rolled back, and
    /// only via the token-matched failure settlers so a newer reservation
    /// cannot be damaged. [`LifecycleOutcome::StillActive`] and other
    /// non-reserving outcomes are no-ops.
    pub fn rollback_unadmitted_reservation(
        &self,
        rule_id: u32,
        proxy_id: &str,
        ownership_generation: u64,
        committed: LifecycleOutcome,
        reserved_at_ms: u64,
    ) {
        match committed {
            LifecycleOutcome::Trigger => {
                self.settle_trigger_failure(
                    rule_id,
                    proxy_id,
                    ownership_generation,
                    reserved_at_ms,
                );
            }
            LifecycleOutcome::Resolve => {
                let Some(RuleState::PendingResolve {
                    left_threshold_at_ms,
                    reserved_at_ms: current,
                }) = self.current_state(rule_id, proxy_id, ownership_generation)
                else {
                    return;
                };
                if current != reserved_at_ms {
                    return;
                }
                self.settle_resolve_failure(
                    rule_id,
                    proxy_id,
                    ownership_generation,
                    left_threshold_at_ms,
                    reserved_at_ms,
                );
            }
            LifecycleOutcome::StillActive
            | LifecycleOutcome::EnteringRecovery
            | LifecycleOutcome::Reactivate
            | LifecycleOutcome::Quiet => {}
        }
    }

    /// Commit a successful Resolve delivery: PendingResolve → Healthy.
    ///
    /// If the incident re-breached while this Resolve was in flight
    /// ([`RuleState::ResolveInFlightRebreached`] carrying this reservation
    /// token), the incident is genuinely alerting again and the delivered
    /// Resolve is stale — converge to [`RuleState::CompensatingTrigger`] so the
    /// next breaching sample re-alerts instead of being suppressed forever.
    pub fn settle_resolve_success(
        &self,
        rule_id: u32,
        proxy_id: &str,
        ownership_generation: u64,
        reserved_at_ms: u64,
    ) {
        self.settle_resolve(
            rule_id,
            proxy_id,
            ownership_generation,
            reserved_at_ms,
            None,
        );
    }

    /// Roll back a failed/abandoned Resolve: PendingResolve → Recovering.
    ///
    /// A re-breach observed while the Resolve was in flight converges to
    /// [`RuleState::CompensatingTrigger`] here too, and deliberately so: a
    /// failed or abandoned Resolve is *not* proof the endpoint did not act.
    /// Transport timeouts, post-write connection errors, and cancellation after
    /// bytes left the process are all reported as failure/abandonment while the
    /// peer may have processed the notification. Treating that uncertain
    /// boundary as "possibly delivered" is the safe direction: the worst case is
    /// one extra Trigger for a genuinely breached incident, versus a silently
    /// suppressed alert.
    pub fn settle_resolve_failure(
        &self,
        rule_id: u32,
        proxy_id: &str,
        ownership_generation: u64,
        left_threshold_at_ms: u64,
        reserved_at_ms: u64,
    ) {
        self.settle_resolve(
            rule_id,
            proxy_id,
            ownership_generation,
            reserved_at_ms,
            Some(left_threshold_at_ms),
        );
    }

    /// Shared Resolve settle. `rollback_to_recovering_at` is `Some` for a
    /// failed/abandoned delivery and `None` for a success.
    ///
    /// Both variants are token-matched, so a stale settle from a superseded
    /// generation or a replaced reservation can never clear a newer row.
    fn settle_resolve(
        &self,
        rule_id: u32,
        proxy_id: &str,
        ownership_generation: u64,
        reserved_at_ms: u64,
        rollback_to_recovering_at: Option<u64>,
    ) {
        let per_generation = self.per_proxy_generations(rule_id, proxy_id);
        let _ = per_generation.with_mut(
            ownership_generation,
            || RuleState::Healthy,
            |state| {
                match *state {
                    RuleState::PendingResolve {
                        reserved_at_ms: current,
                        ..
                    } if current == reserved_at_ms => {
                        *state = match rollback_to_recovering_at {
                            Some(left_threshold_at_ms) => RuleState::Recovering {
                                left_threshold_at_ms,
                            },
                            None => RuleState::Healthy,
                        };
                    }
                    RuleState::ResolveInFlightRebreached {
                        resolve_reserved_at_ms,
                        rebreached_at_ms,
                    } if resolve_reserved_at_ms == reserved_at_ms => {
                        // Uncertain delivery + a real re-breach: owe a Trigger.
                        *state = RuleState::CompensatingTrigger { rebreached_at_ms };
                    }
                    _ => {}
                }
                LifecycleOutcome::Quiet
            },
        );
    }

    /// Returns the current state for the given (rule, proxy, generation)
    /// triple, or `None` if no observation has been recorded yet. Useful for
    /// tests and admin debugging.
    #[allow(dead_code)] // Used by external test crate and future admin debug surface.
    pub fn current_state(
        &self,
        rule_id: u32,
        proxy_id: &str,
        ownership_generation: u64,
    ) -> Option<RuleState> {
        self.state.get(&rule_id).and_then(|per_rule| {
            per_rule
                .get(proxy_id)
                .and_then(|generations| generations.get_copied(&ownership_generation))
        })
    }

    /// Drop recovery rows for proxies absent from `active_proxy_generations`
    /// or whose stored generation does not match the published incarnation.
    ///
    /// Cold-path only: called after incremental plugin-cache commit when a
    /// preserved global/proxy-group instance outlives individual proxies.
    pub fn retain_proxies(&self, active_proxy_generations: &HashMap<&str, u64>) {
        self.state.retain(|_, per_rule| {
            per_rule.retain(|proxy_id, generations| {
                match active_proxy_generations.get(proxy_id.as_str()).copied() {
                    Some(active_gen) => {
                        generations.retain(|&generation, _| generation == active_gen);
                        !generations.is_empty()
                    }
                    None => false,
                }
            });
            !per_rule.is_empty()
        });
    }

    /// Drop terminal `Healthy` rows left after a Resolve (or recovery-less
    /// reset). Active/Recovering incidents are owned by
    /// [`Self::retain_proxies`] so a long-lived breach is never TTL-reset
    /// while its proxy remains in the active set.
    pub fn evict_resolved(&self) {
        self.state.retain(|_, per_rule| {
            per_rule.retain(|_, generations| {
                generations.retain(|_, state| !matches!(*state, RuleState::Healthy));
                !generations.is_empty()
            });
            !per_rule.is_empty()
        });
    }

    /// Whether any rule map currently holds a row for `proxy_id` under any
    /// ownership generation.
    #[allow(dead_code)] // Used by external test crate and admin/debug helpers.
    pub fn contains_proxy(&self, proxy_id: &str) -> bool {
        self.state.iter().any(|entry| {
            entry
                .value()
                .get(proxy_id)
                .is_some_and(|generations| !generations.is_empty())
        })
    }

    /// Whether any rule map holds a row for `(proxy_id, generation)`.
    #[allow(dead_code)] // Used by external test crate.
    pub fn contains_proxy_generation(&self, proxy_id: &str, ownership_generation: u64) -> bool {
        self.state.iter().any(|entry| {
            entry
                .value()
                .get(proxy_id)
                .is_some_and(|generations| generations.contains_key(&ownership_generation))
        })
    }
}
