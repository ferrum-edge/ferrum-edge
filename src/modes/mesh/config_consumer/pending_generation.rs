//! Debounced pending-generation state machine shared by the Ferrum-private
//! (`xds`) and stock (`stock_xds`) ADS clients.
//!
//! An ADS client stages a complete, already-ACKed generation and commits it
//! when the debounce fires (`MeshStreamTimings::apply_debounce`, bounded by
//! `apply_max_delay`) or at a clean remote end of stream. Stream errors differ
//! per client: the `xds` client also commits the staged generation before it
//! surfaces any stream error (including a NACK-circuit-breaker trip), while the
//! `stock_xds` client drops it on every stream error and keeps only the
//! last-installed slice. The machine itself only decides WHAT is staged; each
//! caller decides when to feed it [`PendingGenerationEvent::Commit`].
//!
//! A generation is only ever staged once the client's own completeness gate
//! held at ACK time, so it is independent of any LATER response: a NACK's
//! rollback excludes only the NACKed response, and the staged generation
//! remains a coherent ACKed set (later ACKed responses that did not complete a
//! new set never re-staged). Discarding the staged generation on that NACK
//! would leave the data plane serving the previous generation while the control
//! plane holds ACKs for the staged one (state-of-the-world never resends after
//! an ACK), so [`PendingGenerationEvent::ResponseNacked`] retains it.
//!
//! Making the state an enum keeps the old `(pending, debounce_active,
//! pending_since)` triple from drifting into an unrepresentable combination
//! (an armed timer with nothing staged, or a staged slice with no first-staged
//! instant for the max-delay cap).

use tokio::time::Instant;

/// Whether a debounced generation is waiting to be committed.
#[derive(Debug)]
pub enum PendingGeneration<T> {
    /// Nothing staged; the debounce timer is disarmed.
    NoPending,
    /// A complete, ACKed generation waits for the debounce deadline.
    /// `first_staged_at` anchors the max-delay cap across superseding stages.
    Staged {
        generation: T,
        first_staged_at: Instant,
    },
}

/// One input to [`PendingGeneration::transition`].
#[derive(Debug)]
pub enum PendingGenerationEvent<T> {
    /// A newer complete generation was ACKed and built. It supersedes any
    /// staged one; the first-staged instant is kept so continuous churn cannot
    /// postpone the commit past the max-delay cap.
    Stage { generation: T, now: Instant },
    /// A response was NACKed and its accumulator change rolled back. The
    /// staged generation does not depend on the rejected response, so it is
    /// retained and the debounce stays armed at its existing deadline.
    ResponseNacked,
    /// Commit what is staged: the debounce fired, the remote ended the stream
    /// cleanly, or (`xds` only) the stream is failing and flushes what it
    /// already ACKed.
    Commit,
}

/// What the caller must do after one transition.
#[derive(Debug)]
pub enum PendingGenerationAction<T> {
    /// No externally visible effect.
    None,
    /// Re-arm the debounce timer. The caller computes the deadline from `now`
    /// and `first_staged_at` with its own debounce/max-delay constants.
    ArmDebounce {
        now: Instant,
        first_staged_at: Instant,
    },
    /// Apply this generation now. The state is already `NoPending`.
    Commit(T),
}

impl<T> PendingGeneration<T> {
    /// Whether the debounce timer should be polled.
    pub fn is_staged(&self) -> bool {
        matches!(self, Self::Staged { .. })
    }

    /// The staged generation, if any (observability and tests).
    pub fn staged(&self) -> Option<&T> {
        match self {
            Self::NoPending => None,
            Self::Staged { generation, .. } => Some(generation),
        }
    }

    /// The ONE transition function of the pending-generation machine.
    pub fn transition(&mut self, event: PendingGenerationEvent<T>) -> PendingGenerationAction<T> {
        let current = std::mem::replace(self, Self::NoPending);
        let (next, action) = match (current, event) {
            (Self::NoPending, PendingGenerationEvent::Stage { generation, now }) => (
                Self::Staged {
                    generation,
                    first_staged_at: now,
                },
                PendingGenerationAction::ArmDebounce {
                    now,
                    first_staged_at: now,
                },
            ),
            (
                Self::Staged {
                    first_staged_at, ..
                },
                PendingGenerationEvent::Stage { generation, now },
            ) => (
                Self::Staged {
                    generation,
                    first_staged_at,
                },
                PendingGenerationAction::ArmDebounce {
                    now,
                    first_staged_at,
                },
            ),
            (Self::NoPending, PendingGenerationEvent::ResponseNacked) => {
                (Self::NoPending, PendingGenerationAction::None)
            }
            (staged @ Self::Staged { .. }, PendingGenerationEvent::ResponseNacked) => {
                (staged, PendingGenerationAction::None)
            }
            (Self::NoPending, PendingGenerationEvent::Commit) => {
                (Self::NoPending, PendingGenerationAction::None)
            }
            (Self::Staged { generation, .. }, PendingGenerationEvent::Commit) => {
                (Self::NoPending, PendingGenerationAction::Commit(generation))
            }
        };
        *self = next;
        action
    }
}
