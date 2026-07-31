//! Shared status-planning work budget and fair window selection (#2397).
//!
//! The Gateway API reconciler historically planned status for every
//! status-bearing object and only then truncated writes to 256. That bounded
//! API traffic but not CPU or allocation. Callers select a deterministic
//! rotating window *before* expensive per-object translation/status work so
//! the same cap bounds both.
//!
//! All eligible Gateway API status kinds (including GatewayClass and Gateway)
//! share this deterministic window — planning itself, especially attached-route
//! counts, can be expensive — so every candidate enters the window within at
//! most `ceil(eligible_candidates / limit)` successful planning/patch rounds
//! for a stable candidate set.

/// Default per-reconcile status planning / write budget (Gateway API).
pub const DEFAULT_STATUS_PLAN_WORK_BUDGET: usize = 256;

/// Fair, deterministic work budget for one status-planning pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusPlanBudget {
    /// Maximum number of eligible candidates that may receive expensive
    /// per-object status computation in this pass.
    pub limit: usize,
    /// Rotating cursor advanced across reconciles so every candidate
    /// eventually enters the window.
    pub cursor: usize,
}

impl Default for StatusPlanBudget {
    fn default() -> Self {
        Self {
            limit: DEFAULT_STATUS_PLAN_WORK_BUDGET,
            cursor: 0,
        }
    }
}

impl StatusPlanBudget {
    pub fn new(limit: usize, cursor: usize) -> Self {
        Self { limit, cursor }
    }

    /// Unlimited budget (tests / callers that must plan the full snapshot).
    pub fn unlimited(cursor: usize) -> Self {
        Self {
            limit: usize::MAX,
            cursor,
        }
    }
}

/// Result of selecting a fair work window over a sorted candidate list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FairWorkWindow {
    /// Index into `candidates` where this pass starts (`cursor % len`).
    pub start: usize,
    /// Number of candidates to process (≤ `min(limit, len)`).
    pub take: usize,
    /// Cursor to persist for the next reconcile.
    pub next_cursor: usize,
}

/// Select a rotating window over `candidate_len` sorted candidates.
///
/// `candidates` must already be in deterministic order. The window starts at
/// `cursor % len` and covers up to `limit` entries, wrapping once when needed.
/// When `limit >= len`, the entire set is selected and the cursor advances by
/// `len` so the next pass still rotates relative to a growing set.
pub fn select_fair_work_window(candidate_len: usize, budget: StatusPlanBudget) -> FairWorkWindow {
    if candidate_len == 0 || budget.limit == 0 {
        return FairWorkWindow {
            start: 0,
            take: 0,
            next_cursor: budget.cursor,
        };
    }
    let start = budget.cursor % candidate_len;
    let take = budget.limit.min(candidate_len);
    let next_cursor = budget.cursor.saturating_add(take);
    FairWorkWindow {
        start,
        take,
        next_cursor,
    }
}

/// Iterate `candidates` in fair-window order (wraps at the end of the slice).
///
/// Clamps `take` to `candidates.len()` so a manually constructed inconsistent
/// [`FairWorkWindow`] (for example `take > 0` with an empty slice, or
/// `take > len`) cannot panic on modulo-by-zero or walk past the slice.
pub fn fair_work_window_iter<T>(
    candidates: &[T],
    window: FairWorkWindow,
) -> impl Iterator<Item = (usize, &T)> + '_ {
    let take = window.take.min(candidates.len());
    (0..take).map(move |offset| {
        let index = (window.start + offset) % candidates.len();
        (index, &candidates[index])
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_and_zero_budget_select_nothing() {
        assert_eq!(
            select_fair_work_window(0, StatusPlanBudget::new(256, 0)),
            FairWorkWindow {
                start: 0,
                take: 0,
                next_cursor: 0
            }
        );
        assert_eq!(
            select_fair_work_window(10, StatusPlanBudget::new(0, 3)),
            FairWorkWindow {
                start: 0,
                take: 0,
                next_cursor: 3
            }
        );
    }

    #[test]
    fn budget_smaller_than_set_rotates_deterministically() {
        let first = select_fair_work_window(5, StatusPlanBudget::new(2, 0));
        assert_eq!(
            first,
            FairWorkWindow {
                start: 0,
                take: 2,
                next_cursor: 2
            }
        );
        let second = select_fair_work_window(5, StatusPlanBudget::new(2, first.next_cursor));
        assert_eq!(
            second,
            FairWorkWindow {
                start: 2,
                take: 2,
                next_cursor: 4
            }
        );
        let third = select_fair_work_window(5, StatusPlanBudget::new(2, second.next_cursor));
        assert_eq!(
            third,
            FairWorkWindow {
                start: 4,
                take: 2,
                next_cursor: 6
            }
        );
        let names = ["a", "b", "c", "d", "e"];
        let third_names: Vec<&str> = fair_work_window_iter(&names, third)
            .map(|(_, name)| *name)
            .collect();
        assert_eq!(third_names, vec!["e", "a"]);
    }

    #[test]
    fn budget_at_boundary_covers_exact_set() {
        let window = select_fair_work_window(256, StatusPlanBudget::new(256, 0));
        assert_eq!(window.take, 256);
        assert_eq!(window.next_cursor, 256);
    }

    #[test]
    fn budget_above_set_covers_all_once() {
        let window = select_fair_work_window(10, StatusPlanBudget::new(256, 7));
        assert_eq!(
            window,
            FairWorkWindow {
                start: 7,
                take: 10,
                next_cursor: 17
            }
        );
        let items: Vec<usize> = (0..10).collect();
        let ordered: Vec<usize> = fair_work_window_iter(&items, window)
            .map(|(_, item)| *item)
            .collect();
        assert_eq!(ordered, vec![7, 8, 9, 0, 1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn inconsistent_empty_or_oversized_window_iter_does_not_panic() {
        let empty: [&str; 0] = [];
        let inconsistent_empty = FairWorkWindow {
            start: 3,
            take: 5,
            next_cursor: 8,
        };
        assert!(
            fair_work_window_iter(&empty, inconsistent_empty)
                .collect::<Vec<_>>()
                .is_empty()
        );

        let items = ["a", "b", "c"];
        let oversized = FairWorkWindow {
            start: 1,
            take: 10,
            next_cursor: 11,
        };
        let ordered: Vec<&str> = fair_work_window_iter(&items, oversized)
            .map(|(_, item)| *item)
            .collect();
        assert_eq!(ordered, vec!["b", "c", "a"]);
    }
}
