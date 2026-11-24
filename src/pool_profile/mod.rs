//! Sampled pool acquisition diagnostics. No TLS attribution survives a poll.
//! Inclusive synchronous phase snapshots overlap; never sum them as CPU time.
pub mod schema;
mod store;

use std::cell::Cell;
use std::fmt::Write;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};
use std::time::Instant;

use pin_project_lite::pin_project;

pub use schema::{Event, Family, Phase, Purpose};
pub use store::{current_thread_counters, publish_current_thread, snapshot};

thread_local! {
    static ACTIVE: Cell<Option<usize>> = const { Cell::new(None) };
    static PROBES: Cell<u64> = const { Cell::new(0) };
}

fn active() -> Option<usize> {
    ACTIVE.try_with(Cell::get).ok().flatten()
}

fn add(group: usize, field: usize, amount: u64) {
    store::with_local(|local| local.add(group * schema::STRIDE + field, amount));
}

pub fn event(event: Event) {
    if let Some(group) = active() {
        add(group, event as usize, 1);
        if matches!(event, Event::Probe) {
            let _ = PROBES.try_with(|value| value.set(value.get().saturating_add(1)));
        }
    }
}

// Non-Send and private. Exists only inside a synchronous poll/closure.
struct PollScope {
    previous: Option<usize>,
    probes: u64,
    _thread_bound: PhantomData<Rc<()>>,
}

impl PollScope {
    fn enter(group: Option<usize>) -> Self {
        Self {
            previous: ACTIVE.with(|value| value.replace(group)),
            probes: PROBES.with(|value| value.replace(0)),
            _thread_bound: PhantomData,
        }
    }
}

impl Drop for PollScope {
    fn drop(&mut self) {
        ACTIVE.with(|value| value.set(self.previous));
        PROBES.with(|value| value.set(self.probes));
    }
}

fn nanos(duration: std::time::Duration) -> u64 {
    match u64::try_from(duration.as_nanos()) {
        Ok(value) => value,
        Err(_) => {
            store::with_local(|local| local.add(schema::OVERFLOW, 1));
            u64::MAX
        }
    }
}

/// Snapshot existing H1 process allocator counters on THIS thread. No new
/// allocator callback, global allocator, scope index or H1 meaning is added.
fn allocator_snapshot() -> [u64; 10] {
    let counters = crate::h1_profile::current_thread_counters();
    if counters[crate::h1_profile::schema::OVERFLOW] != 0 {
        store::with_local(|local| local.add(schema::OVERFLOW, 1));
    }
    std::array::from_fn(|i| counters[i])
}

pub fn measure<R>(phase: Phase, operation: impl FnOnce() -> R) -> R {
    let Some(group) = active() else {
        return operation();
    };
    let observer_start = Instant::now();
    let before = allocator_snapshot();
    let start = Instant::now();
    let result = operation();
    let elapsed = nanos(start.elapsed());
    let after = allocator_snapshot();
    let observer = nanos(observer_start.elapsed()).saturating_sub(elapsed);
    let base = schema::EVENTS.len() + phase as usize * schema::FIELDS.len();
    store::with_local(|local| {
        let base = group * schema::STRIDE + base;
        local.add(base, 1);
        local.add(base + 1, elapsed);
        local.add(base + 2, observer);
        for (i, (after, before)) in after.into_iter().zip(before).enumerate() {
            if let Some(delta) = after.checked_sub(before) {
                local.add(base + 3 + i, delta);
            } else {
                local.add(schema::OVERFLOW, 1);
            }
        }
    });
    result
}

pub fn readiness<T, E>(operation: impl FnOnce() -> Option<Result<T, E>>) -> Option<Result<T, E>> {
    let result = measure(Phase::Readiness, operation);
    event(match &result {
        Some(Ok(_)) => Event::Ready,
        Some(Err(_)) => Event::ReadinessError,
        None => Event::Pending,
    });
    result
}

/// Wrap an existing future without adding a readiness poll, wait or wakeup.
pub fn phase_future<F: Future>(phase: Phase, future: F) -> impl Future<Output = F::Output> {
    PhaseFuture {
        future: Some(future),
        phase,
    }
}

pin_project! {
    // An async fn taking F and then pin!(F) retains both the argument and the
    // pinned local in its state. Nested creation/fallback/acquisition wrappers
    // multiply large connection futures in unoptimized builds. Project one F
    // in place instead: each observer adds only fixed-size metadata, no heap.
    struct PhaseFuture<F> {
        #[pin]
        future: Option<F>,
        phase: Phase,
    }
}

impl<F: Future> Future for PhaseFuture<F> {
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();
        let Some(future) = this.future.as_mut().as_pin_mut() else {
            return Poll::Pending;
        };
        let result = measure(*this.phase, || future.poll(cx));
        if result.is_ready() {
            // Match async completion: drop the inner future now, even if the
            // caller keeps this completed wrapper alive. Pin::set drops in place.
            this.future.set(None);
        }
        result
    }
}

struct Acquisition {
    group: usize,
    start: Option<Instant>,
    complete: bool,
    probes: u64,
}

impl Acquisition {
    fn new(group: usize) -> Self {
        let mut sampled = false;
        store::with_local(|local| {
            let sequence = local.selections[group];
            sampled = sequence.is_multiple_of(schema::SAMPLE_EVERY);
            local.selections[group] = sequence.wrapping_add(1);
            local.add(group * schema::STRIDE + Event::Acquisitions as usize, 1);
        });
        let acquisition = Self {
            group,
            start: sampled.then(Instant::now),
            complete: false,
            probes: 0,
        };
        if sampled {
            add(group, Event::Sampled as usize, 1);
        }
        acquisition
    }
}

impl Drop for Acquisition {
    fn drop(&mut self) {
        if let Some(start) = self.start {
            add(self.group, Event::WallNs as usize, nanos(start.elapsed()));
            if !self.complete {
                add(self.group, Event::Cancelled as usize, 1);
            }
            let bucket = match self.probes {
                0 => 0,
                1 => 1,
                2..=4 => 2,
                5..=16 => 3,
                _ => 4,
            };
            let base = schema::EVENTS.len() + schema::PHASES.len() * schema::FIELDS.len();
            add(self.group, base + bucket, 1);
        }
    }
}

pub fn acquisition<T, E>(
    family: Family,
    purpose: Purpose,
    future: impl Future<Output = Result<T, E>>,
) -> impl Future<Output = Result<T, E>> {
    AcquisitionFuture {
        future: Some(future),
        group: family as usize * 2 + purpose as usize,
        acquisition: None,
    }
}

pin_project! {
    struct AcquisitionFuture<F> {
        // Field order also preserves cancellation: drop the inner future
        // before recording the acquisition's wall time and cancellation.
        #[pin]
        future: Option<F>,
        group: usize,
        acquisition: Option<Acquisition>,
    }
}

impl<T, E, F: Future<Output = Result<T, E>>> Future for AcquisitionFuture<F> {
    type Output = Result<T, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();
        let Some(future) = this.future.as_mut().as_pin_mut() else {
            return Poll::Pending;
        };
        // Selection belongs to the first poll's thread, not construction.
        // Dropping an unpolled acquisition must not consume a sample or count.
        let acquisition = this
            .acquisition
            .get_or_insert_with(|| Acquisition::new(*this.group));
        let sampled = acquisition.start.is_some();
        let result = {
            let _scope = PollScope::enter(sampled.then_some(*this.group));
            if sampled {
                measure(Phase::EmptyBracket, || ());
            }
            let result = measure(Phase::Poll, || future.poll(cx));
            event(if result.is_ready() {
                Event::PollReady
            } else {
                Event::PollPending
            });
            acquisition.probes = acquisition.probes.saturating_add(PROBES.with(Cell::get));
            result
        };
        if let Poll::Ready(result) = &result {
            acquisition.complete = true;
            if sampled {
                add(*this.group, Event::Completed as usize, 1);
                if result.is_err() {
                    add(*this.group, Event::Errors as usize, 1);
                }
            }
            // PollScope has already restored the caller's TLS context. Keep
            // inner destruction and terminal accounting outside that scope.
            this.future.set(None);
            drop(this.acquisition.take());
        }
        result
    }
}

/// Fixed integer-only fields appended to the existing authenticated /metrics.
pub fn render_prometheus() -> String {
    let snapshot = snapshot();
    let allocator = crate::h1_profile::snapshot();
    let mut text = String::new();
    for (name, value) in [
        ("schema", 1),
        ("sample_every", schema::SAMPLE_EVERY),
        ("pid", u64::from(std::process::id())),
        (
            "allocator_installed",
            u64::from(crate::h1_profile::allocator_installed()),
        ),
        ("registered_slots", snapshot.registered_slots),
        ("slot_capacity", store::THREAD_SLOTS as u64),
        ("missing_slots", snapshot.missing_slots),
        ("unpublished_events", snapshot.unpublished_events),
        ("lost_events", snapshot.lost_events),
        ("counter_overflow", snapshot.values[schema::OVERFLOW]),
        ("allocator_lost_events", allocator.lost_events),
        (
            "allocator_overflow",
            allocator.values[crate::h1_profile::schema::OVERFLOW],
        ),
    ] {
        let _ = writeln!(text, "ferrum_pool_profile_{name} {value}");
    }
    for (family, family_name) in schema::FAMILIES.iter().enumerate() {
        for (purpose, purpose_name) in schema::PURPOSES.iter().enumerate() {
            let mut index = (family * 2 + purpose) * schema::STRIDE;
            let prefix = format!("ferrum_pool_profile_{family_name}_{purpose_name}");
            for event in schema::EVENTS {
                let _ = writeln!(text, "{prefix}_{event} {}", snapshot.values[index]);
                index += 1;
            }
            for phase in schema::PHASES {
                for field in schema::FIELDS {
                    let _ = writeln!(text, "{prefix}_{phase}_{field} {}", snapshot.values[index]);
                    index += 1;
                }
            }
            for bucket in schema::PROBES {
                let _ = writeln!(text, "{prefix}_{bucket} {}", snapshot.values[index]);
                index += 1;
            }
        }
    }
    text
}
