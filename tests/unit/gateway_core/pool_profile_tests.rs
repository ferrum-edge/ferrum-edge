use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::future::{Future, poll_fn};
use std::marker::PhantomPinned;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};

use ferrum_edge::h1_profile::ForwardingAllocator;
use ferrum_edge::pool_profile::{self as profile, Event, Family, Phase, Purpose, schema};
use futures_util::task::noop_waker;

fn allocation() {
    let allocator = ForwardingAllocator(System);
    let layout = Layout::from_size_align(37, 8).unwrap();
    unsafe {
        let pointer = allocator.alloc(layout);
        assert!(!pointer.is_null());
        allocator.dealloc(pointer, layout);
    }
}

fn poll<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(&noop_waker()))
}

fn event_count(event: Event) -> u64 {
    profile::current_thread_counters()[event as usize]
}

#[test]
fn pool_profile_reports_allocator_installation_from_the_registered_flag() {
    // This test executable links the library but registers no forwarding
    // global allocator, so neither profile may claim allocator coverage
    // (issue #7191: the pool profile used to report `!cfg!(windows)`).
    assert!(!ferrum_edge::h1_profile::allocator_installed());
    assert!(
        profile::render_prometheus()
            .lines()
            .any(|line| line == "ferrum_pool_profile_allocator_installed 0")
    );
}

#[test]
fn pool_profile_nested_future_storage_has_only_fixed_overhead() {
    std::thread::spawn(|| {
        let before = profile::current_thread_counters();
        // Model the inline state of a connection future. Small ready/pending
        // futures cannot expose duplication of F in an async observer wrapper.
        let future = std::future::ready(Ok::<_, ()>([0u8; 16 * 1024]));
        let inner_bytes = std::mem::size_of_val(&future);
        let creation = profile::phase_future(Phase::CreationPoll, future);
        let creation_bytes = std::mem::size_of_val(&creation);
        assert!(
            creation_bytes <= inner_bytes + 64,
            "creation observer duplicated inner state: {inner_bytes} -> {creation_bytes}"
        );
        let fallback = profile::phase_future(Phase::FallbackPoll, creation);
        let fallback_bytes = std::mem::size_of_val(&fallback);
        assert!(
            fallback_bytes <= creation_bytes + 64,
            "fallback observer duplicated inner state: {creation_bytes} -> {fallback_bytes}"
        );
        let acquisition = profile::acquisition(Family::H2, Purpose::Request, fallback);
        let acquisition_bytes = std::mem::size_of_val(&acquisition);
        assert!(
            acquisition_bytes <= fallback_bytes + 128,
            "acquisition observer duplicated inner state: {fallback_bytes} -> {acquisition_bytes}"
        );
        // Construction and unpolled cancellation remain inert, including the
        // first-poll sampling sequence. No allocation is needed by the wrappers.
        assert_eq!(profile::current_thread_counters(), before);
        drop(acquisition);
        assert_eq!(profile::current_thread_counters(), before);
    })
    .join()
    .unwrap();
}

struct PinnedPendingThenError {
    address: Cell<Option<usize>>,
    polls: Arc<AtomicUsize>,
    drops: Arc<AtomicUsize>,
    _pinned: PhantomPinned,
}

impl Future for PinnedPendingThenError {
    type Output = Result<(), u8>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.as_ref().get_ref();
        let address = std::ptr::from_ref(this) as usize;
        if let Some(previous) = this.address.replace(Some(address)) {
            assert_eq!(address, previous, "observer moved a pinned inner future");
        }
        if this.polls.fetch_add(1, Ordering::Relaxed) == 0 {
            cx.waker().wake_by_ref();
            Poll::Pending
        } else {
            Poll::Ready(Err(17))
        }
    }
}

impl Drop for PinnedPendingThenError {
    fn drop(&mut self) {
        if let Some(address) = self.address.get() {
            assert_eq!(std::ptr::from_ref(self) as usize, address);
        }
        self.drops.fetch_add(1, Ordering::Relaxed);
    }
}

#[test]
fn pool_profile_projected_futures_preserve_pinning_and_terminal_drop() {
    for complete in [false, true] {
        std::thread::spawn(move || {
            let polls = Arc::new(AtomicUsize::new(0));
            let drops = Arc::new(AtomicUsize::new(0));
            let inner = PinnedPendingThenError {
                address: Cell::new(None),
                polls: polls.clone(),
                drops: drops.clone(),
                _pinned: PhantomPinned,
            };
            let mut future = Box::pin(profile::acquisition(
                Family::H2,
                Purpose::Request,
                profile::phase_future(
                    Phase::FallbackPoll,
                    profile::phase_future(Phase::CreationPoll, inner),
                ),
            ));
            assert!(poll(future.as_mut()).is_pending());
            assert_eq!(polls.load(Ordering::Relaxed), 1);
            assert_eq!(drops.load(Ordering::Relaxed), 0);
            let before = profile::current_thread_counters();
            profile::event(Event::WarmHit);
            assert_eq!(profile::current_thread_counters(), before);
            if complete {
                assert_eq!(poll(future.as_mut()), Poll::Ready(Err(17)));
                assert_eq!(polls.load(Ordering::Relaxed), 2);
                // The wrapper is still alive: Ready must already have dropped
                // its inner future and recorded completion, including errors.
                assert_eq!(drops.load(Ordering::Relaxed), 1);
                assert_eq!(event_count(Event::Completed), 1);
                assert_eq!(event_count(Event::Errors), 1);
                assert_eq!(event_count(Event::Cancelled), 0);
                let before = profile::current_thread_counters();
                profile::event(Event::WarmHit);
                assert_eq!(profile::current_thread_counters(), before);
                drop(future);
                assert_eq!(profile::current_thread_counters(), before);
            } else {
                drop(future);
                assert_eq!(event_count(Event::Cancelled), 1);
                assert_eq!(event_count(Event::Completed), 0);
                assert_eq!(polls.load(Ordering::Relaxed), 1);
            }
            assert_eq!(drops.load(Ordering::Relaxed), 1);
        })
        .join()
        .unwrap();
    }
}

#[test]
fn pool_profile_migrated_polls_exclude_unrelated_allocations_and_restore_context() {
    let calls = Arc::new(AtomicUsize::new(0));
    let polled = calls.clone();
    let future = profile::acquisition(
        Family::H2,
        Purpose::Request,
        poll_fn(move |_| {
            profile::measure(Phase::Rr, allocation);
            if polled.fetch_add(1, Ordering::Relaxed) == 0 {
                Poll::Pending
            } else {
                Poll::Ready(Ok::<_, ()>(73))
            }
        }),
    );
    let future = std::thread::spawn(move || {
        let mut future = Box::pin(future);
        assert!(poll(future.as_mut()).is_pending());
        let before = profile::current_thread_counters();
        allocation();
        profile::event(Event::WarmHit);
        assert_eq!(profile::current_thread_counters(), before);
        let base = schema::EVENTS.len() + Phase::Rr as usize * schema::FIELDS.len();
        assert_eq!(before[base + 3], 1);
        assert_eq!(before[base + 7], 37);
        future
    })
    .join()
    .unwrap();
    std::thread::spawn(move || {
        let mut future = future;
        assert_eq!(poll(future.as_mut()), Poll::Ready(Ok(73)));
        assert_eq!(event_count(Event::Completed), 1);
        let counters = profile::current_thread_counters();
        let base = schema::EVENTS.len() + Phase::Rr as usize * schema::FIELDS.len();
        assert_eq!(counters[base + 3], 1);
        assert_eq!(counters[base + 7], 37);
    })
    .join()
    .unwrap();
    assert_eq!(calls.load(Ordering::Relaxed), 2);
}

#[test]
fn pool_profile_ready_pending_error_and_cancellation_do_not_repoll() {
    std::thread::spawn(|| {
        let mut calls = 0;
        let mut future = Box::pin(profile::acquisition(Family::H2, Purpose::Request, async {
            assert!(
                profile::readiness(|| {
                    calls += 1;
                    Some(Ok::<_, ()>(()))
                })
                .is_some()
            );
            assert!(
                profile::readiness(|| {
                    calls += 1;
                    None::<Result<(), ()>>
                })
                .is_none()
            );
            assert_eq!(profile::readiness(|| Some(Err::<(), _>(9))), Some(Err(9)));
            std::future::pending::<Result<(), ()>>().await
        }));
        assert!(poll(future.as_mut()).is_pending());
        drop(future);
        assert_eq!(calls, 2);
        assert_eq!(event_count(Event::Ready), 1);
        assert_eq!(event_count(Event::Pending), 1);
        assert_eq!(event_count(Event::ReadinessError), 1);
        assert_eq!(event_count(Event::Cancelled), 1);
        assert_eq!(event_count(Event::Completed), 0);
        let before = profile::current_thread_counters();
        profile::event(Event::SenderClone);
        assert_eq!(profile::current_thread_counters(), before);
    })
    .join()
    .unwrap();
}

#[test]
fn pool_profile_sampling_and_purpose_have_fixed_independent_denominators() {
    std::thread::spawn(|| {
        for family in [Family::H2, Family::Grpc] {
            for purpose in [Purpose::Request, Purpose::Capability] {
                for _ in 0..65 {
                    let mut future = Box::pin(profile::acquisition(family, purpose, async {
                        profile::event(Event::WarmHit);
                        Err::<(), _>(17)
                    }));
                    assert_eq!(poll(future.as_mut()), Poll::Ready(Err(17)));
                }
            }
        }
        let counters = profile::current_thread_counters();
        for group in 0..4 {
            let base = group * schema::STRIDE;
            assert_eq!(counters[base + Event::Acquisitions as usize], 65);
            assert_eq!(counters[base + Event::Sampled as usize], 2);
            assert_eq!(counters[base + Event::WarmHit as usize], 2);
            assert_eq!(counters[base + Event::Errors as usize], 2);
        }
    })
    .join()
    .unwrap();
}

#[test]
fn pool_profile_nested_scopes_restore_outer_family_after_pending() {
    std::thread::spawn(|| {
        let mut inner = Box::pin(profile::acquisition(
            Family::Grpc,
            Purpose::Capability,
            std::future::pending::<Result<(), ()>>(),
        ));
        let mut outer = Box::pin(profile::acquisition(Family::H2, Purpose::Request, async {
            assert!(poll(inner.as_mut()).is_pending());
            profile::event(Event::WarmHit);
            Ok::<_, ()>(())
        }));
        assert!(poll(outer.as_mut()).is_ready());
        drop(outer);
        drop(inner);
        let counters = profile::current_thread_counters();
        assert_eq!(counters[Event::WarmHit as usize], 1);
        assert_eq!(counters[3 * schema::STRIDE + Event::WarmHit as usize], 0);
        assert_eq!(counters[3 * schema::STRIDE + Event::Cancelled as usize], 1);
    })
    .join()
    .unwrap();
}

#[derive(Default)]
struct Manager;

#[async_trait::async_trait]
impl ferrum_edge::pool::PoolManager for Manager {
    type Connection = Arc<std::sync::atomic::AtomicBool>;

    fn build_key(&self, _: &ferrum_edge::Proxy, _: &str, _: u16, _: usize, _: &mut String) {
        unreachable!("test supplies an exact owned key")
    }

    async fn create(&self, _: &str, _: &ferrum_edge::Proxy) -> anyhow::Result<Self::Connection> {
        unreachable!("test supplies its own create closure")
    }

    fn is_healthy(&self, connection: &Self::Connection) -> bool {
        connection.load(Ordering::Relaxed)
    }

    fn destroy(&self, _: Self::Connection) {}
}

#[test]
fn pool_profile_real_pool_coalescing_cancellation_hit_unhealthy_and_failure() {
    std::thread::spawn(|| {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        runtime.block_on(async {
            let pool = ferrum_edge::pool::GenericPool::new(
                Arc::new(Manager),
                ferrum_edge::config::PoolConfig::default(),
                std::time::Duration::from_secs(60),
                16,
            );
            let mut creator = Box::pin(profile::acquisition(
                Family::H2,
                Purpose::Request,
                pool.create_or_get_existing_owned("key".into(), |_| {
                    std::future::pending::<anyhow::Result<Arc<std::sync::atomic::AtomicBool>>>()
                }),
            ));
            assert!(poll(creator.as_mut()).is_pending());
            let connection = Arc::new(std::sync::atomic::AtomicBool::new(true));
            let mut joiner = Box::pin(profile::acquisition(
                Family::Grpc,
                Purpose::Capability,
                pool.create_or_get_existing_owned("key".into(), |_| async {
                    Ok::<_, anyhow::Error>(connection.clone())
                }),
            ));
            assert!(poll(joiner.as_mut()).is_pending());
            drop(creator);
            assert!(poll(joiner.as_mut()).is_ready());
            drop(joiner);
            profile::acquisition(Family::H2, Purpose::Capability, async {
                assert!(Arc::ptr_eq(&pool.cached("key").unwrap(), &connection));
                connection.store(false, Ordering::Relaxed);
                assert!(pool.cached("key").is_none());
                assert!(pool.cached("missing").is_none());
                pool.create_or_get_existing_owned("key".into(), |_| async {
                    Err::<Arc<std::sync::atomic::AtomicBool>, _>(anyhow::anyhow!("failure"))
                })
                .await
            })
            .await
            .unwrap_err();
            let counters = profile::current_thread_counters();
            let count = |group, event: Event| counters[group * schema::STRIDE + event as usize];
            assert_eq!(count(0, Event::CreateOwner), 1);
            assert_eq!(count(0, Event::Cancelled), 1);
            assert_eq!(count(3, Event::CoalescedWait), 1);
            assert_eq!(count(3, Event::CreateOwner), 1);
            assert_eq!(count(3, Event::CreateSuccess), 1);
            assert_eq!(count(1, Event::SenderClone), 2);
            assert_eq!(count(1, Event::Unhealthy), 1);
            assert!(count(1, Event::CacheMiss) >= 1);
            assert_eq!(count(1, Event::CreateError), 1);
            assert_eq!(count(1, Event::Errors), 1);
        });
    })
    .join()
    .unwrap();
}
