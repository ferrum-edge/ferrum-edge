//! Coverage for the OIDC refresh single-flight registry (issue #4640): the
//! cap-reached eviction pass, expired-record replacement, cancelled-leader
//! cleanup, and the follower wait outcomes. Every test drives the registry
//! through the `_test_support` seams with shrunken limits, so no wall-clock
//! sleep is involved and every assertion is deterministic.

use ferrum_edge::_test_support::{
    OidcRefreshFlightJoinForTest, OidcRefreshFlightLeaderForTest, OidcRefreshFlightWaitForTest,
    OidcRefreshFlightsForTest, oidc_refresh_failure_from_string_for_test,
};
use std::time::Duration;

fn key(id: u8) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[0] = id;
    key
}

fn lead(flights: &OidcRefreshFlightsForTest, id: u8) -> OidcRefreshFlightLeaderForTest<'_> {
    match flights.join(key(id)) {
        OidcRefreshFlightJoinForTest::Leader(leader) => leader,
        OidcRefreshFlightJoinForTest::Follower(_) => panic!("key {id} already has a live leader"),
        OidcRefreshFlightJoinForTest::Completed => panic!("key {id} already completed"),
    }
}

fn complete(flights: &OidcRefreshFlightsForTest, id: u8, age: Duration) {
    lead(flights, id)
        .publish_completed_ago(age)
        .expect("the monotonic clock represents the requested age");
}

fn is_follower(join: &OidcRefreshFlightJoinForTest<'_>) -> bool {
    matches!(join, OidcRefreshFlightJoinForTest::Follower(_))
}

#[test]
fn refresh_failure_from_string_is_a_deferrable_other_failure() {
    // Transport, parse, and token-type failures reach `RefreshFailure` through
    // `?` on a `String`; they must never be classified as a spent credential.
    assert_eq!(
        oidc_refresh_failure_from_string_for_test("{\"error\":\"Token refresh failed\"}".into()),
        Some("{\"error\":\"Token refresh failed\"}".to_string())
    );
}

#[test]
fn cap_reached_join_drops_expired_records_before_any_live_completed_record() {
    let retention = Duration::from_secs(10);
    let flights = OidcRefreshFlightsForTest::new(retention, 3);
    complete(&flights, 1, Duration::from_secs(20));
    complete(&flights, 2, Duration::from_secs(5));
    complete(&flights, 3, Duration::from_secs(1));
    assert_eq!(flights.flight_count(), 3);

    // The cap is reached, so the join runs the eviction pass first. Only the
    // expired record goes; once the map is under the cap nothing else does.
    let newcomer = lead(&flights, 4);
    assert!(!flights.contains(&key(1)), "the expired record is evicted");
    assert!(flights.contains(&key(2)), "a record inside retention stays");
    assert!(flights.contains(&key(3)), "a record inside retention stays");
    assert!(flights.contains(&key(4)), "the newcomer owns a fresh slot");
    assert_eq!(flights.flight_count(), 3);

    // A cancelled newcomer frees its own slot and nothing else.
    drop(newcomer);
    assert!(!flights.contains(&key(4)));
    assert_eq!(flights.flight_count(), 2);
}

#[test]
fn cap_reached_join_evicts_the_oldest_completed_record_and_never_a_live_flight() {
    let flights = OidcRefreshFlightsForTest::new(Duration::from_secs(60), 3);
    let live = lead(&flights, 1);
    complete(&flights, 2, Duration::from_secs(5));
    complete(&flights, 3, Duration::from_secs(2));
    assert_eq!(flights.flight_count(), 3);

    // Nothing is expired, so the pass falls through to oldest-completed
    // eviction. The live flight is older than both records but is untouchable:
    // evicting it would let a second leader submit the same token.
    let newcomer = lead(&flights, 4);
    assert!(flights.contains(&key(1)), "the live flight is never evicted");
    assert!(!flights.contains(&key(2)), "the oldest completed record is evicted");
    assert!(flights.contains(&key(3)), "the newer completed record stays");
    assert!(flights.contains(&key(4)));
    assert_eq!(flights.flight_count(), 3);
    assert!(
        is_follower(&flights.join(key(1))),
        "the surviving live flight still coalesces later requests"
    );

    drop(newcomer);
    drop(live);
    assert_eq!(flights.flight_count(), 1, "only the retained record remains");
}

#[test]
fn eviction_pass_with_only_live_flights_removes_nothing() {
    let flights = OidcRefreshFlightsForTest::new(Duration::from_secs(60), 2);
    let first = lead(&flights, 1);
    let second = lead(&flights, 2);
    flights.evict_completed();
    assert_eq!(flights.flight_count(), 2, "live flights are not eviction candidates");

    // Even over the cap, a new generation still gets its leader: the bound
    // limits retained records, not in-flight transitions.
    let third = lead(&flights, 3);
    assert_eq!(flights.flight_count(), 3);
    drop(third);
    drop(second);
    drop(first);
    assert_eq!(flights.flight_count(), 0);
}

#[test]
fn completed_record_inside_retention_is_adopted_and_an_expired_one_is_replaced() {
    let retention = Duration::from_secs(5);
    let flights = OidcRefreshFlightsForTest::new(retention, 64);
    complete(&flights, 1, Duration::from_secs(1));
    complete(&flights, 2, Duration::from_secs(6));
    assert_eq!(flights.flight_count(), 2);

    assert!(
        matches!(flights.join(key(1)), OidcRefreshFlightJoinForTest::Completed),
        "a record inside retention is adopted instead of re-submitting the token"
    );

    // The expired record is replaced in place by a new leader for the same key.
    let replacement = lead(&flights, 2);
    assert_eq!(flights.flight_count(), 2, "replacement reuses the entry");
    assert!(
        is_follower(&flights.join(key(2))),
        "the replacement leader now owns the key"
    );

    // Cancelling the replacement removes exactly its own slot.
    drop(replacement);
    assert!(!flights.contains(&key(2)));
    assert!(flights.contains(&key(1)));
}

#[tokio::test]
async fn published_outcome_reaches_a_waiting_follower_and_stays_adoptable() {
    let flights = OidcRefreshFlightsForTest::new(Duration::from_secs(25), 64);
    let leader = lead(&flights, 1);
    let OidcRefreshFlightJoinForTest::Follower(mut follower) = flights.join(key(1)) else {
        panic!("a second request for the same token must follow the leader");
    };

    leader
        .publish_completed_ago(Duration::ZERO)
        .expect("the monotonic clock represents now");
    assert_eq!(follower.wait().await, OidcRefreshFlightWaitForTest::Published);
    assert!(
        matches!(flights.join(key(1)), OidcRefreshFlightJoinForTest::Completed),
        "a published leader retains its record for late arrivals"
    );
}

#[tokio::test]
async fn cancelled_leader_frees_the_slot_and_a_follower_re_elects() {
    let flights = OidcRefreshFlightsForTest::new(Duration::from_secs(25), 64);
    let leader = lead(&flights, 1);
    let OidcRefreshFlightJoinForTest::Follower(mut follower) = flights.join(key(1)) else {
        panic!("a second request for the same token must follow the leader");
    };

    // The leader's request is cancelled before it publishes: its cleanup must
    // remove the slot so the follower observes the closed channel and can take
    // over as the single replacement leader.
    drop(leader);
    assert!(!flights.contains(&key(1)), "a cancelled leader frees its slot");
    assert_eq!(follower.wait().await, OidcRefreshFlightWaitForTest::LeaderGone);
    let replacement = lead(&flights, 1);
    assert_eq!(flights.flight_count(), 1);
    drop(replacement);
}

#[tokio::test(start_paused = true)]
async fn follower_wait_times_out_without_stealing_the_live_flight() {
    let flights = OidcRefreshFlightsForTest::new(Duration::from_secs(25), 64);
    let leader = lead(&flights, 1);
    let OidcRefreshFlightJoinForTest::Follower(mut follower) = flights.join(key(1)) else {
        panic!("a second request for the same token must follow the leader");
    };

    // The clock is paused, so the only way the wait finishes is the follower
    // bound firing: nothing is ever published and the sender stays alive.
    assert_eq!(follower.wait().await, OidcRefreshFlightWaitForTest::TimedOut);
    assert!(
        is_follower(&flights.join(key(1))),
        "a timed-out follower leaves the live leader in place"
    );
    drop(leader);
    assert!(!flights.contains(&key(1)));
}
