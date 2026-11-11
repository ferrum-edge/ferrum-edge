//! Cold-miss DNS record-type concurrency (`DnsCache::do_resolve`).
//!
//! On a cold miss, an order that leads with SRV followed by A or AAAA (the
//! default `CACHE,SRV,A,CNAME`) sends both queries together through the same
//! caching resolver and takes the first non-empty answer in configured order.
//! A hostname whose answering record type is already known stays sequential.
//!
//! The fixture is a UDP DNS server that can hold or delay SRV replies, hold,
//! fail or rotate A replies, and answer AAAA. Exact query counts use absolute
//! names (trailing dot), so search-list and `ndots` settings cannot skew them.

use crate::scaffolding::port_registry::TestSocket;

use ferrum_edge::dns::{DnsCache, DnsConfig};
use hickory_resolver::proto::{
    op::Message,
    rr::{Name, RData, Record, RecordType, rdata::SRV},
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Prefix of the SRV target name. Its A record answers `SRV_TARGET_IP`; every
/// other A query answers `HOST_IP`, so the result shows which record type won.
const SRV_TARGET_PREFIX: &str = "srv-target.";
const HOST_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
/// Every AAAA query answers this.
const HOST_IP6: Ipv6Addr = Ipv6Addr::LOCALHOST;
const SRV_TARGET_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);
/// Answered for the host's second and later A queries when
/// `Behavior::rotate_host_a` is set.
const ROTATED_HOST_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 3);

/// Well under the resolver's default 5 s per-query timeout, which a
/// sequential SRV-then-A walk must wait out when the SRV reply is held.
const OVERLAP_BUDGET: Duration = Duration::from_secs(3);

struct ColdMissDnsServer {
    addr: SocketAddr,
    srv_queries: Arc<AtomicUsize>,
    a_query_names: Arc<Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}

/// What the fixture answers.
#[derive(Clone, Copy)]
struct Behavior {
    /// When set, SRV queries answer one record pointing at this FQDN;
    /// otherwise they answer NOERROR with no records.
    srv_target: Option<&'static str>,
    /// Defer every SRV reply until the first A or AAAA query arrives.
    hold_srv_until_a: bool,
    /// Send each held SRV reply this long after that first address query.
    srv_delay_after_a: Option<Duration>,
    /// When false, A and AAAA queries answer NOERROR with no records.
    answer_a: bool,
    /// Answer the host's second and later A queries with `ROTATED_HOST_IP`.
    rotate_host_a: bool,
    /// Answer the first A query for each host name NOERROR with no records
    /// (NODATA), as if the record were published just after it. Per name, so
    /// search-list expansions cannot answer in its place.
    negative_first_host_a: bool,
    /// Never answer A queries for the host itself (SRV-target A queries are
    /// still answered).
    hold_host_a: bool,
    /// Never answer the first A query for each host name; answer later ones.
    hold_first_host_a: bool,
    /// Answer the first A query for each host name; never answer later ones.
    hold_repeat_host_a: bool,
    ttl: u32,
}

impl ColdMissDnsServer {
    async fn spawn(behavior: Behavior) -> Self {
        let Behavior {
            srv_target,
            hold_srv_until_a,
            srv_delay_after_a,
            answer_a,
            rotate_host_a,
            negative_first_host_a,
            hold_host_a,
            hold_first_host_a,
            hold_repeat_host_a,
            ttl,
        } = behavior;
        let socket = tokio::net::UdpSocket::bind_test("127.0.0.1:0")
            .await
            .map(Arc::new)
            .expect("bind test DNS server");
        let addr = socket.local_addr().expect("test DNS server address");
        let srv_target = srv_target.map(|target| Name::from_ascii(target).expect("SRV target"));
        let srv_queries = Arc::new(AtomicUsize::new(0));
        let a_query_names = Arc::new(Mutex::new(Vec::new()));
        let task_srv_queries = Arc::clone(&srv_queries);
        let task_a_query_names = Arc::clone(&a_query_names);
        let task = tokio::spawn(async move {
            let mut buffer = [0u8; 2_048];
            let mut held: Vec<(Message, SocketAddr)> = Vec::new();
            let mut address_seen = false;
            let mut host_a_queries = 0usize;
            let mut answered_host_names = std::collections::HashSet::new();
            loop {
                let Ok((length, peer)) = socket.recv_from(&mut buffer).await else {
                    break;
                };
                let Ok(request) = Message::from_vec(&buffer[..length]) else {
                    continue;
                };
                let Some(query_type) = request.queries.first().map(|query| query.query_type())
                else {
                    continue;
                };
                let mut host_ip = HOST_IP;
                let mut answer_addresses = answer_a;
                match query_type {
                    RecordType::SRV => {
                        task_srv_queries.fetch_add(1, Ordering::SeqCst);
                        if hold_srv_until_a && !address_seen {
                            held.push((request, peer));
                            continue;
                        }
                    }
                    RecordType::AAAA => address_seen = true,
                    RecordType::A => {
                        address_seen = true;
                        if let Some(query) = request.queries.first() {
                            let name = query.name().to_string().to_ascii_lowercase();
                            if !name.starts_with(SRV_TARGET_PREFIX) {
                                if rotate_host_a && host_a_queries > 0 {
                                    host_ip = ROTATED_HOST_IP;
                                }
                                let first_for_name = answered_host_names.insert(name.clone());
                                if negative_first_host_a && first_for_name {
                                    answer_addresses = false;
                                }
                                host_a_queries += 1;
                                if hold_host_a
                                    || (hold_first_host_a && first_for_name)
                                    || (hold_repeat_host_a && !first_for_name)
                                {
                                    task_a_query_names.lock().expect("A query log").push(name);
                                    continue;
                                }
                            }
                            task_a_query_names.lock().expect("A query log").push(name);
                        }
                    }
                    _ => {}
                }
                let reply = answer(request, srv_target.as_ref(), answer_addresses, host_ip, ttl);
                if let Some(encoded) = reply {
                    let _ = socket.send_to(&encoded, peer).await;
                }
                if address_seen {
                    for (held_request, held_peer) in held.drain(..) {
                        let reply =
                            answer(held_request, srv_target.as_ref(), answer_a, HOST_IP, ttl);
                        let Some(encoded) = reply else {
                            continue;
                        };
                        let socket = Arc::clone(&socket);
                        tokio::spawn(async move {
                            if let Some(delay) = srv_delay_after_a {
                                tokio::time::sleep(delay).await;
                            }
                            let _ = socket.send_to(&encoded, held_peer).await;
                        });
                    }
                }
            }
        });
        Self {
            addr,
            srv_queries,
            a_query_names,
            task,
        }
    }

    fn cache(&self) -> DnsCache {
        self.cache_with_order(None)
    }

    /// `dns_order: None` is the default `CACHE,SRV,A,CNAME`.
    fn cache_with_order(&self, dns_order: Option<&str>) -> DnsCache {
        DnsCache::new(DnsConfig {
            resolver_addresses: Some(self.addr.to_string()),
            dns_order: dns_order.map(str::to_owned),
            min_ttl_seconds: 1,
            stale_ttl_seconds: 0,
            ..DnsConfig::default()
        })
    }

    fn srv_queries(&self) -> usize {
        self.srv_queries.load(Ordering::SeqCst)
    }

    /// A queries for exactly `fqdn` (lowercase, with the trailing dot).
    fn a_queries_named(&self, fqdn: &str) -> usize {
        self.a_query_names
            .lock()
            .expect("A query log")
            .iter()
            .filter(|name| name.as_str() == fqdn)
            .count()
    }
}

impl Drop for ColdMissDnsServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn answer(
    request: Message,
    srv_target: Option<&Name>,
    answer_a: bool,
    host_ip: Ipv4Addr,
    ttl: u32,
) -> Option<Vec<u8>> {
    let query = request.queries.first().cloned()?;
    let mut response = request.into_response();
    let name = query.name().clone();
    match query.query_type() {
        RecordType::SRV => {
            // A name is never its own SRV target, so the target's SRV query
            // answers empty.
            if let Some(target) = srv_target.filter(|target| **target != name) {
                let data = RData::SRV(SRV::new(10, 10, 443, target.clone()));
                response.add_answer(Record::from_rdata(name, ttl, data));
            }
        }
        RecordType::A if answer_a => {
            let ip = if name
                .to_string()
                .to_ascii_lowercase()
                .starts_with(SRV_TARGET_PREFIX)
            {
                SRV_TARGET_IP
            } else {
                host_ip
            };
            response.add_answer(Record::from_rdata(name, ttl, RData::A(ip.into())));
        }
        RecordType::AAAA if answer_a => {
            let data = RData::AAAA(HOST_IP6.into());
            response.add_answer(Record::from_rdata(name, ttl, data));
        }
        _ => {}
    }
    response.to_vec().ok()
}

impl Default for Behavior {
    fn default() -> Self {
        Self {
            srv_target: None,
            hold_srv_until_a: false,
            srv_delay_after_a: None,
            answer_a: true,
            rotate_host_a: false,
            negative_first_host_a: false,
            hold_host_a: false,
            hold_first_host_a: false,
            hold_repeat_host_a: false,
            ttl: 60,
        }
    }
}

#[tokio::test]
async fn cold_miss_sends_srv_and_a_queries_together() {
    // The SRV reply (empty) is released only once the A query arrives, so the
    // resolve finishes promptly only if both queries are in flight together.
    let dns = ColdMissDnsServer::spawn(Behavior {
        hold_srv_until_a: true,
        ..Behavior::default()
    })
    .await;
    let cache = dns.cache();

    let resolved = tokio::time::timeout(
        OVERLAP_BUDGET,
        cache.resolve("cold-overlap.test.", None, None),
    )
    .await
    .expect("a cold miss must not wait for the SRV reply before sending the A query")
    .expect("the A answer must resolve the host once SRV answers empty");

    assert_eq!(resolved, IpAddr::V4(HOST_IP));
    assert!(dns.srv_queries() >= 1, "SRV is still queried");
    assert_eq!(
        dns.a_queries_named("cold-overlap.test."),
        1,
        "the concurrent A answer is used without a second A query"
    );
}

#[tokio::test]
async fn cold_miss_keeps_srv_preference_when_a_answers_first() {
    // A answers immediately and SRV only after it, yet SRV is earlier in the
    // configured order, so its target address must win.
    let dns = ColdMissDnsServer::spawn(Behavior {
        srv_target: Some("srv-target.cold-pref.test."),
        hold_srv_until_a: true,
        ..Behavior::default()
    })
    .await;
    let cache = dns.cache();

    let resolved =
        tokio::time::timeout(OVERLAP_BUDGET, cache.resolve("cold-pref.test.", None, None))
            .await
            .expect("cold-miss resolve must finish within the overlap budget")
            .expect("the SRV target must resolve");

    assert_eq!(
        resolved,
        IpAddr::V4(SRV_TARGET_IP),
        "the first non-empty answer in configured order (SRV) must win over an earlier A answer"
    );
}

#[tokio::test]
async fn address_answer_that_expired_while_srv_was_pending_is_looked_up_again() {
    // A answers at once with a 1 s TTL, but SRV answers (empty) only 2 s
    // later. The held A answer has expired by then, so A is asked again. The
    // fixture rotates the host's address, so a reused stale answer is visible.
    let dns = ColdMissDnsServer::spawn(Behavior {
        hold_srv_until_a: true,
        srv_delay_after_a: Some(Duration::from_secs(2)),
        rotate_host_a: true,
        ttl: 1,
        ..Behavior::default()
    })
    .await;
    let cache = dns.cache();

    let resolved = tokio::time::timeout(
        Duration::from_secs(4),
        cache.resolve("cold-ttl.test.", None, None),
    )
    .await
    .expect("the delayed SRV reply arrives well inside the resolver timeout")
    .expect("the repeated A lookup must resolve the host");

    assert_eq!(dns.a_queries_named("cold-ttl.test."), 2);
    assert_eq!(
        resolved,
        IpAddr::V4(ROTATED_HOST_IP),
        "the fresh answer must be used, not the one that expired while SRV was pending"
    );
}

#[tokio::test]
async fn cold_miss_overlaps_srv_and_aaaa_when_aaaa_follows_srv() {
    // `SRV,AAAA`: the address type after SRV is AAAA, so AAAA is the query
    // sent alongside SRV. The held SRV reply is released by the AAAA query.
    let dns = ColdMissDnsServer::spawn(Behavior {
        hold_srv_until_a: true,
        ..Behavior::default()
    })
    .await;
    let cache = dns.cache_with_order(Some("SRV,AAAA"));

    let resolved = tokio::time::timeout(OVERLAP_BUDGET, cache.resolve("cold-v6.test.", None, None))
        .await
        .expect("a cold miss must not wait for the SRV reply before sending the AAAA query")
        .expect("the AAAA answer must resolve the host once SRV answers empty");

    assert_eq!(resolved, IpAddr::V6(HOST_IP6));
    assert_eq!(
        dns.a_queries_named("cold-v6.test."),
        0,
        "an SRV,AAAA order sends no A query"
    );
}

#[tokio::test]
async fn srv_answer_returns_while_the_a_query_is_unanswered() {
    // The host's A query is never answered. SRV answers at once, so the
    // resolve must return the SRV target address promptly, dropping the
    // pending A lookup instead of waiting for it.
    let dns = ColdMissDnsServer::spawn(Behavior {
        srv_target: Some("srv-target.cold-hold.test."),
        hold_host_a: true,
        ..Behavior::default()
    })
    .await;
    let cache = dns.cache();

    let resolved =
        tokio::time::timeout(OVERLAP_BUDGET, cache.resolve("cold-hold.test.", None, None))
            .await
            .expect("an SRV answer must not wait for the concurrent A query")
            .expect("the SRV target must resolve");

    assert_eq!(resolved, IpAddr::V4(SRV_TARGET_IP));
}

#[tokio::test]
async fn concurrent_address_query_is_answered_from_the_resolver_cache() {
    // Resolving `seed.dns-seed.test.` follows its SRV record to the target and
    // caches the target's A record in the resolver. The target itself then
    // misses Ferrum's cache: its SRV answers empty, and any further A query
    // for it is never answered. The concurrent A lookup goes through the same
    // caching resolver, so it is answered from that cache without reaching
    // the server. The target has five dots, so even an `ndots:5` search list
    // resolves it as absolute first.
    const TARGET: &str = "cached.a.b.c.dns-seed.test.";
    let dns = ColdMissDnsServer::spawn(Behavior {
        srv_target: Some(TARGET),
        hold_repeat_host_a: true,
        ..Behavior::default()
    })
    .await;
    let cache = dns.cache_with_order(Some("SRV,A"));

    let seeded = cache
        .resolve("seed.dns-seed.test.", None, None)
        .await
        .expect("the seed host resolves through its SRV target");
    assert_eq!(seeded, IpAddr::V4(HOST_IP));
    assert_eq!(
        dns.a_queries_named(TARGET),
        1,
        "the SRV target A lookup seeds the cache"
    );

    let resolved = tokio::time::timeout(OVERLAP_BUDGET, cache.resolve(TARGET, None, None))
        .await
        .expect("the cached A record must answer without waiting on the server")
        .expect("the resolver's cached A record must resolve the target");

    assert_eq!(resolved, IpAddr::V4(HOST_IP));
    assert_eq!(
        dns.a_queries_named(TARGET),
        1,
        "the concurrent A lookup is a resolver cache hit and sends no query"
    );
}

#[tokio::test]
async fn cold_miss_with_no_answers_still_fails() {
    // Every record type answers empty: the resolve must still fail (and be
    // cached as an error) rather than hang or return an empty success.
    let dns = ColdMissDnsServer::spawn(Behavior {
        answer_a: false,
        ..Behavior::default()
    })
    .await;
    let cache = dns.cache();

    let result = tokio::time::timeout(
        OVERLAP_BUDGET,
        cache.resolve("cold-empty.test.", None, None),
    )
    .await
    .expect("an all-empty cold miss must finish within the overlap budget");

    assert!(result.is_err(), "no record type answered, got {result:?}");
    assert!(
        cache.is_cached_error("cold-empty.test."),
        "the failure must still be negatively cached"
    );
}

#[tokio::test]
async fn known_record_type_refresh_stays_serial() {
    assert_known_srv_row_refresh_sends_no_a_query("steady-srv.test.", None).await;
}

#[tokio::test]
async fn known_record_type_refresh_stays_serial_without_cache_token() {
    // Without `CACHE` the known type does not lead the order, but the row
    // still records SRV, so the re-resolve is not a cold miss.
    assert_known_srv_row_refresh_sends_no_a_query("steady-nocache.test.", Some("SRV,A,CNAME"))
        .await;
}

/// After SRV answers once, the row remembers it. The next synchronous resolve
/// walks the order one type at a time, so SRV answers alone and no A query is
/// sent for the host.
async fn assert_known_srv_row_refresh_sends_no_a_query(hostname: &str, dns_order: Option<&str>) {
    let dns = ColdMissDnsServer::spawn(Behavior {
        srv_target: Some("srv-target.steady.test."),
        ttl: 1,
        ..Behavior::default()
    })
    .await;
    let cache = dns.cache_with_order(dns_order);

    let first = cache
        .resolve(hostname, None, Some(1))
        .await
        .expect("cold SRV resolve");
    assert_eq!(first, IpAddr::V4(SRV_TARGET_IP));

    // Past the 1 s TTL with no stale window, so the next call re-resolves.
    // Snapshot after the wait so the cold miss's dropped A query is counted.
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    let srv_before = dns.srv_queries();
    let a_before = dns.a_queries_named(hostname);

    let second = cache
        .resolve(hostname, None, Some(1))
        .await
        .expect("warm SRV resolve");
    assert_eq!(second, IpAddr::V4(SRV_TARGET_IP));
    assert!(
        dns.srv_queries() > srv_before,
        "the second resolve must reach the DNS server"
    );
    assert_eq!(
        dns.a_queries_named(hostname),
        a_before,
        "a known record type must not trigger a concurrent A query"
    );
}
