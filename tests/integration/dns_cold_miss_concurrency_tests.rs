//! Cold-miss DNS record-type concurrency (`DnsCache::do_resolve`).
//!
//! On a cold miss the default `CACHE,SRV,A,CNAME` order starts the SRV and A
//! queries together and still takes the first non-empty answer in configured
//! order. A hostname whose answering record type is already cached stays
//! serial, so steady-state refreshes send no speculative queries.
//!
//! The fixture is a UDP DNS server that can hold every SRV reply until it has
//! seen an A query. Sequential code never sends that A query while the SRV
//! query is pending, so it waits out the resolver timeout instead. It can also
//! delay the released SRV reply past a short A TTL, to pin that an answer
//! buffered behind SRV is not cached beyond its real deadline.

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
                                host_a_queries += 1;
                            }
                            task_a_query_names.lock().expect("A query log").push(name);
                        }
                    }
                    _ => {}
                }
                let reply = answer(request, srv_target.as_ref(), answer_a, host_ip, ttl);
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

    /// A queries for names under `hostname` (search-list expansions included).
    fn a_queries_for(&self, hostname: &str) -> usize {
        self.a_query_names
            .lock()
            .expect("A query log")
            .iter()
            .filter(|name| name.starts_with(hostname))
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
            if let Some(target) = srv_target {
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

#[tokio::test]
async fn cold_miss_sends_srv_and_a_queries_together() {
    // The SRV reply (empty) is released only once the A query arrives, so the
    // resolve finishes promptly only if both queries are in flight together.
    let dns = ColdMissDnsServer::spawn(Behavior {
        srv_target: None,
        hold_srv_until_a: true,
        srv_delay_after_a: None,
        answer_a: true,
        rotate_host_a: false,
        ttl: 60,
    })
    .await;
    let cache = dns.cache();

    let resolved = tokio::time::timeout(
        OVERLAP_BUDGET,
        cache.resolve("cold-overlap.test", None, None),
    )
    .await
    .expect("a cold miss must not wait for the SRV reply before sending the A query")
    .expect("the A answer must resolve the host once SRV answers empty");

    assert_eq!(resolved, IpAddr::V4(HOST_IP));
    assert!(dns.srv_queries() >= 1, "SRV is still queried first");
    assert_eq!(
        dns.a_queries_for("cold-overlap.test"),
        1,
        "a buffered A answer still within its TTL is used without re-querying"
    );
}

#[tokio::test]
async fn buffered_answer_expired_behind_srv_is_requeried() {
    // A answers at once with a 1 s TTL, but the preferred SRV query answers
    // (empty) only 2 s later. By then the buffered A answer has expired, so it
    // must be asked for again rather than cached for a fresh TTL. The fixture
    // rotates the host's address, so a re-used stale answer is visible.
    let dns = ColdMissDnsServer::spawn(Behavior {
        srv_target: None,
        hold_srv_until_a: true,
        srv_delay_after_a: Some(Duration::from_secs(2)),
        answer_a: true,
        rotate_host_a: true,
        ttl: 1,
    })
    .await;
    let cache = dns.cache();

    let resolved = tokio::time::timeout(
        Duration::from_secs(4),
        cache.resolve("cold-ttl.test", None, None),
    )
    .await
    .expect("the delayed SRV reply arrives well inside the resolver timeout")
    .expect("the re-queried A answer must resolve the host");

    assert_eq!(
        dns.a_queries_for("cold-ttl.test"),
        2,
        "the expired buffered A answer must be re-queried once"
    );
    assert_eq!(
        resolved,
        IpAddr::V4(ROTATED_HOST_IP),
        "the cache must hold the fresh answer, not the one that expired while buffered"
    );
}

#[tokio::test]
async fn cold_miss_keeps_srv_preference_when_a_answers_first() {
    // A answers immediately and SRV only after it, yet SRV is earlier in the
    // configured order, so its target address must win.
    let dns = ColdMissDnsServer::spawn(Behavior {
        srv_target: Some("srv-target.cold-pref.test."),
        hold_srv_until_a: true,
        srv_delay_after_a: None,
        answer_a: true,
        rotate_host_a: false,
        ttl: 60,
    })
    .await;
    let cache = dns.cache();

    let resolved =
        tokio::time::timeout(OVERLAP_BUDGET, cache.resolve("cold-pref.test", None, None))
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
async fn buffered_zero_ttl_answer_behind_srv_is_requeried() {
    // A answers at once with TTL 0, then the upstream rotates the address,
    // and the preferred SRV query answers (empty) 1 s later. The sequential
    // walk would have asked for A only after SRV and got the rotated address,
    // so the buffered answer must be asked for again rather than published.
    let dns = ColdMissDnsServer::spawn(Behavior {
        srv_target: None,
        hold_srv_until_a: true,
        srv_delay_after_a: Some(Duration::from_secs(1)),
        answer_a: true,
        rotate_host_a: true,
        ttl: 0,
    })
    .await;
    let cache = dns.cache();

    let resolved = tokio::time::timeout(
        Duration::from_secs(4),
        cache.resolve("cold-ttl-zero.test", None, None),
    )
    .await
    .expect("the delayed SRV reply arrives well inside the resolver timeout")
    .expect("the re-queried A answer must resolve the host");

    assert_eq!(
        dns.a_queries_for("cold-ttl-zero.test"),
        2,
        "the buffered TTL-0 A answer must be re-queried once"
    );
    assert_eq!(
        resolved,
        IpAddr::V4(ROTATED_HOST_IP),
        "the cache must hold the fresh answer, not the buffered TTL-0 one"
    );
}

#[tokio::test]
async fn cold_miss_overlaps_srv_and_aaaa_when_aaaa_follows_srv() {
    // `SRV,AAAA`: the address type after SRV is AAAA, so AAAA is the query
    // sent alongside SRV. The held SRV reply is released by the AAAA query.
    let dns = ColdMissDnsServer::spawn(Behavior {
        srv_target: None,
        hold_srv_until_a: true,
        srv_delay_after_a: None,
        answer_a: true,
        rotate_host_a: false,
        ttl: 60,
    })
    .await;
    let cache = dns.cache_with_order(Some("SRV,AAAA"));

    let resolved = tokio::time::timeout(OVERLAP_BUDGET, cache.resolve("cold-v6.test", None, None))
        .await
        .expect("a cold miss must not wait for the SRV reply before sending the AAAA query")
        .expect("the AAAA answer must resolve the host once SRV answers empty");

    assert_eq!(resolved, IpAddr::V6(HOST_IP6));
    assert_eq!(
        dns.a_queries_for("cold-v6.test"),
        0,
        "an SRV,AAAA order sends no A query"
    );
}

#[tokio::test]
async fn cold_miss_with_no_answers_still_fails() {
    // Every record type answers empty: the resolve must still fail (and be
    // cached as an error) rather than hang or return an empty success.
    let dns = ColdMissDnsServer::spawn(Behavior {
        srv_target: None,
        hold_srv_until_a: false,
        srv_delay_after_a: None,
        answer_a: false,
        rotate_host_a: false,
        ttl: 60,
    })
    .await;
    let cache = dns.cache();

    let result = tokio::time::timeout(OVERLAP_BUDGET, cache.resolve("cold-empty.test", None, None))
        .await
        .expect("an all-empty cold miss must finish within the overlap budget");

    assert!(result.is_err(), "no record type answered, got {result:?}");
    assert!(
        cache.is_cached_error("cold-empty.test"),
        "the failure must still be negatively cached"
    );
}

#[tokio::test]
async fn known_record_type_refresh_stays_serial() {
    assert_known_srv_row_refresh_sends_no_speculative_a("steady-srv.test", None).await;
}

#[tokio::test]
async fn known_record_type_refresh_stays_serial_without_cache_token() {
    // Without `CACHE` the cached type does not lead the order, but the row
    // still records SRV, so the re-resolve is not a cold miss.
    assert_known_srv_row_refresh_sends_no_speculative_a("steady-nocache.test", Some("SRV,A,CNAME"))
        .await;
}

/// After SRV answers once, the row remembers it. The next synchronous resolve
/// walks the order one type at a time, so SRV answers alone and no
/// speculative A query is sent.
async fn assert_known_srv_row_refresh_sends_no_speculative_a(
    hostname: &str,
    dns_order: Option<&str>,
) {
    let dns = ColdMissDnsServer::spawn(Behavior {
        srv_target: Some("srv-target.steady.test."),
        hold_srv_until_a: false,
        srv_delay_after_a: None,
        answer_a: true,
        rotate_host_a: false,
        ttl: 1,
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
    let a_before = dns.a_queries_for(hostname);

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
        dns.a_queries_for(hostname),
        a_before,
        "a known record type must not trigger a speculative A query"
    );
}
