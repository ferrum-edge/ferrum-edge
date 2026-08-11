//! Every protocol family's new-work admission boundary is fenced by the bounded
//! last-known-good configuration gate (issue #3726).
//!
//! The gate itself is a process-global word that only an installed DP tracker
//! writes, and installing one inside a shared test binary would publish a
//! process-wide admission flag into unrelated tests. What still has to be
//! proven is the *wiring*: that each admission site actually consults the gate,
//! and that the H1/H2 site consults it in the right order. These are static
//! contract checks over the production sources, so dropping a protocol family
//! from the fence — or moving the H1/H2 check back behind the ACME early
//! return — fails here rather than silently in production.

const PROXY_MOD: &str = include_str!("../../../src/proxy/mod.rs");
const HTTP3_SERVER: &str = include_str!("../../../src/http3/server.rs");
const TCP_PROXY: &str = include_str!("../../../src/proxy/tcp_proxy.rs");
const UDP_PROXY: &str = include_str!("../../../src/proxy/udp_proxy.rs");

const GATE: &str = "crate::dp_config_freshness::new_traffic_blocked()";

const SINGLE_DATAGRAM_GATE: &str = "refuse_new_udp_source(&overload) && !sessions.contains_key";

const DTLS_PRE_ALLOCATION_GATE: &str = "allow_new_session: Some(Arc::new(move || {\n            \
     !refuse_new_udp_source(&admission_overload)";

const DTLS_POST_ACCEPT_GATE: &str = "if refuse_new_udp_source(&overload) {\n                    \
     client_conn.close().await;";

/// H1/H2 (including gRPC and gRPC-Web) refuse new requests, and the fence runs
/// BEFORE the ACME HTTP-01 early return.
///
/// ACME deliberately outruns *overload* admission — losing a domain validation
/// to load shedding costs a certificate. Authority loss is a different question:
/// the challenge token and the routes that serve it are CP-controlled state the
/// DP can no longer be told to withdraw, so a challenge must not be the one
/// request shape that walks past a stale-config fence. The overload carve-out's
/// own ordering is unchanged.
#[test]
fn http1_and_http2_admission_checks_the_gate_before_the_acme_early_return() {
    let gate = PROXY_MOD
        .find(GATE)
        .expect("H1/H2 admission must consult the stale-configuration gate");
    let acme = PROXY_MOD
        .find("crate::tls::acme::http01_key_authorization_for_path")
        .expect("ACME HTTP-01 early return");
    let overload = PROXY_MOD
        .find(".reject_new_requests")
        .expect("overload admission gate");

    assert!(
        gate < acme,
        "the stale-configuration fence must precede the ACME HTTP-01 early return"
    );
    assert!(
        acme < overload,
        "the deliberate ACME-before-overload ordering must be preserved"
    );
    assert!(
        PROXY_MOD.contains(r#""Gateway configuration stale""#),
        "the refusal must carry the fixed stale-configuration reason"
    );
}

#[test]
fn http3_admission_checks_the_gate() {
    assert!(
        HTTP3_SERVER.contains(GATE),
        "HTTP/3 request admission must consult the stale-configuration gate"
    );
}

#[test]
fn tcp_accept_admission_checks_the_gate() {
    assert!(
        TCP_PROXY.contains(GATE),
        "the TCP accept loop must consult the stale-configuration gate"
    );
}

/// UDP and DTLS have no request boundary, but they do have a real new-session
/// boundary. Every one of them routes through the single `refuse_new_udp_source`
/// predicate, which composes overload shedding with the stale-config gate — so
/// this asserts there is no remaining raw overload-only admission check that a
/// future edit could leave the fence out of.
#[test]
fn every_udp_and_dtls_admission_site_routes_through_the_shared_predicate() {
    assert!(
        UDP_PROXY.contains(GATE),
        "the shared UDP/DTLS admission predicate must consult the gate"
    );
    assert_eq!(
        UDP_PROXY.matches("reject_new_connections").count(),
        1,
        "critical-overload admission in udp_proxy.rs must be reached only through \
         `refuse_new_udp_source`, so the stale-configuration fence cannot be \
         omitted from a UDP/DTLS admission site"
    );

    // Plain UDP: the per-datagram new-source boundary on every receive path
    // (Linux `recvmmsg` batch, PKTINFO batch, non-Linux `try_recv_from` drain)
    // plus the single-datagram `recv_from` arm.
    assert_eq!(
        UDP_PROXY
            .matches("refuse_new_udp_sources && !sessions.contains_key")
            .count(),
        3,
        "each batched UDP receive path must gate new sources"
    );
    assert!(
        UDP_PROXY.contains(SINGLE_DATAGRAM_GATE),
        "the single-datagram UDP receive path must gate new sources"
    );

    // DTLS: both the pre-allocation gate and the post-accept gate, so no race
    // path admits an association behind a stale configuration.
    assert!(
        UDP_PROXY.contains(DTLS_PRE_ALLOCATION_GATE),
        "the DTLS pre-allocation gate must consult the shared predicate"
    );
    assert!(
        UDP_PROXY.contains(DTLS_POST_ACCEPT_GATE),
        "the DTLS post-accept gate must consult the shared predicate"
    );
}

/// The gate must stay a single relaxed load with no allocation, lock, or
/// per-datagram work: the UDP batch paths hoist one decision per batch.
#[test]
fn the_udp_admission_decision_is_hoisted_out_of_the_datagram_loop() {
    assert_eq!(
        UDP_PROXY
            .matches("let refuse_new_udp_sources = refuse_new_udp_source(&overload);")
            .count(),
        3,
        "each batched receive path must decide admission once per batch"
    );
}
