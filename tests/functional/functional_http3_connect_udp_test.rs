//! Live RFC 9298 CONNECT-UDP over HTTP/3 against a real `ferrum-edge` binary.
//!
//! Covers the datapath, not construction:
//!
//! - a real UDP echo target reached through a real QUIC/H3 Extended CONNECT
//!   tunnel, with payloads framed as RFC 9297 DATAGRAM capsules
//! - `Capsule-Protocol: ?1` on the 200
//! - unregistered Context IDs and unknown capsule types dropped, not proxied —
//!   including an unknown capsule twice the configured UDP payload ceiling,
//!   which RFC 9297 §3.1 requires be skipped rather than treated as a fault
//! - an OVER-CEILING DATAGRAM capsule still resetting the tunnel, so the skip
//!   above did not widen the bound on capsules the gateway materializes
//! - a spoofed destination that the matched proxy is not configured to reach
//! - a mixed upstream where the client-requested member requires HBONE while a
//!   sibling is directly dialable: the requested member is still refused.
//!   Reserved `mesh.*` tags enter through trusted projection (the same
//!   boundary mesh materialization uses), not operator file YAML
//! - an open backend circuit breaker not governing a tunnel that dials no
//!   HTTP backend
//! - malformed URI-template expansions
//! - a registered-but-unimplemented `:protocol` (`webtransport`)
//! - the profile disabled by default
//! - an oversized capsule RESETTING the tunnel (never a clean FIN), and a
//!   client FIN in the middle of a capsule doing the same
//! - the RFC 9298 §3 pseudo-header shape (a non-HTTPS `:scheme` never tunnels)
//! - the RFC 9297 §3.2 forbidden fields refused on the request and absent from
//!   the successful response — including spoofed native-gRPC and gRPC-Web
//!   Content-Type values, which must be a plain 400 rather than a gRPC
//!   HTTP-200 trailers response
//! - the concurrent-session limit
//! - a live tunnel torn down by a SIGHUP reload that withdraws the destination
//! - the shared authorization-lifetime contract over a live tunnel (issue
//!   #3860): a continuously active tunnel reset at its credential's `exp`, the
//!   same at the configured authenticated-stream maximum, a flow-control-stalled
//!   client that still cannot outlive its credential, an unauthenticated
//!   tunnel left completely unaffected, a frontend-mTLS leaf whose `notAfter`
//!   is the authoritative deadline, and a request-receipt-anchored maximum
//!   that expires during a pre-handler delay so the 200 is never committed.
//!   Each asserts the bounded `stream_udp` counter on a freshly spawned
//!   gateway; the precommit case also proves the fixed redacted 401 and that
//!   repeated refusals under a one-session limit never degrade to 503.
//!
//! The client-side capsule codec in `tests/scaffolding/clients/http3.rs` is
//! written independently of the gateway's, so these assert wire
//! interoperability rather than agreement between two copies of one encoder.

use crate::scaffolding::port_registry::TestSocket;

use std::time::Duration;

use chrono::Utc;
use ferrum_edge::config::EnvConfig;
use jsonwebtoken::{EncodingKey, Header, encode};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::net::{TcpListener, UdpSocket};

use crate::common::{TestGateway, TrustedProjectedGateway, TrustedProjectedGatewayOptions};
use crate::scaffolding::clients::{Http3Client, Http3ConnectUdp};

const MASQUE_PREFIX: &str = "/.well-known/masque";

/// UDP echo target: reflects every datagram back to its sender.
struct UdpEcho {
    port: u16,
    task: tokio::task::JoinHandle<()>,
}

impl UdpEcho {
    async fn spawn() -> Self {
        let socket = UdpSocket::bind_test("127.0.0.1:0")
            .await
            .expect("bind udp echo");
        let port = socket.local_addr().expect("udp echo addr").port();
        let task = tokio::spawn(async move {
            let mut buf = vec![0u8; 70_000];
            loop {
                match socket.recv_from(&mut buf).await {
                    Ok((len, peer)) => {
                        let _ = socket.send_to(&buf[..len], peer).await;
                    }
                    Err(_) => return,
                }
            }
        });
        Self { port, task }
    }
}

impl Drop for UdpEcho {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn masque_config(target_port: u16) -> String {
    format!(
        r#"version: "1"
proxies:
  - id: "masque"
    listen_path: "{MASQUE_PREFIX}"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {target_port}
    strip_listen_path: false
consumers: []
plugin_configs: []
"#
    )
}

/// The MASQUE route with a hair-trigger circuit breaker on its HTTP backend.
///
/// The backend address is a UDP socket, so any ordinary HTTP request to this
/// route is a connection failure and opens the breaker immediately.
fn masque_config_with_circuit_breaker(target_port: u16) -> String {
    format!(
        r#"version: "1"
proxies:
  - id: "masque"
    listen_path: "{MASQUE_PREFIX}"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {target_port}
    strip_listen_path: false
    circuit_breaker:
      failure_threshold: 1
      timeout_seconds: 300
      trip_on_connection_errors: true
consumers: []
plugin_configs: []
"#
    )
}

/// The same MASQUE route, but its destinations come from a MIXED upstream: one
/// ordinary direct target and one that is tagged as requiring HBONE dispatch.
///
/// `backend_host`/`backend_port` are deliberately a third address that the
/// upstream does not contain, so nothing here can be admitted by the route
/// backend rule.
///
/// The HBONE member is a complete same-cluster Ambient projection
/// (`mesh.hbone` plus the identity tags `mesh_hbone_target_tags` always
/// stamps). It is still not directly dialable: CONNECT-UDP admission refuses
/// any matching target that requires HBONE, mesh mTLS, east-west, or Unix
/// dispatch. These reserved `mesh.*` tags cannot be loaded through operator
/// file/admin config; the live case feeds them through trusted projection.
fn masque_mixed_upstream_config(direct_port: u16, hbone_port: u16, unused_port: u16) -> String {
    format!(
        r#"version: "1"
upstreams:
  - id: "masque-pool"
    targets:
      - host: "127.0.0.1"
        port: {direct_port}
      - host: "127.0.0.1"
        port: {hbone_port}
        tags:
          mesh.hbone: "true"
          mesh.spiffe_id: "spiffe://cluster.local/ns/ferrum/sa/udp-echo"
          mesh.trust_domain: "cluster.local"
          mesh.namespace: "ferrum"
          mesh.protocol: "udp"
proxies:
  - id: "masque"
    listen_path: "{MASQUE_PREFIX}"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {unused_port}
    upstream_id: "masque-pool"
    strip_listen_path: false
consumers: []
plugin_configs: []
"#
    )
}

async fn start_masque_gateway(config: String, extra_env: &[(&str, &str)]) -> (TestGateway, u16) {
    // Own the retry loop here: the HTTPS/QUIC port is chosen outside the
    // harness's own port retry, so every attempt needs a fresh one.
    let mut last_error = None;
    for attempt in 1..=3 {
        let reservation = TcpListener::bind_test("127.0.0.1:0")
            .await
            .expect("reserve port");
        let https_port = reservation.local_addr().expect("reserved addr").port();
        drop(reservation);

        let mut builder = TestGateway::builder()
            .mode_file(config.clone())
            .log_level("warn")
            .max_attempts(1)
            .env("FERRUM_ENABLE_HTTP3", "true")
            // The backend is a UDP socket, so an HTTP warmup probe against it
            // would never answer.
            .env("FERRUM_POOL_WARMUP_ENABLED", "false")
            .env("FERRUM_PROXY_HTTPS_PORT", https_port.to_string())
            .env("FERRUM_FRONTEND_TLS_CERT_PATH", "tests/certs/server.crt")
            .env("FERRUM_FRONTEND_TLS_KEY_PATH", "tests/certs/server.key");
        for (key, value) in extra_env {
            builder = builder.env(*key, *value);
        }
        match builder.spawn().await {
            Ok(gateway) => return (gateway, https_port),
            Err(error) => {
                eprintln!("CONNECT-UDP gateway attempt {attempt}/3 failed: {error}");
                last_error = Some(error.to_string());
            }
        }
    }
    panic!(
        "failed to start CONNECT-UDP gateway after 3 attempts: {}",
        last_error.unwrap_or_else(|| "no error recorded".to_string())
    );
}

/// Spawn the mixed-upstream MASQUE gateway through trusted projection.
///
/// Reserved `mesh.*` target tags are mesh-materialized. Operator file-mode
/// (`TestGateway` / `validate_operator_provided_fields`) rejects them at
/// startup before any listener binds — which is the correct fail-closed
/// operator boundary, but it cannot host this live case. Production mesh
/// projection deserializes + normalizes the same document and never runs
/// that operator check; this helper uses that boundary.
async fn start_masque_gateway_with_projected_mesh_tags(
    config: String,
    excluded_ports: &[u16],
) -> (TrustedProjectedGateway, u16) {
    let env = EnvConfig {
        enable_http3: true,
        http3_connect_udp_enabled: true,
        pool_warmup_enabled: false,
        log_level: "warn".into(),
        frontend_tls_cert_path: Some("tests/certs/server.crt".into()),
        frontend_tls_key_path: Some("tests/certs/server.key".into()),
        ..Default::default()
    };
    let gateway = TrustedProjectedGateway::spawn_from_yaml(
        &config,
        TrustedProjectedGatewayOptions {
            env,
            enable_https: true,
            excluded_ports: excluded_ports.to_vec(),
            ..TrustedProjectedGatewayOptions::default()
        },
    )
    .await
    .expect("spawn CONNECT-UDP gateway via trusted projection");
    gateway
        .wait_for_proxy_port(Duration::from_secs(15))
        .await
        .expect("CONNECT-UDP trusted projected proxy port");
    let https_port = gateway
        .proxy_https_port
        .expect("CONNECT-UDP gateway must expose an HTTPS/QUIC port");
    (gateway, https_port)
}

fn tunnel_url(https_port: u16, target_host: &str, target_port: u16) -> String {
    format!("https://localhost:{https_port}{MASQUE_PREFIX}/udp/{target_host}/{target_port}/")
}

/// Open a tunnel, tolerating the QUIC listener not being up yet.
async fn open_tunnel(client: &Http3Client, url: &str) -> Http3ConnectUdp {
    let mut last_error = None;
    let deadline = std::time::Instant::now() + Duration::from_secs(40);
    loop {
        match client.connect_udp(url).await {
            Ok(tunnel) => return tunnel,
            Err(error) if std::time::Instant::now() < deadline => {
                last_error = Some(error.to_string());
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(error) => panic!(
                "CONNECT-UDP request never completed; last startup error={last_error:?}; final error={error}"
            ),
        }
    }
}

#[ignore]
#[tokio::test]
async fn functional_h3_connect_udp_relays_datagrams_end_to_end() {
    let echo = UdpEcho::spawn().await;
    let (mut gateway, https_port) = start_masque_gateway(
        masque_config(echo.port),
        &[("FERRUM_HTTP3_CONNECT_UDP_ENABLED", "true")],
    )
    .await;

    let client = Http3Client::insecure().expect("H3 client");
    let url = tunnel_url(https_port, "127.0.0.1", echo.port);
    let mut tunnel = open_tunnel(&client, &url).await;

    assert_eq!(tunnel.status.as_u16(), 200, "RFC 9298 tunnel must be 200");
    assert_eq!(
        tunnel
            .headers
            .get("capsule-protocol")
            .and_then(|v| v.to_str().ok()),
        Some("?1"),
        "RFC 9297 §3.4 requires Capsule-Protocol on the successful response"
    );

    for probe in ["first", "second", "third"] {
        tunnel
            .send_datagram(probe.as_bytes())
            .await
            .expect("send datagram");
        let echoed = tunnel
            .recv_datagram(Duration::from_secs(10))
            .await
            .expect("receive echoed datagram");
        assert_eq!(echoed, probe.as_bytes(), "UDP payload must round-trip");
    }

    // A datagram naming an unregistered context and an unknown capsule type
    // must both be dropped, and must not desynchronize the capsule stream.
    tunnel
        .send_datagram_with_context(2, b"must-not-be-proxied")
        .await
        .expect("send unregistered-context datagram");
    tunnel
        .send_capsule(0x17, b"unknown-capsule-value")
        .await
        .expect("send unknown capsule");
    tunnel
        .send_datagram(b"after-drops")
        .await
        .expect("send datagram");
    let echoed = tunnel
        .recv_datagram(Duration::from_secs(10))
        .await
        .expect("receive echoed datagram");
    assert_eq!(
        echoed, b"after-drops",
        "only the Context ID 0 payload may reach the target"
    );

    // RFC 9297 §3.1 puts no length bound on a capsule type the endpoint does
    // not implement, and the RFC 9298 UDP payload ceiling is a property of the
    // payloads this gateway materializes — not of the capsule stream's framing.
    // So an unknown capsule an order of magnitude larger than the whole
    // configured payload ceiling must be skipped over the wire, not treated as
    // a fault, and the following Context ID 0 datagram must still relay.
    // Twice the 65527-byte payload ceiling, and comfortably inside the default
    // 256 KiB QUIC stream receive window so the assertion is about capsule
    // parsing rather than about flow-control credit.
    let large_unknown = vec![0x5au8; 131_072];
    tunnel
        .send_capsule(0x17, &large_unknown)
        .await
        .expect("send an unknown capsule larger than the UDP payload ceiling");
    tunnel
        .send_datagram(b"after-large-skip")
        .await
        .expect("send datagram");
    let echoed = tunnel
        .recv_datagram(Duration::from_secs(10))
        .await
        .expect("a large unknown capsule must be skipped, never reset the tunnel");
    assert_eq!(
        echoed, b"after-large-skip",
        "parsing must resume exactly at the capsule after a skipped unknown one"
    );

    tunnel.close().await;
    gateway.shutdown();
}

#[ignore]
#[tokio::test]
async fn functional_h3_connect_udp_refuses_an_unconfigured_target() {
    let echo = UdpEcho::spawn().await;
    // A second live UDP socket the route was never configured to reach.
    let spoof = UdpEcho::spawn().await;
    let (mut gateway, https_port) = start_masque_gateway(
        masque_config(echo.port),
        &[("FERRUM_HTTP3_CONNECT_UDP_ENABLED", "true")],
    )
    .await;

    let client = Http3Client::insecure().expect("H3 client");
    let url = tunnel_url(https_port, "127.0.0.1", spoof.port);
    let mut tunnel = open_tunnel(&client, &url).await;

    assert_eq!(
        tunnel.status.as_u16(),
        403,
        "a destination the proxy is not configured to reach must be refused"
    );
    let body = tunnel
        .recv_body_text(Duration::from_secs(5))
        .await
        .expect("drain refusal body");
    assert!(
        body.contains("not an allowed destination"),
        "unexpected refusal body: {body}"
    );
    assert!(
        !body.contains(&echo.port.to_string()),
        "the refusal must not disclose the configured destination: {body}"
    );

    gateway.shutdown();
}

#[ignore]
#[tokio::test]
async fn functional_h3_connect_udp_is_not_governed_by_backend_circuit_breaker_state() {
    // A CONNECT-UDP tunnel dials no HTTP backend, so an HTTP backend's failure
    // history must not decide it. Ordinary requests to the same route open the
    // breaker (the "backend" is a UDP socket, so every HTTP dial is refused);
    // the tunnel to the destination the client named and the route admits must
    // still be established and relay.
    let echo = UdpEcho::spawn().await;
    let (mut gateway, https_port) = start_masque_gateway(
        masque_config_with_circuit_breaker(echo.port),
        &[("FERRUM_HTTP3_CONNECT_UDP_ENABLED", "true")],
    )
    .await;

    let client = Http3Client::insecure().expect("H3 client");
    let probe_url = format!("https://localhost:{https_port}{MASQUE_PREFIX}/health-probe");

    // Drive the breaker open, and prove it with the gateway's own 503 rather
    // than assuming the threshold was reached.
    let mut breaker_open = false;
    let deadline = std::time::Instant::now() + Duration::from_secs(40);
    while std::time::Instant::now() < deadline {
        match client.get(&probe_url).await {
            Ok(response) if response.status.as_u16() == 503 => {
                breaker_open = true;
                break;
            }
            Ok(_) | Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    assert!(
        breaker_open,
        "the route's circuit breaker never reported open; the exemption below would be vacuous"
    );

    let mut tunnel = open_tunnel(&client, &tunnel_url(https_port, "127.0.0.1", echo.port)).await;
    assert_eq!(
        tunnel.status.as_u16(),
        200,
        "an open backend circuit breaker must not refuse a CONNECT-UDP tunnel"
    );
    tunnel
        .send_datagram(b"breaker-open")
        .await
        .expect("send datagram");
    let echoed = tunnel
        .recv_datagram(Duration::from_secs(10))
        .await
        .expect("receive echoed datagram");
    assert_eq!(echoed, b"breaker-open");
    tunnel.close().await;

    gateway.shutdown();
}

#[ignore]
#[tokio::test]
async fn functional_h3_connect_udp_refuses_a_transport_constrained_target_in_a_mixed_upstream() {
    // Both members of one upstream are live UDP echo sockets, so the only thing
    // separating them is the transport the operator configured. The direct
    // member proves the route works end to end; the HBONE-tagged member must
    // still be refused, because a direct UDP dial would bypass exactly the
    // transport its tag requires. Whichever member load balancing would have
    // selected is irrelevant — no member is selected for a CONNECT-UDP request.
    let direct = UdpEcho::spawn().await;
    let hbone = UdpEcho::spawn().await;
    let unused = UdpEcho::spawn().await;
    let (mut gateway, https_port) = start_masque_gateway_with_projected_mesh_tags(
        masque_mixed_upstream_config(direct.port, hbone.port, unused.port),
        &[direct.port, hbone.port, unused.port],
    )
    .await;

    let client = Http3Client::insecure().expect("H3 client");

    let mut tunnel = open_tunnel(&client, &tunnel_url(https_port, "127.0.0.1", direct.port)).await;
    assert_eq!(
        tunnel.status.as_u16(),
        200,
        "the directly dialable member of the upstream must tunnel"
    );
    tunnel
        .send_datagram(b"direct-member")
        .await
        .expect("send datagram");
    let echoed = tunnel
        .recv_datagram(Duration::from_secs(10))
        .await
        .expect("receive echoed datagram");
    assert_eq!(echoed, b"direct-member");
    tunnel.close().await;

    let mut refused = open_tunnel(&client, &tunnel_url(https_port, "127.0.0.1", hbone.port)).await;
    assert_eq!(
        refused.status.as_u16(),
        403,
        "a target requiring HBONE dispatch must never be tunnelled over a direct UDP socket"
    );
    let body = refused
        .recv_body_text(Duration::from_secs(5))
        .await
        .expect("drain refusal body");
    assert!(
        body.contains("not an allowed destination"),
        "unexpected refusal body: {body}"
    );
    assert!(
        !body.contains(&direct.port.to_string()),
        "the refusal must not disclose the directly dialable member: {body}"
    );

    gateway.shutdown().await;
}

#[ignore]
#[tokio::test]
async fn functional_h3_connect_udp_refuses_malformed_template_expansions() {
    let echo = UdpEcho::spawn().await;
    let (mut gateway, https_port) = start_masque_gateway(
        masque_config(echo.port),
        &[("FERRUM_HTTP3_CONNECT_UDP_ENABLED", "true")],
    )
    .await;

    let client = Http3Client::insecure().expect("H3 client");

    // Malformed target_host.
    let mut tunnel = open_tunnel(&client, &tunnel_url(https_port, "under_score", 53)).await;
    assert_eq!(tunnel.status.as_u16(), 400);
    let body = tunnel
        .recv_body_text(Duration::from_secs(5))
        .await
        .expect("drain body");
    assert!(body.contains("target_host"), "unexpected body: {body}");

    // Out-of-range target_port.
    let mut tunnel = open_tunnel(&client, &tunnel_url(https_port, "127.0.0.1", 0)).await;
    assert_eq!(tunnel.status.as_u16(), 400);
    let body = tunnel
        .recv_body_text(Duration::from_secs(5))
        .await
        .expect("drain body");
    assert!(body.contains("target_port"), "unexpected body: {body}");

    // A path that is not a template expansion at all.
    let no_anchor = format!("https://localhost:{https_port}{MASQUE_PREFIX}/tcp/127.0.0.1/53/");
    let mut tunnel = open_tunnel(&client, &no_anchor).await;
    assert_eq!(tunnel.status.as_u16(), 400);
    let body = tunnel
        .recv_body_text(Duration::from_secs(5))
        .await
        .expect("drain body");
    assert!(body.contains("URI template"), "unexpected body: {body}");

    gateway.shutdown();
}

#[ignore]
#[tokio::test]
async fn functional_h3_connect_udp_is_disabled_by_default() {
    let echo = UdpEcho::spawn().await;
    let (mut gateway, https_port) = start_masque_gateway(masque_config(echo.port), &[]).await;

    let client = Http3Client::insecure().expect("H3 client");
    let url = tunnel_url(https_port, "127.0.0.1", echo.port);
    let mut tunnel = open_tunnel(&client, &url).await;

    assert_eq!(
        tunnel.status.as_u16(),
        501,
        "the CONNECT-UDP profile must be off unless the operator enables it"
    );
    let body = tunnel
        .recv_body_text(Duration::from_secs(5))
        .await
        .expect("drain body");
    assert!(body.contains("disabled"), "unexpected body: {body}");

    gateway.shutdown();
}

#[ignore]
#[tokio::test]
async fn functional_h3_connect_udp_refuses_an_unimplemented_extended_connect_protocol() {
    let echo = UdpEcho::spawn().await;
    let (mut gateway, https_port) = start_masque_gateway(
        masque_config(echo.port),
        &[("FERRUM_HTTP3_CONNECT_UDP_ENABLED", "true")],
    )
    .await;

    let client = Http3Client::insecure().expect("H3 client");
    let url = tunnel_url(https_port, "127.0.0.1", echo.port);

    let mut last_error = None;
    let deadline = std::time::Instant::now() + Duration::from_secs(40);
    let mut tunnel = loop {
        match client
            .connect_udp_with_protocol(&url, h3::ext::Protocol::WEB_TRANSPORT)
            .await
        {
            Ok(tunnel) => break tunnel,
            Err(error) if std::time::Instant::now() < deadline => {
                last_error = Some(error.to_string());
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(error) => panic!("request never completed; last={last_error:?}; final={error}"),
        }
    };

    assert_eq!(
        tunnel.status.as_u16(),
        405,
        "webtransport must not open a tunnel"
    );
    let body = tunnel
        .recv_body_text(Duration::from_secs(5))
        .await
        .expect("drain body");
    assert!(body.contains("CONNECT"), "unexpected body: {body}");

    gateway.shutdown();
}

#[ignore]
#[tokio::test]
async fn functional_h3_connect_udp_terminates_on_an_oversized_capsule() {
    let echo = UdpEcho::spawn().await;
    let (mut gateway, https_port) = start_masque_gateway(
        masque_config(echo.port),
        &[
            ("FERRUM_HTTP3_CONNECT_UDP_ENABLED", "true"),
            ("FERRUM_HTTP3_CONNECT_UDP_MAX_DATAGRAM_BYTES", "64"),
        ],
    )
    .await;

    let client = Http3Client::insecure().expect("H3 client");
    let url = tunnel_url(https_port, "127.0.0.1", echo.port);
    let mut tunnel = open_tunnel(&client, &url).await;
    assert_eq!(tunnel.status.as_u16(), 200);

    // Inside the ceiling: still relayed.
    tunnel.send_datagram(b"small").await.expect("send small");
    let echoed = tunnel
        .recv_datagram(Duration::from_secs(10))
        .await
        .expect("receive echoed datagram");
    assert_eq!(echoed, b"small");

    // Above the ceiling: the capsule stream is unrecoverable, so the tunnel
    // must fail closed rather than truncate or resynchronize.
    let mut value = vec![0u8];
    value.extend_from_slice(&vec![0x41u8; 4096]);
    tunnel
        .send_capsule(0x00, &value)
        .await
        .expect("send oversized capsule");
    // RFC 9297 §3.5 / RFC 9114 §4.1.2: a capsule over the ceiling is a
    // MALFORMED message. A clean FIN here would be indistinguishable from a
    // successful end of response, so the assertion is a reset specifically —
    // never "either is fine".
    tunnel
        .expect_stream_reset(Duration::from_secs(10))
        .await
        .expect("an oversized capsule must RESET the tunnel, not FIN it");

    gateway.shutdown();
}

#[ignore]
#[tokio::test]
async fn functional_h3_connect_udp_enforces_the_session_limit() {
    let echo = UdpEcho::spawn().await;
    let (mut gateway, https_port) = start_masque_gateway(
        masque_config(echo.port),
        &[
            ("FERRUM_HTTP3_CONNECT_UDP_ENABLED", "true"),
            ("FERRUM_HTTP3_CONNECT_UDP_MAX_SESSIONS", "1"),
        ],
    )
    .await;

    let client = Http3Client::insecure().expect("H3 client");
    let url = tunnel_url(https_port, "127.0.0.1", echo.port);

    let mut first = open_tunnel(&client, &url).await;
    assert_eq!(first.status.as_u16(), 200);
    // Prove the first tunnel is live and therefore holding the only permit.
    first.send_datagram(b"hold").await.expect("send");
    assert_eq!(
        first
            .recv_datagram(Duration::from_secs(10))
            .await
            .expect("receive"),
        b"hold"
    );

    let mut second = client.connect_udp(&url).await.expect("second request");
    assert_eq!(
        second.status.as_u16(),
        503,
        "the concurrent-session limit must refuse the second tunnel"
    );
    let body = second
        .recv_body_text(Duration::from_secs(5))
        .await
        .expect("drain body");
    assert!(body.contains("session limit"), "unexpected body: {body}");

    // Releasing the first permit must let a new tunnel in.
    first.close().await;
    let mut third = None;
    for _ in 0..40 {
        let candidate = client.connect_udp(&url).await.expect("third request");
        if candidate.status.as_u16() == 200 {
            third = Some(candidate);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let third = third.expect("the permit must be released when a tunnel closes");
    assert_eq!(third.status.as_u16(), 200);
    third.close().await;

    gateway.shutdown();
}

#[cfg(unix)]
#[ignore]
#[tokio::test]
async fn functional_h3_connect_udp_closes_live_tunnels_on_route_withdrawal() {
    let echo = UdpEcho::spawn().await;
    let replacement = UdpEcho::spawn().await;
    let (mut gateway, https_port) = start_masque_gateway(
        masque_config(echo.port),
        &[("FERRUM_HTTP3_CONNECT_UDP_ENABLED", "true")],
    )
    .await;

    let client = Http3Client::insecure().expect("H3 client");
    let url = tunnel_url(https_port, "127.0.0.1", echo.port);
    let mut tunnel = open_tunnel(&client, &url).await;
    assert_eq!(tunnel.status.as_u16(), 200);
    tunnel.send_datagram(b"live").await.expect("send");
    assert_eq!(
        tunnel
            .recv_datagram(Duration::from_secs(10))
            .await
            .expect("receive"),
        b"live"
    );

    // Reload with the destination withdrawn: the proxy still exists, but it is
    // no longer configured to reach the port this tunnel is relaying to.
    let config_path = gateway
        .config_path
        .as_ref()
        .expect("file-mode harness must populate config_path");
    std::fs::write(config_path, masque_config(replacement.port)).expect("rewrite config");
    let pid = gateway.pid().expect("gateway still running");
    let _ = std::process::Command::new("kill")
        .args(["-HUP", &pid.to_string()])
        .output();

    // Route withdrawal is an ordinary end of tunnel, not a protocol fault, so
    // the client must observe a clean FIN — the counterpart assertion to the
    // malformed-capsule reset above.
    tunnel
        .expect_clean_stream_end(Duration::from_secs(20))
        .await
        .expect("a withdrawn destination must tear the live tunnel down");

    // The replacement destination is now the admitted one.
    let new_url = tunnel_url(https_port, "127.0.0.1", replacement.port);
    let mut reopened = None;
    for _ in 0..40 {
        let candidate = client.connect_udp(&new_url).await.expect("reopen");
        if candidate.status.as_u16() == 200 {
            reopened = Some(candidate);
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let mut reopened = reopened.expect("the reloaded destination must be reachable");
    reopened.send_datagram(b"reloaded").await.expect("send");
    assert_eq!(
        reopened
            .recv_datagram(Duration::from_secs(10))
            .await
            .expect("receive"),
        b"reloaded"
    );
    reopened.close().await;

    gateway.shutdown();
}

#[ignore]
#[tokio::test]
async fn functional_h3_connect_udp_resets_on_a_client_fin_inside_a_capsule() {
    let echo = UdpEcho::spawn().await;
    let (mut gateway, https_port) = start_masque_gateway(
        masque_config(echo.port),
        &[("FERRUM_HTTP3_CONNECT_UDP_ENABLED", "true")],
    )
    .await;

    let client = Http3Client::insecure().expect("H3 client");
    let url = tunnel_url(https_port, "127.0.0.1", echo.port);
    let mut tunnel = open_tunnel(&client, &url).await;
    assert_eq!(tunnel.status.as_u16(), 200);

    // Prove the tunnel is live first, so the reset below cannot be confused
    // with a failure to establish.
    tunnel.send_datagram(b"live").await.expect("send");
    assert_eq!(
        tunnel
            .recv_datagram(Duration::from_secs(10))
            .await
            .expect("receive"),
        b"live"
    );

    // A DATAGRAM capsule header declaring 32 bytes of value, followed by 4.
    // Then a clean FIN. RFC 9297 §3.3: "If the stream is closed in the middle
    // of a capsule, this MUST be treated as a malformed message." A tidy FIN
    // from the client does not make a truncated capsule stream an EOF.
    tunnel
        .send_raw(&[0x00, 0x20, 0x00, 0xde, 0xad, 0xbe])
        .await
        .expect("send a truncated capsule");
    tunnel.half_close().await.expect("client FIN");

    tunnel
        .expect_stream_reset(Duration::from_secs(15))
        .await
        .expect("a FIN in the middle of a capsule must RESET, never FIN cleanly");

    gateway.shutdown();
}

#[ignore]
#[tokio::test]
async fn functional_h3_connect_udp_refuses_a_non_https_scheme() {
    let echo = UdpEcho::spawn().await;
    let (mut gateway, https_port) = start_masque_gateway(
        masque_config(echo.port),
        &[("FERRUM_HTTP3_CONNECT_UDP_ENABLED", "true")],
    )
    .await;

    let client = Http3Client::insecure().expect("H3 client");
    // Same QUIC listener, same expansion — only `:scheme` differs. RFC 9298 §3
    // bootstraps over HTTPS; the handler must not assume it.
    let http_scheme = format!(
        "http://localhost:{https_port}{MASQUE_PREFIX}/udp/127.0.0.1/{}/",
        echo.port
    );
    let mut tunnel = open_tunnel(&client, &http_scheme).await;

    assert_eq!(
        tunnel.status.as_u16(),
        400,
        "a connect-udp request whose :scheme is not https must never tunnel"
    );
    let body = tunnel
        .recv_body_text(Duration::from_secs(5))
        .await
        .expect("drain body");
    assert!(body.contains(":scheme"), "unexpected body: {body}");

    gateway.shutdown();
}

#[ignore]
#[tokio::test]
async fn functional_h3_connect_udp_refuses_capsule_protocol_forbidden_fields() {
    let echo = UdpEcho::spawn().await;
    let (mut gateway, https_port) = start_masque_gateway(
        masque_config(echo.port),
        &[("FERRUM_HTTP3_CONNECT_UDP_ENABLED", "true")],
    )
    .await;

    let client = Http3Client::insecure().expect("H3 client");
    let url = tunnel_url(https_port, "127.0.0.1", echo.port);

    // RFC 9297 §3.2: none of these may appear on a message that uses the
    // Capsule Protocol. Each must be refused before a UDP socket exists.
    for (name, value, marker) in [
        ("content-length", "0", "Content-Length"),
        ("content-type", "application/octet-stream", "Content-Type"),
    ] {
        let mut last_error = None;
        let deadline = std::time::Instant::now() + Duration::from_secs(40);
        let mut tunnel = loop {
            match client
                .connect_udp_with_headers(&url, &[(name, value)])
                .await
            {
                Ok(tunnel) => break tunnel,
                Err(error) if std::time::Instant::now() < deadline => {
                    last_error = Some(error.to_string());
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Err(error) => panic!("request never completed; last={last_error:?}; final={error}"),
            }
        };
        assert_eq!(
            tunnel.status.as_u16(),
            400,
            "{name} must be refused on a Capsule Protocol message"
        );
        let body = tunnel
            .recv_body_text(Duration::from_secs(5))
            .await
            .expect("drain body");
        assert!(body.contains(marker), "unexpected body for {name}: {body}");
    }

    // And the successful response must not carry them either.
    let tunnel = open_tunnel(&client, &url).await;
    assert_eq!(tunnel.status.as_u16(), 200);
    for forbidden in ["content-length", "content-type", "transfer-encoding"] {
        assert!(
            tunnel.headers.get(forbidden).is_none(),
            "RFC 9297 §3.2 forbids {forbidden} on the CONNECT-UDP response"
        );
    }
    assert_eq!(
        tunnel
            .headers
            .get("capsule-protocol")
            .and_then(|v| v.to_str().ok()),
        Some("?1")
    );
    tunnel.close().await;

    gateway.shutdown();
}

#[ignore]
#[tokio::test]
async fn functional_h3_connect_udp_refuses_spoofed_grpc_content_types_as_plain_400() {
    // Extended CONNECT classification must win over Content-Type: a CONNECT-UDP
    // request with forbidden `application/grpc` or `application/grpc-web*` is
    // still a Capsule Protocol malformed message (RFC 9297 §3.2), not a gRPC
    // RPC. The 400 must be a plain JSON body, never HTTP 200 + trailers.
    let echo = UdpEcho::spawn().await;
    let (mut gateway, https_port) = start_masque_gateway(
        masque_config(echo.port),
        &[("FERRUM_HTTP3_CONNECT_UDP_ENABLED", "true")],
    )
    .await;

    let client = Http3Client::insecure().expect("H3 client");
    let url = tunnel_url(https_port, "127.0.0.1", echo.port);

    for content_type in ["application/grpc", "application/grpc-web+proto"] {
        let mut last_error = None;
        let deadline = std::time::Instant::now() + Duration::from_secs(40);
        let mut tunnel = loop {
            match client
                .connect_udp_with_headers(&url, &[("content-type", content_type)])
                .await
            {
                Ok(tunnel) => break tunnel,
                Err(error) if std::time::Instant::now() < deadline => {
                    last_error = Some(error.to_string());
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Err(error) => panic!("request never completed; last={last_error:?}; final={error}"),
            }
        };
        assert_eq!(
            tunnel.status.as_u16(),
            400,
            "{content_type} must be a plain malformed CONNECT-UDP rejection, not a gRPC 200"
        );
        assert!(
            tunnel.headers.get("grpc-status").is_none(),
            "{content_type} must not be shaped as native gRPC trailers; headers={:?}",
            tunnel.headers
        );
        let response_content_type = tunnel
            .headers
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        assert!(
            !response_content_type
                .to_ascii_lowercase()
                .starts_with("application/grpc"),
            "{content_type} must not return a gRPC media type, got {response_content_type}"
        );
        let body = tunnel
            .recv_body_text(Duration::from_secs(5))
            .await
            .expect("drain body");
        assert!(
            body.contains("Content-Type"),
            "unexpected body for {content_type}: {body}"
        );
        assert!(
            !body.contains("grpc-status"),
            "plain 400 must not carry a gRPC status payload for {content_type}: {body}"
        );
    }

    gateway.shutdown();
}

// ---------------------------------------------------------------------------
// Authorization lifetime over a live tunnel (issue #3860)
//
// The composition of the shared authorization-lifetime contract and this
// transport: a CONNECT-UDP tunnel opened by an authenticated principal must not
// outlive the credential that admitted it, and datagram activity — which keeps
// the tunnel's own idle timer alive indefinitely — must never extend that
// bound. Each of these runs on a FRESHLY SPAWNED gateway process, so the
// bounded `stream_udp` counters start at zero and "exactly once" is assertable.
//
// The PRE-COMMITMENT arm is covered live below
// (`functional_h3_connect_udp_expiry_before_200_is_a_fixed_redacted_401`): a
// request-receipt-anchored maximum plus a `fault_injection` before_proxy delay
// makes the captured plan elapsed before the handler offers a 200. Unit tests
// in `tests/unit/gateway_core/http3_connect_udp_tests.rs` additionally pin the
// resource-ordering (early gate before permit/DNS/socket, final gate before
// the HEADERS write) without test-only production instrumentation.
// ---------------------------------------------------------------------------

/// Consumer identity and shared HMAC secret for the authenticated MASQUE route.
const AUTH_CONSUMER: &str = "masque-alice";
const AUTH_JWT_SECRET: &str = "masque-connect-udp-auth-lifetime-secret-2026";

/// Seconds of credential validity granted to a tunnel.
///
/// `credential_deadline_from_unix_seconds` floors `exp - now` to whole seconds,
/// so the effective monotonic deadline lands `TTL - 1 ..= TTL` after the
/// request. Long enough to establish the tunnel and prove it carries traffic,
/// short enough to keep the test quick.
const AUTH_TOKEN_TTL_SECS: i64 = 6;

/// Bounded grace allowed between the authorization deadline and the observed
/// termination. Generous for a loaded CI runner, and far below the idle,
/// session, and QUIC bounds these tests deliberately configure out of the way.
const AUTH_TERMINATION_GRACE: Duration = Duration::from_secs(25);

/// Mint a real HS256 JWT for [`AUTH_CONSUMER`] with an explicit TTL. The
/// gateway's `jwt_auth` plugin validates it and publishes the authoritative
/// credential deadline onto the request.
fn mint_masque_token(ttl_secs: i64) -> String {
    let now = Utc::now();
    let claims = json!({
        "sub": AUTH_CONSUMER,
        "iat": now.timestamp(),
        "exp": (now + chrono::Duration::seconds(ttl_secs)).timestamp(),
    });
    encode(
        &Header::new(jsonwebtoken::Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(AUTH_JWT_SECRET.as_bytes()),
    )
    .expect("encode MASQUE consumer JWT")
}

/// [`masque_config`] behind `jwt_auth`, so a tunnel is opened by an
/// authenticated principal rather than anonymously.
fn masque_authenticated_config(target_port: u16) -> String {
    let config = json!({
        "version": "1",
        "proxies": [{
            "id": "masque",
            "listen_path": MASQUE_PREFIX,
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": target_port,
            "strip_listen_path": false,
            "plugins": [{"plugin_config_id": "masque-jwt"}],
        }],
        "consumers": [{
            "id": AUTH_CONSUMER,
            "username": AUTH_CONSUMER,
            "credentials": {"jwt": [{"secret": AUTH_JWT_SECRET}]},
        }],
        "upstreams": [],
        "plugin_configs": [{
            "id": "masque-jwt",
            "plugin_name": "jwt_auth",
            "scope": "proxy",
            "proxy_id": "masque",
            "enabled": true,
            "config": {
                "token_lookup": "header:Authorization",
                "consumer_claim_field": "sub",
            },
        }],
    });
    serde_yaml::to_string(&config).expect("yaml serialize")
}

/// Environment that leaves the authorization lifetime as the ONLY bound that
/// can end a live tunnel: the idle timer, the QUIC idle timer, and the session
/// limit are all pushed far beyond the whole test.
fn auth_lifetime_env(max_lifetime_seconds: &'static str) -> Vec<(&'static str, &'static str)> {
    vec![
        ("FERRUM_HTTP3_CONNECT_UDP_ENABLED", "true"),
        (
            "FERRUM_AUTHENTICATED_STREAM_MAX_LIFETIME_SECONDS",
            max_lifetime_seconds,
        ),
        ("FERRUM_HTTP3_CONNECT_UDP_IDLE_TIMEOUT_SECONDS", "600"),
    ]
}

/// Open an authenticated CONNECT-UDP tunnel, tolerating a QUIC listener that is
/// not up yet. Mirrors [`open_tunnel`] but carries the bearer credential.
async fn open_authenticated_connect_udp_tunnel(
    client: &Http3Client,
    url: &str,
    token: &str,
) -> Http3ConnectUdp {
    let authorization = format!("Bearer {token}");
    let mut last_error = None;
    let deadline = std::time::Instant::now() + Duration::from_secs(40);
    loop {
        match client
            .connect_udp_with_headers(url, &[("authorization", authorization.as_str())])
            .await
        {
            Ok(tunnel) => return tunnel,
            Err(error) if std::time::Instant::now() < deadline => {
                last_error = Some(error.to_string());
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(error) => panic!(
                "authenticated CONNECT-UDP request never completed; last startup \
                 error={last_error:?}; final error={error}"
            ),
        }
    }
}

/// Read one bounded authorization-lifetime counter for the `stream_udp` family
/// from the authenticated `GET /metrics/runtime` snapshot.
///
/// `class` is `credential_expired` or `authenticated_stream_max_lifetime` — the
/// complete closed set. There is no other label dimension to read.
async fn stream_udp_terminations(gateway: &TestGateway, class: &str) -> u64 {
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("build admin client");
    let body: Value = http
        .get(gateway.admin_url("/metrics/runtime"))
        .header("Authorization", gateway.auth_header())
        .send()
        .await
        .expect("GET /metrics/runtime")
        .json()
        .await
        .expect("runtime metrics must be JSON");
    body["authorization_lifetime"][class]["stream_udp"]
        .as_u64()
        .unwrap_or_else(|| {
            panic!(
                "runtime snapshot must expose authorization_lifetime.{class}.stream_udp; \
                 got {body:#?}"
            )
        })
}

/// Poll until the counter reaches `expected`, then prove it does not go past
/// it. The runtime snapshot is cached (`FERRUM_METRICS_RUNTIME_CACHE_MS`), so a
/// second read after the cache window is what shows the terminal accounting
/// fired once for the tunnel rather than once per relayed datagram.
async fn assert_exactly_one_stream_udp_termination(gateway: &TestGateway, class: &str) {
    let expected = 1u64;
    let deadline = std::time::Instant::now() + AUTH_TERMINATION_GRACE;
    let observed = loop {
        let value = stream_udp_terminations(gateway, class).await;
        if value >= expected || std::time::Instant::now() >= deadline {
            break value;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    assert_eq!(
        observed, expected,
        "expected exactly {expected} stream_udp {class} termination(s) on a freshly spawned \
         gateway; observed {observed}"
    );
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(
        stream_udp_terminations(gateway, class).await,
        expected,
        "{class} must not keep incrementing after the tunnel ended"
    );
}

/// Relay datagrams continuously for `window`, returning how many round trips
/// completed. Stops early if the gateway ends the tunnel.
///
/// This traffic is the point of the test, not scaffolding: it keeps the RFC
/// 9298 idle timer permanently refreshed, so if activity could also refresh the
/// authorization deadline the tunnel would survive well past the grace.
async fn relay_datagrams_for(tunnel: &mut Http3ConnectUdp, window: Duration) -> usize {
    let until = std::time::Instant::now() + window;
    let mut round_trips = 0usize;
    while std::time::Instant::now() < until {
        if tunnel.send_datagram(b"keepalive").await.is_err() {
            break;
        }
        if tunnel.recv_datagram(Duration::from_secs(2)).await.is_err() {
            break;
        }
        round_trips += 1;
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    round_trips
}

#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn functional_h3_connect_udp_credential_expiry_terminates_a_continuously_active_tunnel() {
    let echo = UdpEcho::spawn().await;
    // The fallback maximum is an hour, so the credential's own `exp` is
    // provably the bound AND the reported class.
    let yaml = masque_authenticated_config(echo.port);
    let env = auth_lifetime_env("3600");
    let (mut gateway, https_port) = start_masque_gateway(yaml, &env).await;

    let client = Http3Client::insecure().expect("H3 client");
    let url = tunnel_url(https_port, "127.0.0.1", echo.port);
    let token = mint_masque_token(AUTH_TOKEN_TTL_SECS);
    let mut tunnel = open_authenticated_connect_udp_tunnel(&client, &url, &token).await;

    assert_eq!(
        tunnel.status.as_u16(),
        200,
        "an authenticated RFC 9298 tunnel must still be 200"
    );

    // Bidirectional UDP works while the credential is live.
    tunnel
        .send_datagram(b"before-expiry")
        .await
        .expect("send datagram before expiry");
    assert_eq!(
        tunnel
            .recv_datagram(Duration::from_secs(10))
            .await
            .expect("receive echoed datagram before expiry"),
        b"before-expiry",
        "the tunnel must carry UDP payloads before the credential expires"
    );

    // Traffic right up to (and past) the credential deadline.
    let window = Duration::from_secs(AUTH_TOKEN_TTL_SECS as u64 + 2);
    let round_trips = relay_datagrams_for(&mut tunnel, window).await;
    assert!(
        round_trips > 0,
        "the tunnel must have carried traffic before the credential expired"
    );

    // After the 200 the only honest terminal is a reset: a clean FIN would
    // present a successfully completed capsule stream at the exact moment the
    // gateway took the tunnel away from an unauthorized principal.
    tunnel
        .expect_stream_reset(AUTH_TERMINATION_GRACE)
        .await
        .expect("the tunnel must reset at the credential deadline, never clean-FIN");

    assert_exactly_one_stream_udp_termination(&gateway, "credential_expired").await;
    assert_eq!(
        stream_udp_terminations(&gateway, "authenticated_stream_max_lifetime").await,
        0,
        "the credential's own expiry — not the fallback maximum — must be the reported class"
    );

    gateway.shutdown();
}

#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn functional_h3_connect_udp_configured_maximum_lifetime_terminates_an_active_tunnel() {
    let echo = UdpEcho::spawn().await;
    // The credential is valid for an hour, so the only remaining bound is the
    // finite authenticated-stream maximum. A credential with no authoritative
    // expiry at all reaches the same arm by the same route: `earliest` selects
    // the maximum whenever it is the earlier instant.
    let yaml = masque_authenticated_config(echo.port);
    let env = auth_lifetime_env("6");
    let (mut gateway, https_port) = start_masque_gateway(yaml, &env).await;

    let client = Http3Client::insecure().expect("H3 client");
    let url = tunnel_url(https_port, "127.0.0.1", echo.port);
    let token = mint_masque_token(3_600);
    let mut tunnel = open_authenticated_connect_udp_tunnel(&client, &url, &token).await;
    assert_eq!(tunnel.status.as_u16(), 200);

    let round_trips = relay_datagrams_for(&mut tunnel, Duration::from_secs(8)).await;
    assert!(
        round_trips > 0,
        "the tunnel must have carried traffic before the maximum lifetime elapsed"
    );

    tunnel
        .expect_stream_reset(AUTH_TERMINATION_GRACE)
        .await
        .expect("the tunnel must reset at the configured maximum lifetime, never clean-FIN");

    assert_exactly_one_stream_udp_termination(&gateway, "authenticated_stream_max_lifetime").await;
    assert_eq!(
        stream_udp_terminations(&gateway, "credential_expired").await,
        0,
        "a live credential must not be reported as expired"
    );

    gateway.shutdown();
}

#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn functional_h3_connect_udp_flow_control_stalled_client_cannot_outlive_its_credential() {
    let echo = UdpEcho::spawn().await;
    let yaml = masque_authenticated_config(echo.port);
    let env = auth_lifetime_env("3600");
    let (mut gateway, https_port) = start_masque_gateway(yaml, &env).await;

    // A deliberately tiny per-stream receive window. The echo target returns
    // every payload, so a client that stops reading parks the gateway's
    // client-bound relay inside `send_data` on QUIC flow control — the exact
    // state in which that relay can never return to its own `select!` and can
    // never consume a supervisor close command.
    let client = Http3Client::insecure_with_stream_receive_window(16 * 1024).expect("H3 client");
    let url = tunnel_url(https_port, "127.0.0.1", echo.port);
    let token = mint_masque_token(AUTH_TOKEN_TTL_SECS);
    let mut tunnel = open_authenticated_connect_udp_tunnel(&client, &url, &token).await;
    assert_eq!(tunnel.status.as_u16(), 200);

    // Push far more back through the tunnel than the client's window can hold,
    // then never read a byte of it.
    let payload = vec![0xa5u8; 60_000];
    for _ in 0..40 {
        if tunnel.send_datagram(&payload).await.is_err() {
            break;
        }
    }

    // The supervisor's own timer must fire on time regardless, and teardown
    // must abort and join the stalled relay within its bounded grace. The
    // counter is the observation that does not require reading the stream —
    // reading would relieve the very flow-control stall under test.
    assert_exactly_one_stream_udp_termination(&gateway, "credential_expired").await;

    // Only now, once the termination is recorded, read: the stalled tunnel must
    // still have been reset rather than presented as a completed capsule
    // stream.
    tunnel
        .expect_stream_reset(AUTH_TERMINATION_GRACE)
        .await
        .expect("a flow-control-stalled tunnel must still reset at the credential deadline");

    gateway.shutdown();
}

#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn functional_h3_connect_udp_unauthenticated_tunnels_are_untouched_by_the_contract() {
    let echo = UdpEcho::spawn().await;
    // The same aggressive maximum the authenticated tunnel above dies to. No
    // principal is admitted on this route, so this contract does not bound it
    // and every pre-existing RFC 9298 bound applies unchanged.
    let yaml = masque_config(echo.port);
    let env = auth_lifetime_env("3");
    let (mut gateway, https_port) = start_masque_gateway(yaml, &env).await;

    let client = Http3Client::insecure().expect("H3 client");
    let url = tunnel_url(https_port, "127.0.0.1", echo.port);
    let mut tunnel = open_tunnel(&client, &url).await;
    assert_eq!(tunnel.status.as_u16(), 200);

    // Well past the configured maximum, with continuous traffic throughout.
    // `relay_datagrams_for` stops the moment the gateway ends the tunnel, so
    // the ELAPSED window — not the round-trip count — is what proves the
    // authenticated-stream maximum never applied here.
    let started = std::time::Instant::now();
    let round_trips = relay_datagrams_for(&mut tunnel, Duration::from_secs(9)).await;
    assert!(
        started.elapsed() >= Duration::from_secs(9),
        "an unauthenticated tunnel must keep relaying past the authenticated-stream \
         maximum, but it stopped after {:?} ({round_trips} round trips)",
        started.elapsed()
    );

    // Still usable after the window an authenticated tunnel would have died in.
    tunnel
        .send_datagram(b"still-open")
        .await
        .expect("send datagram after the authenticated-stream maximum");
    assert_eq!(
        tunnel
            .recv_datagram(Duration::from_secs(10))
            .await
            .expect("receive echoed datagram after the authenticated-stream maximum"),
        b"still-open"
    );

    assert_eq!(
        stream_udp_terminations(&gateway, "credential_expired").await,
        0,
        "an unauthenticated tunnel must never record a credential termination"
    );
    assert_eq!(
        stream_udp_terminations(&gateway, "authenticated_stream_max_lifetime").await,
        0,
        "an unauthenticated tunnel must never record a maximum-lifetime termination"
    );

    tunnel.close().await;
    gateway.shutdown();
}

/// The authenticated MASQUE route plus a `before_proxy` delay so a
/// request-receipt-anchored maximum can elapse before the handler commits a
/// 200. `jwt_auth` still admits the principal; `fault_injection` only consumes
/// time.
fn masque_authenticated_config_with_precommit_delay(target_port: u16, delay_ms: u64) -> String {
    let config = json!({
        "version": "1",
        "proxies": [{
            "id": "masque",
            "listen_path": MASQUE_PREFIX,
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": target_port,
            "strip_listen_path": false,
            "plugins": [
                {"plugin_config_id": "masque-jwt"},
                {"plugin_config_id": "masque-delay"},
            ],
        }],
        "consumers": [{
            "id": AUTH_CONSUMER,
            "username": AUTH_CONSUMER,
            "credentials": {"jwt": [{"secret": AUTH_JWT_SECRET}]},
        }],
        "upstreams": [],
        "plugin_configs": [{
            "id": "masque-jwt",
            "plugin_name": "jwt_auth",
            "scope": "proxy",
            "proxy_id": "masque",
            "enabled": true,
            "config": {
                "token_lookup": "header:Authorization",
                "consumer_claim_field": "sub",
            },
        }, {
            "id": "masque-delay",
            "plugin_name": "fault_injection",
            "scope": "proxy",
            "proxy_id": "masque",
            "enabled": true,
            "config": {
                "delay": {"duration_ms": delay_ms, "percentage": 100.0},
            },
        }],
    });
    serde_yaml::to_string(&config).expect("yaml serialize")
}

const MTLS_CONSUMER: &str = "alice.h3.local";

struct GeneratedCa {
    cert_pem: String,
    issuer: Issuer<'static, KeyPair>,
}

struct GeneratedCert {
    cert_pem: String,
    key_pem: String,
}

fn generate_ca(cn: &str) -> GeneratedCa {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("generate CA key");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn);
    params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    params.key_usages.push(KeyUsagePurpose::CrlSign);
    let cert = params.self_signed(&key_pair).expect("self-sign CA");
    GeneratedCa {
        cert_pem: cert.pem(),
        issuer: Issuer::new(params, key_pair),
    }
}

fn generate_short_lived_client_cert(
    ca: &GeneratedCa,
    cn: &str,
    ttl: time::Duration,
) -> GeneratedCert {
    let key_pair =
        KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("generate client key");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("client params");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn);
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ClientAuth);
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::seconds(5);
    params.not_after = now + ttl;
    let cert = params.signed_by(&key_pair, &ca.issuer).expect("sign leaf");
    GeneratedCert {
        cert_pem: cert.pem(),
        key_pem: key_pair.serialize_pem(),
    }
}

fn write_pem(dir: &TempDir, name: &str, data: &str) -> String {
    let path = dir.path().join(name);
    std::fs::write(&path, data).expect("write PEM");
    path.to_str().expect("PEM path is UTF-8").to_string()
}

fn masque_mtls_config(target_port: u16) -> String {
    let config = json!({
        "version": "1",
        "proxies": [{
            "id": "masque",
            "listen_path": MASQUE_PREFIX,
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": target_port,
            "strip_listen_path": false,
            "plugins": [{"plugin_config_id": "masque-mtls"}],
        }],
        "consumers": [{
            "id": "alice",
            "username": "alice",
            "credentials": {"mtls_auth": [{"identity": MTLS_CONSUMER}]},
        }],
        "upstreams": [],
        "plugin_configs": [{
            "id": "masque-mtls",
            "plugin_name": "mtls_auth",
            "scope": "proxy",
            "proxy_id": "masque",
            "enabled": true,
            "config": {"cert_field": "subject_cn"},
        }],
    });
    serde_yaml::to_string(&config).expect("yaml serialize")
}

/// Open a CONNECT-UDP request, retrying only transport/startup failures. A
/// completed response — including a 401 — is returned as-is so precommit
/// refusals are not retried into a 200.
async fn connect_udp_until_headers(
    client: &Http3Client,
    url: &str,
    extra_headers: &[(&str, &str)],
) -> Http3ConnectUdp {
    let mut last_error = None;
    let deadline = std::time::Instant::now() + Duration::from_secs(40);
    loop {
        match client.connect_udp_with_headers(url, extra_headers).await {
            Ok(tunnel) => return tunnel,
            Err(error) if std::time::Instant::now() < deadline => {
                last_error = Some(error.to_string());
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(error) => panic!(
                "CONNECT-UDP request never completed; last startup error={last_error:?}; \
                 final error={error}"
            ),
        }
    }
}

async fn start_masque_gateway_owned(
    config: String,
    extra_env: &[(String, String)],
) -> (TestGateway, u16) {
    let extra: Vec<(&str, &str)> = extra_env
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    start_masque_gateway(config, &extra).await
}

#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn functional_h3_connect_udp_mtls_not_after_terminates_a_live_tunnel() {
    let echo = UdpEcho::spawn().await;
    let dir = TempDir::new().expect("temp dir");
    let ca = generate_ca("H3-CONNECT-UDP-MTLS-CA");
    let ca_path = write_pem(&dir, "client-ca.pem", &ca.cert_pem);

    let yaml = masque_mtls_config(echo.port);
    let extra = vec![
        (
            "FERRUM_HTTP3_CONNECT_UDP_ENABLED".to_string(),
            "true".to_string(),
        ),
        (
            "FERRUM_AUTHENTICATED_STREAM_MAX_LIFETIME_SECONDS".to_string(),
            "3600".to_string(),
        ),
        (
            "FERRUM_HTTP3_CONNECT_UDP_IDLE_TIMEOUT_SECONDS".to_string(),
            "600".to_string(),
        ),
        (
            "FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH".to_string(),
            ca_path,
        ),
    ];
    let (mut gateway, https_port) = start_masque_gateway_owned(yaml, &extra).await;

    // Mint the leaf AFTER the gateway is up so `notAfter` is measured from
    // the moment we will actually handshake, not from process startup.
    let alice = generate_short_lived_client_cert(&ca, MTLS_CONSUMER, time::Duration::seconds(15));
    let client = Http3Client::insecure_with_client_auth(&alice.cert_pem, &alice.key_pem)
        .expect("mTLS H3 client");
    let url = tunnel_url(https_port, "127.0.0.1", echo.port);
    let mut tunnel = connect_udp_until_headers(&client, &url, &[]).await;
    assert_eq!(
        tunnel.status.as_u16(),
        200,
        "a live mTLS CONNECT-UDP tunnel must still be 200 while notAfter is in the future"
    );

    tunnel
        .send_datagram(b"before-not-after")
        .await
        .expect("send datagram before notAfter");
    assert_eq!(
        tunnel
            .recv_datagram(Duration::from_secs(10))
            .await
            .expect("receive echoed datagram before notAfter"),
        b"before-not-after"
    );

    let round_trips = relay_datagrams_for(&mut tunnel, Duration::from_secs(8)).await;
    assert!(
        round_trips > 0,
        "the tunnel must have carried traffic before the leaf notAfter elapsed"
    );

    tunnel
        .expect_stream_reset(AUTH_TERMINATION_GRACE)
        .await
        .expect("the tunnel must reset at the mtls_auth leaf notAfter, never clean-FIN");

    assert_exactly_one_stream_udp_termination(&gateway, "credential_expired").await;
    assert_eq!(
        stream_udp_terminations(&gateway, "authenticated_stream_max_lifetime").await,
        0,
        "the leaf notAfter — not the fallback maximum — must be the reported class"
    );

    gateway.shutdown();
}

#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn functional_h3_connect_udp_expiry_before_200_is_a_fixed_redacted_401() {
    let echo = UdpEcho::spawn().await;
    // Maximum of 2s, anchored at request receipt. A 4s before_proxy delay
    // consumes that budget before the handler can offer a 200. The JWT itself
    // is valid for an hour, so the reported class is the maximum.
    let yaml = masque_authenticated_config_with_precommit_delay(echo.port, 4_000);
    let env = [
        ("FERRUM_HTTP3_CONNECT_UDP_ENABLED", "true"),
        ("FERRUM_AUTHENTICATED_STREAM_MAX_LIFETIME_SECONDS", "2"),
        ("FERRUM_HTTP3_CONNECT_UDP_IDLE_TIMEOUT_SECONDS", "600"),
        ("FERRUM_HTTP3_CONNECT_UDP_MAX_SESSIONS", "1"),
    ];
    let (mut gateway, https_port) = start_masque_gateway(yaml, &env).await;

    let client = Http3Client::insecure().expect("H3 client");
    let url = tunnel_url(https_port, "127.0.0.1", echo.port);
    let token = mint_masque_token(3_600);
    let authorization = format!("Bearer {token}");

    for attempt in 1..=3 {
        let mut refused =
            connect_udp_until_headers(&client, &url, &[("authorization", authorization.as_str())])
                .await;
        assert_eq!(
            refused.status.as_u16(),
            401,
            "attempt {attempt}: expiry before the 200 must be the fixed 401, not a tunnel"
        );
        let body = refused
            .recv_body_text(Duration::from_secs(5))
            .await
            .expect("drain 401 body");
        assert!(
            body.contains("Unauthorized"),
            "attempt {attempt}: the 401 body must be the shared redacted terminal, got {body}"
        );
        assert!(
            !body.contains("session limit"),
            "attempt {attempt}: a precommit expiry must not consume a session permit"
        );
        assert!(
            !body.contains(&token),
            "attempt {attempt}: the 401 must not echo the credential"
        );
    }

    let deadline = std::time::Instant::now() + AUTH_TERMINATION_GRACE;
    let observed = loop {
        let value = stream_udp_terminations(&gateway, "authenticated_stream_max_lifetime").await;
        if value >= 3 || std::time::Instant::now() >= deadline {
            break value;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    assert_eq!(
        observed, 3,
        "each precommit refusal must record exactly one stream_udp maximum-lifetime termination"
    );
    assert_eq!(
        stream_udp_terminations(&gateway, "credential_expired").await,
        0,
        "a live JWT must not be reported as expired when the maximum is the bound"
    );

    gateway.shutdown();
}
