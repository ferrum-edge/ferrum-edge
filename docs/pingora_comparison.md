# Ferrum Gateway vs Cloudflare Pingora: Deep Technical Comparison

A detailed comparison of runtime proxy implementations between Ferrum Gateway and Cloudflare's Pingora framework, covering HTTP/1.1, HTTP/2, HTTP/3, WebSocket, gRPC, connection pooling, load balancing, TLS, and runtime architecture.

---

## Executive Summary

| Capability | Ferrum Gateway | Pingora |
|-----------|----------------|---------|
| **HTTP/1.1 + HTTP/2** | Full proxy (hyper 1.0 + reqwest) | Full proxy (custom h1 + h2 crate) |
| **HTTP/3 (QUIC)** | Native support (quinn + h3) | Not supported |
| **WebSocket** | Native upgrade + bidirectional proxy | Via custom protocol abstraction |
| **gRPC** | Dedicated proxy with trailer forwarding | gRPC-web bridge; native gRPC via H2 |
| **Connection Pool** | DashMap + reqwest built-in pooling | Lock-free hot queue + cold HashMap |
| **Load Balancing** | 4 algorithms + health checks | Round-robin, consistent hashing, weighted |
| **TLS** | rustls (pure Rust) | OpenSSL/BoringSSL/rustls/s2n (pluggable) |
| **Runtime** | Standard tokio multi-threaded | Custom no-steal runtime option |
| **Plugin System** | 20 built-in plugins, 6-phase lifecycle | Trait-based filter phases (no built-in plugins) |
| **Deployment** | Single binary, 5 operating modes | Library/framework (embed in your binary) |

**Key takeaway**: Ferrum is a batteries-included API gateway; Pingora is a proxy-building framework. Their strengths are complementary — Ferrum excels at operational completeness and HTTP/3 support, while Pingora excels at low-level connection management and customizability.

---

## 1. HTTP/1.1 and HTTP/2 Proxy

### Ferrum's Approach

Ferrum uses **hyper 1.0's auto builder** for frontend connections, automatically negotiating HTTP/1.1 or HTTP/2 based on ALPN (TLS) or h2c upgrade (plaintext). Backend connections use **reqwest** (built on hyper), which handles connection pooling and protocol negotiation transparently.

**Strengths:**
- Automatic HTTP/1.1 ↔ HTTP/2 negotiation on both frontend and backend — zero configuration
- `hyper-util::auto::Builder` handles h2c (cleartext HTTP/2) without special handling
- Hop-by-hop header stripping per RFC 7230 Section 6.1 on both request and response paths
- Max header size configuration for both HTTP/1.1 (`max_buf_size`) and HTTP/2 (`max_header_list_size`)

**File**: `src/proxy/mod.rs:364-408` (frontend), `src/connection_pool.rs` (backend)

### Pingora's Approach

Pingora implements HTTP/1.1 and HTTP/2 **separately at the protocol level** with dedicated session types (`HttpSession` for H1, `Http2Session` for H2). The proxy layer (`proxy_h1.rs`, `proxy_h2.rs`) handles protocol conversion transparently.

**Strengths:**
- Fine-grained control over each protocol's behavior (buffer sizes, keepalive, timeouts per protocol)
- Separate `BodyReader`/`BodyWriter` with explicit chunked/content-length/close-delimited modes
- H2→H1 conversion carefully strips HTTP/2-incompatible headers (Transfer-Encoding, Connection, Upgrade)
- Explicit `respect_keepalive()` call for H1 connection reuse decisions
- `update_h2_scheme_authority()` validates and reconstructs `:authority` pseudo-header

**File**: `pingora-core/src/protocols/http/v1/client.rs`, `pingora-proxy/src/proxy_h1.rs`, `pingora-proxy/src/proxy_h2.rs`

### Comparison

| Aspect | Ferrum | Pingora | Winner |
|--------|--------|---------|--------|
| Protocol negotiation | Automatic via hyper auto builder | Manual ALPN + protocol session dispatch | Ferrum (simpler) |
| H1↔H2 conversion | Handled by hyper/reqwest internally | Explicit conversion in proxy_h1.rs/proxy_h2.rs | Pingora (more control) |
| Body handling | Stream vs Full via `ProxyBody` enum | Separate `BodyReader`/`BodyWriter` per protocol | Pingora (more granular) |
| Connection reuse | reqwest handles automatically | Explicit `respect_keepalive()` + pool release | Pingora (more control) |
| Ease of use | Zero-config protocol handling | Requires implementing `ProxyHttp` trait | Ferrum (turnkey) |

### Where Ferrum Could Improve

1. **Per-protocol body handling**: Ferrum's `ProxyBody` enum (Full vs Stream) is binary. Pingora's separate body reader/writer per protocol allows finer control over chunked encoding, content-length negotiation, and close-delimited responses. Consider adding explicit chunked ↔ content-length conversion options.

2. **Explicit keepalive control**: Ferrum delegates keepalive entirely to reqwest. Adding per-proxy keepalive policy (max requests per connection, idle timeout per upstream) would give operators more tuning options.

### Where Pingora Could Learn from Ferrum

1. **Automatic protocol negotiation**: Ferrum's auto builder approach is zero-configuration and handles h2c transparently. Pingora requires users to configure ALPN settings and handle protocol dispatch manually.

2. **Integrated DNS caching**: Ferrum's `DnsCacheResolver` feeds warmed DNS results directly into reqwest, with stale-while-revalidate and per-proxy TTL overrides. Pingora's DNS resolution is simpler and doesn't include built-in cache warming.

---

## 2. HTTP/3 (QUIC)

### Ferrum: Native HTTP/3 Support

Ferrum has **full HTTP/3 support** via quinn (QUIC) + h3 (HTTP/3 framing):

- **Server**: Listens on the same port as HTTPS (UDP), accepts QUIC connections, multiplexes HTTP/3 streams
- **Client**: Can proxy to HTTP/3 backends via `Http3Client`
- **Security**: 0-RTT disabled (prevents replay attacks on API gateways), TLS 1.3 enforced
- **Transport**: Configurable idle timeout, max concurrent bidirectional streams
- **Full plugin lifecycle**: HTTP/3 requests run through the same 6-phase plugin pipeline as HTTP/1.1/2

**Files**: `src/http3/server.rs` (773 lines), `src/http3/client.rs` (153 lines)

### Pingora: No HTTP/3 Support

Pingora does not support HTTP/3 or QUIC. There are no references to h3, quinn, or QUIC anywhere in the codebase.

### Verdict

**Ferrum wins decisively.** HTTP/3 adoption is accelerating (used by Google, Meta, Cloudflare's own CDN), and having native support is a significant differentiator. Ferrum's implementation is security-conscious (0-RTT disabled, TLS 1.3 enforced) and feature-complete (full plugin pipeline for H3 requests).

**Where Ferrum could improve**: The H3 client currently buffers the full response body (no streaming) due to h3 crate API limitations. As the h3 crate matures, adding streaming response support would improve performance for large response bodies over HTTP/3.

---

## 3. WebSocket Proxy

### Ferrum's Approach

Ferrum implements WebSocket proxying as a **first-class feature** in the main proxy handler:

1. **Detection**: Checks `connection: upgrade`, `upgrade: websocket`, `sec-websocket-key`, `sec-websocket-version: 13`
2. **Security-first**: WebSocket upgrade happens AFTER authentication and authorization plugins run — prevents unauthenticated upgrades
3. **Backend-first verification**: Connects to the backend WebSocket BEFORE sending 101 to the client — if backend is unreachable, returns 502 instead of a premature 101
4. **Bidirectional proxy**: Uses tokio-tungstenite for full-duplex message forwarding
5. **TLS support**: ws:// and wss:// with per-proxy TLS config (custom CA, client certs, cert verification override)
6. **Size limits**: `max_frame_size` 16MB, `max_message_size` 64MB

**File**: `src/proxy/mod.rs:48-64` (detection), `src/proxy/mod.rs:417-814` (upgrade + proxy)

### Pingora's Approach

Pingora handles WebSocket via the **custom protocol abstraction**:

1. **Detection**: Recognizes 101 Switching Protocols as a terminal response
2. **Architecture**: `CustomMessageReader` (Stream) + `CustomMessageWriter` (async trait) for protocol-agnostic bidirectional messaging
3. **Proxying**: `proxy_to_custom_upstream()` orchestrates full-duplex channels
4. **Extensibility**: The same abstraction handles any upgrade protocol, not just WebSocket

**File**: `pingora-core/src/protocols/http/custom/mod.rs`, `pingora-proxy/src/proxy_custom.rs`

### Comparison

| Aspect | Ferrum | Pingora | Winner |
|--------|--------|---------|--------|
| Authentication before upgrade | Yes (plugin pipeline runs first) | User must implement in filter phase | Ferrum |
| Backend verification before 101 | Yes (prevents premature 101) | Not built-in | Ferrum |
| Protocol-agnostic upgrades | WebSocket-specific | Any protocol via custom abstraction | Pingora |
| TLS on WebSocket backend | Full support (wss://) | Via transport layer | Tie |
| Frame size limits | Configurable (16MB/64MB defaults) | Protocol-dependent | Ferrum |

### Where Ferrum Could Improve

1. **Protocol-agnostic upgrade handling**: Pingora's custom protocol abstraction is elegant — the same code handles WebSocket, gRPC-web, or any future upgrade protocol. Ferrum's WebSocket handling is tightly coupled. Consider extracting a generic upgrade proxy trait that WebSocket implements.

### Where Pingora Could Learn from Ferrum

1. **Backend-first verification**: Ferrum's pattern of connecting to the backend before sending 101 to the client prevents a common failure mode where the client gets 101 but the backend is down, leaving the client in a broken upgraded state.

2. **Integrated auth before upgrade**: Ferrum's plugin pipeline running before WebSocket upgrade is a significant security advantage for API gateway use cases.

---

## 4. gRPC Proxy

### Ferrum's Approach

Ferrum has a **dedicated gRPC proxy** (`grpc_proxy.rs`) separate from the regular HTTP/2 proxy:

- **Dedicated connection pool**: `GrpcConnectionPool` uses hyper's HTTP/2 client directly (not reqwest) for maximum control over h2 settings
- **Trailer forwarding**: HTTP/2 trailers (gRPC status, gRPC-message) forwarded as response headers
- **h2c support**: Cleartext HTTP/2 via prior-knowledge handshake for internal gRPC services
- **Connection reuse**: Cached `SendRequest` handles per `host:port:use_tls` key, with staleness detection
- **Keep-alive**: HTTP/2 PING frames with configurable interval and timeout
- **mTLS**: Per-proxy client certificates for gRPC backends

**File**: `src/proxy/grpc_proxy.rs` (700+ lines)

### Pingora's Approach

Pingora handles gRPC via two mechanisms:

1. **Native gRPC** (HTTP/2): No special gRPC logic — standard H2 proxying handles gRPC frames, trailers, and stream multiplexing via the h2 crate
2. **gRPC-web bridge**: `GrpcWebCtx` in `bridge/grpc_web.rs` translates between gRPC-web (HTTP/1.1 clients) and native gRPC (HTTP/2 backends):
   - Request: converts `application/grpc-web` → `application/grpc`, adds `te: trailers`
   - Response: converts gRPC H2 responses back to gRPC-web format
   - Trailer: bridges HTTP/2 trailers to gRPC-web trailer encoding

**Files**: `pingora-core/src/protocols/http/bridge/grpc_web.rs`, `pingora-core/src/modules/http/grpc_web.rs`

### Comparison

| Aspect | Ferrum | Pingora | Winner |
|--------|--------|---------|--------|
| Dedicated gRPC handling | Yes (separate pool, trailers) | No (standard H2) | Ferrum (more optimized) |
| gRPC-web bridging | Not supported | Full gRPC ↔ gRPC-web bridge | Pingora |
| h2c for gRPC | Native support | Via H2 ALPN config | Tie |
| Connection reuse | Cached SendRequest handles | Via H2 connection pool | Tie |
| Trailer forwarding | Explicit trailer → header mapping | Via h2 crate natively | Tie |

### Where Ferrum Could Improve

1. **gRPC-web support**: Pingora's gRPC-web bridge enables HTTP/1.1 browser clients to call gRPC services. This is increasingly important for web apps using gRPC. Adding a gRPC-web plugin would be valuable.

### Where Pingora Could Learn from Ferrum

1. **Dedicated gRPC pool**: Ferrum's separate `GrpcConnectionPool` with hyper h2 directly (bypassing reqwest) allows gRPC-specific tuning (PING intervals, max concurrent streams). Pingora uses the same H2 pool for all HTTP/2 traffic.

---

## 5. Connection Pooling

### Ferrum's Approach

- **Storage**: `DashMap<String, PoolEntry>` — sharded concurrent map for lock-free reads
- **Client**: Each pool entry is a `reqwest::Client` (which has its own internal per-host connection pool)
- **Key**: `destination:protocol:max_idle:dns_override` — includes pool config to prevent sharing between differently-configured proxies
- **DNS**: Custom `DnsCacheResolver` feeds warmed DNS cache directly into reqwest
- **Cleanup**: Background task every 30 seconds evicts idle clients (atomic reads only, no locks during iteration)
- **gRPC**: Separate `GrpcConnectionPool` with cached hyper h2 `SendRequest` handles

**File**: `src/connection_pool.rs`

### Pingora's Approach

- **Storage**: Dual-tier — `ArrayQueue<(ID, T)>` (lock-free, 16 slots) for hot connections + `HashMap<ID, T>` for cold overflow
- **Key**: `GroupKey` = hash of peer address + SNI + protocol
- **H1**: Keepalive-aware reuse (respects Connection header, checks stream reusability)
- **H2**: Multiplexed across requests on same pool key, tracks concurrent stream count
- **Release**: Explicit `release_http_session()` with idle timeout

**File**: `pingora-pool/src/connection.rs`

### Comparison

| Aspect | Ferrum | Pingora | Winner |
|--------|--------|---------|--------|
| Lock-free reads | DashMap (sharded) | ArrayQueue (true lock-free) | Pingora |
| Connection granularity | Per-client (reqwest manages internal pool) | Per-TCP-connection | Pingora (more control) |
| Hot path performance | DashMap shard lookup → reqwest internal pool | ArrayQueue pop (O(1), no locks) | Pingora |
| DNS integration | Built-in cache resolver | Separate DNS resolution | Ferrum |
| Cleanup strategy | Timer-based eviction (30s) | Explicit release with idle timeout | Tie |

### Where Ferrum Could Improve

1. **Lock-free hot queue**: Pingora's dual-tier pool (lock-free ArrayQueue for hot connections, HashMap for overflow) is more efficient on the hot path than DashMap. Consider a similar hot/cold tier for the gRPC connection pool.

2. **Per-connection granularity**: Ferrum pools at the reqwest::Client level rather than per-TCP-connection. This means reqwest's internal pool decisions are opaque. For workloads needing precise connection lifecycle control, consider exposing per-connection pool metrics.

### Where Pingora Could Learn from Ferrum

1. **DNS-integrated pooling**: Ferrum's `DnsCacheResolver` ensures pool connections use pre-warmed DNS results, avoiding DNS resolution on the hot path. Pingora's pool relies on standard resolution.

2. **Automatic cleanup**: Ferrum's background eviction task prevents unbounded pool growth without requiring explicit release calls.

---

## 6. Load Balancing

### Ferrum

Four algorithms, all lock-free on the hot path:

| Algorithm | State | Complexity |
|-----------|-------|-----------|
| Round-Robin | `AtomicU64` counter | O(1) |
| Weighted Round-Robin | Smooth WRR via `Mutex<Vec<i64>>` (sub-μs critical section) | O(n) |
| Least Connections | `DashMap<String, AtomicI64>` per target | O(n) |
| Consistent Hashing | Pre-built hash ring (150 vnodes/target) | O(log n) |

Plus: health-filtered selection, `select_excluding()` for retry avoidance, automatic fallback to all targets when all are unhealthy.

### Pingora

Algorithms via the `pingora-load-balancing` crate:
- Round-robin
- Consistent hashing (ketama)
- Weighted round-robin

Health checking via `TcpHealthCheck` with consecutive success/failure thresholds and health-changed callbacks.

### Comparison

| Aspect | Ferrum | Pingora | Winner |
|--------|--------|---------|--------|
| Algorithm count | 4 | 3 | Ferrum |
| Least-connections | Yes | No | Ferrum |
| Health checking | Active + Passive (with windowed counting) | Active (TCP probes with thresholds) | Ferrum |
| Retry exclusion | `select_excluding()` built-in | User implements in upstream_peer() | Ferrum |
| Extensibility | Fixed algorithms | User can implement custom selection | Pingora |

---

## 7. TLS/mTLS

### Ferrum

- **Library**: rustls 0.23 with ring crypto provider (pure Rust, no C dependencies)
- **Versions**: TLS 1.2 and 1.3 (configurable via env vars)
- **Ciphers**: ECDHE + AES-GCM / CHACHA20-POLY1305 (AEAD only)
- **Key exchange**: X25519, secp256r1, secp384r1
- **mTLS**: Client certs per-proxy or global (proxy overrides global)
- **0-RTT**: Disabled for security

### Pingora

- **Libraries**: Pluggable — OpenSSL, BoringSSL, rustls, or AWS s2n (feature-gated)
- **Custom ALPN**: Extensible `CustomALPN` with wire-format support
- **SNI handling**: Leftmost underscore replacement for OpenSSL compliance
- **Debugging**: SSLKEYLOG support for Wireshark decryption
- **mTLS**: Per-peer client cert override, alternative CN matching

### Comparison

| Aspect | Ferrum | Pingora | Winner |
|--------|--------|---------|--------|
| Library flexibility | rustls only | 4 backends (OpenSSL, BoringSSL, rustls, s2n) | Pingora |
| No C dependencies | Yes (pure Rust) | Only with rustls feature | Ferrum |
| Cipher configurability | Env var driven, AEAD-only | Per-backend configuration | Tie |
| SSLKEYLOG debugging | Not supported | Supported | Pingora |
| 0-RTT protection | Explicitly disabled | Not mentioned | Ferrum |

### Where Ferrum Could Improve

1. **SSLKEYLOG support**: Pingora's SSLKEYLOG env var support enables Wireshark TLS decryption for debugging. This is very useful for diagnosing production TLS issues.

2. **TLS backend flexibility**: For organizations that require FIPS-validated crypto (BoringSSL, s2n) or have existing OpenSSL infrastructure, Pingora's pluggable backend is a significant advantage. Consider feature-gating an OpenSSL/BoringSSL backend option.

---

## 8. Runtime Architecture

### Ferrum

- **Runtime**: Standard `#[tokio::main]` multi-threaded runtime with work-stealing
- **Concurrency**: One tokio task per TCP connection, requests handled in-task
- **Shutdown**: Graceful via `tokio::sync::watch` channel (SIGINT/SIGTERM)
- **Listeners**: Independent tokio tasks per listener (HTTP, HTTPS, HTTP/3, Admin HTTP, Admin HTTPS)
- **Config reload**: Atomic swap via ArcSwap — zero downtime, no lock contention

### Pingora

- **Runtime**: Custom `RuntimeBuilder` with two flavors:
  - **Steal** (standard tokio multi-threaded with work-stealing)
  - **NoSteal** (multiple independent tokio single-threaded runtimes, one per thread)
- **Rationale**: NoSteal reduces lock contention on high-concurrency workloads at the cost of lower CPU utilization under variable load
- **Shutdown**: Graceful with 300s EXIT_TIMEOUT for existing sessions
- **Upgrade**: Graceful upgrade support (new process binds sockets before old process exits, 5s CLOSE_TIMEOUT)

### Comparison

| Aspect | Ferrum | Pingora | Winner |
|--------|--------|---------|--------|
| Runtime flexibility | Standard tokio only | Steal + NoSteal options | Pingora |
| Lock contention under load | Mitigated via ArcSwap/DashMap | Eliminated via NoSteal + lock-free queues | Pingora |
| Graceful upgrade | Restart required | Zero-downtime process upgrade | Pingora |
| Config reload | Atomic ArcSwap (zero downtime, in-process) | Depends on user implementation | Ferrum |
| Operational simplicity | Single binary, 5 modes | Framework (user builds binary) | Ferrum |

### Where Ferrum Could Improve

1. **NoSteal runtime option**: Pingora's NoSteal mode (independent single-threaded runtimes per core) eliminates cross-thread task stealing overhead. Under high connection counts, this can reduce tail latency. Consider exposing a `FERRUM_RUNTIME_MODE=no_steal` option.

2. **Graceful binary upgrade**: Pingora supports upgrading the binary without dropping connections (new process binds sockets → old process drains → old exits). Ferrum currently requires a restart for binary upgrades.

### Where Pingora Could Learn from Ferrum

1. **Atomic config reload**: Ferrum's ArcSwap-based config reload is a significant operational advantage. Config changes take effect atomically without process restart, connection drain, or any downtime. Pingora leaves config management to the user.

2. **Multi-mode deployment**: Ferrum's 5 operating modes (database, file, control-plane, data-plane, migrate) from a single binary is operationally elegant. Pingora requires building a custom binary for each deployment topology.

---

## 9. Performance Comparison

### Existing Benchmark Data (Ferrum vs Kong vs Tyk)

From Ferrum's comparison suite (`comparison/`), testing pure proxy overhead with no plugins:

| Gateway | HTTP /health req/s | HTTPS req/s | E2E TLS req/s | HTTP Latency |
|---------|-------------------|-------------|---------------|--------------|
| **Ferrum** (native) | 98,391 | 94,166 | 88,006 | 0.98 ms |
| **Kong 3.9** (Docker) | 25,588 | 24,461 | 23,444 | 3.77 ms |
| **Tyk v5.7** (Docker) | 2,563 | 3,450 | 1,931 | 7.00 ms |

Ferrum is **3.3x faster than Kong** and **33x faster than Tyk** on raw proxy throughput (even after adjusting for Docker overhead).

### Adding Pingora to the Benchmark Suite

Pingora is a **framework**, not a ready-to-run gateway. To benchmark it fairly:

1. Build a minimal Pingora proxy binary that mirrors Ferrum's test config (listen on 8000/8443, proxy to backend on 3001/3443)
2. Implement `ProxyHttp` trait with:
   - `upstream_peer()` → return backend address
   - No authentication, no rate limiting (matching the "pure proxy" test conditions)
3. Run the same wrk benchmarks with identical parameters

**Expected performance characteristics:**
- **Throughput**: Likely comparable or slightly higher than Ferrum on raw proxy throughput. Pingora's lock-free connection pool and optional NoSteal runtime are optimized for maximum RPS. However, Ferrum's hyper 1.0 foundation is also highly optimized.
- **Latency**: Pingora's NoSteal runtime may show lower P99 latency under high connection counts due to reduced cross-thread contention.
- **TLS**: If using BoringSSL/OpenSSL, Pingora may have slightly faster TLS handshakes than rustls for RSA operations (OpenSSL has assembly-optimized RSA). For ECDSA (which Ferrum defaults to), rustls with ring is competitive.

### Benchmark Implementation Plan

To add Pingora to the comparison suite, create the following:

```
comparison/
├── configs/
│   └── pingora/
│       └── proxy.rs          # Minimal Pingora proxy binary source
├── run_comparison.sh          # Add start_pingora/stop_pingora/test_pingora functions
└── scripts/
    └── generate_comparison_report.py  # Add "pingora" to GATEWAYS list
```

The Pingora proxy binary would be approximately 100 lines of Rust implementing the `ProxyHttp` trait with a hardcoded upstream peer.

---

## 10. Summary: What Each Project Does Better

### Ferrum Does Better

| Area | Why |
|------|-----|
| **HTTP/3 support** | Full QUIC support; Pingora has none |
| **API Gateway features** | 20 built-in plugins, auth, rate limiting, CORS, body validation — Pingora has zero |
| **WebSocket security** | Auth before upgrade, backend-first verification |
| **gRPC optimization** | Dedicated pool with hyper h2 directly, PING keep-alive |
| **DNS caching** | Stale-while-revalidate, per-proxy TTL, cache warming at startup |
| **Load balancing** | 4 algorithms including least-connections; passive + active health checks |
| **Config management** | 5 operating modes, atomic ArcSwap reload, DB/file/gRPC config sources |
| **Operational simplicity** | Single binary, env-var config, runs out of the box |
| **E2E TLS efficiency** | Only 10.6% throughput drop for full double-encryption |

### Pingora Does Better

| Area | Why |
|------|-----|
| **Connection pool design** | Lock-free ArrayQueue hot tier; per-connection granularity |
| **Runtime flexibility** | NoSteal mode eliminates cross-thread contention |
| **TLS backend options** | OpenSSL, BoringSSL, rustls, s2n — choose per deployment |
| **Protocol-level control** | Separate H1/H2 session types with fine-grained body handling |
| **gRPC-web bridge** | Built-in HTTP/1.1 ↔ gRPC translation |
| **Graceful binary upgrade** | Zero-downtime process replacement |
| **Customizability** | Trait-based; users build exactly what they need |
| **SSLKEYLOG debugging** | Wireshark TLS decryption support |

---

## 11. Recommended Improvements for Ferrum

Based on this analysis, the highest-impact improvements Ferrum could adopt from Pingora:

### High Priority

1. **gRPC-web plugin** — Bridge HTTP/1.1 browser clients to gRPC backends. Increasingly needed as gRPC adoption grows in web apps.

2. **NoSteal runtime option** — Add `FERRUM_RUNTIME_MODE=no_steal` to create independent per-core runtimes. Benefits high-connection-count deployments with lower P99 latency.

3. **Graceful binary upgrade** — Support upgrading the gateway binary without dropping connections. Critical for zero-downtime deployments at scale.

### Medium Priority

4. **SSLKEYLOG support** — Add env var to dump TLS session keys for Wireshark debugging. Trivial to implement with rustls, very useful for diagnosing TLS issues.

5. **Lock-free hot queue for gRPC pool** — Replace DashMap in `GrpcConnectionPool` with an ArrayQueue hot tier for frequently-used connections.

6. **Per-protocol body handling** — Add explicit chunked ↔ content-length conversion options and close-delimited response support.

### Lower Priority

7. **TLS backend flexibility** — Feature-gate OpenSSL/BoringSSL as an alternative to rustls for FIPS compliance requirements.

8. **Protocol-agnostic upgrade abstraction** — Extract WebSocket handling into a generic upgrade proxy trait that could support future protocols (e.g., WebTransport).

9. **HTTP/3 streaming responses** — As the h3 crate matures, add streaming body support for the HTTP/3 client (currently buffers full response).
