---
paths:
  - "src/proxy/**"
  - "src/http3/**"
  - "src/dtls/**"
  - "src/dns/**"
  - "src/pool/**"
  - "src/connection_pool.rs"
  - "src/router_cache.rs"
  - "src/load_balancer.rs"
  - "src/health_check.rs"
  - "src/circuit_breaker.rs"
  - "src/retry.rs"
  - "src/socket_opts.rs"
  - "src/tls_offload.rs"
  - "src/adaptive_buffer.rs"
  - "src/lazy_timeout.rs"
  - "vendor/reqwest-0.13.3-ferrum-patched/**"
  - "vendor/h3-0.0.8-ferrum-patched/**"
  - "docs/http3.md"
  - "docs/tcp_udp_proxy.md"
  - "docs/upstream-reqwest-patches/**"
  - "docs/upstream-h3-patches/**"
  - "docs/routing.md"
  - "docs/dns_resolver.md"
  - "docs/connection_pooling.md"
  - "docs/load_balancing.md"
  - "docs/response_body_streaming.md"
  - "docs/error_classification.md"
  - "docs/retry.md"
  - "tests/unit/gateway_core/**"
  - "tests/integration/*{grpc,http2,http3,dtls,tcp,hbone,pool}*"
  - "tests/functional/*{grpc,websocket,tcp,udp,passthrough,protocol,rout,capability,balancer,retry,overload,dns,circuit}*"
---

# Proxy And Protocol Rules

## Routing And Proxy Contracts

- Route order per host tier is exact host, wildcard, catch-all. Within each tier: exact path `=/path`, indexed prefix, indexed regex `RegexSet`, then host-only fallback.
- Never replace prefix matching with O(n) scans or regex matching with sequential per-pattern checks.
- Router cache is a `DashMap`, sized by `FERRUM_ROUTER_CACHE_MAX_ENTRIES` defaulting to `max(10000, proxies * 3)`. Negative lookups are cached.
- Exact listen paths match after query stripping. Regex listen paths use `~` and are auto-anchored full-path. Prefix-style regexes must end with `.*`.
- HTTP-family proxies (`http`, `https`, `ws`, `wss`, `grpc`, `grpcs`, `h3`) route by hosts and listen path. At least one is required; `listen_port` must be `None`.
- Stream-family proxies (`tcp`, `tcp_tls`, `udp`, `dtls`) route by `listen_port`; `listen_path` must be `None`.
- Host-only HTTP proxies match all paths for their hosts; `strip_listen_path` is a no-op there.
- HTTP-family `backend_scheme` accepts `http` or `https` and defaults to `https`. Stream-family requires an explicit scheme.
- gRPC and WebSocket are runtime flavors, not schemes. `backend_dispatch::detect_http_flavor()` classifies once, with one header lookup and no allocation.
- A single `https` proxy serves plain HTTP, gRPC, and WebSocket traffic. HTTPS backends are classified into H1, H2 TLS, H3, H2 TLS gRPC, and H2C gRPC buckets.

## Protocol Validation

- `check_protocol_headers()` runs on every inbound request. Preserve rejects for HTTP/1.0+TE, CL+TE smuggling, duplicate/mismatched/empty Content-Length, duplicate Host, bad H2/H3 TE, non-numeric Content-Length, TRACE, and unsupported CONNECT.
- `check_host_authority_consistency()` rejects H2/H3 Host vs `:authority` disagreement before routing after default-port normalization.
- Host/authority normalization strips valid ports, preserves bracketed IPv6, rejects unbracketed IPv6, strips trailing dots, and lowercases ASCII.
- H2 Extended CONNECT (RFC 8441) and H3 Extended CONNECT (RFC 9220), both with `:protocol=websocket`, are the only allowed CONNECT variants.
- H3 WebSocket client frames are unmasked per RFC 9220. Do not apply RFC 6455 client-mask assumptions to H3.
- Response paths strip hop-by-hop headers across protocols: `connection`, `keep-alive`, `proxy-authenticate`, `proxy-connection`, `te`, `trailer`, `transfer-encoding`, `upgrade`.
- Frontend TLS/DTLS handshakes are bounded by `FERRUM_FRONTEND_TLS_HANDSHAKE_TIMEOUT_SECONDS` before HTTP header timers start.
- Backend TLS/H2/gRPC/H3 handshakes are bounded by the per-proxy `backend_connect_timeout_ms` end-to-end connect budget.
- TLS/DTLS-terminating frontends must complete frontend crypto/admission before backend dispatch. Frontend handshake failures and plugin rejects must not dial backends or trip backend circuit breakers.
- HTTP/3 0-RTT is disabled by default, method-gated by `FERRUM_TLS_EARLY_DATA_METHODS`, strips client `Early-Data`, and reinjects `Early-Data: 1` outbound.

## Protocol Paths

- HTTP/1.1: hyper to reqwest through `ConnectionPool`; streaming default.
- HTTP/2: hyper ALPN to reqwest or `Http2ConnectionPool`; streaming default.
- HTTP/3: quinn/h3 standalone server to `Http3ConnectionPool` or cross-protocol bridge; streaming through the shared H3 coalescer.
- gRPC: hyper H2 direct through `GrpcConnectionPool`, not reqwest, to preserve trailers.
- WebSocket: hyper upgrade or H2/H3 Extended CONNECT to backend WebSocket transport; persistent and frame-by-frame.
- TCP: `TcpListener` to `TcpStream::connect`; splice on Linux unconditionally for plain-to-plain (and for TLS frontends when kTLS install succeeds), else userspace copy. The splice loops enforce `tcp_idle_timeout_seconds`, `tcp_half_close_max_wait_seconds`, `backend_read_timeout_ms`, and `backend_write_timeout_ms` inline via per-direction watermarks — there is no eligibility gate based on timeout configuration.
- UDP: `UdpSocket` per session; GSO-batched send on Linux.
- `Proxy.dispatch_kind` is precomputed at config load by `GatewayConfig::resolve_dispatch_kind()`.
- Buffer only when a plugin requires request/response body buffering or retry needs replay. SSE always streams.
- `ProxyBody` response coalescing uses one generic `Coalescing<S: FrameSource>` adapter with reqwest, H2/gRPC, and H3 sources. Do not create parallel per-protocol coalescers.
- Direct-H2 plain responses bypass `coalescing_h2_body` only when `Content-Length` is known, within max response limit, and at least 512 KiB.

## HTTP/3 And gRPC

- H3 clients can hit any `https` backend. Native H3 backend dispatch is used only when the capability registry proves the concrete target supports H3.
- H3 WebSocket bridges to the same backend WebSocket transport and frame-plugin pipeline as H1/H2; the H3 frontend never speaks WebSocket directly to a backend.
- H3 cross-protocol buffering: request bodies buffer because `RequestStream` cannot be captured by reqwest's static body; responses stream with the H3 coalesce window.
- Forward gRPC trailers with `send_trailers` on buffered and streaming H3 bridge responses.
- QUIC connection migration must compare `remote_address()` per request. Rebuild `Arc<str>` only on actual change so per-IP limits follow migrated clients.
- The vendored `h3` crate at `vendor/h3-0.0.8-ferrum-patched/` carries Ferrum's frame-drain-on-QUIC-close, H3 WebSocket Extended CONNECT, and buffered-trailer-peek (`peek_recv_trailers`) patches. Keep `docs/upstream-h3-patches/` lifecycle notes in sync when touching H3 dispatch, graceful-close classification, or the vendor copy.
- gRPC `GrpcBody::Streaming(Incoming)` is used when no body plugins and no retries. Otherwise use `Buffered(Full<Bytes>)`.
- Streaming gRPC responses use `coalescing_h2_body`, preserve trailers, and keep the 128 KiB target unless tests justify a change.

## Stream Proxy Rules

- `passthrough: true` stream proxies forward encrypted bytes without termination. TCP peeks ClientHello for SNI, then `bidirectional_copy`; UDP parses first DTLS ClientHello for SNI and uses a plain UDP backend.
- Passthrough is stream-only, mutually exclusive with `frontend_tls`, and rejects backend TLS fields.
- `StreamConnectionContext.sni_hostname` and `consumer_username` from `effective_identity()` must flow to stream lifecycle plugins.
- Do not move terminating TLS/DTLS frontends to backend-first ordering.
- TCP userspace `copy_bidirectional` fast path is enabled only when idle timeout, half-close max wait, backend read timeout, and backend write timeout are all zero. The Linux splice and io_uring splice paths enforce these bounds inline and stay engaged regardless of timeout configuration.
- Direction-tracking userspace TCP relay is the default when any bound is nonzero; it provides idle timeout, half-close cap, byte counters, and first-failure attribution.
- TCP read/write timeouts refresh on read progress or partial-write progress. Slow but progressing backends must not be classified as inactive. This applies to userspace copy, splice, io_uring splice, and kTLS splice paths uniformly — `splice_one_direction_no_guard`, `libc_splice_loop`, and `io_uring_splice_loop` refresh the same per-direction watermarks the userspace path uses.
- Stream proxy port validation happens at config, admin API, startup reconcile, and runtime reconcile. Startup bind is fatal in db/file and non-fatal in DP. Runtime reconcile never crashes.
- DP does not revalidate CP-pushed port conflicts; bind failure skips only the conflicting proxy.

## Pool Keys And DNS

- Pool keys must include every field affecting connection identity: destination, protocol/TLS, DNS override, upstream subset, CA, mTLS cert/key, SNI, SAN digest, verification flag, and SVID generation.
- HTTP/reqwest keys additionally include builder-only client settings that cannot be applied per request (idle timeout, TCP keepalive, HTTP/2 keep-alive / windows / adaptive-window / max-frame-size). Divergent values partition clients so first-creator-wins leakage cannot occur.
- HTTP key shell: `{dest}|{proto}|{dns_override}|{subset}|{ca}|{mtls_cert}|{mtls_key}|{sni}|{san_digest}|{verify}|{svid_generation}|{reqwest_builder_identity}`.
- gRPC and direct-H2 keys include host, port, DNS override, subset, TLS identity fields, verification, SVID generation, and shard suffix `#N`.
- H3 keys include host, port, LB target index, DNS override, subset, TLS identity fields, verification, and SVID generation.
- Never add per-request policy fields such as connect/read timeouts or global-only pool sizes to pool keys.
- Subset must partition pools so DestinationRule subset TLS overlays cannot share connections accidentally.
- Per-request timeouts are applied per request. Shared reqwest clients must not leak connect/read timeouts across proxies.
- Direct-H2 still documents a first-materializer tradeoff for TCP keepalive applied at dial time (not in the H2 pool key); that does not apply to the reqwest pool, where builder-only settings are part of client identity.
- Per-request `connect_timeout` depends on the vendored reqwest patch at `vendor/reqwest-0.13.3-ferrum-patched/` (`docs/upstream-reqwest-patches/001-per-request-connect-timeout/`). Do not change pool sharing or timeout semantics without preserving that request-scoped override behavior.
- Every production `reqwest::Client::builder()` must install `DnsCacheResolver` from the shared DNS cache.
- DNS cache is shared by normalized hostname, prewarmed, native-TTL by default, floored by `FERRUM_DNS_MIN_TTL_SECONDS`, stale-while-revalidate, and supports TCP fallback for truncated UDP. Shared entries store record data (`resolved_at`, native TTL, addresses); each caller evaluates freshness with its own effective TTL (per-proxy > global override > native). Refresh remains single-flight per hostname.

## Capability, Errors, And Health

- Backend capability registry chooses native H3, direct H2, or reqwest for plain HTTPS by concrete target. `Unknown` and `Unsupported` route through reqwest.
- Warmup populates capabilities when `FERRUM_POOL_WARMUP_ENABLED=true`; otherwise the refresh task runs an initial probe. Reloads coalesce to at most one in-flight refresh and one queued rerun.
- H3 downgrade must use `mark_h3_unsupported`/`mark_h2_tls_unsupported` guards and must not treat client disconnects, payload-size errors, graceful remote close, or `H3_NO_ERROR` GOAWAY as capability failures.
- `BackendResponse::connection_error` means exactly "the request body never reached the backend application layer."
- For H3, `H3PoolError::request_on_wire()` is authoritative for `connection_error`; do not AND it with generic error-class labels.
- Connect-phase reset/refused is a pre-wire connection failure. Mid-stream transport failures can still be capability-downgrade signals.
- Active health is shared per upstream target. Passive health is isolated per proxy. Never merge these maps or key passive health by upstream.
- `compute_health_bitset()` should keep O(1) map lookups and stack `u128` bitset for up to 128 targets, with Vec fallback above that.

## Performance Guards

- Keep `Arc<UpstreamTarget>` selection, response-header `get_mut()` before key allocation, preallocated body Vec from Content-Length, and retry header maps only when retry is configured.
- Keep hyper HTTP/1 `.writev(true)` on cleartext and TLS server builders.
- Avoid `Proxy.clone()` in gRPC/TCP hot paths; extract fields into parameter structs.
- Preserve H2 flow control budgets for gRPC, UDP `recvmmsg` frontend receive, QUIC 8-32 KiB coalescing with 2 ms flush, and Linux splice for plain-to-plain TCP.
- Never splice TLS without kTLS.
- Keep active optimizations unless tests prove removal is safe: router cache eviction CMS, `IP_BIND_ADDRESS_NO_PORT`, `TCP_FASTOPEN`, Date cache, TLS offload runtime, RED shedding, adaptive UDP buffers, `lazy_timeout`, cacheability predictor, `TCP_INFO`, kTLS, io_uring splice, UDP GSO, PKTINFO reply-source selection, `SO_BUSY_POLL`, and `HealthBitset`.
