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
- HTTP-family proxies (`http`, `https`, `ws`, `wss`, `grpc`, `grpcs`, `h3`) route by hosts and listen path. At least one is required. Optional `listen_port` scopes matching to that frontend port (Gateway API listener identity); omit it for port-agnostic matching.
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
- `sanitize_client_response_headers_for_wire` is the one final client-response boundary and its `Content-Length` decision is a TYPED `ClientResponseFraming`, never a bool and never inferred from a response header: `ExactBody` publishes the derived length, `Streaming` REMOVES the field (an unverifiable claim on bytes not yet written), `Head` is the only arm that preserves a valid `1*DIGIT` representation length, and `TrailersOnly` removes it. Derive `Head` only from the trusted request method / gateway-selected status (`for_streaming_response` / `for_buffered_response` / `for_final_reject`). Streaming writers that need the declared length internally (H3 graceful-close completeness, direct-H2 large-response coalescer bypass, body preallocation) must capture it with `preserved_response_content_length` BEFORE the boundary. Plugin/config surfaces may not author these destinations: `is_protocol_managed_plugin_response_destination` gates `response_transformer`, `response_mock`, `mesh_route_dispatch.response_transform`, `security_headers.set`, `opa.deny_headers`/`fail_closed_headers`, and `mcp_gateway.sessions.downstream_session_header`.
- Frontend TLS/DTLS handshakes are bounded by `FERRUM_FRONTEND_TLS_HANDSHAKE_TIMEOUT_SECONDS` before HTTP header timers start.
- Backend TLS/H2/gRPC/H3 handshakes are bounded by the per-proxy `backend_connect_timeout_ms` end-to-end connect budget.
- TLS/DTLS-terminating frontends must complete frontend crypto/admission before backend dispatch. Frontend handshake failures and plugin rejects must not dial backends or trip backend circuit breakers.
- HTTP/3 0-RTT is disabled by default, method-gated by `FERRUM_TLS_EARLY_DATA_METHODS`, strips client `Early-Data`, and reinjects `Early-Data: 1` outbound. When enabled on a non-mTLS listener, QUIC rustls `max_early_data_size` is `u32::MAX` (quinn accepts only `0` or `2^32-1`; no finite QUIC TLS byte cap). A listener with a frontend client-cert verifier sets that TLS value to `0` and refuses the 0.5-RTT `into_0rtt()` accept path (`zero_rtt_admitted`), because 0.5-RTT materialization precedes client authentication and makes `peer_identity()` unknowable. H3 peer identity + early-data state are one per-connection `ArcSwap` snapshot (`http3::peer_identity::H3ConnectionIdentity`), read once per accepted request stream and published exactly once after a successful handshake; the 0.5-RTT accept loop drains already-ready streams before publishing. An identity-bearing snapshot is never early data, and a failed/cancelled handshake leaves the slot empty and early-data-gated.

## Protocol Paths

- HTTP/1.1: hyper to reqwest through `ConnectionPool`; streaming default.
- HTTP/2: hyper ALPN to reqwest or `Http2ConnectionPool`; streaming default.
- HTTP/3: quinn/h3 standalone server to `Http3ConnectionPool` or cross-protocol bridge; streaming through the shared H3 coalescer.
- gRPC: hyper H2 direct through `GrpcConnectionPool`, not reqwest, to preserve trailers.
- WebSocket: hyper upgrade or H2/H3 Extended CONNECT to backend WebSocket transport; persistent and frame-by-frame.
- TCP: `TcpListener` to `TcpStream::connect`; splice on Linux unconditionally for plain-to-plain (and for TLS frontends when kTLS install succeeds), else userspace copy. Frontend-TLS kTLS handoff runs from `proxy::ktls_accept` — an `UnbufferedServerConnection` driven to `WriteTraffic` with record-exact socket reads, then `dangerous_into_kernel_connection` (issues #2955/#3619). It is TLS 1.2 only (TLS 1.3 KeyUpdate is refused, not approximated), requires a plain backend and no decrypted first-bytes plugin, and decides eligibility from a PEEKED ClientHello so every refusal falls back to the buffered tokio-rustls accept with the socket untouched. Never hand off from the buffered `TlsStream`: its inbound deframer alignment is not observable. `UnbufferedServerConnection` has NO `server_name()` accessor, so the kTLS leg re-parses SNI from the peeked hello with `sni::extract_sni_from_client_hello`, whose DNS validator is deliberately STRICTER than rustls's `DnsName` (it refuses underscore labels and a trailing root dot, which rustls accepts and would surface). A hello carrying a `server_name` extension that this parse cannot represent therefore DECLINES the handoff (`ClientHelloKtlsFacts::sni_is_representable`, checked before the handoff handshake) so the buffered accept reports rustls's own value — never relay a kTLS leg whose `sni_hostname` would differ from the userspace path's, and do not "fix" this by loosening the shared passthrough SNI validator. `FERRUM_FRONTEND_TLS_HANDSHAKE_TIMEOUT_SECONDS` is ONE deadline shared by the hello peek, the unbuffered handshake, and the buffered fallback (`tls::frontend_tls_handshake_deadline` + `accept_with_optional_deadline`), never a fresh timer per stage, and the timeout/failure metric is recorded once. On a spliced kTLS connection the TLS close handshake is explicit in both directions (`proxy::ktls_record`): a receive-side `splice` `EINVAL` is resolved by reading the queued record with the `SOL_TLS`/`TLS_GET_RECORD_TYPE` `recvmsg` contract and ONLY an authenticated warning-level `close_notify` is clean EOF (fatal/other alerts, other control records, malformed alert bodies, and unrelated `EINVAL` stay attributed errors). A bare FIN is NOT an EOF on a kTLS receive side: both `splice` `n == 0` and a zero-byte `recvmsg` while resolving `EINVAL` are attributed read failures (TLS truncation). A clean backend EOF emits exactly one warning `close_notify` via `TLS_SET_RECORD_TYPE` `sendmsg` before `shutdown(SHUT_WR)`, and only a `sendmsg` reporting EXACTLY the two alert bytes counts as emitted — short/zero/oversized is an attributed write error, while the raw half-close still follows to prevent teardown from hanging. Every `msg_control` buffer is `ktls_record::AlignedCmsgBuf` (storage overlaid with a real `libc::cmsghdr`); never point `msg_control` at a `[u8; N]`, and gate every `CMSG_DATA` read on the header declaring at least `CMSG_LEN(1)`. rustls stops counting protected messages at `dangerous_into_kernel_connection`, so the relay owns the traffic-key confidentiality budget (`proxy::ktls_confidentiality`): the negotiated suite's `CipherSuiteCommon::confidentiality_limit` is read from rustls (2^24 for TLS 1.2 AES-GCM, `u64::MAX` for ChaCha20-Poly1305, which is therefore unenforced by design), each direction gets its own guard seeded from a post-install `getsockopt(SOL_TLS, TLS_TX/TLS_RX)` `rec_seq` readback so the handshake's own records are already counted, and every relay syscall PRE-CHARGES its worst-case record count (`ceil(bytes/2^14)+1` for transmit; `receive-ceiling/29` for receive) so a kernel observation is paid for only when the window closes. Plaintext byte counters are NOT a record bound — a peer picks its own record sizes. Finite-limit AES-GCM suites MUST be removed from kTLS ClientHello eligibility before the handshake consumes the socket: Linux `FIONREAD` omits out-of-order skbs admitted before an `SO_RCVBUF` pin, so a safe receive-record ceiling cannot be established post-accept. Those connections fall back to buffered userspace rustls; only unlimited ChaCha20-Poly1305 remains eligible for kTLS. Do not restore AES-GCM handoff using `FIONREAD`, `SO_RCVBUF`, `tcp_rmem`, `/proc`, or another userspace queue sample. Never make enforcement per-byte, never widen a window without re-observing, and never treat an unreadable/malformed/non-monotonic `rec_seq`, an exhausted budget, or a step larger than the remaining budget as anything but an attributed relay failure (receive → read side, transmit → write side). Every cipher with a finite limit is dropped from ClientHello eligibility, so the refusal happens before the handshake is consumed. Cipher installability is probed with `setsockopt(SOL_TLS, TLS_TX)` and the kernel compares `optlen` against its own `tls12_crypto_info_*` size for EXACT equality, so `socket_opts::ktls` pins all three struct layouts (size and `rec_seq` offset) to `libc`'s UAPI definitions with compile-time assertions: ChaCha20-Poly1305's salt member is ZERO-length (56-byte struct, not 60), and a wrong length is `EINVAL`, which is indistinguishable from a kernel that lacks the cipher. The availability probe therefore records each cipher's install `errno`, and `ktls::ktls_availability_diagnostic()` is what the live gate's failure message reports — never a bare boolean. `bidirectional_copy` may not carry a kTLS client leg. The live-kernel proof is `proxy::ktls_live_kernel_tests`, run by the required `Unit Tests` job with `FERRUM_KTLS_LIVE_REQUIRED=1`; it must exercise the production ChaCha20-Poly1305 handoff (unlimited policy) and the AES-GCM refusal-before-consumption path on the hosted kernel — do not weaken it to a unit-only path, silently skip unavailable production coverage, or re-pin the live offer set to AES, and keep its expected pass count at three by folding new live coverage into an existing test. The splice loops enforce `tcp_idle_timeout_seconds`, `tcp_half_close_max_wait_seconds`, `backend_read_timeout_ms`, and `backend_write_timeout_ms` inline via per-direction watermarks — there is no eligibility gate based on timeout configuration. Opt-in outbound PROXY protocol v2 (`backend_proxy_protocol: v2`) writes the header on the backend TCP socket immediately after connect and before any relayed bytes (including before backend TLS handshake and before splice/kTLS engagement).
- UDP: `UdpSocket` per session; GSO-batched send on Linux.
- `Proxy.dispatch_kind` is precomputed at config load by `GatewayConfig::resolve_dispatch_kind()`.
- Buffer only when a plugin requires request/response body buffering or retry needs replay. SSE always streams.
- `ProxyBody` response coalescing uses one generic `Coalescing<S: FrameSource>` adapter with reqwest, H2/gRPC, and H3 sources. Do not create parallel per-protocol coalescers.
- Direct-H2 plain responses bypass `coalescing_h2_body` only when `Content-Length` is known, within max response limit, and at least 512 KiB.

## HTTP/3 And gRPC

- H3 clients can hit any `https` backend. Native H3 backend dispatch is used only when the capability registry proves the concrete target supports H3.
- H3 WebSocket bridges to the same backend WebSocket transport and frame-plugin pipeline as H1/H2; the H3 frontend never speaks WebSocket directly to a backend.
- H3 cross-protocol request bodies use bounded channel bridges: Plain streams into reqwest and non-replayable native gRPC streams DATA/trailers into `GrpcBody::Channel`; retry/body-plugin/pre-buffered gRPC retains the buffered representation. Responses stream with the H3 coalesce window when retry/plugin policy allows.
- Forward gRPC trailers with `send_trailers` on buffered and streaming H3 bridge responses.
- QUIC connection migration must compare `remote_address()` per request. Rebuild `Arc<str>` only on actual change so per-IP limits follow migrated clients.
- The vendored `h3` crate at `vendor/h3-0.0.8-ferrum-patched/` carries Ferrum's frame-drain-on-QUIC-close, H3 WebSocket Extended CONNECT, and buffered-trailer-peek (`peek_recv_trailers`) patches. Keep `docs/upstream-h3-patches/` lifecycle notes in sync when touching H3 dispatch, graceful-close classification, or the vendor copy.
- gRPC uses `GrpcBody::Streaming(Incoming)` for H1/H2 frontends and `GrpcBody::Channel` for the H3-to-H2 bridge when no body plugins and no retries. Otherwise use a buffered variant.
- Streaming gRPC responses use `coalescing_h2_body`, preserve trailers, and keep the 128 KiB target unless tests justify a change.
- The H3→gRPC bridge is the ONE H3 surface with mesh transport dispatch (issue #3284). Both `dispatch_grpc` (buffered/retryable) and `dispatch_grpc_streaming` (channel-backed) resolve the LB-selected target through `grpc_proxy::GrpcDispatchTransport::for_target` BEFORE reading the body or dialing, and re-resolve it PER RETRY ATTEMPT. `Direct` is the untagged pool; a `mesh.mtls` target rides `state.mesh_mtls_pool` (same-cluster pinned peer, or the cross-cluster east-west branch) with the request `:authority` from the SHARED `proxy::mesh_mtls_dispatch_authority`; a `mesh.hbone` target rides a NESTED `hyper::client::conn::http2` client over `state.hbone_pool`'s CONNECT byte tunnel (the destination relay byte-copies to the app socket, so the inner connection is ordinary h2c and trailers survive — which the generic HTTP-family HBONE path's inner HTTP/1.1 client cannot do). There is deliberately NO “direct dial anyway” arm: an unsupported class, an ambiguous both-tags target, or unmaterializable identity/SNI/trust metadata FAILS CLOSED with a Trailers-Only gRPC UNAVAILABLE whose message is a fixed constant that never echoes a SPIFFE ID, SNI name, trust domain, or dial address. The H3→HTTP plain bridge, the native-H3 backend pool, and the H3 WebSocket bridge still refuse ANY mesh-tagged target — do not generalize the gRPC transport to them without wiring their own trailer/upgrade semantics.

## Stream Proxy Rules

- `passthrough: true` stream proxies forward encrypted bytes without termination. TCP peeks ClientHello for SNI, then `bidirectional_copy`; UDP parses first DTLS ClientHello for SNI and uses a plain UDP backend.
- Passthrough is stream-only, mutually exclusive with `frontend_tls`, and rejects backend TLS fields.
- Opaque-TLS SNI routing is NOT limited to passthrough (issue #3264). The plane is `Proxy::joins_opaque_tls_sni_plane()` — `passthrough: true` on any stream scheme, OR an ordinary `tcp` listener with `frontend_tls: false`. `stream_listener::joins_sni_plane` mirrors it and the two must stay in step: grouping and validation would otherwise disagree about which listener owns a port. A port becomes an `__sni_{port}` group when more than one passthrough candidate shares it OR any plane candidate declares `hosts`; every plane candidate on such a port joins the group (a hostless one is its catch-all). `tcp_proxy` re-derives "this is an SNI group" as "any candidate is passthrough or declares hosts" — sound only because an `__l4_{port}` group can contain neither. `hosts` on a stream listener that cannot read a ClientHello (`frontend_tls`, `tcps`, non-passthrough `udp`/`dtls`) is a validation ERROR, never silently inert.
- Route precedence on an SNI group is absolute, not declaration order: exact host → wildcard → the single empty-`hosts` catch-all → refuse. An empty-`hosts` candidate is the DEFAULT route and does NOT count as a host overlap (validation caps it at one); do not re-route it through `hosts_overlap`, which is the HTTP router's helper and would make the third tier unreachable. Candidates that all carry `stream_match` keep Istio first-match-wins instead.
- `src/proxy/sni.rs` is the ONE ClientHello parser (opaque SNI routing, mesh inbound, kTLS gate, DTLS passthrough). `extract_sni_from_tcp_stream` is a projection of `peek_client_hello_sni`; `peek_client_hello_sni`/`classify_client_hello` answer "what hostname, and why not" as `ClientHelloSni`. Route classification MUST validate the bounded wire span and the complete declared ClientHello BEFORE invoking the lenient hostname extractor: an early readable SNI must never hide an oversized hello, malformed trailing extension data, a duplicate extension of ANY type (the TLS grammar forbids repeating any extension type, not just `server_name`), or a `ServerNameList` repeating any `name_type`. Both duplicate checks use a fixed code-point bitset (`SeenCodePoints`), never a rescan of the already-seen values — the extension vector is attacker-controlled up to the 16 KiB cap, so a quadratic detector would be hostile-input work. `extract_sni_from_client_hello` is the shared raw-slice extractor used only after that strict gate (and by non-admission consumers). Do not add a second parser and do not loosen the DNS validator (kTLS depends on its strictness).
- SNI route selection fails closed: `Sni` routes by host, `NoSni` uses the catch-all tier, `NotTls` is refused unless `FERRUM_STREAM_SNI_PLAINTEXT_FALLBACK=true`, and EVERY `Indeterminate` (timeout / 16 KiB peek cap / EOF / truncated / malformed / unrepresentable `server_name`) is refused REGARDLESS of that flag — an unreadable hello may have declared any tenant's hostname. Refusal happens before route resolution, so no backend is selected, dialed, health-scored, or breaker-charged. The peek is non-consuming, so every inspected byte is replayed verbatim to the chosen backend.
- `StreamConnectionContext.sni_hostname` and `consumer_username` from `effective_identity()` must flow to stream lifecycle plugins.
- Do not move terminating TLS/DTLS frontends to backend-first ordering.
- TCP userspace `copy_bidirectional` fast path is enabled only when idle timeout, half-close max wait, backend read timeout, and backend write timeout are all zero. The Linux splice and io_uring splice paths enforce these bounds inline and stay engaged regardless of timeout configuration.
- Direction-tracking userspace TCP relay is the default when any bound is nonzero; it provides idle timeout, half-close cap, byte counters, and first-failure attribution.
- TCP read/write timeouts refresh on read progress or partial-write progress. Slow but progressing backends must not be classified as inactive. This applies to userspace copy, splice, io_uring splice, and kTLS splice paths uniformly — `splice_one_direction_no_guard`, `libc_splice_loop`, and `io_uring_splice_loop` refresh the same per-direction watermarks the userspace path uses.
- Stream proxy port validation happens at config, admin API, startup reconcile, and runtime reconcile. Startup bind is fatal in db/file and non-fatal in DP. Runtime reconcile never crashes.
- DP does not revalidate CP-pushed port conflicts; bind failure skips only the conflicting proxy.
- TCP `FERRUM_ACCEPT_THREADS > 1` SO_REUSEPORT accept loops are supervised as peers: any unexpected loop exit cancels siblings, clears `started`, and fails the listener task so reconcile/readiness cannot stay healthy with silently reduced accept capacity. Operator shutdown remains a clean success.
- DTLS frontend `DtlsServer::run` is supervised beside `accept()`: unexpected recv-loop exit (error, panic, or unexpected cancel) clears `started` and fails the listener for reconcile/restart; operator/global shutdown remains a clean success.

## Pool Keys And DNS

- Pool keys must include every field affecting connection identity: destination, protocol/TLS, DNS override, upstream subset, direct-H2/gRPC effective `pool_http2_max_concurrent_streams`, CA, mTLS cert/key, SNI, SAN digest, verification flag, and SVID generation.
- HTTP key shell: `{dest}|{proto}|{dns_override}|{subset}|{ca}|{mtls_cert}|{mtls_key}|{sni}|{san_digest}|{verify}|{svid_generation}|{rcfg}`.
- The trailing `rcfg=…` segment on the reqwest pool key encodes every client-level setting that `create_client` bakes into the shared `reqwest::Client` (idle timeout, TCP keepalive, H2 keepalive/windows/adaptive/max-frame). Adaptive window (`aw=1`) takes precedence over fixed initial windows, so `sw`/`cw` appear only when adaptive is off. Secrets never appear in pool keys or key logs. Reqwest does not consume `http2_max_concurrent_streams`, so that field stays out of `rcfg`.
- gRPC and direct-H2 keys include host, port, DNS override, subset, effective H2 max concurrent streams (`none` or decimal), TLS identity fields, verification, SVID generation, and shard suffix `#N`.
- H3 keys include host, port, LB target index, DNS override, subset, TLS identity fields, verification, and SVID generation.
- Exclude request-only policy fields that dispatch can apply per request (connect/read timeouts). Exclude `max_idle_per_host` from the reqwest key by deliberate global-only tradeoff (per-proxy values would over-fragment). Direct-H2/gRPC may still document first-materializer tradeoffs for remaining builder settings that are not in those keys (for example keepalive), but `pool_http2_max_concurrent_streams` is keyed.
- Subset must partition pools so DestinationRule subset TLS overlays cannot share connections accidentally.
- Request-only policy fields are applied per request. Shared reqwest clients must not leak request timeouts across proxies; client-baked settings are isolated by the `rcfg` key segment instead.
- Per-request `connect_timeout` depends on the vendored reqwest patch at `vendor/reqwest-0.13.3-ferrum-patched/` (`docs/upstream-reqwest-patches/001-per-request-connect-timeout/`). Do not change pool sharing or timeout semantics without preserving that request-scoped override behavior.
- Every production `reqwest::Client::builder()` must install `DnsCacheResolver` from the shared DNS cache.
- DNS cache is shared, prewarmed, native-TTL by default, floored by `FERRUM_DNS_MIN_TTL_SECONDS`, stale-while-revalidate, and supports TCP fallback for truncated UDP.

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
