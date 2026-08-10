# WebSocket Proxying

Ferrum Edge supports bidirectional WebSocket proxying for `ws://` and `wss://` backend protocols.

## Architecture

WebSocket requests are classified once by `detect_http_flavor()` and routed separately from ordinary HTTP. Three client-facing frontends are supported; all share the same plugin pipeline (`on_ws_frame`, `on_ws_disconnect`, sticky-session cookies) and the same backend relay:

| Frontend | Mechanism | Client response |
|----------|-----------|-----------------|
| HTTP/1.1 | `Upgrade: websocket` (RFC 6455) | `101 Switching Protocols` with `Sec-WebSocket-Accept` |
| HTTP/2 | Extended CONNECT with `:protocol=websocket` (RFC 8441) | `200 OK` (no H1 upgrade headers) |
| HTTP/3 | Extended CONNECT with `:protocol=websocket` (RFC 9220) | `200 OK` over QUIC DATA frames |

The H3 frontend is gated by `FERRUM_HTTP3_WEBSOCKET_ENABLED` (default: `true`). When disabled, the H3 listener does not advertise Extended CONNECT support and returns `501` to WebSocket CONNECT requests. See [FEATURES.md](FEATURES.md) and [docs/http3.md](docs/http3.md).

Common path after classification:

1. **Route matching** - Uses the same router cache as HTTP for O(1) lookups
2. **Authentication & Authorization** - All WebSocket connections go through the full plugin authentication and authorization pipeline, the same pipeline used for HTTP requests
3. **Handshake** - H1 returns `101 Switching Protocols`; H2/H3 Extended CONNECT returns `200 OK`
4. **Connection takeover** - H1 extracts `OnUpgrade` and spawns the relay task; H2/H3 open the tunneled stream directly
5. **Bidirectional forwarding** - `handle_websocket_proxying()` splits both client and backend streams, forwarding messages in both directions via `tokio::select!`

```
Client <--ws--> Gateway <--ws/wss--> Backend
```

The gateway terminates the client WebSocket connection and opens a separate connection to the backend. Text, binary, ping, pong, and close frames are all forwarded.

## TLS for `wss://` Backends

Backend `wss://` dials build a `rustls` client config through `build_websocket_tls_connector()` (same `BackendTlsConfigBuilder` / `build_root_cert_store` path as HTTP/HTTPS backends) and connect via Ferrum's own dial path: TCP is opened first, the byte-level `WsActivityIo` idle adapter is installed under TLS, then `client_async_tls_with_config()` completes the handshake on that stream. Ferrum deliberately does **not** use `connect_async_tls_with_config()` — that helper dials TCP internally and cannot install the idle adapter beneath the TLS layer.

- **TLS library**: rustls (not native-tls/OpenSSL)
- **Root CA store (exclusive, first match wins)**:
  1. Per-proxy `backend_tls_server_ca_cert_path` — when set, **only** certificates from this bundle are trusted
  2. Global `FERRUM_TLS_CA_BUNDLE_PATH` — when no per-proxy CA is set but this is set, **only** certificates from this bundle are trusted
  3. Built-in `webpki-roots` — used only when neither custom CA path is configured

  Custom CAs **replace** public roots; they are not additive. If you need both an internal CA and publicly-signed backends, concatenate the public roots into your custom PEM bundle (see [docs/backend_mtls.md](docs/backend_mtls.md)).
- **Server certificate verification**: Controlled by proxy-level `backend_tls_verify_server_cert` (default: `true`) and global `FERRUM_TLS_NO_VERIFY`
- **Client certificates (mTLS)**: Proxy-level `backend_tls_client_cert_path`/`backend_tls_client_key_path` take priority; falls back to global `FERRUM_BACKEND_TLS_CLIENT_CERT_PATH`/`FERRUM_BACKEND_TLS_CLIENT_KEY_PATH`

This matches the same TLS configuration hierarchy used by HTTP/HTTPS backends in `connection_pool.rs`.

## Header Forwarding

Client request headers are forwarded to the backend WebSocket server during the upgrade handshake. The following hop-by-hop and WebSocket handshake headers are excluded:

- `connection`, `upgrade`, `transfer-encoding`, `te`, `trailer`, `keep-alive`
- `sec-websocket-key`, `sec-websocket-version`, `sec-websocket-accept`
- `host`, `proxy-authorization`, `proxy-connection`

All other headers (including `authorization`, `cookie`, `sec-websocket-protocol`, custom headers, etc.) are forwarded to the backend.

## Timeouts and Limits

- **Connect timeout**: Uses the proxy's `backend_connect_timeout_ms` setting (default: 5000ms) for the backend WebSocket connection
- **Active connection cap**: `FERRUM_WEBSOCKET_MAX_CONNECTIONS` limits concurrently upgraded WebSocket connections (default: 20,000). Upgrades beyond the cap are rejected with `503 Service Unavailable`
- **Max frame size**: `FERRUM_MAX_WEBSOCKET_FRAME_SIZE_BYTES` (default: 16 MiB / 16,777,216 bytes) per WebSocket frame
- **Max message size**: 4× the frame limit (default: 64 MiB / 67,108,864 bytes); a message can span multiple frames. Plugins with tighter `ws_message_size_limiting` rules may lower the effective ceiling
- **Upgrade flood protection**: WebSocket requests go through the normal plugin pipeline before upgrade, so `rate_limiting` and `ip_restriction` can throttle abusive upgrade bursts
- **Absolute authorization lifetime**: `FERRUM_WEBSOCKET_MAX_LIFETIME_SECONDS` (default: 3600, valid range: 1–86400) bounds every session from request receipt. When JWT, JWKS, OIDC, or OAuth2 introspection supplies an authoritative expiry, the earlier validated credential deadline wins. JWT/OIDC leeway is included exactly once using the provider's existing validation setting. Traffic, Ping/Pong, and low-rate bidirectional streams never extend this deadline. Credentials without expiry remain bounded by the configured maximum.

Idle timeout and authorization lifetime are independent. Idle timeout answers “has either peer been quiet?” and can be refreshed by traffic. Authorization lifetime answers “is this upgraded session still allowed to exist?” and is absolute. The H1 Upgrade, H2 Extended CONNECT, and H3 Extended CONNECT paths share the same deadline/cancellation implementation. Expiry or graceful drain closes both relay directions with a fixed, non-secret close reason when frame-aware closure is possible; tunnel mode deterministically drops both transports at the same deadline.

A policy close is not a relay failure. `on_ws_disconnect` reports no `error_class` for it, so `ferrum_websocket_sessions_total` records `result="success"` and the cause is carried by `termination_reason` (`credential_expired`, `max_lifetime`, or `drain`) — a stalled relay stays distinguishable from a session that simply reached its bound. Upgrades refused because the deadline elapsed before the handshake completed are logged as the `websocket_credential_expired` (`401`) or `websocket_max_lifetime` (`503`) rejection phase on all three frontends. Tunnel-mode sessions cancelled at the deadline cannot report their relayed byte totals (the raw copy owns its counters and only publishes them when it returns); use frame mode when byte accounting must survive a forced close.

## Tunnel Mode

`FERRUM_WEBSOCKET_TUNNEL_MODE` defaults to `false`. When enabled for an
HTTP/1.1 or HTTP/2 WebSocket session with no frame-level plugins, Ferrum Edge
bypasses WebSocket frame parsing after the upgrade and relays bytes with raw
bidirectional TCP copy. This improves throughput for large payloads, but frame
inspection, per-frame size limits, and frame counters are unavailable. Attach a
frame-level plugin or leave tunnel mode disabled when those features are
required.

Tunnel takeover preserves any backend bytes read together with the
`101 Switching Protocols` response and forwards them before starting the raw
relay. This is important for server-push protocols: discarding the WebSocket
codec's buffered bytes during takeover would lose an initial frame coalesced
with the upgrade response.

Tunnel mode does not apply to HTTP/3 WebSockets. QUIC has no underlying raw TCP
stream to copy, so H3 sessions always use frame parsing and retain frame-level
plugin behavior even when `FERRUM_WEBSOCKET_TUNNEL_MODE=true`.

## URL Routing

WebSocket backend URLs are built using the same path logic as HTTP proxying:

- `strip_listen_path`: When `true`, the proxy's `listen_path` prefix is stripped from the forwarded path
- `backend_path`: Prepended to the forwarded path
- Query strings are preserved and forwarded

## Key Files

| File | Purpose |
|------|---------|
| `src/proxy/mod.rs` | H1/H2 WebSocket upgrade handling, backend TLS connector, and bidirectional proxying |
| `src/http3/websocket.rs` | H3 Extended CONNECT (RFC 9220) frontend and bridge to the shared relay |
| `tests/functional/functional_websocket_test.rs` | Functional tests |
| `tests/unit/gateway_core/websocket_auth_tests.rs` | Auth integration tests |
| `tests/helpers/bin/websocket_echo_server.rs` | Echo server for testing |
