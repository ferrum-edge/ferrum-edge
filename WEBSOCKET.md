# WebSocket Proxying

Ferrum Gateway supports bidirectional WebSocket proxying for `ws://` and `wss://` backend protocols.

## Architecture

WebSocket requests are detected via the `Upgrade: websocket` header and routed separately from normal HTTP:

1. **Upgrade detection** - `is_websocket_upgrade()` checks for WebSocket upgrade headers
2. **Route matching** - Uses the same router cache as HTTP for O(1) lookups
3. **Authentication** - Proxies with plugins go through `handle_websocket_request_authenticated()`; those without go through `handle_websocket_request()`
4. **Handshake** - Gateway returns HTTP 101 Switching Protocols with the `sec-websocket-accept` key
5. **Connection takeover** - `OnUpgrade` is extracted from the request; a spawned task awaits the upgrade and begins proxying
6. **Bidirectional forwarding** - `handle_websocket_proxying()` splits both client and backend streams, forwarding messages in both directions via `tokio::select!`

```
Client <--ws--> Gateway <--ws/wss--> Backend
```

The gateway terminates the client WebSocket connection and opens a separate connection to the backend. Text, binary, ping, pong, and close frames are all forwarded.

## TLS for `wss://` Backends

Backend WebSocket connections use `tokio_tungstenite::connect_async_tls_with_config()` with a custom `rustls` TLS connector that respects both proxy-level and global TLS settings:

- **TLS library**: rustls (not native-tls/OpenSSL)
- **Root CA store**: `webpki-roots` (Mozilla's root certificates compiled into the binary), plus any custom CA bundles
- **Server certificate verification**: Controlled by proxy-level `backend_tls_verify_server_cert` (default: `true`) and global `FERRUM_BACKEND_TLS_NO_VERIFY`
- **Custom CA bundles**: Proxy-level `backend_tls_server_ca_cert_path` takes priority; falls back to global `FERRUM_BACKEND_TLS_CA_BUNDLE_PATH`
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
- **Max frame size**: 16 MiB per WebSocket frame
- **Max message size**: 64 MiB per WebSocket message (a message can span multiple frames)

## URL Routing

WebSocket backend URLs are built using the same path logic as HTTP proxying:

- `strip_listen_path`: When `true`, the proxy's `listen_path` prefix is stripped from the forwarded path
- `backend_path`: Prepended to the forwarded path
- Query strings are preserved and forwarded

## Key Files

| File | Purpose |
|------|---------|
| `src/proxy/mod.rs` | WebSocket upgrade handling, TLS connector, and bidirectional proxying |
| `tests/functional/functional_websocket_test.rs` | Functional tests |
| `tests/unit/gateway_core/websocket_auth_tests.rs` | Auth integration tests |
| `tests/helpers/bin/websocket_echo_server.rs` | Echo server for testing |
