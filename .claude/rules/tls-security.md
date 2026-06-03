---
paths:
  - "src/tls/**"
  - "src/dtls/**"
  - "src/secrets/**"
  - "src/identity/**"
  - "src/modes/tls_reload.rs"
  - "src/admin/jwt_auth.rs"
  - "src/plugins/*auth*.rs"
  - "src/plugins/mtls_auth.rs"
  - "src/plugins/jwks_auth.rs"
  - "src/plugins/utils/http_client.rs"
  - "src/plugins/utils/metadata_redaction.rs"
  - "docs/frontend_tls.md"
  - "docs/backend_mtls.md"
  - "docs/database_tls.md"
  - "SECURITY.md"
  - "tests/unit/tls/**"
  - "tests/unit/secrets/**"
  - "tests/unit/identity/**"
  - "tests/integration/*tls*"
  - "tests/integration/*svid*"
  - "tests/integration/*mtls*"
  - "tests/functional/*tls*"
  - "tests/functional/*secrets*"
  - "tests/functional/*mtls*"
---

# TLS, Secrets, And Security Rules

## Boundary Security

- Validate hostile input at trust boundaries: path traversal, malformed PEM/DER, invalid SANs, oversized bodies, recursive embedded credentials, and archive/file names.
- Escape user input when interpolating JSON/XML response bodies.
- Preserve transaction metadata redaction for all logger sinks.

## TLS-Only And Frontend Admission

- Port `0` on plaintext proxy/admin/CP gRPC listener settings disables plaintext and is excluded from `reserved_gateway_ports()`.
- Gateway warns if plaintext is disabled and no TLS listener is configured.
- TLS/DTLS-terminating client-facing protocols must complete frontend crypto and plugin admission before dialing a backend.
- Frontend handshake failures and plugin rejects must not trip backend circuit breakers.
- Frontend TLS/DTLS handshakes are bounded by `FERRUM_FRONTEND_TLS_HANDSHAKE_TIMEOUT_SECONDS`, default 10s. `0` disables.
- DTLS demux state is capped before per-peer channel/task allocation and released on handshake timeout.

## TLS Rotation Model

- Most file-based TLS materials are static operational inputs. Cert/key file changes require gateway restart or rolling redeploy unless explicitly listed below.
- Mesh peer-auth reload is limited to resolved inbound mTLS mode and frontend client CA verifier when `FERRUM_MESH_PEER_AUTH_LIVE_RELOAD_ENABLED=true`.
- Frontend cert/key live reload is enabled only when `FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED=true`.
- Frontend watcher covers proxy HTTPS/H2/H3 and admin HTTPS cert/key paths at `FERRUM_FRONTEND_TLS_WATCH_INTERVAL_SECONDS`, default 30s.
- On validated frontend change, rebuild rustls `ServerConfig`, rerun early-data and kTLS-secret-extraction settings, swap `SharedFrontendTls`, and notify H3 to call `Endpoint::set_server_config`.
- Reload parse, expiry, not-yet-valid, or key mismatch failures keep the previous config and emit `warn!`.
- In-flight TLS sessions keep their original `ServerConfig`; swapping must not tear down live sessions.
- DTLS frontend and operator-supplied per-proxy backend TLS paths remain static under frontend live reload.
- Gateway SVID cert/key/trust-bundle files are watched for backend client SVID rotation. Valid reload updates the SVID slot, preserves CP-delivered trust-bundle override, bumps `|svidg=<generation>`, drains old backend TLS caches, restarts HTTP health probes, and optionally force-drains old-generation pool entries after `FERRUM_MESH_SVID_ROTATION_DRAIN_SECONDS`.
- Backend CA bundles and ordinary backend client cert/key paths remain restart-required.

## Backend Trust

- Backend CA chain order is proxy `backend_tls_server_ca_cert_path`, then global `FERRUM_TLS_CA_BUNDLE_PATH`, then webpki/system roots.
- Opt-out is explicit: `backend_tls_verify_server_cert: false` or `FERRUM_TLS_NO_VERIFY=true`.
- Proxy backend reqwest paths pass a fully built rustls `ClientConfig` through `use_preconfigured_tls(...)`; trust store construction stays in-house.
- Custom CA is exclusive and replaces built-in roots. For reqwest use `.tls_certs_only([cert])`; for rustls start with `RootCertStore::empty()`.
- Reqwest no-custom-CA helper clients use `rustls-platform-verifier` through the bundled `rustls` feature: macOS keychain, Windows cert store, then webpki fallback on Linux.
- Helper-client verifier behavior applies only when no global or per-plugin CA is configured.

## Validation, Expiry, And CRL

- Per-proxy TLS paths are validated by `validate_all_fields_with_ip_policy()` at config load.
- File mode refuses startup for invalid TLS paths. DB mode warns. DP rejects the update and keeps cached config. No silent fallback.
- `check_cert_expiry()` checks `notBefore` and `notAfter` on all surfaces. Expired certs are hard failures.
- Warn within `FERRUM_TLS_CERT_EXPIRY_WARNING_DAYS`, default 30.
- `FERRUM_TLS_CRL_FILE_PATH` is PEM, loaded once, and `Arc`-shared.
- CRL applies to frontend mTLS for H1/H2/H3/DTLS, all rustls backend paths, and rustls logging sinks.
- CRL does not apply to DP-to-CP gRPC or reqwest-based plugin paths because those stacks do not expose compatible CRL config.
- CRL reload requires restart.

## Pooling And Non-Rustls Paths

- Reqwest TLS paths use distinct `reqwest::Client` instances per cert/trust identity.
- The shared `PluginHttpClient` disables HTTP redirect following (`reqwest::redirect::Policy::none()`) in every constructor, matching the backend proxy client. A server-returned 3xx is surfaced to the caller, never chased, so a spoofed/compromised upstream cannot bounce plugin egress (log/webhook sinks, OIDC/JWKS discovery, AI federation) to an internal or cloud-metadata host. First-hop host pinning in callers like `jwks_auth` is necessary but not sufficient; the `DnsCacheResolver` IP screen (`check_backend_ip_allowed`) only blocks private/loopback/link-local under a restrictive `FERRUM_BACKEND_ALLOW_IPS`, not the default `Both`.
- Rustls direct H2 and gRPC paths configure TLS per connection.
- `kafka_logging` uses librdkafka/OpenSSL: map `FERRUM_TLS_CA_BUNDLE_PATH` to `ssl.ca.location`, `FERRUM_TLS_NO_VERIFY` to `enable.ssl.certificate.verification=false`, and CRL to `producer_config.ssl.crl.location`.
- Redis applies global TLS flags through `PluginHttpClient` accessors.
- Rustls logging sinks (`tcp_logging` TLS, `ws_logging` wss, `udp_logging` DTLS) apply gateway CRLs through `PluginHttpClient::tls_crls()`.
- Plugins that bypass proxy dispatch and use shared `PluginHttpClient`, such as `ai_federation`, get global TLS only. For private endpoints, include internal CAs in the global bundle and include public roots too because custom CA is exclusive.

## External Secrets

- Secret resolution runs at startup before config load and before concurrent env access.
- Env suffixes resolve the base key: `_VAULT`, `_AWS`, `_AZURE`, `_GCP`, and `_FILE`.
- Backends are grouped per provider so one client is reused.
- Two providers setting the same base key is a conflict and must fail.
- Do not expose resolved secret values in errors or logs.

## Identity And SPIFFE

- Preserve SPIFFE/SVID trust-domain parsing and URI SAN validation behavior.
- SVID rotation must not mix stale cert/key material with new trust bundles.
- Gateway SVID pool-key generation uses the SVID generation marker to prevent pool poisoning across rotations.
- kTLS paths must zeroize secret material on drop and must not consume the TLS stream before kernel install is confirmed.
- Dev-only identity shortcuts stay double-gated. The self-signed CA bootstrap (`bootstrap_dev_root`) requires `FERRUM_MESH_CA_BOOTSTRAP_DEV=true`, the `StaticAttestor` requires `FERRUM_MESH_ALLOW_STATIC_ID=true`, and a `mesh` data plane with **no workload identity** — no file-based gateway SVID material (`FERRUM_GATEWAY_SVID_*`; the CA backend is validated but not yet wired to load a runtime SVID) — requires `FERRUM_MESH_ALLOW_NO_CA=true` (enforced in `EnvConfig::validate()`; fail-closed otherwise). All three opt-ins are read directly from the environment (NOT from `ferrum.conf`/`EnvConfig`) and are refused unconditionally when `FERRUM_MESH_PRODUCTION_MODE=true` — itself read via the canonical `identity::production_mode()` helper — so a config-file-only value can never bypass the production guard. Production PERMISSIVE mesh inbound TLS must also fail closed when `FERRUM_FRONTEND_TLS_CERT_PATH` / `FERRUM_FRONTEND_TLS_KEY_PATH` are absent; gateway SVID material is outbound identity and must not be treated as the inbound listener certificate/key. Do not relax any gate or collapse the per-posture opt-ins (`FERRUM_MESH_CA_BOOTSTRAP_DEV`, `FERRUM_MESH_ALLOW_STATIC_ID`, `FERRUM_MESH_ALLOW_NO_CA`) into a single flag.
