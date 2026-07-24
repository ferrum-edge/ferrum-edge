# Configuration Reference

Ferrum Edge is configured primarily through environment variables. An optional `ferrum.conf` file can provide defaults.

This page is the canonical human-readable reference for `FERRUM_*` variables and built-in defaults. Runtime behavior is defined in [`src/config/env_config.rs`](../src/config/env_config.rs); the root `ferrum.conf` is an editable operator template that mirrors this reference with concise comments and example values. When variables or defaults change, update the code, this reference, and then `ferrum.conf` so the template stays in sync without becoming the primary reference. The DOC-03 coverage contract in [`src/config/public_env_inventory.rs`](../src/config/public_env_inventory.rs) defines one complete machine-readable inventory of public operator `FERRUM_*` settings (including controls resolved outside `EnvConfig`). `tests/unit/config/env_docs_parity_tests.rs` fails closed when an inventory setting lacks either a variable-table row here or a `ferrum.conf` template assignment, and when production `EnvConfig` acceptance sites omit a key from that inventory.

## TLS Material Sources

TLS certificate, key, CA bundle, CRL, and OCSP staple variables that end in `_PATH` can also be supplied through a `_SOURCE` sibling. When both are set, `_SOURCE` wins and a startup warning names only the variable names, not the value.

Supported source values are filesystem paths, `file://` URIs, inline PEM values beginning with `-----BEGIN `, and typed external source URIs. Inline PEM is redacted in debug output and hashed in backend pool keys so private-key bytes are not logged or embedded in cache identifiers. `vault://`, `aws://`, `azure://`, and `gcp://` sources load through the same secret backends as the existing `_VAULT`, `_AWS`, `_AZURE`, and `_GCP` env-var suffixes, so they require the matching Cargo feature and provider credentials. Azure Key Vault references (`_AZURE` values and `azure://` identifiers) use `https://<vault>/secrets/<name>` for the latest version and `https://<vault>/secrets/<name>/<version>` to pin an exact version; extra path segments are rejected. A versioned URL always requests that version from Key Vault and never silently falls back to latest. Typed TLS `azure://` sources may also set `?version=<id>`; when both a path version and `?version=` are present they must match or the load fails closed. Inventory and material metadata report the version Key Vault actually returned. Kubernetes Secret sources use `k8s://<namespace>/<secret>#<data-key>` or `k8s://<namespace>/<secret>?key=<data-key>` and authenticate through the default `kube` client environment: in-cluster service account first, then local kubeconfig. If the data key is omitted, Ferrum defaults to `tls.crt` for certs, `tls.key` for keys, `ca.crt` for CA bundles, `tls.crl` for CRLs, `jwks.json` for JWKS material, and `ocsp.der` for OCSP responses. Frontend/admin, backend TLS, database TLS, and CP/DP gRPC TLS live reload register Kubernetes watches for named Secrets so cert-manager updates queue immediate source reloads; polling remains active as the fallback. Admin-managed records use `managed://certificates/<id>#cert`, `managed://certificates/<id>#key`, `managed://ca-bundles/<id>`, `managed://crls/<id>`, `managed://ocsp-responses/<id>#ocsp`, or `managed://jwks/<id>#jwks` and are stored under `FERRUM_TLS_MANAGED_STORE_PATH`. ACME-issued records use `acme://certificates/<id>#cert` and `acme://certificates/<id>#key`; they are stored under the same directory in `acme-certificates.json` and can be imported through `/admin/tls/acme/certificates` or issued through `/admin/tls/acme/orders`. ACME account credentials are persisted separately in `acme-accounts.json` for renewal reuse and are never returned by the admin API. HTTP-01, TLS-ALPN-01, and DNS-01 order challenge records are stored in `acme-orders.json`; proxy listeners serve `/.well-known/acme-challenge/{token}` before normal route matching for HTTP-01, TLS listeners return RFC 8737 validation certificates for ClientHello messages that offer only `acme-tls/1` with matching SNI while the order is pending, ready, or processing, and DNS-01 records expose `_acme-challenge.<domain>` TXT names and values that must be published before finalization. The optional `acme` Cargo feature compiles the `instant-acme` account/order client substrate used by HTTP-01, TLS-ALPN-01, DNS-01 order creation/finalization, and the ACME renewal scheduler. When `FERRUM_ACME_AUTO_RENEW_ENABLED=true`, serving modes scan issued ACME certificates, renew those inside `FERRUM_ACME_RENEW_WHEN_REMAINING_DAYS`, and automatically finalize HTTP-01/TLS-ALPN-01 renewals after storing their challenge material. DNS-01 auto-renewal can run a provider hook from `FERRUM_ACME_DNS01_HOOK_COMMAND`; Ferrum invokes the executable without a shell, passes challenge details through `FERRUM_ACME_DNS01_*` environment variables, waits `FERRUM_ACME_DNS01_PROPAGATION_SECONDS`, then asks the ACME directory to validate. Frontend/admin live reload polls external sources when `FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED=true`; backend TLS live reload polls backend cert/key/CA/CRL sources when `FERRUM_BACKEND_TLS_LIVE_RELOAD_ENABLED=true`; database TLS live reload polls DB CA/client cert/client key sources when `FERRUM_DB_TLS_LIVE_RELOAD_ENABLED=true` in database or CP mode. CP/DP gRPC TLS sources are watched by their owning mode whenever TLS material is configured. The default external-source poll interval is `FERRUM_SECRET_REFRESH_INTERVAL_SECONDS` and a source URI can override it with `?poll=60s`, `?poll=5m`, `?poll=1h`, or `?poll=1d`. Other runtime surfaces materialize external sources when their owning config is built. With the optional `pkcs11` Cargo feature, `FERRUM_FRONTEND_TLS_KEY_SOURCE`, `FERRUM_ADMIN_TLS_KEY_SOURCE`, and `FERRUM_BACKEND_TLS_CLIENT_KEY_SOURCE` may use `pkcs11://<label>?module=/path/to/pkcs11.so&pin_env=FERRUM_PKCS11_PIN` or `pkcs11://ignored?module_env=FERRUM_PKCS11_MODULE_PATH&label=<label>&id_hex=<hex>` for non-extractable RSA TLS keys. Ferrum loads the certificate chain from the configured cert source, opens the token for each TLS signing operation, and never materializes the private key as PEM. Without the `pkcs11` feature, `pkcs11://` key sources fail validation with a build-feature error. PKCS#11 support is currently scoped to rustls surfaces that accept custom signers: frontend/Admin API server TLS and backend TLS client authentication. Database, SVID, DTLS, and CP/DP gRPC key sources still require materializable PEM. See [pkcs11_tls.md](pkcs11_tls.md) for HSM deployment notes and the token-backed SoftHSM smoke test.

Available `_SOURCE` siblings:

`FERRUM_FRONTEND_TLS_CERT_SOURCE`, `FERRUM_FRONTEND_TLS_KEY_SOURCE`, `FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_SOURCE`, `FERRUM_FRONTEND_TLS_OCSP_RESPONSE_SOURCE`, `FERRUM_ADMIN_TLS_CERT_SOURCE`, `FERRUM_ADMIN_TLS_KEY_SOURCE`, `FERRUM_ADMIN_TLS_CLIENT_CA_BUNDLE_SOURCE`, `FERRUM_ADMIN_TLS_OCSP_RESPONSE_SOURCE`, `FERRUM_DB_TLS_CA_CERT_SOURCE`, `FERRUM_DB_TLS_CLIENT_CERT_SOURCE`, `FERRUM_DB_TLS_CLIENT_KEY_SOURCE`, `FERRUM_CP_GRPC_TLS_CERT_SOURCE`, `FERRUM_CP_GRPC_TLS_KEY_SOURCE`, `FERRUM_CP_GRPC_TLS_CLIENT_CA_SOURCE`, `FERRUM_DP_GRPC_TLS_CA_CERT_SOURCE`, `FERRUM_DP_GRPC_TLS_CLIENT_CERT_SOURCE`, `FERRUM_DP_GRPC_TLS_CLIENT_KEY_SOURCE`, `FERRUM_TLS_CA_BUNDLE_SOURCE`, `FERRUM_BACKEND_TLS_CLIENT_CERT_SOURCE`, `FERRUM_BACKEND_TLS_CLIENT_KEY_SOURCE`, `FERRUM_GATEWAY_SVID_CERT_SOURCE`, `FERRUM_GATEWAY_SVID_KEY_SOURCE`, `FERRUM_GATEWAY_SVID_TRUST_BUNDLE_SOURCE`, `FERRUM_DTLS_CERT_SOURCE`, `FERRUM_DTLS_KEY_SOURCE`, `FERRUM_DTLS_CLIENT_CA_CERT_SOURCE`, and `FERRUM_TLS_CRL_SOURCE`.

File-backed and external frontend/admin cert-key, client-CA, OCSP response, and CRL sources can use the frontend live-reload watcher. A frontend/admin or backend mTLS `pkcs11://` key source contributes a stable selector fingerprint so adjacent cert, client-CA, OCSP, and CRL rotations still reload cleanly; changing the token key behind the same URI requires changing the cert/source config or restarting so operators can validate the new certificate-key pairing. Backend cert/key/CA/CRL sources use the backend TLS live-reload watcher, which validates the active backend TLS configurations, refreshes the backend CRL slot, and clears backend client pools so new backend connections rebuild with the rotated material. Backend sources include global backend mTLS env vars, per-proxy settings, per-upstream settings, and direct-backend `mesh_route_dispatch.rules[].destination.backend_tls` overrides. The backend watcher recollects sources from the current gateway config on each pass, so config reloads that add or replace backend TLS sources are watched without restarting Ferrum. Database TLS sources can use the database TLS watcher in database and CP modes; on changed bytes Ferrum rebuilds the effective primary/read-replica URLs and reconnects the active SQL pool or MongoDB client so new DB connections use the rotated material. CP gRPC TLS sources are watched in CP mode and update the active TLS slot for new handshakes; DP gRPC TLS sources are watched in DP mode and reconnect the long-lived CP stream with fresh CA/client cert/key material. Watchers compare material byte fingerprints, so same-byte rewrites or same-value external-source fetches do not churn TLS configs. `k8s://` sources add a Kubernetes Secret watch for prompt cert-manager propagation and still use fingerprint polling as a backstop. Inline sources are static until config reload. Gateway SVID file rotation is enabled only when all three SVID sources resolve to files; `/admin/tls/rotate/svid` can force a source reload for any supported SVID source form. SQL and MongoDB drivers that require file paths receive secure temporary PEM files when the configured source is inline PEM, `file://`, or external PEM; the source value itself is never logged.

## Environment Variables

### Core Settings

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_CONF_PATH` | No | `./ferrum.conf` | Path to optional conf file (provides defaults; env vars override) |
| `FERRUM_MODE` | **Yes** | — | Operating mode: `database`, `file`, `cp`, `dp`, `mesh`, `injector`, `node_agent`, `migrate` |
| `FERRUM_NAMESPACE` | No | `ferrum` | Namespace this gateway loads and manages |
| `FERRUM_LOG_LEVEL` | No | `warn` | Log verbosity: `error`, `warn`, `info`, `debug`, `trace`. Controls the runtime tracing logs only; per-transaction access logs from the `stdout_logging` plugin are emitted independent of this level |
| `FERRUM_LOG_BUFFER_CAPACITY` | No | `4096` | Per-sink hard record-slot limit (stdout/access logs share one sink; stderr is separate). Actual admission is also constrained by `FERRUM_LOG_BUFFER_BYTES`. Clamped to 1–65,536; admission is lossy and non-blocking when either limit is full |
| `FERRUM_LOG_BUFFER_BYTES` | No | `33554432` | Per-sink aggregate serialized-payload byte budget. Admission provisionally reserves `FERRUM_LOG_MAX_RECORD_BYTES` before serialization, then queues an exact-sized allocation and shrinks that reservation to the serialized length until write completion. Clamped between `FERRUM_LOG_MAX_RECORD_BYTES` and 1 GiB |
| `FERRUM_LOG_MAX_RECORD_BYTES` | No | `65536` | Maximum serialized bytes for one runtime/access-log record, including its newline. Clamped to 1 KiB–1 MiB; larger records are dropped and counted |
| `FERRUM_LOG_SHUTDOWN_DRAIN_TIMEOUT_MS` | No | `2000` | Shared absolute budget for deferred terminal/mirror tasks and queued observability workers, followed by the per-process-log-sink drain. Clamped to 100–30,000 ms; tasks or records still outstanding at a lifecycle deadline are cancelled and counted |
| `FERRUM_LOG_REDACT_METADATA_KEYS` | No | — | Comma-separated additional metadata-key substrings to redact from `TransactionSummary.metadata` and `StreamTransactionSummary.metadata` before log serialization. Built-in sensitive substrings such as `authorization`, `cookie`, `password`, `secret`, and `token` are always redacted. Operators can further reshape per-plugin log output (rename keys, drop fields, reorder, add static / derived fields, flatten metadata, change timestamp format) via per-logging-plugin `schema:` blocks or a shared `transaction_log_schema` plugin — see [docs/log_schema.md](log_schema.md) |
| `FERRUM_SECRET_FETCH_TIMEOUT_SECONDS` | No | `30` | Timeout for each external secret fetch from file sources (`_FILE`, including FIFO/stalled-mount reads on a detached thread) and cloud backends (`_VAULT`/`_AWS`/`_AZURE`/`_GCP`), and for async cloud client/credential construction during startup batch resolution. **Startup env-secret resolution reads this from the environment only, not from `ferrum.conf`** — it runs before the settings file is parsed, and consulting the conf-file cache there would freeze it before a `FERRUM_CONF_PATH_FILE` source could install the intended settings path. A `ferrum.conf` value still applies to later runtime fetches (typed TLS provider URIs) |
| `FERRUM_GCP_SECRET_MANAGER_ENDPOINT` | No | — | Override the GCP Secret Manager service endpoint (base URL) used by `_GCP` / `gcp://` secret resolution. When set, the client targets this endpoint with anonymous credentials instead of `secretmanager.googleapis.com` with Application Default Credentials. Intended for pointing the real client at a local fake/emulator or an in-cluster proxy in tests and air-gapped setups; leave unset for normal production use. Requires the `secrets-gcp` Cargo feature. **Startup env-secret resolution reads this from the environment only, not from `ferrum.conf`**, for the same reason as `FERRUM_SECRET_FETCH_TIMEOUT_SECONDS` above: the GCP client is built while startup resolution is still running, so a conf-file lookup there would freeze the settings-file cache before a `FERRUM_CONF_PATH_FILE` source could install the intended path. A `ferrum.conf` value still applies to later runtime `gcp://` TLS-material fetches |
| `FERRUM_SECRET_REFRESH_INTERVAL_SECONDS` | No | `300` | Default poll interval for external TLS material sources (`vault://`, `aws://`, `azure://`, `gcp://`, `k8s://`, `acme://`, `managed://`) when a source URI does not include `?poll=`. Clamped to 1 second minimum and 24 hours maximum |
| `FERRUM_ACME_AUTO_RENEW_ENABLED` | No | `false` | Enable the ACME renewal scheduler in serving modes. Requires the `acme` Cargo feature |
| `FERRUM_ACME_RENEW_WHEN_REMAINING_DAYS` | No | `30` | Renew ACME-issued certificates when their `not_after` is within this many days |
| `FERRUM_ACME_RENEW_CHECK_INTERVAL_SECONDS` | No | `3600` | Interval between ACME renewal scans. Clamped to 60 seconds minimum and 24 hours maximum |
| `FERRUM_ACME_RENEW_CHALLENGE_TYPE` | No | `http01` | Challenge type prepared by automatic renewal: `http01`, `tls_alpn01`, or `dns01` |
| `FERRUM_ACME_RENEW_POLL_TIMEOUT_SECONDS` | No | `60` | Maximum ACME readiness/certificate polling time per automatic renewal |
| `FERRUM_ACME_DNS01_HOOK_COMMAND` | No | — | Executable provider hook for DNS-01 automation. Ferrum invokes it without a shell and passes `FERRUM_ACME_DNS01_ACTION`, `FERRUM_ACME_DNS01_IDENTIFIER`, `FERRUM_ACME_DNS01_TOKEN`, `FERRUM_ACME_DNS01_TXT_RECORD_NAME`, and `FERRUM_ACME_DNS01_TXT_VALUE` |
| `FERRUM_ACME_DNS01_PROPAGATION_SECONDS` | No | `60` | Wait time after DNS-01 hook publication before Ferrum asks the ACME directory to validate the challenge |
| `FERRUM_TLS_MANAGED_STORE_PATH` | No | `./ferrum-managed-tls` | Directory for file-backed admin-managed TLS records and recent TLS rotation events. The store persists uploaded certificates, private keys, CA bundles, and CRLs in `managed-tls.json` and bounded rotation history in `tls-events.json`; private keys are written with owner-only permissions on Unix |
| `FERRUM_PKCS11_MODULE_PATH` | No | — | Default PKCS#11 module path used by frontend/admin/backend mTLS `pkcs11://` key sources when the URI omits `?module=` and `?module_env=`. Requires the `pkcs11` Cargo feature |
| `FERRUM_PKCS11_PIN` | No | — | Optional example token user PIN variable for `pkcs11://...?pin_env=FERRUM_PKCS11_PIN`. Ferrum only reads it when a PKCS#11 key source references it, and never logs the value |
| `FERRUM_CLICKHOUSE_PASSWORD` | No | — | Optional materialized password used by the `api_chargeback_sink` plugin when its `clickhouse.password_ref` is set to `FERRUM_CLICKHOUSE_PASSWORD`. The plugin only accepts `FERRUM_*` password references. Populate this value directly or through existing secret suffixes such as `FERRUM_CLICKHOUSE_PASSWORD_FILE` / `_VAULT` / `_AWS` / `_AZURE` / `_GCP` |
| `FERRUM_NODE_ID` | No | `$HOSTNAME`, then `/etc/hostname`, then `unknown` | Stable node identity used by `api_chargeback_sink` for spool ownership under `<spool.dir>/<node_id>/` and written onto exported charge events. Accepts any non-empty trimmed string (whitespace-only is ignored); values longer than 512 characters are truncated. When `spool.dir` is on persistent storage, set a stable identity such as a StatefulSet ordinal so restarts do not orphan sibling spool directories from a previous identity |

Process-log admission always needs one maximum-record reservation while a new
record is serialized. After serialization, diagnostics report the actual bytes
retained by completed records plus any still-provisional reservation. Raising
`FERRUM_LOG_BUFFER_CAPACITY` alone has no effect when the byte budget is the
limiting constraint; size both limits from observed serialized record sizes and
leave at least `FERRUM_LOG_MAX_RECORD_BYTES` of byte headroom for the next
producer. If any supplied `FERRUM_LOG_*` numeric value is changed by its clamp,
Ferrum emits a startup warning naming the variable, supplied value, and applied
value.

### Proxy Listener

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_PROXY_HTTP_PORT` | No | `8000` | HTTP proxy listener port. Set to `0` to disable the plaintext HTTP listener (TLS-only operation) |
| `FERRUM_PROXY_HTTPS_PORT` | No | `8443` | HTTPS proxy listener port |
| `FERRUM_COMPRESSION_GZIP_ENABLED` | No | `true` | Process-wide gzip content-coding gate for the built-in `compression` plugin. When `false`, gzip (including the `x-gzip` compatibility token) is removed from every instance's response `algorithms` and opt-in gzip request decompression is disabled. Per-plugin configuration can narrow this global policy but cannot re-enable gzip |
| `FERRUM_COMPRESSION_BROTLI_ENABLED` | No | `true` | Process-wide Brotli content-coding gate for the built-in `compression` plugin. When `false`, `br` is removed from every instance's response `algorithms` and opt-in Brotli request decompression is disabled. Per-plugin configuration can narrow this global policy but cannot re-enable Brotli |
| `FERRUM_PROXY_BIND_ADDRESS` | No | `0.0.0.0` | Bind address for proxy listeners (HTTP, HTTPS, HTTP/3). Set to `::` for dual-stack IPv4+IPv6 |
| `FERRUM_FRONTEND_TLS_CERT_PATH` | If HTTPS | — | PEM certificate the gateway presents to incoming clients (HTTPS, WebSocket, gRPC, TCP/TLS) |
| `FERRUM_FRONTEND_TLS_CERT_SOURCE` | If HTTPS and set | — | Source override for `FERRUM_FRONTEND_TLS_CERT_PATH`; accepts path, `file://`, inline PEM, or provider URI |
| `FERRUM_FRONTEND_TLS_KEY_PATH` | If HTTPS | — | PEM private key for the gateway's frontend TLS certificate |
| `FERRUM_FRONTEND_TLS_KEY_SOURCE` | If HTTPS and set | — | Source override for `FERRUM_FRONTEND_TLS_KEY_PATH`; accepts path, `file://`, inline PEM, provider URI, or `pkcs11://` RSA signer URI when built with the `pkcs11` feature |
| `FERRUM_FRONTEND_TLS_OCSP_RESPONSE_SOURCE` | No | — | Source for DER OCSP response bytes to staple on frontend TLS handshakes. File/provider-backed sources are watched when frontend TLS live reload is enabled |
| `FERRUM_FRONTEND_TLS_HANDSHAKE_TIMEOUT_SECONDS` | No | `10` | Seconds allowed for frontend TLS/DTLS handshakes before HTTP header parsing or stream proxy handling begins. `0` disables |
| `FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED` | No | `false` | Opt in to live reload of proxy HTTPS / H2 / HTTP/3, admin HTTPS, and frontend DTLS cert/key/client-CA/OCSP/CRL material when any active frontend/admin/DTLS source is file-backed (`PATH` or `file://`) or external-source-backed (`vault://`, `aws://`, `azure://`, `gcp://`, `k8s://`, `acme://`, `managed://`). Inline PEM is static until config reload. The watcher compares material byte fingerprints, so same-byte rewrites or same-value external fetches do not churn TLS configs. External sources use `FERRUM_SECRET_REFRESH_INTERVAL_SECONDS` unless the source URI has `?poll=`. A failed validation keeps the previous config and emits a `warn!`; in-flight TLS/DTLS sessions keep their original config |
| `FERRUM_FRONTEND_TLS_WATCH_INTERVAL_SECONDS` | No | `30` | Poll interval for the frontend/admin TLS source watcher when live reload is enabled. Ignored when `FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED=false`. Clamped to a 1-second minimum so an accidental `0` does not busy-loop source polling |
| `FERRUM_BACKEND_TLS_LIVE_RELOAD_ENABLED` | No | `true` | Live reload global and per-proxy backend TLS cert/key/CA/CRL sources. On changed bytes, Ferrum validates active backend TLS configs, refreshes the backend CRL slot, clears backend client config caches and pools, and restarts active health checks. Existing in-flight backend requests keep their current connections; new backend connections rebuild from the rotated material |
| `FERRUM_BACKEND_TLS_WATCH_INTERVAL_SECONDS` | No | `30` | Poll interval for file-backed backend TLS source watching. External sources use `FERRUM_SECRET_REFRESH_INTERVAL_SECONDS` unless their URI includes `?poll=` |

### Admin API

> **Security — plaintext admin exposure.** The admin API is a management plane
> and is **safe by default**: `FERRUM_ADMIN_BIND_ADDRESS` defaults to loopback
> (`127.0.0.1`), so admin is not reachable from the network (the proxy
> data-plane bind, `FERRUM_PROXY_BIND_ADDRESS`, still defaults to `0.0.0.0`). If
> you move the admin API to any non-loopback address (`0.0.0.0`/`::`, a public
> IP, or a private/VPC interface IP — all reachable beyond this host),
> the `database`/`cp` modes **refuse to start** while the plaintext
> listener (`FERRUM_ADMIN_HTTP_PORT`, non-zero) has no `FERRUM_ADMIN_ALLOWED_CIDRS`
> allowlist — otherwise the admin API and any operator bearer tokens
> would be served in cleartext on every interface. **This applies even with
> `FERRUM_ADMIN_READ_ONLY=true`**: read-only blocks mutations, but the admin API
> still serves sensitive management-plane reads (e.g. unredacted `/backup`) and a
> plaintext listener still exposes operator bearer tokens on the wire, so
> read-only is not a substitute for loopback, TLS, or an allowlist. To expose
> admin, do one of: set an allowlist (`FERRUM_ADMIN_ALLOWED_CIDRS`), serve admin
> over TLS and disable plaintext (`FERRUM_ADMIN_TLS_CERT_PATH`/`FERRUM_ADMIN_TLS_KEY_PATH` +
> `FERRUM_ADMIN_HTTP_PORT=0`), or — for local development only — set
> `FERRUM_ALLOW_INSECURE_ADMIN_HTTP=true`. The hard fail is scoped to the
> write-capable `database`/`cp` modes (where read-only is only an opt-in toggle
> that does not reduce read/token exposure); the inherently read-only modes
> (`file`/`dp`/`mesh`) emit a high-severity warning instead of failing. (Note:
> `file`/`mesh` fall back to a random, unguessable admin JWT secret when
> `FERRUM_ADMIN_JWT_SECRET` is unset, so externally-minted tokens cannot validate
> there; `dp` requires the secret and aborts startup if it is missing. Either way,
> if you bind a plaintext admin listener beyond loopback, prefer an allowlist or
> TLS.) The `node_agent` admin listener also defaults to loopback.

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_ADMIN_HTTP_PORT` | No | `9000` | Admin API HTTP port. Set to `0` to disable the plaintext admin HTTP listener (TLS-only operation; recommended for production) |
| `FERRUM_ADMIN_HTTPS_PORT` | No | `9443` | Admin API HTTPS port. Set to `0` to disable the admin HTTPS listener in every serving mode, even when `FERRUM_ADMIN_TLS_CERT_PATH`/`FERRUM_ADMIN_TLS_KEY_PATH` are still configured — the serving mode never loads the certificate and key into an admin TLS runtime, no TLS reload watcher is started, and no socket is bound. This gate is config-level and therefore does **not** cover startup-wide external-secret resolution, which runs before `EnvConfig` is parsed: a suffixed admin TLS input (`FERRUM_ADMIN_TLS_CERT_SOURCE_FILE`, `_VAULT`, `_AWS`, `_AZURE`, `_GCP`) is still resolved — reading the PEM for `_FILE`, or failing startup when the secret is missing or the provider is unreachable — even with the listener disabled. The only exception to the listener suppression itself is not reachable from configuration: an in-process embedder can pass file mode an already-bound admin HTTPS socket through `ServeOptions`, which takes precedence over port `0`. File mode serves that socket only when both admin TLS paths are configured; that path loads the TLS material and sets up its live-reload watcher (starting it when live reload is enabled). Without both paths, file mode drops the socket unused. The `ferrum-edge` binary never passes a pre-bound socket |
| `FERRUM_ADMIN_BIND_ADDRESS` | No | `127.0.0.1` | Bind address for admin listeners (HTTP, HTTPS). Loopback by default (safe — admin not network-exposed). Set to `0.0.0.0`/`::` to expose; in `database`/`cp` modes a public plaintext bind also needs an allowlist, TLS, or `FERRUM_ALLOW_INSECURE_ADMIN_HTTP` (see the security note above) |
| `FERRUM_ADMIN_ALLOWED_CIDRS` | No | — | Comma-separated CIDRs/IPs allowed to connect to the admin API. Empty permits all |
| `FERRUM_METRICS_ALLOWED_CIDRS` | No | — | Comma-separated CIDRs/IPs allowed to scrape `/metrics` (and see detailed `/health` / `/overload`) **without** a credential. Empty (default) requires an admin JWT or `FERRUM_METRICS_BEARER_TOKEN`; set this to opt a Prometheus subnet into unauthenticated scraping |
| `FERRUM_METRICS_BEARER_TOKEN` | No | — | Dedicated bearer token that authorizes `/metrics` scraping (and detailed `/health` / `/overload`) without a full admin JWT. Empty (default) disables this path. Use for Prometheus deployments that cannot mint admin JWTs |
| `FERRUM_ALLOW_INSECURE_ADMIN_HTTP` | No | `false` | Dev-only escape hatch. When `true`, downgrades the `database`/`cp` public-plaintext-admin startup guard (applies to read-only `database`/`cp` too) from a hard error to a warning. Never enable in production |
| `FERRUM_ADMIN_MAX_CONNECTIONS` | No | `1024` | Max concurrent connections across all admin/management-plane listeners (plaintext + TLS share one cap). Independent of the data-plane `FERRUM_MAX_CONNECTIONS`. Enforced after the admin CIDR allowlist and before the TLS handshake / request parsing; over-limit connections are dropped (TCP RST). `0` = unlimited |
| `FERRUM_ADMIN_MAX_CONNECTIONS_PER_IP` | No | `0` | Max concurrent admin connections per resolved source IP. `0` (default) disables per-IP limiting so a single monitoring/load-balancer source is not capped by accident |
| `FERRUM_ADMIN_BODY_READ_TIMEOUT_SECONDS` | No | `10` | Idle timeout while reading an admin request body (HTTP/1.1 and HTTP/2). Each received body frame re-arms the deadline; a stall returns `408 Request Timeout`. `0` disables the idle deadline (byte caps still apply) |
| `FERRUM_ADMIN_HTTP2_MAX_CONCURRENT_STREAMS` | No | `32` | Max concurrent HTTP/2 streams per admin connection. Bounds multiplexed slow-stream retention independently of `FERRUM_ADMIN_MAX_CONNECTIONS` |
| `FERRUM_ADMIN_TLS_CERT_PATH` | If HTTPS | — | Path to admin TLS certificate |
| `FERRUM_ADMIN_TLS_CERT_SOURCE` | If HTTPS and set | — | Source override for `FERRUM_ADMIN_TLS_CERT_PATH`; accepts path, `file://`, inline PEM, or provider URI |
| `FERRUM_ADMIN_TLS_KEY_PATH` | If HTTPS | — | Path to admin TLS private key |
| `FERRUM_ADMIN_TLS_KEY_SOURCE` | If HTTPS and set | — | Source override for `FERRUM_ADMIN_TLS_KEY_PATH`; accepts path, `file://`, inline PEM, provider URI, or `pkcs11://` RSA signer URI when built with the `pkcs11` feature |
| `FERRUM_ADMIN_TLS_OCSP_RESPONSE_SOURCE` | No | — | Source for DER OCSP response bytes to staple on admin TLS handshakes. File/provider-backed sources are watched when frontend/admin TLS live reload is enabled |
| `FERRUM_ADMIN_JWT_SECRET` | DB/CP modes | — | HS256 secret for Admin API JWT auth. Must be at least 32 characters. Tokens must include `role: viewer`, `role: operator`, or `role: admin`; tokens without a `role` claim fail closed |
| `FERRUM_ADMIN_JWT_ISSUER` | No | `ferrum-edge` | Required `iss` claim for Admin API JWT tokens |
| `FERRUM_ADMIN_JWT_AUDIENCE` | No | — | Optional expected `aud` (audience) claim for Admin API JWT tokens. When set, tokens must carry a matching `aud`. When unset (default), tokens without `aud` pass but tokens carrying `aud` are rejected (RFC 7519 strict audience handling) |
| `FERRUM_ADMIN_JWT_MAX_TTL` | No | `3600` | Maximum accepted token lifetime (seconds) for externally minted Admin API JWTs, enforced against verifier time so future-shifted timestamps cannot extend real validity. The nominal lifetime (`exp - iat`) must be positive and within this value; `iat` must not be later than verifier time plus the 60-second clock-skew leeway; the remaining lifetime (`exp - now`) must be within this value **plus that same 60-second leeway** (one skew window, so an issuer whose clock runs fast can still mint full-length tokens); and `exp` must still be in the future at verifier time, with no additional expiry grace. Effective maximum real validity is therefore `FERRUM_ADMIN_JWT_MAX_TTL + 60s`. `0` intentionally disables the lifetime cap; a value above `9223372036854775807` is rejected at startup as invalid rather than treated as unlimited |
| `FERRUM_ADMIN_READ_ONLY` | No | `false` | Set Admin API to read-only mode (DP mode defaults to true). Blocks mutations only — it does **not** exempt the plaintext-admin startup guard above, since read endpoints (e.g. `/backup`) and bearer tokens remain sensitive |
| `FERRUM_ADMIN_AUDIT_ENABLED` | No | `false` | Enable database-backed audit events for successful Admin API mutations. Responses wait only for bounded queue enqueue; persistence is asynchronous best-effort |
| `FERRUM_ADMIN_REQUIRE_NAMESPACE_CLAIM` | No | `false` | When `true`, namespace-scoped Admin API routes (proxies, consumers, upstreams, plugin configs, api-specs, batch, backup, restore, audit) require the admin JWT to carry an `ns` claim (single string or array of strings, same shapes as the CP/DP gRPC plane) authorizing the `X-Ferrum-Namespace` value; requests outside the claimed namespaces are rejected with 403. When `false` (default), any valid admin JWT may address any namespace and the header is a routing selector only |
| `FERRUM_ADMIN_TLS_CLIENT_CA_BUNDLE_PATH` | No | — | PEM CA bundle for Admin API client certificate verification |
| `FERRUM_ADMIN_TLS_CLIENT_CA_BUNDLE_SOURCE` | No | — | Source override for `FERRUM_ADMIN_TLS_CLIENT_CA_BUNDLE_PATH`; accepts path, `file://`, inline PEM, or provider URI |
| `FERRUM_ADMIN_TLS_NO_VERIFY` | No | `false` | Skip Admin API TLS certificate verification (testing only) |
| `FERRUM_ADMIN_RESTORE_MAX_BODY_SIZE_MIB` | No | `100` | Max request body size in MiB for `POST /restore` |
| `FERRUM_ADMIN_SPEC_MAX_BODY_SIZE_MIB` | No | `25` | Max request body size in MiB for `POST/PUT /api-specs`. Specs are stored gzip-compressed; large API definitions (e.g. AWS combined services) can approach 30–50 MiB uncompressed. MongoDB backends are additionally bounded by the BSON 16 MB document limit, enforced at write time |

### Database

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_DB_TYPE` | DB/CP modes | — | Database type: `postgres`, `mysql`, `sqlite`, `mongodb` |
| `FERRUM_DB_URL` | DB/CP modes | — | Database connection string. For MongoDB: `mongodb://` or `mongodb+srv://` |
| `FERRUM_DB_POLL_INTERVAL` | No | `30` | Seconds between DB config polls. Incremental polling reads durable `config_changes` records after the last accepted sequence cursor, then point-loads changed IDs only. If polling fails or the cursor is older than retained change history, Ferrum falls back to a full runtime reload. SQL full reloads use transaction-scoped keyset pagination, MongoDB replica-set full reloads use snapshot transactions, and standalone MongoDB pollers use full reloads because change records are not crash-atomic without transactions; failed candidates keep the last known-good runtime config active. |
| `FERRUM_DB_REJECTED_DELTA_BACKOFF_INITIAL_SECONDS` | No | `1` | Database-mode initial retry backoff after a DB incremental delta is rejected by validation. The poller retries after this delay and does not advance the accepted cursor. CP mode uses `FERRUM_DB_POLL_INTERVAL`. |
| `FERRUM_DB_REJECTED_DELTA_BACKOFF_MAX_SECONDS` | No | `30` | Database-mode maximum retry backoff for the same rejected DB incremental delta. Values below the initial backoff are clamped up to the initial value. |
| `FERRUM_DB_REJECTED_DELTA_FULL_RELOAD_THRESHOLD` | No | `3` | Database-mode number of identical rejected DB incremental deltas before attempting an authoritative primary-backed full reload while preserving the last known-good config if that snapshot fails or is rejected. |
| `FERRUM_DB_CONFIG_BACKUP_PATH` | No | — | Path to externally provided JSON config backup, used as a startup fallback in two cases. (1) Connect-time bootstrap (**SQL backends only**): when every configured SQL database URL is unreachable at startup with a transient connectivity/resource/connect-timeout error, the gateway comes up on a lazy pool serving the backup while background polling retries the primary and failover URLs. MongoDB has no lazy-pool bootstrap — if all configured Mongo URLs are unreachable at startup the process exits. (2) Post-connect load fallback (**all backends, including MongoDB**): when the database connects/migrates but the initial config load fails transiently, the backup is served. In both cases a non-transient schema/auth/config/query failure fails startup instead of bootstrapping from the backup, so a broken primary is never masked by stale on-disk config. |
| `FERRUM_DB_FAILOVER_URLS` | No | — | Comma-separated failover database URLs. SQL failover is attempted only for transient connectivity, resource-exhaustion, and connection-timeout errors; query/statement timeouts and other query, schema, data, constraint, authentication, and configuration errors fail startup/reconnect without switching databases. For MongoDB replica sets, prefer listing all members in `FERRUM_DB_URL` instead |
| `FERRUM_DB_READ_REPLICA_URL` | No | — | SQL read replica URL for eligible admin-only reads. Runtime config polling and writes always use the active primary/failover pool. The configured read replica is eligible only while the configured primary topology is active; Ferrum closes and suppresses its pool during failover, then reconnects it once after primary failback. MongoDB read preferences are ignored by Ferrum's config store |
| `FERRUM_DB_SLOW_QUERY_THRESHOLD_MS` | No | — | Log database queries slower than this threshold |
| `FERRUM_DB_FULL_LOAD_PAGE_SIZE` | No | `10000` | Max rows per query during full config loading (SQL only). Clamped to 100..=100000 |

#### Database Backend Applicability

| Setting family | PostgreSQL | MySQL | SQLite | MongoDB |
|---|---|---|---|---|
| Core `FERRUM_DB_TYPE`, `FERRUM_DB_URL`, `FERRUM_DB_POLL_INTERVAL`, rejected-delta backoff fields, `FERRUM_DB_CONFIG_BACKUP_PATH`, `FERRUM_DB_SLOW_QUERY_THRESHOLD_MS` | Yes | Yes | Yes | Yes |
| `FERRUM_DB_FAILOVER_URLS` | Yes | Yes | Yes | Yes, but replica sets should list all members in `FERRUM_DB_URL` |
| `FERRUM_DB_READ_REPLICA_URL` | Yes, admin reads only | Yes, admin reads only | No | No; Ferrum forces primary reads |
| `FERRUM_DB_TLS_MODE` and DB TLS certificate paths | Yes | Yes | `disable` only as a no-op; cert paths rejected | Yes; `disable`, `require`, and `verify-full` via MongoDB driver `TlsOptions` |
| `FERRUM_DB_FULL_LOAD_PAGE_SIZE` | Yes | Yes | Yes | Ignored; MongoDB uses cursor-based loading |
| `FERRUM_DB_POOL_*` SQL pool fields | Yes | Yes | Yes | Ignored; use MongoDB URI pool options such as `maxPoolSize` and `minPoolSize` |
| `FERRUM_MONGO_*` fields | No | No | No | Yes |

#### Runtime Config Lifecycle Invariants

File, database, and DP modes apply runtime configuration through explicit
`Applied`, `Unchanged`, or `Rejected` outcomes. `Applied` swaps the new config
and rebuilds the derived caches. `Unchanged` confirms the source is still valid
without churning caches. `Rejected` keeps the last known-good runtime config and
does not commit database poll bookkeeping. CP mode validates database poll
candidates before storing and broadcasting them, but it does not use those
`ProxyState` apply outcomes on every broadcast path.

Database-mode polling commits the accepted `config_changes.sequence` cursor only
after an `Applied` or `Unchanged` candidate. Full reload candidates follow the
same rule: a rejected full snapshot cannot poison the later incremental cursor.
SQL runtime polling always uses the primary pool; `FERRUM_DB_READ_REPLICA_URL`
is only for eligible admin reads. MongoDB config reads force primary read
preference, and standalone MongoDB polling intentionally uses full reloads
instead of accepting non-transactional incremental cursors.

Full-load guarantees are backend-specific but fail closed. PostgreSQL uses a
repeatable-read, read-only transaction; MySQL requires repeatable-read
transaction isolation; SQLite reads through one transaction snapshot; MongoDB
replica sets use snapshot transactions. If a query, decode, relationship, or
runtime validation step fails, the whole candidate is rejected and the previous
config keeps serving.

Normal incremental polling is durable-change-log based. SQL and MongoDB
replica-set pollers read ordered `config_changes` rows/documents after the
accepted cursor, collapse each resource to the final operation in the batch, and
point-load only those changed IDs. Delete records carry removals, so normal
incremental polling does not scan every runtime collection or table ID.
Retained-history gaps and saturated change batches force the same authoritative
full-reload path.

Repeated rejected database deltas use bounded backoff and low-cardinality
metrics. After `FERRUM_DB_REJECTED_DELTA_FULL_RELOAD_THRESHOLD` identical
rejections, database mode attempts an authoritative full reload and keeps the
last known-good config if that reload fails or is also rejected. The public
health and metrics surfaces report degraded database polling without exposing
resource IDs or validation strings as unbounded labels.

Listener readiness and supervision are part of the same fail-closed lifecycle.
File and database modes report startup ready only after configured HTTP, HTTPS,
HTTP/3, and stream listeners have bound or been adopted. Supervised HTTP-family
and admin listener task failures trigger sibling shutdown instead of leaving a
partially serving process. Stream listener bind/startup failures are fatal in
file/database modes; after startup, stream listener exits are handled by stream
listener reconciliation and retry rather than by shutting down sibling listeners
or the process.
In-process file-mode callers that pass pre-bound listeners reserve those actual
ports for stream-listener conflict validation; env-config ports are used only
when no listener is pre-bound.

TLS source ownership is explicit. Database TLS live reload reconnects the active
SQL primary pool or MongoDB client, plus SQL admin-read replicas when present.
MongoDB driver paths that require filesystem PEMs receive owner-scoped temporary
files with restrictive permissions; those files remain only while the connection
bundle that may need them is alive.

#### MySQL minimum version

MySQL backends require **MySQL 8.0+**. The V001 schema applies an explicit
`COLLATE utf8mb4_0900_as_cs` on identifier columns (`id`, `namespace`, `name`,
`username`, `custom_id`, `plugin_name`, `proxy_id`, `upstream_id`,
`upstream_subset`, `api_spec_id`, `content_hash`, `spec_version`,
`backend_host`, `backend_tls_sni`), which is only available on MySQL 8.0 and
later. This makes uniqueness on `(namespace, name)`, `(namespace, username)`,
etc. **byte-exact** rather than the case-insensitive default — so `Alpha` and
`alpha` are distinct identifiers on MySQL just as they are on PostgreSQL and
SQLite. Operators upgrading a populated 5.x MySQL deployment must run the
matching `ALTER TABLE ... CONVERT TO CHARACTER SET utf8mb4 COLLATE
utf8mb4_0900_as_cs` themselves; this is consistent with the build-out
compatibility policy of folding schema changes into the V001 baseline rather
than shipping incremental migrations.

MySQL full runtime loads require `REPEATABLE READ` transaction isolation. If the
server or session default is weaker, Ferrum rejects the candidate full load and
keeps the last known-good runtime config instead of publishing a mixed snapshot.

### Database TLS

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_DB_TLS_MODE` | No | — | Database TLS policy. PostgreSQL: `disable`, `allow`, `prefer`, `require`, `verify-ca`, `verify-full`; MySQL: `disable`, `prefer`, `require`, `verify-ca`, `verify-full`; MongoDB: `disable`, `require`, `verify-full` |
| `FERRUM_DB_TLS_CA_CERT_PATH` | No | — | Path to CA certificate for database server verification |
| `FERRUM_DB_TLS_CA_CERT_SOURCE` | No | — | Source override for `FERRUM_DB_TLS_CA_CERT_PATH`; accepts path, `file://`, inline PEM, or provider URI |
| `FERRUM_DB_TLS_CLIENT_CERT_PATH` | No | — | Path to client certificate for database mTLS. SQL requires pairing with `FERRUM_DB_TLS_CLIENT_KEY_PATH`; MongoDB may use this alone as an already-combined cert+key PEM |
| `FERRUM_DB_TLS_CLIENT_CERT_SOURCE` | No | — | Source override for `FERRUM_DB_TLS_CLIENT_CERT_PATH`; accepts path, `file://`, inline PEM, or provider URI |
| `FERRUM_DB_TLS_CLIENT_KEY_PATH` | No | — | Path to client private key for database mTLS; must be paired with `FERRUM_DB_TLS_CLIENT_CERT_PATH` |
| `FERRUM_DB_TLS_CLIENT_KEY_SOURCE` | No | — | Source override for `FERRUM_DB_TLS_CLIENT_KEY_PATH`; accepts path, `file://`, inline PEM, or provider URI |
| `FERRUM_DB_TLS_LIVE_RELOAD_ENABLED` | No | `false` | Opt in to live reload of database TLS CA/client cert/client key sources in database and CP modes. On changed bytes, Ferrum reconnects the active primary pool/client and SQL admin-read replica pool so new database connections use rotated material. Inline PEM is static until config reload |
| `FERRUM_DB_TLS_WATCH_INTERVAL_SECONDS` | No | `30` | Poll interval for file-backed database TLS source watching. External sources use `FERRUM_SECRET_REFRESH_INTERVAL_SECONDS` unless their URI includes `?poll=`. Ignored unless database TLS live reload is enabled |

For MongoDB, configure TLS in exactly one place. When
`FERRUM_DB_TLS_MODE` is set (including `disable`), `FERRUM_DB_URL` and every
`FERRUM_DB_FAILOVER_URLS` entry must not contain MongoDB TLS/SSL query options,
and must not use `mongodb+srv://` (which enables TLS implicitly). A conflict is
a startup error; URI options never silently override the canonical environment
policy. Leave `FERRUM_DB_TLS_MODE` unset when TLS is intentionally owned by a
MongoDB URI or SRV record.

See [database_tls.md](database_tls.md) for detailed configuration examples and TLS mode descriptions.

### Database Pool

SQL pool settings apply to PostgreSQL, MySQL, and SQLite. MongoDB uses driver connection-string pool options such as `maxPoolSize` and `minPoolSize`.

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_DB_POOL_MAX_CONNECTIONS` | No | `32` | Maximum SQL pool connections |
| `FERRUM_DB_POOL_MIN_CONNECTIONS` | No | `1` | Minimum idle SQL pool connections |
| `FERRUM_DB_POOL_ACQUIRE_TIMEOUT_SECONDS` | No | `30` | Max wait for a pool connection |
| `FERRUM_DB_POOL_IDLE_TIMEOUT_SECONDS` | No | `600` | Max idle age before a SQL connection is closed |
| `FERRUM_DB_POOL_MAX_LIFETIME_SECONDS` | No | `300` | Max SQL connection lifetime |
| `FERRUM_DB_POOL_CONNECT_TIMEOUT_SECONDS` | No | `10` | Max TCP connect time for new database connections; `0` disables |
| `FERRUM_DB_POOL_STATEMENT_TIMEOUT_SECONDS` | No | `30` | Per-statement SQL timeout; `0` disables |

### MongoDB

These settings only apply when `FERRUM_DB_TYPE=mongodb`. `FERRUM_DB_POOL_*` settings are SQL-only and ignored for MongoDB.

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_MONGO_DATABASE` | No | `ferrum` | MongoDB database name |
| `FERRUM_MONGO_APP_NAME` | No | — | App name for server-side connection tracking |
| `FERRUM_MONGO_REPLICA_SET` | No | — | Replica set name. Required for transactions and change streams |
| `FERRUM_MONGO_AUTH_MECHANISM` | No | (auto) | Auth mechanism override: `SCRAM-SHA-256`, `MONGODB-X509`, etc. |
| `FERRUM_MONGO_SERVER_SELECTION_TIMEOUT_SECONDS` | No | `30` | Server selection timeout |
| `FERRUM_MONGO_CONNECT_TIMEOUT_SECONDS` | No | `10` | TCP connection timeout |

See [mongodb.md](mongodb.md) for the full deployment guide including read preference, replica sets, Atlas, and Kubernetes examples.

### File Mode

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_FILE_CONFIG_PATH` | File mode | — | Path to YAML/JSON config file |

### Control Plane / Data Plane

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_CP_GRPC_LISTEN_ADDR` | No | `0.0.0.0:50051` in CP mode | gRPC listen address. Port `0` disables plaintext gRPC. **Secure-by-default:** binding a non-loopback address in plaintext (no CP gRPC TLS) is refused at startup unless `FERRUM_CP_DP_GRPC_ALLOW_PLAINTEXT=true` |
| `FERRUM_CP_DP_GRPC_ALLOW_PLAINTEXT` | No | `false` | Permit plaintext (non-TLS) CP/DP gRPC config sync on a non-loopback address. When `false`, the CP refuses to bind a non-loopback plaintext gRPC listener and the DP refuses a non-loopback `http://` CP URL — the channel carries DP authentication JWTs and the full gateway config, which plaintext exposes unencrypted and unauthenticated against MITM. Loopback (`127.0.0.1`/`::1`/`localhost`) plaintext is always permitted for local development. Set `true` only on a trusted network with compensating controls; a high-severity warning is logged whenever plaintext is used (CP and DP) |
| `FERRUM_CP_DP_GRPC_JWT_SECRET` | CP, DP & mesh modes | — | Shared JWT secret for CP/DP/mesh gRPC auth (DP/mesh clients generate short-lived JWTs, CP validates). Must be at least 32 characters. This is the only DP authentication factor unless CP gRPC mTLS (`FERRUM_CP_GRPC_TLS_CLIENT_CA_PATH`) is configured |
| `FERRUM_CP_DP_GRPC_JWT_ISSUER` | No | `ferrum-edge-cp-dp` | Required `iss` claim on CP/DP/mesh gRPC JWTs. The CP rejects tokens whose issuer does not match; DP/mesh clients stamp minted tokens with this value. Defaults to a dedicated gRPC issuer namespace so a leaked admin JWT cannot authenticate on the CP/DP channel (and vice versa). Set the same value on the CP and every DP/mesh client |
| `FERRUM_CP_GRPC_TLS_CERT_PATH` | If CP gRPC TLS | — | CP gRPC server TLS certificate. File/provider/Kubernetes-backed sources are watched in CP mode; new handshakes use rotated material after validation |
| `FERRUM_CP_GRPC_TLS_CERT_SOURCE` | If CP gRPC TLS and set | — | Source override for `FERRUM_CP_GRPC_TLS_CERT_PATH`; accepts path, `file://`, inline PEM, or provider URI |
| `FERRUM_CP_GRPC_TLS_KEY_PATH` | If CP gRPC TLS | — | CP gRPC server TLS private key. File/provider/Kubernetes-backed sources are watched with the cert and optional client CA |
| `FERRUM_CP_GRPC_TLS_KEY_SOURCE` | If CP gRPC TLS and set | — | Source override for `FERRUM_CP_GRPC_TLS_KEY_PATH`; accepts path, `file://`, inline PEM, or provider URI |
| `FERRUM_CP_GRPC_TLS_CLIENT_CA_PATH` | No | — | CA bundle for verifying DP client certificates (mTLS). Watched with the CP gRPC cert/key when TLS is configured |
| `FERRUM_CP_GRPC_TLS_CLIENT_CA_SOURCE` | No | — | Source override for `FERRUM_CP_GRPC_TLS_CLIENT_CA_PATH`; accepts path, `file://`, inline PEM, or provider URI |
| `FERRUM_CP_BROADCAST_CHANNEL_CAPACITY` | No | `128` | Per-channel capacity for the CP's two independent broadcast channels (one for DP `ConfigSync.Subscribe`, one for mesh `MeshConfigSync.MeshSubscribe`). Multi-namespace CPs also size their per-namespace `ConfigSync.Subscribe` partitions at this capacity, so total memory is `capacity * |namespaces|`. Lagging subscribers on any channel auto-recover with a full snapshot |
| `FERRUM_CP_NAMESPACES` | No | unset (single-namespace) | Multi-namespace control plane scope. Accepts `*` (every namespace in the database), a comma-separated list (`prod,staging`), or empty/unset (back-compat: serve only `FERRUM_NAMESPACE`). `Set` and `All` scopes automatically require JWT `ns` claims and partition ConfigSync, native mesh, xDS, K8s-triggered updates, and trust material before serialisation |
| `FERRUM_CP_REQUIRE_NAMESPACE_CLAIM` | No | `false` | When `true`, also requires JWT `ns` claims in single-namespace CP mode. Multi-namespace `Set` and `All` scopes enforce this automatically even when the flag is `false`. The `ns` claim is a single string or array of strings for request-namespaced protocols; xDS ADS requires exactly one namespace because ADS has no namespace request field. See [cp_namespace_tenancy.md](cp_namespace_tenancy.md) |
| `FERRUM_XDS_ENABLED` | No | `false` | Enable Phase B xDS ADS (`StreamAggregatedResources` and `DeltaAggregatedResources`) on the CP gRPC listener |
| `FERRUM_XDS_STREAM_CHANNEL_CAPACITY` | No | `32` | Per-ADS-stream response queue capacity before slow xDS readers apply backpressure to their own stream task |
| `FERRUM_XDS_MAX_STREAMS_PER_NODE` | No | `4` | Maximum concurrent ADS streams the CP admits per node id (only meaningful when `FERRUM_XDS_ENABLED=true`). A healthy DP keeps a single stream; the default headroom tolerates brief reconnect overlap. Streams beyond the ceiling are rejected with gRPC `RESOURCE_EXHAUSTED` and counted by `ferrum_xds_streams_rejected_total`. Set `0` to disable the cap (unbounded). This is a per-node DoS guard for fleets where many authenticated xDS clients share a node id |
| `FERRUM_DP_CP_GRPC_URLS` | DP/mesh mode | — | Comma-separated priority-ordered CP URLs for DP/mesh failover |
| `FERRUM_DP_CP_FAILOVER_PRIMARY_RETRY_SECS` | No | `300` | Retry primary CP interval (seconds) when connected to a fallback. `0` = disabled |
| `FERRUM_DP_GRPC_TLS_CA_CERT_PATH` | No | — | CA certificate for verifying the CP server |
| `FERRUM_DP_GRPC_TLS_CA_CERT_SOURCE` | No | — | Source override for `FERRUM_DP_GRPC_TLS_CA_CERT_PATH`; accepts path, `file://`, inline PEM, or provider URI |
| `FERRUM_DP_GRPC_TLS_CLIENT_CERT_PATH` | No | — | DP client certificate for CP mTLS |
| `FERRUM_DP_GRPC_TLS_CLIENT_CERT_SOURCE` | No | — | Source override for `FERRUM_DP_GRPC_TLS_CLIENT_CERT_PATH`; accepts path, `file://`, inline PEM, or provider URI |
| `FERRUM_DP_GRPC_TLS_CLIENT_KEY_PATH` | No | — | DP client private key for CP mTLS |
| `FERRUM_DP_GRPC_TLS_CLIENT_KEY_SOURCE` | No | — | Source override for `FERRUM_DP_GRPC_TLS_CLIENT_KEY_PATH`; accepts path, `file://`, inline PEM, or provider URI |
| `FERRUM_DP_GRPC_TLS_NO_VERIFY` | No | `false` | **Not supported — rejected at startup when `true`.** The tonic-managed CP/DP gRPC client exposes no hook to skip server certificate verification, so the flag only ever offered false confidence. To connect to a CP presenting a self-signed certificate, pin its CA via `FERRUM_DP_GRPC_TLS_CA_CERT_PATH` (one-way TLS) or supply `FERRUM_DP_GRPC_TLS_CLIENT_CERT_PATH`/`KEY_PATH` (mTLS) |

See [cp_dp_mode.md](cp_dp_mode.md) for CP/DP TLS environment variables (`FERRUM_CP_GRPC_TLS_*`, `FERRUM_DP_GRPC_TLS_*`) and [multi_region_ha.md](multi_region_ha.md) for multi-region deployment patterns.

### Mesh Runtime

Mesh mode consumes Layer 2 mesh slices from the control protocols and prepares the shared sidecar/ambient data-plane listeners. Non-mesh modes do not instantiate this runtime.

With the native `MeshSubscribe` protocol, mesh mode waits for the first delivered mesh slice before serving, builds the proxy/plugin runtime from that slice, and hot-applies later valid slices atomically. Duplicate-content slices are skipped before rebuilding the proxy runtime. Invalid slice updates are logged and ignored so the last accepted runtime config keeps serving. The xDS ADS consumer coalesces bursts with a short debounce and a bounded max-delay cap, so continuous control-plane churn cannot indefinitely postpone applying the latest valid snapshot.

With the xDS ADS protocol, invalid resource updates are NACKed and the last accepted snapshot remains active. If one known xDS resource type produces 5 consecutive NACKs without an ACK, the mesh client closes that ADS stream and relies on the existing reconnect/failover loop instead of NACKing the same bad control-plane state forever. In a single-CP deployment that keeps serving the same invalid resource, this becomes a bounded reconnect/NACK cycle governed by the normal jittered backoff until the CP config is corrected. Unknown type URLs are NACKed but not counted in the breaker because this client can never ACK them. Any already-ACKed slice waiting in the debounce window is applied before the stream is closed so reconnect version hints cannot advance past the local runtime.

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_MESH_CONFIG_PROTOCOL` | No | `native` | Mesh config source. `native` uses Ferrum `MeshSubscribe`; `xds` uses the mesh ADS client against a Ferrum or compatible xDS control plane; `file` builds the mesh slice locally from `FERRUM_MESH_FILE_CONFIG_PATH` with no control plane (`FERRUM_DP_CP_GRPC_URLS` / `FERRUM_CP_DP_GRPC_JWT_SECRET` not required) |
| `FERRUM_MESH_FILE_CONFIG_PATH` | `file` protocol only | — | Path to the localized mesh config document (YAML/JSON, optional `version` plus the `mesh` section only). Fail-closed at startup; reloaded on SIGHUP (Unix), keeping the last good slice when a reload fails |
| `FERRUM_MESH_XDS_NODE_CLUSTER` | No | `FERRUM_NAMESPACE` | xDS `Node.cluster` identity sent by mesh-mode ADS clients |
| `FERRUM_MESH_XDS_CONNECT_TIMEOUT_SECONDS` | No | `10` | Mesh xDS client connect timeout. `0` disables the explicit tonic connect timeout |
| `FERRUM_MESH_NODE_ID` | No | `$HOSTNAME` or `ferrum-mesh-node` | Stable mesh data-plane node ID used for xDS/MeshSubscribe |
| `FERRUM_MESH_TOPOLOGY` | No | `sidecar` | Mesh topology flag: `sidecar`, `ambient`, `node_waypoint`, `service_waypoint`, `east_west_gateway`, or `egress_gateway`. All share the same data-plane path |
| `FERRUM_MESH_WAYPOINT_NAME` | ServiceWaypoint only | — | Required when `FERRUM_MESH_TOPOLOGY=service_waypoint`; names the GAMMA waypoint binding requested from the CP via native `MeshSubscribe` and stamped onto xDS-reconstructed local slices for admin visibility |
| `FERRUM_MESH_INBOUND_LISTEN_ADDR` | No | `0.0.0.0:15006` | Sidecar inbound mTLS listener address |
| `FERRUM_MESH_OUTBOUND_LISTEN_ADDR` | No | `127.0.0.1:15001` | Mesh outbound capture listener address for plaintext-in to mTLS-out or HBONE encapsulation. In NodeWaypoint topology its **port** also sets the node-agent's eBPF `connect4` rewrite target and the per-pod in-netns listener port, so co-deployed node-agent + proxy must set it consistently (port `0` disables outbound capture) |
| `FERRUM_MESH_HBONE_LISTEN_ADDR` | No | `0.0.0.0:15008` | Ambient HBONE termination listener address (Istio-flavored HBONE over mTLS) |
| `FERRUM_MESH_EAST_WEST_LISTEN_PORT` | No | `15443` | Shared TCP passthrough listener port for `east_west_gateway` topology; routes by TLS SNI using `mesh.multi_cluster.east_west_gateways` |
| `FERRUM_MESH_EGRESS_HBONE_PORT` | No | `15008` | Port dialed on **destination** workloads for Ambient egress HBONE (materialized outbound routes). Set when the mesh's HBONE listeners are not on Istio's conventional `15008`; stamped onto egress targets as the `mesh.hbone_port` tag when non-default |
| `FERRUM_MESH_EGRESS_MTLS_PORT` | No | `15006` | Port dialed on **destination** sidecars for Sidecar egress SVID-mTLS (materialized outbound routes). Set when the mesh's sidecar inbound listeners are not on Istio's conventional `15006`; stamped onto egress targets as the `mesh.mtls_port` tag when non-default |
| `FERRUM_MESH_EGRESS_LISTEN_ADDR` | No | `0.0.0.0:15090` | Egress gateway mTLS listener address for `egress_gateway` topology. Requires `FERRUM_FRONTEND_TLS_CERT_PATH`, `FERRUM_FRONTEND_TLS_KEY_PATH`, and `FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH` |
| `FERRUM_MESH_WORKLOAD_SPIFFE_ID` | No | — | Workload SPIFFE ID hint sent to native MeshSubscribe and xDS. Required when `FERRUM_MESH_CA_BACKEND=spire|internal` is the selected identity source so the issued runtime SVID matches the local mesh workload identity |
| `FERRUM_MESH_WORKLOAD_LABELS` | No | — | Workload labels for this mesh data plane (`k1=v1,k2=v2`). Drives `mesh_authz` `PolicyScope` filtering and `PeerAuthentication` selector filtering. For authorization, only policies whose scope (`MeshWide`, `Namespace`, or `WorkloadSelector`) matches these labels apply to this proxy. Set explicitly for current Kubernetes and non-K8s deployments; the injector can later populate this from pod labels via the downward API |
| `FERRUM_MESH_CA_BACKEND` | No | `none` | Mesh certificate authority backend: `internal` (Ferrum's own dev-only self-signed CA, gated behind `FERRUM_MESH_CA_BOOTSTRAP_DEV` — see the production guardrails below), `spire` (delegate to a SPIRE Agent over UDS; `spire_agent` / `spire-agent` are accepted aliases), `none` (no automatic SVID issuance). When set to `spire` or `internal`, mesh startup waits for an initial runtime SVID before binding listeners, installs it into the gateway SVID slot for outbound HBONE/SVID-mTLS and inbound SPIFFE verification, and uses it as a dynamic inbound server identity when explicit `FERRUM_FRONTEND_TLS_*` material is absent. Requires `FERRUM_MESH_WORKLOAD_SPIFFE_ID` unless explicit file-based `FERRUM_GATEWAY_SVID_*` material is also configured; in that case the file SVID takes precedence and automatic CA-backed issuance is not started |
| `FERRUM_MESH_ALLOW_NO_CA` | No | `false` | Dev/test opt-in to run `mesh` mode with **no workload identity** — neither file-based gateway SVID material (`FERRUM_GATEWAY_SVID_CERT_PATH`/`KEY_PATH`/`TRUST_BUNDLE_PATH`) nor automatic CA-backed runtime SVID (`FERRUM_MESH_CA_BACKEND=spire|internal`). Without identity the mesh can't establish or verify mTLS, so PeerAuthentication's PERMISSIVE default would silently accept unauthenticated plaintext — mesh startup **fails closed** unless this is `true`. Like the other identity dev shortcuts it is **read directly from the environment** (not honored from `ferrum.conf`) and **refused unconditionally when `FERRUM_MESH_PRODUCTION_MODE=true`**. Configure a CA backend or gateway SVID material instead. Lab/test only |
| `FERRUM_MESH_SPIRE_AGENT_SOCKET` | No | `/run/spire/sockets/agent.sock` | Path to the SPIRE Agent's Workload API Unix domain socket. Only used when `FERRUM_MESH_CA_BACKEND=spire`. See [docs/spire_deployment.md](spire_deployment.md) for socket mount options (hostPath vs SPIFFE CSI driver) |
| `FERRUM_MESH_CERT_TTL_SECONDS` | No | `3600` | SVID lifetime hint (seconds) passed to the CA backend. The CA may clamp or ignore this value |
| `FERRUM_MESH_PRODUCTION_MODE` | No | `false` | Master production guardrail for the mesh identity dev shortcuts. When `true`, the dev-only self-signed CA bootstrap (`FERRUM_MESH_CA_BOOTSTRAP_DEV`), the dev-only static attestor (`FERRUM_MESH_ALLOW_STATIC_ID`), and the no-workload-identity posture (`FERRUM_MESH_ALLOW_NO_CA`) are **refused unconditionally**, **and at runtime the inbound mTLS/HBONE termination listener must resolve to a usable mTLS server config — it fails startup closed rather than serving plaintext** (PeerAuthentication DISABLE, no usable server identity, or a configured-but-unloadable gateway SVID verifier). Read directly by the identity helpers, not parsed into `EnvConfig`. Set `true` in every production deployment |
| `FERRUM_MESH_CA_BOOTSTRAP_DEV` | No | `false` | Dev-only opt-in to mint a self-signed root for the `internal` CA backend. The bootstrap helper in `src/identity/ca/bootstrap.rs` refuses unless this is `true` **and** `FERRUM_MESH_PRODUCTION_MODE` is not `true`. Emits a loud dev-only warning when it runs. Lab/test only — there is no externally-provided-root env var today |
| `FERRUM_MESH_ALLOW_STATIC_ID` | No | `false` | Dev-only opt-in for the `StaticAttestor`, which returns a hard-coded SPIFFE ID for any peer (zero proof of identity). Refused unless `true` and `FERRUM_MESH_PRODUCTION_MODE` is not `true`. Lab/test only |
| `FERRUM_MESH_CAPTURE_MODE` | No | `explicit` | Traffic capture mode used by injector/capture planning: `explicit`, `iptables`, or `ebpf`. eBPF capture requires a build with `--features ebpf` on Linux; the default published image uses a no-op mock backend. eBPF planning falls back to iptables when the kernel is unsupported |
| `FERRUM_MESH_PROXY_UID` | No | `1337` in injector patches | UID used to exempt Ferrum's own outbound traffic from iptables capture |
| `FERRUM_MESH_IP6TABLES_ENABLED` | No | `auto` | IPv6 iptables fan-out: `auto` probes and skips IPv6 rules when `ip6tables` is unavailable, `true` requires it when IPv6 CIDRs are configured and fails all capture setup before IPv4 rules if unavailable, `false` emits IPv4-only capture rules |
| `FERRUM_MESH_TRUST_DOMAIN_ALIASES` | No | — | Comma-separated SPIFFE trust domains accepted as equivalent to the peer cert's trust domain when validating HBONE baggage `source.principal`. Default empty: strict same-trust-domain match. Mirror of Istio `MeshConfig.trustDomainAliases` for federated multi-cluster setups |
| `FERRUM_MESH_TRUSTED_HBONE_ASSERTORS` | No | — | Comma-separated allow-list of HBONE peer identities trusted to rewrite the `mesh_authz` principal via baggage `source.principal`. Each entry is either a bare Kubernetes service-account name (matched against the Istio convention `ns/<ns>/sa/<sa>`) or a full `spiffe://` SPIFFE id (exact-identity pinning). Default empty: `mesh_authz` uses the built-in defaults `[ztunnel, waypoint]`, except identity-backed `NodeWaypoint` derives exact assertor SPIFFE IDs from the scope-authorized CP-derived `node_waypoint_assertors` inventory and uses an empty list when none exists. Authenticated peers outside this list keep their own peer-cert identity and the dropped baggage surfaces as `mesh_authz.ignored_baggage.untrusted_assertor=true`. Configure a `mesh_authz` plugin override with `trusted_hbone_assertors: []` to disable baggage rewriting entirely |
| `FERRUM_MESH_EGRESS_STRIP_BAGGAGE_KEYS` | No | — | Comma-separated W3C `baggage` key prefixes stripped from outbound requests at dispatch. Default empty: forward unchanged for ordinary egress. Gateway-originated HBONE inner requests always strip identity-shaped baggage keys (`source.*`, `destination.*`, and aliases) while preserving non-identity baggage |
| `FERRUM_MESH_SIDECAR_ENFORCED` | No | `false` | When `true`, the slice builder applies Istio `Sidecar` egress scope narrowing: services, service-entries, and destination-rules outside the applicable `Sidecar`'s egress scope are filtered out before being sent to data planes. `Sidecar` resources are parsed and persisted unconditionally; this flag only gates the slice-narrowing pass so operators can opt in after vetting their `Sidecar` definitions |
| `FERRUM_MESH_SIDECAR_ENFORCED_DRY_RUN` | No | `false` | Computes the applicable `Sidecar` egress scope and reports would-deny counts while leaving the slice unchanged. Use with the JWT-authenticated `/mesh/egress-scope` admin endpoints before enabling `FERRUM_MESH_SIDECAR_ENFORCED` |
| `FERRUM_MESH_PEER_AUTH_LIVE_RELOAD_ENABLED` | No | `false` | Opt in to live reload of PeerAuthentication-derived inbound mTLS mode and frontend client CA verifier on mesh slice apply. This flag does not rotate frontend server cert/key material; use `FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED=true` for file-backed frontend/admin server cert-key/client-CA/CRL reload |
| `FERRUM_MESH_REQUEST_AUTH_REQUIRE_EXP` | No | `true` | Whether the auto-injected mesh `RequestAuthentication` (`jwks_auth`) plugin requires the JWT `exp` claim. Secure default `true` rejects `exp`-less tokens so they cannot live forever. Set `false` only for Istio issuers that legitimately omit `exp`. Independent of expiry *validation*: a present-but-expired `exp` is always rejected regardless of this flag |
| `FERRUM_MESH_FEDERATION_POLL_INTERVAL_SECONDS` | No | `300` | Polling interval (seconds) for SPIFFE trust-bundle federation. The poller fetches each `RemoteCluster.federation_endpoint` and overlays the result on `TrustBundleSet.federated` for cross-cluster mTLS. Set to `0` to disable the poller entirely; cross-cluster bundles then come only from the CP-supplied slice. Per-target backoff uses the same 1s→30s ±25% jitter as the CP-reconnect loop on transient failures. Mesh validation caps `mesh.multi_cluster.remote_clusters` at 256 entries, bounding federation task fan-out |
| `FERRUM_MESH_FEDERATION_POLL_TIMEOUT_SECONDS` | No | `30` | Per-request HTTP timeout (seconds) for a single federation bundle fetch. Slow or hung endpoints fall through to backoff once this fires |
| `FERRUM_MESH_FEDERATION_MAX_STALE_SECONDS` | No | `3600` | Maximum age for a last-good polled federation bundle after poll failures. When the age exceeds this window, the bundle is withdrawn from the active trust set and slice apply is woken so outbound mTLS and inbound SPIFFE verification fail closed until a later successful poll reinstalls fresh trust. Set `0` only for dev/test indefinite retention; production mode rejects `0` while federation polling is enabled |
| `FERRUM_MESH_FEDERATION_FAIL_OPEN` | No | `false` | Federation bootstrap policy for remote clusters that declare `federation_endpoint`. `false` blocks CP-supplied fallback bundles until the federation poller installs a last-good bundle for that trust domain. `true` allows the CP fallback before the first successful poll. Both modes preserve last-good polled bundles across transient poll failures and use the effective trust set for outbound mTLS and inbound SPIFFE verification |
| `FERRUM_MESH_REMOTE_DISCOVERY_POLL_INTERVAL_SECONDS` | No | `0` | Cross-cluster endpoint discovery polling interval (seconds). `0` disables it (multi-cluster stays east-west SNI passthrough + federated trust only). When `> 0`, each `RemoteCluster.control_plane_url` is dialed over native MeshSubscribe to fetch remote service endpoints, which are aggregated into local upstream targets tagged with remote locality so locality-aware priority LB fails over local→remote. Fail-closed on trust: only remote clusters with a federated trust bundle for their trust domain are dialed. Per-target backoff matches the federation poller (1s→30s ±25%). Mesh validation caps `mesh.multi_cluster.remote_clusters` at 256 entries, bounding endpoint-discovery task fan-out. **Precondition:** the local workload source locality (`topology.kubernetes.io/region`+`zone` on the SPIFFE-matched workload, or label-based fallback) must be set for the local-first priority-tier behavior to engage; without it the LB returns local and remote endpoints together. Ferrum emits a startup `WARN` when this precondition is not met. Set `FERRUM_MESH_LOCALITY_LB_STRICT=true` to fail closed to local endpoints instead of returning the mixed pool when source locality is absent; config validation emits a `WARN` advisory (any mode, never an error) whenever discovery is enabled with `FERRUM_MESH_LOCALITY_LB_STRICT=false`, recommending strict mode (east-west gateway failover targets are already local-first and unaffected). See `docs/mesh.md` "Cross-Cluster Endpoint Discovery" |
| `FERRUM_MESH_REMOTE_DISCOVERY_POLL_TIMEOUT_SECONDS` | No | `30` | Per-poll timeout (seconds) for the remote-cluster MeshSubscribe fetch |
| `FERRUM_MESH_REMOTE_DISCOVERY_MAX_STALE_SECONDS` | No | `300` | Maximum age for last-good remote-cluster endpoints after discovery poll failures. When the age exceeds this window, endpoints and their success/age metrics are withdrawn while the poller keeps retrying, so recovered peers can reinstall without a slice change. Set `0` only for dev/test indefinite retention; production mode rejects `0` while remote discovery is enabled |
| `FERRUM_MESH_REMOTE_DISCOVERY_CREDENTIALS` | No | _(unset)_ | JSON object mapping a credential reference to the JWT secret the **remote** cluster's control plane accepts, e.g. `{"clusterB":"<secretB>","clusterC":"<secretC>"}`. A `RemoteCluster` selects its credential with `discovery_credential_ref`; the data plane mints its remote-MeshSubscribe token with that secret. Each secret must be at least 32 characters (the same minimum the shared `FERRUM_CP_DP_GRPC_JWT_SECRET` enforces); a shorter value is rejected at parse time. Because the remote CP validates with its own secret (HS256), a token signed for cluster B will not verify at cluster C, so a per-remote credential cannot authenticate to the wrong cluster. The raw secret is never serialized into the slice/config and is never logged. Resolvable through the external-secret suffixes (`_VAULT`/`_AWS`/`_AZURE`/`_GCP`/`_FILE`). A `discovery_credential_ref` that does not resolve to an entry here **fails that cluster closed** (it is not polled). When a `RemoteCluster` sets no `discovery_credential_ref`, discovery falls back to the shared `FERRUM_CP_DP_GRPC_JWT_SECRET` (deprecated in production multi-cluster; a startup `WARN` is emitted). Malformed JSON disables the per-remote map (every referencing cluster then fails closed). See `docs/mesh.md` "Per-RemoteCluster discovery credentials" |
| `FERRUM_MESH_LOCALITY_LB_STRICT` | No | `false` | Strict local-first locality load balancing for mesh upstreams. Default `false` (fail-open): when an upstream's source locality is absent/unresolved the locality-aware LB returns mixed local + remote endpoints. When `true` (fail-closed-to-local): an absent source locality restricts selection to LOCAL-locality endpoints (targets not tagged with the synthetic `remote-<cluster>` locality) and will not widen to remote unless there are no local endpoints, in which case it falls back to the full healthy pool with a one-time `WARN` rather than black-holing. Inert when a source locality IS resolved (priority-tier preference unchanged in both modes). Stamped onto upstreams at slice apply; not settable via the admin API. Recommended `true` whenever remote endpoint discovery is enabled (`FERRUM_MESH_REMOTE_DISCOVERY_POLL_INTERVAL_SECONDS > 0`): config validation emits a `WARN` advisory for the enabled-discovery + non-strict combination so an absent source locality cannot mix remote endpoints into selection while local endpoints are healthy. See `docs/mesh.md` "Locality-Aware Load Balancing" |
| `FERRUM_MESH_NODE_WAYPOINT_CGROUP_SWEEP_INTERVAL_SECS` | No | `30` | Node-waypoint cgroup-inode lifecycle sweep interval. Identities enrolled with a cgroup v2 path are evicted when the cgroup is gone (pod removed) or its inode/fingerprint no longer matches (pod restarted under the same UID, including inode-reuse cases). This controls only cgroup-bound identities and is best-effort GC, not a security boundary — the fail-closed accept-path check on unknown cookies is unchanged. Set to `0` to disable cgroup stats without disabling lazy identity GC |
| `FERRUM_MESH_NODE_WAYPOINT_IDLE_GC_INTERVAL_SECS` | No | `30` | Node-waypoint lazy identity GC interval. Identities enrolled without a cgroup binding are evicted when their pod UID is no longer referenced by any live cookie record and no open HTTP/HBONE connection still holds the identity. This bounds lazy hash-join enrollment under pod churn independently from the cgroup-inode sweep. Set to `0` only if another component explicitly removes lazy identities |
| `FERRUM_MESH_NODE_WAYPOINT_POD_REGISTRY_DIR` | No | `/run/ferrum/node-waypoint-pods` | Directory where the node-agent publishes the enrolled-pod registry (one file per pod, name=pod_uid, contents=cgroup path line 1, pod IP line 2) for the mesh proxy's in-netns capture listeners to consume. In-netns outbound capture is always on for node-waypoint topology (the proxy binds a `127.0.0.1:<outbound port>` listener inside each enrolled pod's netns); this only tunes the registry path |
| `FERRUM_MESH_SVID_ROTATION_DRAIN_SECONDS` | No | `0` | Seconds to wait after a backend client SVID rotation before force-draining old-generation backend pool entries. `0` keeps existing connections until normal idle/health cleanup; new backend connections use the fresh SVID immediately after the rotation revision is observed, and active HTTP health probes are restarted on each observed revision |
| `FERRUM_MESH_POLICY_DENY_LOG_CAPACITY` | No | `10000` | Ring capacity of the in-memory `mesh_authz` deny recorder consumed by `GET /mesh/policy-denies/recent`. Each entry is ~200–400 bytes. The recorder is exception-path only (touched only when `mesh_authz` rejects a request or stream connection) and bounded FIFO: oldest entries evicted first. `0` disables the recorder entirely while keeping the endpoint serving an empty `grouped` array |
| `FERRUM_MESH_SIDECAR_IDENTITY_NARROWING` | No | `false` | When `true` and `FERRUM_MESH_SIDECAR_ENFORCED=true`, the slice builder filters `workloads` to SPIFFE identities referenced by services admitted by the applicable Sidecar. Default-off for one release; mTLS peer verification still uses trust bundles, and HBONE baggage trust-domain checks still use peer certs plus `FERRUM_MESH_TRUST_DOMAIN_ALIASES` |
| `FERRUM_MESH_EGRESS_STREAM_ENABLED` | No | `false` | Opt-in for stream-family (TCP / UDP) egress proxy materialization in `EgressGateway` topology. When enabled, each per-port stream egress listener terminates SVID-mTLS (reusing the mesh-inbound `ServerConfig` — server identity = gateway SVID, peer verifier = SPIFFE against the trust bundle) and runs `mesh_authz` at accept, the same authn/z as HTTP egress. **A verified client certificate is required:** because the egress gateway is a security boundary onto external networks, a `PERMISSIVE` `PeerAuthentication` (the default when no STRICT policy is in force) is escalated to require a client cert for this topology, so a cert-less client is rejected at the handshake instead of being admitted to the external backend. Fail-closed: if no mTLS material is loaded the stream listener defers its bind instead of falling back to plaintext (mirrors the inbound posture); if `PERMISSIVE` resolves with no trust anchor at all the listener cannot authenticate clients and refuses to start. Set `FERRUM_MESH_EGRESS_STREAM_ALLOW_PLAINTEXT=true` to restore the legacy plaintext + unauthenticated posture. HTTP-family egress is unaffected by this flag |
| `FERRUM_MESH_EGRESS_STREAM_ALLOW_PLAINTEXT` | No | `false` | Explicit opt-out that makes stream-family egress listeners plaintext + unauthenticated (the legacy posture). Only meaningful with `FERRUM_MESH_EGRESS_STREAM_ENABLED=true`. Default-off: stream egress terminates SVID-mTLS and runs `mesh_authz`. When `true`, `mesh_authz` cannot verify SPIFFE peer identity (no TLS client cert), so any pod that can reach the egress gateway reaches the external destination through it with no authorization check — a loud warning is logged at startup. Enable only with compensating network controls |
| `FERRUM_MESH_DNS_PROXY_ENABLED` | No | `false` | Enable the transparent mesh DNS proxy. Requires traffic capture rules to redirect workload DNS traffic to `FERRUM_MESH_DNS_LISTEN_ADDR` |
| `FERRUM_MESH_DNS_LISTEN_ADDR` | No | `127.0.0.1:15053` | UDP/TCP listen address for transparent DNS. TCP is used for truncated responses and resolver fallback |
| `FERRUM_MESH_DNS_UPSTREAM_ADDR` | No | `127.0.0.53:53` | Upstream DNS resolver for non-mesh names. The default targets systemd-resolved; set this to your node, pod, or cluster resolver (for example CoreDNS) in non-systemd environments |
| `FERRUM_MESH_DNS_TTL_SECONDS` | No | `60` | TTL used for synthetic A/AAAA records resolved from mesh ServiceEntry and MeshService state |
| `FERRUM_MESH_DNS_MAX_CONCURRENT_QUERIES` | No | `1024` | Maximum admitted DNS query tasks and outstanding upstream UDP forwards before the proxy returns SERVFAIL |
| `FERRUM_MESH_DNS_RESPONSE_CACHE_MAX_ENTRIES` | No | `4096` | Maximum per-slice cached synthetic mesh DNS response templates. Raise for very large meshes with many service names, qtypes, EDNS sizes, or wildcard variants |
| `FERRUM_MESH_CLUSTER_DOMAIN` | No | `cluster.local` | Kubernetes cluster DNS domain used when synthesizing `{service}.{namespace}.svc.<domain>` names |
| `FERRUM_MESH_OUTBOUND_TRAFFIC_POLICY` | No | `allow_any` | Istio-compatible mesh-wide outbound policy: `allow_any` (no gate) or `registry_only`. When `registry_only`, HTTP-family egress is gated by the auto-injected `mesh_outbound_registry` plugin and by the same configured reject status on outbound-capture route misses (both use `FERRUM_MESH_OUTBOUND_REGISTRY_REJECT_STATUS`), and stream-family egress (TCP / UDP / TCP+TLS / UDP+DTLS) on mesh outbound capture listener ports is also enforced — admitted destinations come from services, ServiceEntries (including wildcard hosts), and workload addresses; an empty registry fails closed for both HTTP and stream paths. Stream rejects use connection-level drop semantics (TCP: graceful close before backend dial; UDP: silent datagram drop) — the reject-status env var is HTTP-only. Inbound sidecar/ambient traffic is not gated. Native/CRD slice-supplied `outbound_traffic_policy` takes precedence when present; xDS ADS uses this env fallback until MeshConfig translation is wired |
| `FERRUM_MESH_OUTBOUND_REGISTRY_REJECT_STATUS` | No | `502` | HTTP 4xx/5xx status returned when `registry_only` rejects an unknown HTTP destination — both on the auto-injected `mesh_outbound_registry` plugin path and on outbound-capture route misses that would otherwise return a generic 404 before the plugin chain runs. **HTTP-family only** — stream-family egress (TCP / UDP / TCP+TLS / UDP+DTLS) does not have an "HTTP status" concept and instead rejects with a connection-level close (TCP) or silent datagram drop (UDP). Stream rejects increment `ferrum_mesh_outbound_registry_stream_decisions_total{protocol, decision="deny"}` instead of the HTTP host-bucketed counter |

Mesh DNS caches serialized response templates per mesh slice for mesh-owned names, bounded by `FERRUM_MESH_DNS_RESPONSE_CACHE_MAX_ENTRIES` (default 4,096). The cache is rebuilt with the slice, excludes the client transaction ID, and patches the caller's ID into each returned response, so repeated A/AAAA and mesh-owned empty responses avoid repeated wire-format serialization without leaking IDs across clients.

Mesh DNS forwards non-mesh UDP queries through a shared upstream socket with rewritten transaction IDs. If all 65,536 upstream IDs are simultaneously in flight, the proxy SERVFAILs the new query and increments `ferrum_mesh_dns_upstream_id_exhaustions_total` in the Prometheus registry so resolver outages or pathological query bursts are visible. The counter is process-wide and intentionally has no namespace label because the upstream UDP socket is process-wide. The counter is emitted from startup with value `0` so first-event alerting has a stable series.

Mesh observability emits Istio/GAMMA-shaped RED metrics through the existing Prometheus plugin when mesh metadata is present. The added series are `ferrum_mesh_requests_total` and `ferrum_mesh_request_duration_ms`, labelled with source/destination workload, namespace, principal, app, service, request protocol, response code, response flags, and connection security policy. HBONE tunnel copy failures after a CONNECT response has already been sent increment `ferrum_mesh_hbone_relay_failures_total` with `proxy_id`, `direction`, and `error_class` labels. Mesh identity and control-plane telemetry adds `ferrum_mesh_cert_expiry_seconds`, `ferrum_mesh_cert_rotation_failures_total`, `ferrum_mesh_ca_health`, `ferrum_mesh_trust_bundle_version`, `ferrum_mesh_config_last_received_timestamp_seconds`, and `ferrum_mesh_mtls_handshake_failures_total`.

The `mesh_outbound_registry` plugin emits `ferrum_mesh_outbound_registry_decisions_total` with `mesh_namespace`, `host`, and `decision` labels. Cardinality is intentionally bounded to three fixed `host` buckets: `<admit_explicit>` (exact-registry admits), `<admit_wildcard>` (one-label wildcard admits), and `<denied>` (every deny, including outbound-capture route misses under `registry_only`). The request Host header is never used as a label value. Operators triaging denied traffic should consult application logs for the requested host — the metric only signals the *rate* of denied egress per namespace, not the specific hosts.

Stream-family egress (TCP / UDP / TCP+TLS / UDP+DTLS) under `outbound_traffic_policy: registry_only` emits a sibling counter `ferrum_mesh_outbound_registry_stream_decisions_total` with `mesh_namespace`, `protocol`, and `decision` labels. Protocol values come from a fixed, pre-interned set (`tcp`, `tcp_tls`, `udp`, `udp_dtls`) so dashboards can break down stream rejects per transport without unbounded label growth. The counter is kept distinct from the HTTP one rather than adding a `protocol` label to the existing counter so the Wave-1 mesh dashboard series continue to render without splitting. Stream rejects do not include a per-host label — TCP closes happen before SNI / Host material is observed in a structured way, and UDP rejects drop the first datagram, so the protocol label is the only dimension Grafana panels need.

HBONE identity metadata is read from all `baggage` headers on authenticated HBONE requests where the peer already presented a SPIFFE identity. Baggage values may be percent-encoded, and Ferrum decodes them before extracting `source.principal` or `destination.principal`. Baggage parsing and egress stripping are quoted-value aware, so user-defined members with quoted commas are preserved. Plain HTTP requests, or requests without an authenticated peer, cannot supply `source.principal` through baggage for `mesh_authz` or `workload_metrics`; when unauthenticated HBONE baggage is present, Ferrum stamps `mesh_authz.ignored_baggage.unauthenticated = "true"` and `mesh.ignored_baggage = "unauthenticated_hbone"` for log triage.

Baggage SPIFFE identities are additionally gated by trust-domain matching: a baggage `source.principal` is honored only when its SPIFFE trust domain matches the peer cert's trust domain, or appears in `FERRUM_MESH_TRUST_DOMAIN_ALIASES`. Mismatches stamp `mesh_authz.ignored_baggage.trust_domain_mismatch = "true"` and keep `mesh_authz.ignored_baggage` as a comma-separated compatibility summary (and `mesh.ignored_baggage` from `workload_metrics`); the gateway falls back to the peer cert's identity. When the resulting authorization is rejected, the deny policy is annotated as `trust_domain_mismatch` for audit log triage.

HBONE CONNECT streams are always kept in streaming mode through authentication so the HTTP/2 upgrade handle remains available to the tunnel relay. Request-body plugins that run after authentication are skipped by the HBONE relay path. Digest-backed `hmac_auth` is therefore incompatible with HBONE CONNECT: Ferrum cannot consume tunnel DATA to verify the signed request-body digest without destroying the upgrade stream, so it fails closed with 401 before establishing the tunnel. Use mesh identity and authorization for HBONE authentication and enforce tunnel payload policy with workload controls instead.

Operators may strip mesh-internal baggage members at egress via `FERRUM_MESH_EGRESS_STRIP_BAGGAGE_KEYS`. Members whose key starts with any configured prefix are removed from the `baggage` header before backend dispatch; the rest of the baggage (e.g., user-defined tracing keys) propagates verbatim. The default empty list is a no-op for ordinary egress. Gateway-originated HBONE tunnels additionally strip identity-shaped baggage (`source.*`, `source_*`, `destination.*`, `destination_*`, `src.*`, `src_*`, `dst.*`, `dst_*`) from the inner HTTP request; the trusted gateway identity is sent only on the CONNECT-level baggage that the receiving sidecar validates against SPIFFE mTLS.

Layer 10 multi-cluster configuration lives under `mesh.multi_cluster` in the canonical config. Remote clusters carry trust domains and federation endpoints, VM `WorkloadEntry` resources populate workload addresses/network/cluster metadata, and east-west gateway entries are materialized as SNI-routed passthrough stream proxies only in `east_west_gateway` topology. A slice may declare at most 256 `remote_clusters`; larger sets fail validation before any federation or endpoint-discovery pollers are spawned.

### Kubernetes Mesh Integration

Phase D adds Kubernetes source translation and sidecar-injector scaffolding. Kubernetes resources translate into `GatewayConfig` / `MeshConfig`; no config source talks directly to the proxy runtime or xDS server.

Istio `DestinationRule` resources are translated: `connectionPool.tcp.connectTimeout` maps to `backend_connect_timeout_ms`, `outlierDetection` maps to passive health checks (`consecutive5xxErrors`, `interval`, `baseEjectionTime`), `loadBalancer` maps to Ferrum algorithms (`ROUND_ROBIN`, `LEAST_REQUEST`/`LEAST_CONN`, `RANDOM`, `consistentHash`), top-level `loadBalancer.localityLbSetting` honors `enabled`, weighted `distribute`, and region `failover` on top of the priority-tier preference projected from `source_locality`, `trafficPolicy.tls` projects to upstream backend TLS settings, and `subsets` are preserved with per-subset traffic policy overrides including subset-scoped `consistentHash` keys. Port-level `portLevelSettings[]` can override connect timeout, load balancing, outlier detection, locality LB, TCP keepalive/max-connections, supported HTTP connection-pool settings, and `tls` for the matching destination port; phantom ports are skipped at apply time with a warning. `portLevelSettings[].tls` is applied per-port: it resolves over upstream-/subset-level `trafficPolicy.tls` onto `port_overrides[port].tls` and projects onto the effective proxy's `resolved_tls` (part of the backend pool key). The translator rejects combined locality-LB modes (`distribute`, `failover`, `failoverPriority`), unsupported `failoverPriority`, and invalid ports instead of silently dropping them.

Istio `VirtualService` per-route features are translated: `retries` maps to Ferrum `RetryConfig` (with `retryOn` tokens for `5xx`, `gateway-error`, `connect-failure`, `reset`, `retriable-4xx`, and numeric status codes), `timeout` maps to `backend_read_timeout_ms` (Go-style duration strings: `10s`, `500ms`, `1m`, `1h`), and `fault` injection rides on each emitted `mesh_route_dispatch` rule (`abort.httpStatus`/`percentage` and `delay.fixedDelay`/`percentage`). Valid fault delays above Ferrum's 60-second runtime cap are clamped with translator-warning and Istio-status visibility. Per-rule fault percentages are static; RTDS keys apply only to explicitly configured `fault_injection` instances with a non-null `runtime_overlay_scope` (null is equivalent to omission). See [VirtualService fault injection](mesh.md#fault-injection).

Istio `AuthorizationPolicy` `requestPrincipals` field is enforced: the `jwks_auth` plugin emits `{issuer}/{subject}` as `request_principal` metadata, and `mesh_authz` evaluates `request_principals` glob patterns against it. Non-empty `request_principals` with no JWT present results in implicit deny (Istio semantics for anonymous requests).

Do not overload a single “deferred” label across Istio surfaces — support is dimensional (model/translation, Kubernetes watcher/RBAC, native transport, xDS ECDS carrier, runtime enforcement, status). See [Istio CRD capability dimensions](#istio-crd-capability-dimensions). Surfaces that remain unimplemented or out of scope: `EnvoyFilter`, `WasmPlugin`, and `WorkloadEntry` VM lifecycle (Pod auto-discovery and status reporting — `weight`, `locality`, `serviceAccount` are translated; locality-aware load balancing consumes source/target locality and honors `DestinationRule.trafficPolicy.loadBalancer.localityLbSetting.distribute` / `failover` / `enabled`). `Telemetry` provider-specific config beyond the basic tracing/metrics/access-log envelopes is still limited. `ProxyConfig` is **not** broadly deferred: the mesh model, K8s translator, native `MeshSubscribe`, and Ferrum xDS `ProxyConfigsCarrier` all carry it, and `tracing.sampling` merges into injected `workload_metrics` sampling; what is missing is the Kubernetes watcher/RBAC/status path (`ISTIO_CRDS` / status writer skip it). `AuthorizationPolicy` negative-match fields (`notMethods`, `notPaths`, `notHosts`, `notPorts`) are translated and enforced conjunctively with positive matchers (literal `notPorts` only — wildcard `notPorts` patterns fail closed at translation). Configure equivalent behavior with Ferrum proxy/upstream fields where a surface is unimplemented. Telemetry tracing providers support inline config plus name-only lookup through `meshConfig.extensionProviders` and `meshConfig.defaultProviders.tracing`. The outbound port inclusion annotations (`traffic.sidecar.istio.io/includeOutboundPorts` and `ferrum.io/includeOutboundPorts`), outbound port exclusion annotations (`traffic.sidecar.istio.io/excludeOutboundPorts` and `ferrum.io/excludeOutboundPorts`), inbound port exclusion annotations (`traffic.sidecar.istio.io/excludeInboundPorts` and `ferrum.io/excludeInboundPorts`), and CIDR-range capture annotations (`traffic.sidecar.istio.io/excludeOutboundIPRanges`, `traffic.sidecar.istio.io/includeOutboundIPRanges`) are supported and merged into the iptables capture plan.

Gateway API `HTTPRoute.backendRefs` and Istio `VirtualService.http[].route` splits are preserved during translation. A single backend becomes a direct Ferrum proxy backend; multiple non-zero backends create a generated `Upstream` and the proxy references it through `upstream_id`. Generated upstreams use `weighted_round_robin` only when backend weights differ, otherwise `round_robin`. Each HTTPRoute `matches[]` path and each VirtualService `match[]` URI, including regex URI matches, becomes its own proxy, so path alternatives are not collapsed into the first match. Empty HTTPRoute match entries and omitted `matches` / `match` fields create the route's default catch-all `/` proxy. Gateway API HTTPRoute method/header/queryParam matches and Istio `VirtualService` method/header/queryParam matches are translated unconditionally into proxy-scoped `mesh_route_dispatch` plugins (enabled by default — no opt-in env var or kill switch); same-path and URI-less ordered routes are collapsed into ordered dispatch-rule lists when needed to preserve fall-through to later routes, URI-less matches use a regex catch-all so they do not shadow real regex URI routes, and unsupported predicate-only candidates emit proxy-scoped `request_termination` instead of materializing unguarded proxies or falling through to later broader routes. Ordered-route collapse carries per-rule `timeout`/`retries` (including `retry_disabled: true` to clear an inherited proxy-scoped retry policy) on each dispatch rule, and the data plane plumbs the per-rule overrides through `RequestContext.route_override_*` so pool keys, the capability registry, and circuit-breaker target keys derive from the effective destination. Admission plugins still evaluate the original public proxy identity. Same-path Gateway API HTTP/GRPC route collisions are resolved before config materialization: for the same parent reference, hostname, and listen path, the oldest `metadata.creationTimestamp` wins, with `{namespace}/{name}` as the deterministic tiebreaker. Losing routes are skipped and reported through Gateway API status as conflicted. GRPCRoute method/service matches continue to translate to a deduplicated catch-all `/` proxy because gRPC method selection is encoded in the HTTP path at request time. Gateway API `weight: 0` backendRefs are skipped; if every backendRef in a matched rule has `weight: 0`, Ferrum keeps the rule traffic-capturing and attaches the same synthesized 100% HTTP 500 fault-abort used for wholly invalid or unresolved backendRefs, so traffic cannot fall through to a broader later route. In Istio multi-destination splits, omitted weights and `weight: 0` destinations are inactive; a lone Istio destination still receives all traffic. Malformed or out-of-range route weights are rejected during translation. Gateway API v1.5 defines `HTTPBackendRef.port` as a numeric `PortNumber` identifying the Service port, not the target port, so the CRD has no named backendRef-port surface to implement. After the numeric backendRef port selects a `Service.spec.ports[]` entry, Ferrum supports either a numeric `targetPort` or a named `targetPort`; named target ports resolve against `EndpointSlice.ports[].name` when pod discovery is enabled. Istio `VirtualService` destinations separately support both `port.number` and `port.name`; named destination ports are resolved against the `Service.spec.ports[].name` index built from collected core/v1 `Service` objects in the same translation batch. The cluster domain suffix for FQDN host matching is configurable via `FERRUM_K8S_CLUSTER_DOMAIN` (default `cluster.local`).

Translation notes: Istio `AuthorizationPolicy` resources preserve Istio's action semantics. An `ALLOW` policy with no `rules` is treated as allow-nothing for the selected workload, so it creates a mesh authorization rule that never matches instead of accidentally broadening access. `DENY` and `AUDIT` policies with no `rules` remain no-ops.

Gateway API `HTTPRoute` path matches preserve Kubernetes semantics: `PathPrefix` stays a prefix route, `Exact` is translated to an exact-path route for whole-path matching, and `RegularExpression` is passed through as a Ferrum regex route. Istio `VirtualService` URI matches follow the same shape for `prefix`, `exact`, and `regex`. Translated mesh routes do not strip the listen path before forwarding, so upgrades from older mesh previews should expect backends to receive the original Kubernetes request path.

Gateway API cross-namespace `backendRefs` require an exact matching `ReferenceGrant`, including the source API group/kind and target group/kind. Ferrum currently supports core Kubernetes `Service` backend references and fails closed for other backend target kinds in both same-namespace and cross-namespace routes.

When the Kubernetes controller watches Gateway API resources, it also patches the Gateway API status subresource for Ferrum-owned `GatewayClass` objects plus `Gateway`, `HTTPRoute`, and `GRPCRoute` objects. Ferrum writes `Accepted`, `Programmed`, `ResolvedRefs`, and `Conflicted` conditions using controller name `ferrum.io/gateway-controller`; translation failures such as invalid ports, missing Services, or missing cross-namespace `ReferenceGrant` permissions are reflected as rejected/unresolved route conditions. Gateway status includes listener conditions and, when `FERRUM_GATEWAY_API_STATUS_ADDRESS` is set, `status.addresses`. If `FERRUM_GATEWAY_API_DATA_PLANE_SERVICE_NAMESPACE` and `FERRUM_GATEWAY_API_DATA_PLANE_SERVICE_NAME` are set, Gateway `Programmed=True` is gated on that serving data-plane Service having at least one ready EndpointSlice endpoint; otherwise `Programmed` reflects translation/materialization only. Conflicting HTTP-family routes are resolved deterministically: the oldest `creationTimestamp` wins, with route namespace/name as the tiebreaker.

Kubernetes Gateway API and Istio mesh translators fail closed when a resource declares a port outside the Kubernetes service-port range (`1`-`65535`). Invalid ports are rejected during translation instead of wrapping into an unintended backend/listener port. Istio `AuthorizationPolicy.rules[].to[].operation.ports` also preserves wildcard string matches such as `"*"` and `"8*"` through Ferrum mesh policy `port_patterns`; non-numeric, non-pattern port strings still fail closed.

The Istio `AuthorizationPolicy` translator consumes the positive-match operation fields `methods`, `paths`, `hosts`, and `ports` plus the negative-match siblings `notMethods`, `notPaths`, `notHosts`, and `notPorts`. Negative matchers are conjunctive with positive fields in the same rule (see [mesh.md](mesh.md#authorization)). Literal numeric `notPorts` are enforced; wildcard `notPorts` patterns are rejected at translation time. Any other field on `rules[].to[].operation` is rejected at translation time so policies do not silently weaken authorization. `RequestMatch.hosts` host patterns submitted directly to mesh config are likewise validated at config-load — bare hostnames, bracketed IPv6 literals, and `host:port` / `host:*` are accepted, while `host:`, `host:abc`, or values with multiple unbracketed colons are rejected.

Service / namespace names embedded in destination hosts are matched case-sensitively against the collected Kubernetes object metadata (matching how the API server stores those names). The trailing cluster-domain suffix is matched case-insensitively per DNS semantics, so `<svc>.<ns>.svc.Cluster.Local` resolves the same as `<svc>.<ns>.svc.cluster.local`, but `Reviews.Default.svc.cluster.local` will not match a Service whose stored name is `reviews` in namespace `default`.

`FERRUM_K8S_POD_DISCOVERY_ENABLED=true` enables the CP-side native Kubernetes registry bridge when `FERRUM_K8S_CONTROLLER_ENABLED=true`. The controller watches Pods, Services, and EndpointSlices; translates ready Pods into mesh workloads; translates Services into mesh services using `spec.ports[]`; and links Services to Pods through EndpointSlices. Pending, terminating, failed, succeeded, or not-ready Pods are not surfaced. Explicit Istio `WorkloadEntry` / `ServiceEntry` resources override the auto-derived Pod/Service entries for the same service. The controller service account needs `get`, `list`, and `watch` permissions for namespaced `pods`, `services`, and `endpointslices`. Set `FERRUM_K8S_NODE_LOCALITY_ENABLED=true` only when the controller service account also has cluster-scoped `nodes` permissions; then Node topology labels are copied into workload locality.

**T2-B default-on in K8s pods**: `FERRUM_K8S_CONTROLLER_ENABLED` and `FERRUM_K8S_POD_DISCOVERY_ENABLED` default to `true` when the gateway process is running inside a Kubernetes pod (detected via the standard injected `KUBERNETES_SERVICE_HOST` env var, the same heuristic `kube-rs`'s `Config::incluster()` uses). Outside a pod — CLI invocations, Docker containers without `KUBERNETES_SERVICE_HOST`, dev environments — they keep the historic `false` default so tests and local runs are unaffected. Explicit `=false` from the operator (env var or `ferrum.conf`) always wins, so pod-side opt-out remains one setting away. **T2-B Istio status sub-resources**: when the K8s controller runs with `FERRUM_K8S_WATCH_ISTIO_CRDS=true`, it patches `status.conditions[]` (a `FerrumAccepted` condition plus `status.ferrum.translation`) on all nine watched/translated Istio kinds — `AuthorizationPolicy`, `PeerAuthentication`, `RequestAuthentication`, `DestinationRule`, `VirtualService`, `ServiceEntry`, `WorkloadEntry`, `Sidecar`, and `Telemetry` — so `kubectl describe` surfaces Ferrum's translation outcome (accepted, rejected, deferred-field list). The controller's service account needs `get` plus `patch`/`update` on those CRDs' `status` subresources because Ferrum reads live conditions before merge-patching its own — see the chart in `charts/ferrum-mesh/templates/control-plane-rbac.yaml`. `ProxyConfig` is translated when present in a translation batch and rides native/xDS carriers, but it is not in `ISTIO_CRDS` and the status writer does not patch it. **T2-B K8s watch scope**: when `FERRUM_K8S_WATCH_NAMESPACES` is unset, the controller derives its watch scope from the T2-A CP scope (`FERRUM_CP_NAMESPACES`). `CpScope::Single`/`Set` translate to namespaced watches; `CpScope::All` becomes a cluster-wide watch (requires `ClusterRole`-level permissions the chart already grants). Operators with an explicit `FERRUM_K8S_WATCH_NAMESPACES` value still win — the override is preserved for hand-tuned cases where the K8s watch scope intentionally differs from the CP scope.

#### Istio CRD capability dimensions

Support is not a single boolean. The contract below is the shared source of truth for `docs/configuration.md` and `docs/mesh.md` (pinned by `tests/unit/config/istio_docs_capability_parity_tests.rs` against `ISTIO_CRDS`, the status writer, and the ECDS carrier markers).

| Kind / surface | Model / translation | K8s watcher + RBAC | Native `MeshSubscribe` | xDS ECDS carrier | Runtime enforcement | Istio status (`FerrumAccepted`) |
|---|---|---|---|---|---|---|
| `AuthorizationPolicy` | Yes | Yes (`ISTIO_CRDS`) | Yes | Yes (`MeshPoliciesCarrier`) | Yes (incl. `notMethods`/`notPaths`/`notHosts`/`notPorts`) | Yes |
| `PeerAuthentication` | Yes | Yes | Yes | Yes (`PeerAuthenticationsCarrier`) | Yes | Yes |
| `RequestAuthentication` | Yes | Yes | Yes | Yes (`RequestAuthenticationsCarrier`) | Yes | Yes |
| `DestinationRule` | Yes | Yes | Yes | Yes (DR carrier + baked CDS/EDS) | Yes (incl. `portLevelSettings[].tls`) | Yes |
| `VirtualService` | Yes | Yes | Yes (via materialized proxies/plugins) | Partial (routes via CDS/EDS/LDS/RDS; CORS policies carrier) | Yes | Yes |
| `ServiceEntry` | Yes | Yes | Yes | Yes (`ServiceEntriesCarrier`) | Yes | Yes |
| `WorkloadEntry` | Yes | Yes | Yes (as workloads) | Yes (`WorkloadsCarrier`) | Yes | Yes |
| `Sidecar` | Yes | Yes | Yes (egress/ingress scope) | Yes (`SidecarEgressScopeCarrier` + ingress carriers) | Yes when enforcement flags enabled | Yes |
| `Telemetry` | Yes | Yes | Yes | Yes (`TelemetryResourcesCarrier`) | Yes (tracing/metrics/access-log envelopes) | Yes |
| `ProxyConfig` | Yes | **No** (not in `ISTIO_CRDS` / chart Istio RBAC) | Yes | Yes (`ProxyConfigsCarrier` — Ferrum-to-Ferrum ECDS, not stock Envoy xDS) | Partial (`tracing.sampling` → `workload_metrics`; concurrency/image/env informational) | **No** |
| `EnvoyFilter` / `WasmPlugin` | No | No | No | No | No | No |

`<!-- istio-capability-contract:v1 -->` marks this table for the parity test.

For NodeWaypoint discovery, `FERRUM_K8S_CONTROLLER_NAMESPACE` identifies the namespace where the Ferrum controller and ambient NodeWaypoint DaemonSet are installed. It defaults to `FERRUM_NAMESPACE` for non-Helm deployments. The Helm chart sets it to the release namespace so `FERRUM_NAMESPACE` can continue to represent the managed workload namespace without causing the CP to trust or watch the wrong NodeWaypoint pods.

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_K8S_CONTROLLER_ENABLED` | No | `true` in K8s pods (detected via `KUBERNETES_SERVICE_HOST`), `false` otherwise | Master switch for the CP-side K8s CRD controller. T2-B flipped the default to on inside a pod; explicit `=false` still disables it. When on, also enables `FERRUM_K8S_POD_DISCOVERY_ENABLED` by the same in-cluster heuristic |
| `FERRUM_K8S_POD_DISCOVERY_ENABLED` | No | `true` in K8s pods (detected via `KUBERNETES_SERVICE_HOST`), `false` otherwise | Enables native Kubernetes Pod/Service/EndpointSlice discovery in the CP K8s controller. T2-B flipped the default to on inside a pod; explicit `=false` still disables it |
| `FERRUM_K8S_WATCH_NAMESPACES` | No | unset (inherit `FERRUM_CP_NAMESPACES`) | Comma-separated Kubernetes namespaces the CP controller watches. Empty/unset inherits the T2-A CP scope from `FERRUM_CP_NAMESPACES` (`Single`/`Set` → namespaced watches; `All`/`*` → cluster-wide watch, requiring ClusterRole permissions). An explicit value overrides CP scope when the K8s watch boundary intentionally differs |
| `FERRUM_K8S_WATCH_ISTIO_CRDS` | No | `true` | Watch and translate Istio CRDs in the CP K8s controller, and write `status.conditions[]` on translated resources. Only effective when `FERRUM_K8S_CONTROLLER_ENABLED=true` |
| `FERRUM_K8S_CONTROLLER_NAMESPACE` | No | `FERRUM_NAMESPACE` | Namespace where the Ferrum K8s controller and ambient NodeWaypoint DaemonSet are installed. Helm renders this as the release namespace so managed workload namespace overrides do not break trusted NodeWaypoint discovery |
| `FERRUM_K8S_NODE_NAME` | NodeWaypoint SPIRE Helm profile | — | Kubernetes node name injected into ambient NodeWaypoint Pods with downward API `spec.nodeName`. The Helm SPIRE profile uses it in `FERRUM_MESH_WORKLOAD_SPIFFE_ID` as `$(FERRUM_K8S_NODE_NAME)` so each DaemonSet Pod receives a distinct per-node SPIFFE ID; Ferrum does not otherwise require operators to set it directly |
| `FERRUM_K8S_NODE_LOCALITY_ENABLED` | No | `false` | Enables optional cluster-scoped Node watching so topology labels can enrich auto-discovered pod workload locality |
| `FERRUM_K8S_CLUSTER_DOMAIN` | No | `cluster.local` | Kubernetes cluster DNS domain used by the source translator for FQDN host matching. VirtualService destinations of the form `<svc>.<ns>.svc.<cluster_domain>` (and bare/short forms) resolve port names against the matching `Service` |
| `FERRUM_K8S_TRUST_DOMAIN` | No | `cluster.local` | SPIFFE trust domain for derived workload identities. In `node_agent` mode it derives each enrolled pod's workload SPIFFE ID (`spiffe://{trust_domain}/ns/{namespace}/sa/{service_account}`) when writing the `FERRUM_WORKLOAD_IDENTITY` eBPF map, so it must match the CP-side SPIFFE format the node-waypoint resolver enrolls |
| `FERRUM_K8S_ISTIO_ROOT_NAMESPACE` | No | `istio-system` | Istio root namespace used by the K8s source translator for mesh-wide resources, including root-namespace `Sidecar` defaults/selectors and root-scoped `PeerAuthentication`, `RequestAuthentication`, `Telemetry`, and `ProxyConfig` resources |
| `FERRUM_K8S_WATCH_MESH_CONFIG` | No | `true` | Watch the root-namespace `istio` ConfigMap for `meshConfig.extensionProviders` / `defaultProviders.tracing` lookup. Requires `configmaps` `get/list/watch` RBAC in the istio root namespace (the watcher is scoped with a `metadata.name=istio` field selector). Set to `false` to skip the watch when the gateway runs in a different trust boundary from `istio-system` and cannot easily grant cross-namespace ConfigMap access. Only effective when `FERRUM_K8S_WATCH_ISTIO_CRDS=true` |
| `FERRUM_K8S_WATCH_GATEWAY_API_CRDS` | No | `true` | Enable watching Gateway API CRDs (`gateway.networking.k8s.io`: GatewayClass/Gateway/HTTPRoute/GRPCRoute) in the CP K8s controller. Only effective when `FERRUM_K8S_CONTROLLER_ENABLED=true` |
| `FERRUM_GATEWAY_API_DATA_PLANE_SERVICE_NAMESPACE` | No | — | Namespace of the routable Ferrum data-plane Service used to gate Gateway API `Gateway.status.conditions[Programmed]`. Set together with `FERRUM_GATEWAY_API_DATA_PLANE_SERVICE_NAME`; when unset, Gateway `Programmed` reflects translation/materialization only |
| `FERRUM_GATEWAY_API_DATA_PLANE_SERVICE_NAME` | No | — | Name of the routable Ferrum data-plane Service used to gate Gateway API `Gateway.status.conditions[Programmed]`. The controller watches EndpointSlices and reports `Programmed=True` only after the Service has at least one ready endpoint |
| `FERRUM_GATEWAY_API_STATUS_ADDRESS` | No | — | Optional Gateway API address advertised in `Gateway.status.addresses`. IP strings are reported as `IPAddress`; other values are reported as `Hostname` |
| `FERRUM_K8S_FULL_SYNC_INTERVAL_SECS` | No | `300` | Periodic full re-list interval (seconds) for the K8s controller. Safety valve against missed watch events |
| `FERRUM_K8S_RECONCILE_DEBOUNCE_MS` | No | `500` | Debounce window (ms) for the K8s controller — watch events arriving within this window are batched into a single reconciliation |
| `FERRUM_K8S_KUBECONFIG_PATH` | No | — | Override kubeconfig path for out-of-cluster development. When unset, the controller tries the in-cluster service-account config first, then falls back to standard kubeconfig inference (`KUBECONFIG` / `~/.kube/config`) |
| `FERRUM_INJECTOR_LISTEN_ADDR` | Injector mode | `0.0.0.0:9443` | Admission webhook bind address for `POST /mutate` |
| `FERRUM_INJECTOR_ADMISSION_REVIEW_MAX_BODY_SIZE_MIB` | No | `4` | Maximum `POST /mutate` AdmissionReview request body size, in MiB, accepted before JSON parsing. Values must be 1..64 |
| `FERRUM_INJECTOR_SIDECAR_IMAGE` | No | `ferrum-edge:latest` | Image injected into workload pods as the Ferrum mesh sidecar |
| `FERRUM_INJECTOR_REQUIRE_ANNOTATION` | No | `true` | Require pod label `ferrum.io/mesh=enabled` or annotation `ferrum.io/inject=true` before injecting |
| `FERRUM_INJECTOR_TRUST_DOMAIN` | No | `cluster.local` | Trust domain used to derive injected sidecar `FERRUM_MESH_WORKLOAD_SPIFFE_ID` from pod namespace and service account |
| `FERRUM_INJECTOR_JWT_SECRET_REF_NAME` | No | — | Kubernetes Secret name used as the injected sidecar `FERRUM_CP_DP_GRPC_JWT_SECRET` source |
| `FERRUM_INJECTOR_JWT_SECRET_REF_KEY` | No | — | Key inside `FERRUM_INJECTOR_JWT_SECRET_REF_NAME` used as the injected sidecar `FERRUM_CP_DP_GRPC_JWT_SECRET` source |
| `FERRUM_MESH_EXCLUDE_OUTBOUND_PORTS` | No | — | Comma-separated TCP destination ports that the injector excludes from outbound iptables capture |
| `FERRUM_INJECTOR_SIDECAR_CPU_REQUEST` | No | `25m` | CPU request injected for the Ferrum sidecar container |
| `FERRUM_INJECTOR_SIDECAR_MEMORY_REQUEST` | No | `64Mi` | Memory request injected for the Ferrum sidecar container |
| `FERRUM_INJECTOR_SIDECAR_CPU_LIMIT` | No | `250m` | CPU limit injected for the Ferrum sidecar container |
| `FERRUM_INJECTOR_SIDECAR_MEMORY_LIMIT` | No | `256Mi` | Memory limit injected for the Ferrum sidecar container |
| `FERRUM_INJECTOR_INIT_CPU_REQUEST` | No | `10m` | CPU request injected for the iptables init container |
| `FERRUM_INJECTOR_INIT_MEMORY_REQUEST` | No | `32Mi` | Memory request injected for the iptables init container |
| `FERRUM_INJECTOR_INIT_CPU_LIMIT` | No | `100m` | CPU limit injected for the iptables init container |
| `FERRUM_INJECTOR_INIT_MEMORY_LIMIT` | No | `128Mi` | Memory limit injected for the iptables init container |
| `FERRUM_INJECTOR_TLS_CERT_PATH` | Kubernetes webhook deployments | — | TLS certificate presented by the injector webhook server. Required together with the key unless `FERRUM_INJECTOR_ALLOW_PLAINTEXT=true` |
| `FERRUM_INJECTOR_TLS_KEY_PATH` | Kubernetes webhook deployments | — | TLS private key for `FERRUM_INJECTOR_TLS_CERT_PATH`. Required together with the cert unless `FERRUM_INJECTOR_ALLOW_PLAINTEXT=true` |
| `FERRUM_INJECTOR_ALLOW_PLAINTEXT` | No | `false` | Dev-only escape hatch for plaintext HTTP serving. Kubernetes mandates HTTPS for admission webhooks, so the injector refuses to start without `FERRUM_INJECTOR_TLS_CERT_PATH`+`FERRUM_INJECTOR_TLS_KEY_PATH` when this is `false` (default). Set `true` only for local development; the injector serves plaintext HTTP and logs a startup warning |
| `FERRUM_MESH_IP6TABLES_ENABLED` | No | `auto` | IPv6 iptables fan-out for injected init containers and capture fallback: `auto` probes and skips IPv6 rules when `ip6tables` is unavailable, `true` requires it whenever IPv6 CIDRs are configured and fails all capture setup before IPv4 rules if unavailable, `false` emits IPv4-only capture rules |

The injector copies non-secret mesh sidecar control-plane env vars from its own environment into injected containers when set: `FERRUM_DP_CP_GRPC_URLS`, `FERRUM_CP_DP_GRPC_JWT_ISSUER`, DP gRPC TLS vars, and `FERRUM_MESH_CONFIG_PROTOCOL`. It does not copy plaintext `FERRUM_CP_DP_GRPC_JWT_SECRET`; set `FERRUM_INJECTOR_JWT_SECRET_REF_NAME` and `FERRUM_INJECTOR_JWT_SECRET_REF_KEY` to inject that variable via `valueFrom.secretKeyRef`.

Outbound capture can be narrowed per pod with `traffic.sidecar.istio.io/includeOutboundPorts` or `ferrum.io/includeOutboundPorts`, using comma-separated TCP destination ports or `*` for all outbound ports. When explicit ports are present without an explicit include-CIDR annotation, the init container suppresses the implicit `0.0.0.0/0` catch-all and renders per-port outbound REDIRECT rules. When explicit include CIDRs are also set, capture is additive: all ports inside those CIDRs are captured, plus the listed ports to any destination. The `*` wildcard captures all outbound ports to any destination, even when explicit include CIDRs are also configured. IPv6 port rules are rendered through `ip6tables` whenever an IPv6 include or exclude CIDR activates the IPv6 address family.

Outbound capture exclusions can also be set per pod with `traffic.sidecar.istio.io/excludeOutboundPorts` or `ferrum.io/excludeOutboundPorts`, using comma-separated TCP ports. Global and pod-local lists are merged and deduplicated before the init container renders iptables `RETURN` rules.

Inbound port exclusions use the parallel annotations `traffic.sidecar.istio.io/excludeInboundPorts` / `ferrum.io/excludeInboundPorts`; the RETURN rules are emitted BEFORE the inbound REDIRECT/TPROXY catch-all so TCP and UDP exclusions are honored. CIDR-range exclusions use `traffic.sidecar.istio.io/excludeOutboundIPRanges` (APPENDS to the env-derived `FERRUM_MESH_CAPTURE_EXCLUDE_CIDRS`) and `traffic.sidecar.istio.io/includeOutboundIPRanges` (REPLACES the env-derived `FERRUM_MESH_CAPTURE_INCLUDE_CIDRS` when present, matching Istio's include-overrides-include semantics). Invalid ports or CIDRs in any annotation are rejected by the admission webhook with an error naming the offending annotation. Any IPv6 CIDR in include or exclude ranges activates IPv6 capture planning; IPv6 rules are partitioned into an `ip6tables` rule block. `FERRUM_MESH_IP6TABLES_ENABLED=auto` skips that block when the binary is missing, `true` requires it and fails before applying IPv4 rules if unavailable, and `false` emits IPv4-only rules.

Injected sidecars run as the configured mesh proxy UID with `runAsNonRoot=true`, `allowPrivilegeEscalation=false`, `readOnlyRootFilesystem=true`, `seccompProfile=RuntimeDefault`, and all Linux capabilities dropped. `FERRUM_MESH_PROXY_UID=0` is rejected at injector startup because Kubernetes would reject a sidecar that combines UID 0 with `runAsNonRoot=true`. The iptables init container explicitly sets `runAsUser=0`, `runAsNonRoot=false`, and `seccompProfile=RuntimeDefault`; it runs as root only long enough to program capture rules, drops all capabilities before adding back `NET_ADMIN` and `NET_RAW`, disables privilege escalation, and receives bounded CPU/memory requests and limits. Injector startup validates those resource quantity env vars so malformed values fail before admission requests are served. Its root filesystem remains writable because iptables needs the xtables lock path while programming capture rules.

UDP capture (`FERRUM_MESH_CAPTURE_UDP_ENABLED`, default off) is read by both the injector and the node-agent capture fallback; the injector folds it (with `FERRUM_MESH_CAPTURE_UDP_PORT` and `FERRUM_MESH_TPROXY_MARK`) into the rendered init-container script. Because UDP has no per-datagram recoverable original destination under iptables REDIRECT, captured UDP uses TPROXY in the `mangle` table (which delivers the datagram without rewriting its destination) plus a fwmark and an `ip rule add priority`/`ip route add local <table>` for transparent delivery. The routing TABLE is a **Ferrum-owned number, `33133`**, deliberately NOT Istio's inbound-TPROXY table `133`, so cleanup never risks a co-resident Istio install's routes; the `ip rule` carries an **explicit low priority (`100`) — separate from the table number** so it sits BELOW the kernel `main` table rule (priority `32766`), or `main` would resolve the marked datagram before the fwmark lookup and captured UDP would black-hole — and is delete-before-add so reruns stay idempotent. **Fail closed:** TPROXY local delivery is useless without that routing, so the setup script **fatally** requires `ip` (`iproute2`) before installing any UDP rule and does **not** `|| true` the load-bearing routing adds — the TPROXY rules and the routing go in together or not at all, never a TPROXY-without-routing half-state (the delete-before-add and cleanup stay best-effort). The PREROUTING-visible (forwarded/inbound) UDP chains ride `mangle PREROUTING` and are kept direction-disjoint by `-m addrtype --dst-type LOCAL` (inbound = the pod's own IP) / `! --dst-type LOCAL` (outbound = a real off-box destination), with the outbound jump installed before the inbound catch-all so egress isn't swallowed. The init container already grants `NET_ADMIN`, which covers the TPROXY target, the `addrtype` scoping, and the `ip rule`/`ip route` plumbing, so no extra capability is needed. **TPROXY runs only in `PREROUTING`, never directly from `mangle OUTPUT`** (jumping into a `-j TPROXY` chain from OUTPUT is invalid), but a pod's **own** locally-generated UDP egress routes through OUTPUT and never PREROUTING — so to capture it the injector (pod-netns) path installs an **OUTPUT-MARK → lo-reroute → PREROUTING-TPROXY loop**: a `mangle OUTPUT` chain `FERRUM_MESH_UDP_OUTPUT_MARK` does a `-j MARK` (not TPROXY) with the same fwmark, scoped by an anti-loop `-m mark ... -j RETURN` guard and a proxy-UID `-m owner --uid-owner <uid> -j RETURN` self-exclusion (owner-match is valid in OUTPUT but not PREROUTING) so loopback/self traffic is excluded; the existing fwmark `ip rule` (priority `100`) → table `33133` → `ip route add local 0.0.0.0/0 dev lo` reroutes the marked datagram to loopback (treated as INPUT, so OUTPUT runs once — no loop); and a `FERRUM_MESH_UDP_REINJECT` chain (jumped from PREROUTING first) holds one **mark-match** `-j TPROXY` rule that captures it to the UDP port. The OUTPUT-MARK rules also carry the **same `-m addrtype ! --dst-type LOCAL` egress scope** as the PREROUTING outbound chain, so pod-to-self / loopback UDP (which is `--dst-type LOCAL` in the OUTPUT context) is excluded and never fwmark-rerouted; the proxy-UID owner RETURN additionally excludes the proxy's own egress. So **locally-generated pod UDP egress IS captured** — but only to **real, non-local destinations**. This is the **injector pod-netns path only**: the **node-agent host-netns iptables fallback emits NO UDP rules** (the `addrtype` direction split is wrong in the host netns), and **eBPF does not cover UDP either** (its connect()-cgroup hooks are TCP-only) — node-agent host-netns UDP capture is unsupported this stage. The consuming UDP listener arrives in F3 §3.3 Stage 3. See [mesh.md](mesh.md) for the full model.

### Node Agent

`FERRUM_MODE=node_agent` runs a per-node DaemonSet agent that manages eBPF-based traffic capture for mesh sidecars, replacing the per-pod privileged init container. See [mesh.md](mesh.md#node-agent-mode) for architecture details.

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_NODE_AGENT_NODE_NAME` | Yes (node_agent) | — | Kubernetes node name, set via downward API (`spec.nodeName`) |
| `FERRUM_NODE_AGENT_NODE_IP` | Yes (node_waypoint) | — | Single trusted host source IP used to reach local pods. Required in NodeWaypoint: the inbound HBONE relay dials backend pods from this node-local source, and the source-bound guard drops the relay's traffic (and all direct inbound to enrolled pods) without it — the agent fails closed when no node source IP is set. Also exempts kubelet HTTP/TCP/gRPC probe ports derived from the enrolled pod spec. CNI-specific (e.g. the pod-CIDR gateway, which may differ from `status.hostIP`); the Helm chart does not auto-populate this value |
| `FERRUM_NODE_AGENT_NODE_IPS` | Yes (node_waypoint) | — | Comma-separated trusted host source IPs; merged with `FERRUM_NODE_AGENT_NODE_IP` for the same allowlist. Required in NodeWaypoint for every address family used by enrolled pods — a dual-stack node needs both an IPv4 and an IPv6 source, or that family's relay dials are dropped and enrollment reports the topology degraded. Do not include broad host-network sources |
| `FERRUM_NODE_AGENT_CGROUP_ROOT` | No | `/sys/fs/cgroup` | cgroup v2 mount point for pod cgroup resolution |
| `FERRUM_NODE_AGENT_BPF_FS_PATH` | No | `/sys/fs/bpf` | BPF filesystem mount point for pinned maps |
| `FERRUM_NODE_AGENT_BPF_ELF_PATH` | Linux `ebpf` feature | build-tree eBPF target path | Compiled `ferrum-ebpf` ELF loaded by the aya backend |
| `FERRUM_BPF_SOCK_OPS_RINGBUF_BYTES` | No | `4194304` (4 MiB) | SOCK_OPS event ringbuf size sized at BPF load time by the node-agent and consumed by the mesh-proxy via the pinned map at `/sys/fs/bpf/ferrum/sock_ops_events`. Must be a power of two ≥ 4096; invalid values fall back to the default with a warn. Raise when `ferrum_mesh_bpf_ringbuf_overruns_total` advances under load |
| `FERRUM_NODE_AGENT_PROXY_MODE` | No | `local_pod` | Capture topology contract: `local_pod` or `node_waypoint` |
| `FERRUM_NODE_AGENT_ADMIN_ENABLED` | No | `false` | Enables the node-agent read-only admin listener for metrics/health. When enabled, defaults to loopback unless `FERRUM_ADMIN_BIND_ADDRESS` or `FERRUM_ADMIN_ALLOWED_CIDRS` is set. `/live` and basic `/health` (status/ready) are unauthenticated; `/metrics` and detailed `/health` require an admin JWT, `FERRUM_METRICS_BEARER_TOKEN`, or `FERRUM_METRICS_ALLOWED_CIDRS` |
| `FERRUM_NODE_AGENT_HBONE_REDIRECT_PORT` | No | `15008` | HBONE redirect/listener port written into the node-agent capture contract and BPF config map. Must match the mesh proxy HBONE listener (`15008` today) |
| `FERRUM_NODE_AGENT_CNI_ENABLED` | No | `false` | Opts in to the CNI-style install. When `true`, the node-agent binds a Unix socket and listens for ADD/DEL/CHECK calls forwarded by the `ferrum-cni` binary that the Helm chart drops into `/opt/cni/bin/`. ADD fetches pod metadata immediately, while the kube-rs watcher remains the reconciliation source of truth. See [node_agent.md](node_agent.md#cni-plugin-install-optional) |
| `FERRUM_NODE_AGENT_CNI_SOCKET_PATH` | No | `/var/run/ferrum/node-agent-cni.sock` | Unix socket the node-agent listens on for CNI plugin RPCs. Only consulted when `FERRUM_NODE_AGENT_CNI_ENABLED=true`. The CNI plugin and the node-agent must agree on the path; the Helm chart renders both from one value |
| `FERRUM_NODE_AGENT_FALLBACK_MODE` | No | `fail` | Behaviour when eBPF prerequisites are missing (kernel < 5.7, cgroup v1, or bpffs unmounted). Default `fail` refuses startup with a structured error so DaemonSet readiness fails fast on degraded nodes. `iptables` keeps the node serving via host iptables capture and stamps `ferrum_mesh_node_topology_degraded=1`, but requires a runtime image with `/bin/sh`, `iptables`, and `ip6tables` when IPv6 capture is enabled. See [mesh.md](mesh.md#mixed-kernel-clusters) and [node_agent.md](node_agent.md#kernel-fallback) |
| `FERRUM_NODE_AGENT_EXCLUDED_NAMESPACES` | No | — | Extra namespaces to exclude from capture (comma-separated; `kube-system`, `kube-public`, `kube-node-lease` always excluded) |
| `FERRUM_MESH_CAPTURE_INCLUDE_CIDRS` | No | `0.0.0.0/0` | CIDRs to capture for outbound traffic (comma-separated). Per-pod annotation `traffic.sidecar.istio.io/includeOutboundIPRanges` REPLACES this value when present |
| `FERRUM_MESH_CAPTURE_EXCLUDE_CIDRS` | No | — | CIDRs to exclude from outbound capture (comma-separated, highest priority). Per-pod annotation `traffic.sidecar.istio.io/excludeOutboundIPRanges` APPENDS to this value |
| `FERRUM_MESH_CAPTURE_EXCLUDE_PORTS` | No | `15001,15006,15008,15020` | Destination TCP ports excluded from outbound capture (comma-separated) |
| `FERRUM_MESH_CAPTURE_EXCLUDE_INBOUND_PORTS` | No | — | Destination TCP and UDP ports excluded from inbound capture (comma-separated; mirrors Istio `excludeInboundPorts`). Per-pod annotation `traffic.sidecar.istio.io/excludeInboundPorts` is additive. RETURN rules are emitted before the inbound REDIRECT/TPROXY catch-all so the exclusion is honored |
| `FERRUM_MESH_IP6TABLES_ENABLED` | No | `auto` | IPv6 iptables fan-out: `auto` probes and skips IPv6 rules when `ip6tables` is unavailable, `true` requires it when IPv6 CIDRs are configured and fails all capture setup before IPv4 rules if unavailable, `false` emits IPv4-only capture rules |
| `FERRUM_MESH_CAPTURE_UDP_ENABLED` | No | `false` | Emit UDP TPROXY capture rules (F3 §3.3 Stage 2). Accepts the repo-wide boolean forms: case-insensitive `true`/`false` plus `1`/`0`. UDP cannot use the TCP REDIRECT model, so captured UDP uses TPROXY in the `mangle` table plus a fwmark and an `ip rule`/`ip route local` for transparent delivery. **Default off:** the consuming UDP listener arrives in Stage 3, so enabling this before then would redirect UDP into a void. When off, no `mangle`/TPROXY/routing rules are emitted at all |
| `FERRUM_MESH_CAPTURE_UDP_PORT` | No | `15011` | UDP TPROXY listener port (Stage 3 consumer). Distinct from the TCP outbound port (`15001`) because UDP and TCP cannot share one listener socket |
| `FERRUM_MESH_TPROXY_MARK` | No | `0x733` (1843) | Firewall mark (`fwmark`) stamped on TPROXY'd UDP datagrams; the policy routing rule matches it to steer them to the Ferrum-owned local-delivery route table (`33133`, deliberately **not** Istio's table `133`). Accepts `0x`-prefixed hex or decimal; must be non-zero. The default is **Ferrum-owned and deliberately NOT Istio's conventional TPROXY mark `0x539`**: Ferrum's higher-priority fwmark rule (priority `100`) matches the mark, so defaulting to `0x539` would hijack a co-resident Istio's marked packets into Ferrum's table and break Istio traffic. The default also avoids common masked CNI mark classes such as `0xF00/0xF00`. Within Ferrum it is collision-free (no other packet marks; the `1337` proxy UID is a socket-owner match, a disjoint namespace from `skb->mark`) |

### Migration

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_MIGRATE_ACTION` | No | `up` | Migration action: `up`, `status`, or `config` |
| `FERRUM_MIGRATE_DRY_RUN` | No | `false` | Preview migration work without applying changes |
| `FERRUM_AUTO_APPLY_PLUGIN_MIGRATIONS` | No | `false` | When `true`, the `database`/`cp` startup path applies pending custom-plugin migrations (declared via `plugin_migrations()` in compiled `custom_plugins/`) before loading config; a failed migration is fatal. When `false` (default), pending plugin migrations are logged as a `warn!` but the schema is never auto-mutated — run `FERRUM_MODE=migrate FERRUM_MIGRATE_ACTION=up` explicitly. After offline/backup bootstrap recovers a previously unreachable SQL database, database mode retries the same pending-state probe and warn/auto-apply policy before re-enabling admin writes or publishing recovered configuration. In warn-only mode (`false`), a pending-state **probe failure** is logged and does not block publication (matching ordinary startup / a process restart); a probe that succeeds and reports pending migrations still warns without auto-mutating schema. Auto-apply mode (`true`) stays fail-closed on probe or apply failure and retries on the next successful poll. Pool topology changes (DNS reconnect / failover) reset the reconcile gate so the next poll re-probes. Core gateway schema migrations always run regardless of this flag. The standalone `migrate` mode always applies plugin migrations. Pedagogical examples under `custom_plugins/examples/` are not compiled (and therefore contribute no migrations) unless listed in build-time `FERRUM_CUSTOM_PLUGINS` |

### Size Limits

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_MAX_HEADER_SIZE_BYTES` | No | `32768` | Maximum total request header size (all headers combined) |
| `FERRUM_MAX_SINGLE_HEADER_SIZE_BYTES` | No | `16384` | Maximum size of any single request header (name + value) |
| `FERRUM_MAX_HEADER_COUNT` | No | `100` | Max number of request headers allowed (0=unlimited) |
| `FERRUM_MAX_REQUEST_BODY_SIZE_BYTES` | No | `10485760` | Maximum request body size (0=unlimited) |
| `FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES` | No | `10485760` | Maximum response body size from backends (0=unlimited) |
| `FERRUM_RESPONSE_BUFFER_CUTOFF_BYTES` | No | `65536` | Eager-buffer known-size responses at or below this size; `0` always streams |
| `FERRUM_H2_COALESCE_TARGET_BYTES` | No | `131072` | Target chunk size for HTTP/2 response body coalescing; clamped 16 KiB..1 MiB |
| `FERRUM_MAX_URL_LENGTH_BYTES` | No | `8192` | Maximum URL length in bytes (path + query string, 0=unlimited) |
| `FERRUM_MAX_QUERY_PARAMS` | No | `100` | Maximum number of query parameters allowed (0=unlimited) |
| `FERRUM_MAX_GRPC_RECV_SIZE_BYTES` | No | `4194304` | Maximum total received gRPC payload size in bytes (0=unlimited) |
| `FERRUM_MAX_WEBSOCKET_FRAME_SIZE_BYTES` | No | `16777216` | Maximum WebSocket frame size in bytes; max message size = 4x frame size |
| `FERRUM_WEBSOCKET_WRITE_BUFFER_SIZE` | No | `131072` | WebSocket write buffer size (128 KB). Increase for large WS frames (1 MB+). Only applies when frame-level plugins are active |
| `FERRUM_WEBSOCKET_TUNNEL_MODE` | No | `false` | When true and no frame-level plugins are configured, bypass WebSocket frame parsing and use raw TCP bidirectional copy. Significantly improves throughput for large payloads (9 MB: 25→110 RPS). `FERRUM_MAX_WEBSOCKET_FRAME_SIZE_BYTES` is not enforced in tunnel mode (no DoS risk — data streams through a fixed-size copy buffer). Backend bytes that arrive in the same read as the backend `101 Switching Protocols` response are recovered and forwarded to the client before the raw relay starts, preserving push-first backends without parsing frames. Attach a frame-level plugin or disable tunnel mode when frame inspection, per-frame limits, or frame counters are required |
| `FERRUM_WEBSOCKET_IDLE_TIMEOUT_SECONDS` | No | `300` | Global default connection-wide WebSocket idle timeout in seconds for frame-parsed and tunnel-mode sessions. The session closes only when neither direction produces traffic within the window; activity from either side — including Ping/Pong heartbeats — keeps it open. Tracked at the transport byte level in both modes, so a partially received large/fragmented message counts as activity while its bytes are still arriving. The per-proxy `websocket_idle_timeout_seconds` overrides this. Recommended production values: `300` (5 min) for typical apps, `600`+ for sparse server-push streams that heartbeat infrequently. Most production clients (browsers, Socket.IO, gRPC-over-WS) ping more often than every 5 minutes and stay open indefinitely; raise the value or set `0` for protocols that legitimately go silent for longer than the window without a heartbeat. `0` disables the bound — idle sessions then live forever, bounded only by `FERRUM_WEBSOCKET_MAX_CONNECTIONS` (resource-hoarding risk; a startup warning is logged). **HTTP/3 caveat:** on QUIC frontends the connection-level transport idle timeout `FERRUM_HTTP3_IDLE_TIMEOUT` (default 30s) also applies. On an otherwise-idle H3 connection, QUIC may close before a longer WebSocket idle timer; multiplexed H3 connections with other active streams may stay open. Startup/reload warnings are logged only for affected proxies when an H3 WebSocket listener is actually reachable. Raise `FERRUM_HTTP3_IDLE_TIMEOUT` if isolated H3 WebSockets must honor a longer idle window |
| `FERRUM_HTTP_HEADER_READ_TIMEOUT_SECONDS` | No | `10` | HTTP/1.1 header read timeout for proxy and admin listeners and for injector-mode (`FERRUM_MODE=injector`) admission-webhook connections; on admin listeners the same value also drives the connection idle-read deadline used for incomplete HTTP/2 HEADERS/CONTINUATION streams and HTTP/2 keep-alive. `0` disables these timers, leaving incomplete header blocks unbounded |

See [size_limits.md](size_limits.md) for detailed sizing guidance.

### DNS

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_DNS_TTL_OVERRIDE_SECONDS` | No | Disabled | Global TTL override — forces all records to use this fixed TTL. Disabled by default (native record TTL is respected). Capped at 86400s (1 day) |
| `FERRUM_DNS_MIN_TTL_SECONDS` | No | `5` | Minimum TTL floor to prevent 0-TTL abuse. Capped at 86400s (1 day) |
| `FERRUM_DNS_OVERRIDES` | No | `{}` | JSON map of hostname→IP static overrides |
| `FERRUM_DNS_RESOLVER_ADDRESS` | No | resolv.conf | Comma-separated nameservers (ip[:port]) |
| `FERRUM_DNS_RESOLVER_HOSTS_FILE` | No | `/etc/hosts` | Path to custom hosts file |
| `FERRUM_DNS_ORDER` | No | `CACHE,SRV,A,CNAME` | Record type query order (comma-separated) |
| `FERRUM_DNS_STALE_TTL` | No | `3600` | Stale data usage time (seconds) during refresh. Capped at 86400s (1 day) |
| `FERRUM_DNS_ERROR_TTL` | No | `5` | TTL (seconds) for errors/empty responses. Capped at 86400s (1 day) |
| `FERRUM_DNS_CACHE_MAX_SIZE` | No | `10000` | Maximum DNS cache entries |
| `FERRUM_DNS_WARMUP_CONCURRENCY` | No | `500` | Maximum concurrent DNS warmup resolutions during startup/config reload |
| `FERRUM_DNS_SLOW_THRESHOLD_MS` | No | Disabled | Log slow DNS resolutions above this threshold (ms) |
| `FERRUM_DNS_REFRESH_THRESHOLD_PERCENT` | No | `90` | Percentage of TTL elapsed before background refresh (1-99) |
| `FERRUM_DNS_FAILED_RETRY_INTERVAL_SECONDS` | No | `10` | Interval (seconds) for retrying failed DNS lookups. `0` = disabled. Capped at 86400s (1 day) |
| `FERRUM_DNS_TRY_TCP_ON_ERROR` | No | `true` | Retry over TCP when UDP DNS responses are truncated or fail |
| `FERRUM_DNS_NUM_CONCURRENT_REQS` | No | `3` | Nameservers to query concurrently per lookup; clamped 1..10 |
| `FERRUM_DNS_MAX_ACTIVE_REQUESTS` | No | `512` | Max in-flight queries per multiplexed DNS connection; clamped 1..4096 |
| `FERRUM_DNS_MAX_CONCURRENT_REFRESHES` | No | `64` | Maximum concurrent stale-while-revalidate background refresh tasks system-wide. Prevents unbounded task spawning when many stale hostnames are hit simultaneously. Range: 1-1000 |

See [dns_resolver.md](dns_resolver.md) for full configuration reference.

### TLS / mTLS

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_TLS_CA_BUNDLE_PATH` | No | — | Path to PEM CA bundle for all outbound TLS verification |
| `FERRUM_TLS_CA_BUNDLE_SOURCE` | No | — | Source override for `FERRUM_TLS_CA_BUNDLE_PATH`; accepts path, `file://`, inline PEM, or provider URI |
| `FERRUM_BACKEND_TLS_CLIENT_CERT_PATH` | No | — | Path to client certificate for backend mTLS |
| `FERRUM_BACKEND_TLS_CLIENT_CERT_SOURCE` | No | — | Source override for `FERRUM_BACKEND_TLS_CLIENT_CERT_PATH`; accepts path, `file://`, inline PEM, or provider URI |
| `FERRUM_BACKEND_TLS_CLIENT_KEY_PATH` | No | — | Path to client private key for backend mTLS |
| `FERRUM_BACKEND_TLS_CLIENT_KEY_SOURCE` | No | — | Source override for `FERRUM_BACKEND_TLS_CLIENT_KEY_PATH`; accepts path, `file://`, inline PEM, provider URI, or `pkcs11://` RSA signer URI when built with the `pkcs11` feature |
| `FERRUM_GATEWAY_SVID_CERT_PATH` | No | — | Leaf-first PEM X.509-SVID certificate chain used as the gateway's SPIFFE identity for gateway-to-mesh TLS. Watched for content changes; rotation drains old backend pool entries. See [docs/spire_deployment.md](spire_deployment.md) for how to wire SPIRE-issued SVIDs into these files via [SPIFFE Helper](https://github.com/spiffe/spiffe-helper) |
| `FERRUM_GATEWAY_SVID_CERT_SOURCE` | No | — | Source override for `FERRUM_GATEWAY_SVID_CERT_PATH`; accepts path, `file://`, inline PEM, or provider URI. File rotation is enabled only when all three SVID sources are file-backed |
| `FERRUM_GATEWAY_SVID_KEY_PATH` | No | — | Unencrypted PKCS#8 private key for `FERRUM_GATEWAY_SVID_CERT_PATH`; legacy `BEGIN RSA PRIVATE KEY` / `BEGIN EC PRIVATE KEY` files are rejected |
| `FERRUM_GATEWAY_SVID_KEY_SOURCE` | No | — | Source override for `FERRUM_GATEWAY_SVID_KEY_PATH`; accepts path, `file://`, inline PEM, or provider URI |
| `FERRUM_GATEWAY_SVID_TRUST_BUNDLE_PATH` | No | — | PEM trust bundle used to verify mesh SPIFFE peers. Used for backend (gateway-to-mesh) TLS and, when all three `FERRUM_GATEWAY_SVID_*` paths are set, for **inbound** mesh mTLS/HBONE peer verification: inbound peer certs are validated chain-to-bundle and the peer SPIFFE SAN's trust domain is checked against this local bundle plus the slice's federated bundles. Without gateway SVID material, inbound listeners fall back to chain-only verification against `FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH` |
| `FERRUM_GATEWAY_SVID_TRUST_BUNDLE_SOURCE` | No | — | Source override for `FERRUM_GATEWAY_SVID_TRUST_BUNDLE_PATH`; accepts path, `file://`, inline PEM, or provider URI |
| `FERRUM_GATEWAY_SPIFFE_ID` | No | — | Explicit SPIFFE URI fallback when the gateway SVID certificate has no SPIFFE URI SAN |
| `FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH` | No | — | Path to client CA bundle for mTLS verification |
| `FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_SOURCE` | No | — | Source override for `FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH`; accepts path, `file://`, inline PEM, or provider URI |
| `FERRUM_TLS_NO_VERIFY` | No | `false` | Disable outbound TLS verification for all connections (testing only); also bypasses backend SAN allow-list enforcement and logs a warning when an allow-list is configured |
| `FERRUM_TLS_CRL_FILE_PATH` | No | — | PEM CRL bundle for revocation checks across TLS/DTLS surfaces |
| `FERRUM_TLS_CRL_SOURCE` | No | — | Source override for `FERRUM_TLS_CRL_FILE_PATH`; accepts path, `file://`, inline PEM, or provider URI |
| `FERRUM_TLS_MIN_VERSION` | No | `1.2` | Minimum TLS protocol version, inbound + outbound (`1.2` or `1.3`) |
| `FERRUM_TLS_MAX_VERSION` | No | `1.3` | Maximum TLS protocol version, inbound + outbound (`1.2` or `1.3`) |
| `FERRUM_TLS_CIPHER_SUITES` | No | *(secure defaults)* | Comma-separated cipher suites, inbound + outbound (see [TLS Policy Hardening](frontend_tls.md#tls-policy-hardening)) |
| `FERRUM_TLS_KEY_EXCHANGE_GROUPS` | No | `X25519,secp256r1` | Comma-separated key exchange groups, inbound + outbound. `FERRUM_TLS_CURVES` is accepted as an alias |
| `FERRUM_TLS_PREFER_SERVER_CIPHER_ORDER` | No | `true` | Prefer server cipher order during TLS 1.2 negotiation (inbound only) |
| `FERRUM_TLS_SESSION_CACHE_SIZE` | No | `4096` | TLS session resumption cache size (inbound only, TLS 1.2 stateful session IDs) |
| `FERRUM_TLS_CERT_EXPIRY_WARNING_DAYS` | No | `30` | Warn when configured certificates expire within this many days; `0` disables warnings |
| `FERRUM_TLS_EARLY_DATA_METHODS` | No | — | Comma-separated methods allowed as TLS 1.3 0-RTT early data |

These TLS policy settings apply uniformly to both inbound (frontend) and outbound (backend) connections across all TLS-capable protocols (HTTP/1.1, HTTP/2, HTTP/3, gRPC, WebSocket, TCP-TLS). DTLS uses a separate library and is not affected. See [frontend_tls.md](frontend_tls.md) and [backend_mtls.md](backend_mtls.md) for detailed TLS configuration guides.

Gateway SVID material is validated at startup. When all three SVID sources resolve to files, they are also watched for backend/gateway-to-mesh client-SVID rotation; inline PEM and provider URI SVID sources are static until provider watch support is added. Set all three SVID path/source variables together; the gateway rejects partial configuration and validates the leaf certificate, intermediate certificate freshness, PKCS#8 key match, and trust bundle before serving or publishing a later reload. A successful file reload updates the gateway SVID slot, bumps the backend SVID generation, restarts active HTTP health probes, and lets new backend TLS connections rebuild client identity state without restarting. The SPIFFE ID is read from the leaf URI SAN when present; `FERRUM_GATEWAY_SPIFFE_ID` is only a fallback for bundles without a SPIFFE URI SAN. Private keys must be unencrypted PKCS#8 PEM (`BEGIN PRIVATE KEY`; `openssl pkcs8 -topk8 -nocrypt` can convert legacy RSA/EC PEM keys); legacy `BEGIN RSA PRIVATE KEY` or `BEGIN EC PRIVATE KEY` files are rejected. Other TLS material sources are loaded when their owning runtime/config is built; backend connection pools keep the TLS config they were created with until their pool key changes or the process restarts.

Gateway DPs can also receive mesh SPIFFE trust bundles from the CP. `GatewayConfig.trust_bundles` uses the same serializable `TrustBundleSet` shape as mesh config on the CP side, but CP `ConfigUpdate` and `FullConfigResponse` messages carry that material only in the `trust_bundles_json` side channel so older DPs can keep deserializing full snapshot `GatewayConfig` JSON safely. Stream snapshots, stream deltas, and unary full snapshots all refresh gateway-to-mesh trust material; JSON `null` explicitly clears previously delivered CP trust, including when the CP rejects invalid trust-bundle material and must revoke stale anchors instead of leaving them unchanged. When a gateway SVID is loaded from files, received trust bundles temporarily override the SVID bundle's trust material in the lock-free slot; if a later authoritative CP update clears them, the DP restores the latest validated file trust. Without a local SVID, the DP still stores CP-delivered bundles for later gateway-mesh features.

Gateway-to-mesh HBONE dispatch is opt-in per upstream target. A target tagged `mesh.hbone=true` is probed on the standard sidecar HBONE port `15008` (override with `mesh.hbone_port`) when the gateway has a loaded SVID. Plain HTTP requests to that target use an HTTP/2 CONNECT tunnel with SPIFFE mTLS before the ordinary H3/H2/reqwest backend chain is considered. A `Supported`, `Unknown`, or not-yet-cached HBONE capability can attempt the live tunnel so cold or timed-out probes do not block first traffic; an explicit `Unsupported` capability, missing gateway SVID, replayable retry requirement, or request-body-buffering requirement fails closed instead of direct-dialing the application endpoint. The HBONE pool uses the proxy's effective `pool_*` overrides for connection count, idle timeout, TCP keepalive, and HTTP/2 flow-control settings, and coalesces concurrent first connects for the same target/SVID key within the proxy's `backend_connect_timeout_ms` budget. Ferrum injects `source.principal` baggage from the gateway SVID on the CONNECT request; mesh sidecars still validate baggage against the authenticated peer identity before trusting it. Capability-level tunnel establishment failures such as TCP, TLS, DNS, or HTTP/2 handshake errors downgrade only the cached HBONE capability for that target, so later mesh-tagged requests continue to fail closed until the next capability refresh succeeds. Per-request CONNECT rejections do not downgrade HBONE support.

When a gateway SVID is loaded, Ferrum also enables gateway-originated mesh metrics. If no global `workload_metrics` plugin exists, the runtime adds an internal global plugin with `workload_spiffe_id` set to the gateway SPIFFE ID. If an operator-managed global `workload_metrics` plugin already exists in the gateway namespace, Ferrum leaves the plugin in place and fills `workload_spiffe_id` only when it is missing. Requests actually dispatched through HBONE are labeled with `mesh.connection_security_policy=mutual_tls`, `mesh.gateway.transport=hbone`, and any mesh destination tags present on the selected upstream target.

Admin listener TLS and mTLS variables are listed in [Admin API](#admin-api).

### HTTP/3 (QUIC)

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_ENABLE_HTTP3` | No | `false` | Enable HTTP/3 (QUIC) listener on the HTTPS port |
| `FERRUM_HTTP3_IDLE_TIMEOUT` | No | `30` | HTTP/3 connection idle timeout in seconds |
| `FERRUM_HTTP3_MAX_STREAMS` | No | `1000` | Maximum concurrent HTTP/3 streams per connection |
| `FERRUM_HTTP3_STREAM_RECEIVE_WINDOW` | No | `262144` | HTTP/3 per-stream receive window in bytes (default: 256 KiB — conservative for frontend listeners serving untrusted clients) |
| `FERRUM_HTTP3_RECEIVE_WINDOW` | No | `2097152` | HTTP/3 connection-level receive window in bytes (default: 2 MiB — conservative for frontend listeners serving untrusted clients) |
| `FERRUM_HTTP3_SEND_WINDOW` | No | `2097152` | HTTP/3 per-connection send window in bytes (default: 2 MiB — conservative for frontend listeners) |
| `FERRUM_HTTP3_CONNECTIONS_PER_BACKEND` | No | `4` | QUIC connections per H3 backend (pool sharding) |
| `FERRUM_HTTP3_POOL_IDLE_TIMEOUT_SECONDS` | No | `120` | H3 backend connection idle eviction in seconds |
| `FERRUM_HTTP3_COALESCE_MIN_BYTES` | No | `32768` | Response coalesce flush target (native H3 + cross-protocol bridge) |
| `FERRUM_HTTP3_COALESCE_MAX_BYTES` | No | `32768` | Response coalesce buffer capacity and `min_bytes` clamp |
| `FERRUM_HTTP3_FLUSH_INTERVAL_MICROS` | No | `200` | Response coalesce time-based flush interval (µs) |
| `FERRUM_HTTP3_REQUEST_BODY_CHANNEL_CAPACITY` | No | `32` | Bounded mpsc capacity for the H3→non-H3 cross-protocol request-body bridge. Bounds in-flight request memory to approximately `capacity × average_h3_chunk_size` during streaming uploads. Range: 1–1024. |
| `FERRUM_HTTP3_WEBSOCKET_ENABLED` | No | `true` | Advertise `SETTINGS_ENABLE_CONNECT_PROTOCOL` and accept RFC 9220 Extended CONNECT (`:method=CONNECT`, `:protocol=websocket`) on the H3 listener. When `false`, the H3 server does not advertise the setting and the bridge returns 501. The WebSocket plugin pipeline (`on_ws_frame`, `on_ws_disconnect`, `ws_rate_limit`, `ws_message_size_limiting`, `ws_frame_logging`) and admission control (`FERRUM_WEBSOCKET_MAX_CONNECTIONS`) work on H3 sessions whether or not `FERRUM_WEBSOCKET_TUNNEL_MODE` is set — H3 always frame-parses since there is no raw TCP underneath QUIC. See [docs/http3.md](http3.md#websocket-over-http3-rfc-9220-extended-connect). |
| `FERRUM_HTTP3_INITIAL_MTU` | No | `1500` | Initial QUIC path MTU (clamped 1200–65527) |
| `FERRUM_H3_REQUEST_BODY_DRAIN_MS` | No | `50` | Courtesy drain window before STOP_SENDING on small/successful H3 responses |

See [docs/http3.md](http3.md) for the full HTTP/3 dispatch model, cross-protocol bridge behavior, and WebSocket-over-H3 bridging.

### Stream Proxy (TCP/UDP/DTLS)

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_STREAM_PROXY_BIND_ADDRESS` | No | `0.0.0.0` | Bind address for TCP/UDP/DTLS stream proxy listeners |
| `FERRUM_TCP_IDLE_TIMEOUT_SECONDS` | No | `300` | Default TCP idle timeout; `0` disables |
| `FERRUM_TCP_HALF_CLOSE_MAX_WAIT_SECONDS` | No | `300` | Hard cap for TCP half-close drain; the userspace `copy_bidirectional` fast path requires this, `FERRUM_TCP_IDLE_TIMEOUT_SECONDS`, `backend_read_timeout_ms`, and `backend_write_timeout_ms` all set to `0`. Linux splice paths enforce these bounds inline and do not require disabling them. |
| `FERRUM_UDP_MAX_SESSIONS` | No | `10000` | Maximum concurrent UDP sessions per proxy |
| `FERRUM_UDP_CLEANUP_INTERVAL_SECONDS` | No | `10` | UDP session cleanup interval |
| `FERRUM_UDP_RECVMMSG_BATCH_SIZE` | No | `64` | Linux `recvmmsg` receive batch size; clamped 1..1024 |
| `FERRUM_DTLS_CERT_PATH` | No | — | PEM certificate for frontend DTLS termination (ECDSA P-256 or P-384 only) |
| `FERRUM_DTLS_CERT_SOURCE` | No | — | Source override for `FERRUM_DTLS_CERT_PATH`; accepts path, `file://`, inline PEM, or provider URI |
| `FERRUM_DTLS_KEY_PATH` | No | — | PEM private key for frontend DTLS termination |
| `FERRUM_DTLS_KEY_SOURCE` | No | — | Source override for `FERRUM_DTLS_KEY_PATH`; accepts path, `file://`, inline PEM, or provider URI |
| `FERRUM_DTLS_CLIENT_CA_CERT_PATH` | No | — | PEM CA certificate for verifying DTLS client certs (frontend mTLS) |
| `FERRUM_DTLS_CLIENT_CA_CERT_SOURCE` | No | — | Source override for `FERRUM_DTLS_CLIENT_CA_CERT_PATH`; accepts path, `file://`, inline PEM, or provider URI |
| `FERRUM_DTLS_MAX_PLAINTEXT_BYTES` | No | `16384` | Maximum plaintext payload bytes per DTLS record |
| `FERRUM_DTLS_RECORD_OVERHEAD_BYTES` | No | `64` | DTLS record overhead budget for per-session output buffers |
| `FERRUM_FRONTEND_TLS_HANDSHAKE_TIMEOUT_SECONDS` | No | `10` | Shared frontend TCP+TLS and UDP+DTLS handshake timeout. DTLS peers still in handshake count against `FERRUM_UDP_MAX_SESSIONS` until this deadline releases them |

See [tcp_udp_proxy.md](tcp_udp_proxy.md) for full TCP/UDP proxy documentation.

### Authentication

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_BASIC_AUTH_HMAC_SECRET` | When `basic_auth` is enabled | — | Unique random server secret of at least 32 bytes for HMAC-SHA256 password verification. The Admin API stores `hmac_sha256:<64 lowercase hex>` hashes. There is no default; missing or weak values fail plugin construction. Rotating this secret invalidates every existing Basic-auth password hash, so re-hash credentials as part of the same rollout. |
| `FERRUM_MAX_CREDENTIALS_PER_TYPE` | No | `2` | Maximum active credential entries per type per consumer |
| `FERRUM_TRUSTED_PROXIES` | No | — | Comma-separated trusted proxy CIDRs/IPs. Ferrum trusts `X-Forwarded-For` from these direct peers for client-IP resolution. For the original browser-facing scheme, a singleton `X-Forwarded-Proto` value of `http` or `https` is treated as the direct proxy's overwrite-only assertion; a multi-value safely appended list is accepted only when its entries align one-for-one with `X-Forwarded-For`, then Ferrum selects the scheme at the first untrusted XFF boundary after validating the trusted suffix. Missing, malformed, or misaligned scheme chains are ignored. The accepted scheme drives secure-cookie and authentication URL decisions and the `X-Forwarded-Proto`/RFC 7239 `Forwarded` metadata regenerated for backends. List only proxies that overwrite or safely append both headers. |
| `FERRUM_BACKEND_ALLOW_IPS` | No | `both` | Backend egress mode: `both` (any IP), `private` (only private/reserved), or `public` (only public — blocks all private/reserved). Composes with the CIDR lists and the dangerous-range baseline below |
| `FERRUM_BACKEND_BLOCK_DANGEROUS_RANGES` | No | `true` | When `true` (default), backend egress to cloud-metadata/link-local (`169.254.0.0/16`, `fe80::/10`), the AWS IPv6 instance-metadata host (`fd00:ec2::254`), the Alibaba Cloud/ENS metadata host (`100.100.100.200`, an exact-host block since it sits in CGNAT not link-local), multicast (`224.0.0.0/4`, `ff00::/8`), and unspecified/this-host (`0.0.0.0/8`, `::`, `255.255.255.255`) is **blocked even under `both`** — including IPv4-mapped (`::ffff:…`) and NAT64 (`64:ff9b::/96`) encodings of those ranges, so an IPv6-only DNS answer can't bypass the block. Loopback and RFC1918/ULA stay allowed. Set `false` to restore fully-open egress (logs an unrestricted-egress warning) |
| `FERRUM_BACKEND_ALLOW_CIDRS` | No | — | Comma-separated CIDRs/IPs that are **always allowed** regardless of mode, deny list, or baseline (the escape hatch). E.g. `169.254.169.254/32` to permit a real IMDS proxy, or `10.1.2.0/24` to carve a private subnet out of `public` mode |
| `FERRUM_BACKEND_DENY_CIDRS` | No | — | Comma-separated CIDRs/IPs that are **denied** (unless also in the allow list). E.g. `10.0.0.0/8` to forbid an internal range while otherwise allowing private backends. Invalid entries fail startup |
| `FERRUM_ADD_VIA_HEADER` | No | `true` | Add `Via` on request and response paths |
| `FERRUM_VIA_PSEUDONYM` | No | `ferrum-edge` | Pseudonym used in the `Via` header |
| `FERRUM_ADD_FORWARDED_HEADER` | No | `false` | Add RFC 7239 `Forwarded` alongside `X-Forwarded-*` |
| `FERRUM_REAL_IP_HEADER` | No | — | Authoritative real-IP header name (e.g., `CF-Connecting-IP`, `X-Real-IP`). Its effective value is reserved from `correlation_id.header_name` case-insensitively so correlation processing cannot overwrite backend-visible client attribution. In CP/DP mode it is an enforced cluster-wide setting: every DP advertises its value and the CP rejects missing or mismatched advertisements before distributing config. Configure the same value (or no value) on every CP and DP. |

OAuth2/OIDC authentication is configured through plugin configs rather than `FERRUM_*` variables. `oauth2_introspection`, `oidc_relying_party`, `jwks_auth`, and `jwt_auth` support issuer/audience constraints and claim-based authorization; see [plugins.md](plugins.md#authentication-plugins) and [oidc_relying_party.md](oidc_relying_party.md) for configuration examples.

See [client_ip_resolution.md](client_ip_resolution.md) for the security model and deployment examples.

### Observability

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_ENABLE_STREAMING_LATENCY_TRACKING` | No | `false` | Track streaming response total latency (adds per-stream overhead) |
| `FERRUM_METRICS_SYSTEM_SAMPLE_INTERVAL_MS` | No | `1000` | Background sampler interval for `/metrics/runtime` system metrics (minimum 100ms) |
| `FERRUM_METRICS_WINDOW_1M_SECONDS` | No | `60` | Short status-code/request-rate window exposed by `/metrics/runtime` |
| `FERRUM_METRICS_WINDOW_5M_SECONDS` | No | `300` | Long status-code/request-rate window exposed by `/metrics/runtime` |
| `FERRUM_METRICS_LOG_COUNTER_ENABLED` | No | `true` | Count Ferrum tracing events by level and bounded category for `/metrics/runtime`, after applying the output `FERRUM_LOG_LEVEL` / `RUST_LOG` filter |
| `FERRUM_METRICS_RUNTIME_CACHE_MS` | No | `1000` | Admin JSON cache TTL for `GET /metrics/runtime` |
| `FERRUM_METRICS_POOL_TRACKING_ENABLED` | No | `true` | Count backend pool creation, failure, and eviction churn in `/metrics/runtime` |
| `FERRUM_METRICS_STATUS_TRACKING_ENABLED` | No | `true` | Count extra 1m/5m HTTP status windows for `/metrics/runtime`; disable to remove the additional per-request status-window counters |
| `FERRUM_PLUGIN_HTTP_SLOW_THRESHOLD_MS` | No | `1000` | Threshold (ms) for logging slow plugin outbound HTTP calls |
| `FERRUM_PLUGIN_HTTP_MAX_RETRIES` | No | `0` | Retry count for safe plugin outbound HTTP calls on transport failures (JWKS/OIDC fetches, etc.) |
| `FERRUM_PLUGIN_HTTP_RETRY_DELAY_MS` | No | `100` | Delay between plugin HTTP transport retry attempts |

### Runtime Tuning

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_WORKER_THREADS` | No | CPU cores | Tokio async worker threads |
| `FERRUM_BLOCKING_THREADS` | No | `512` | Max tokio blocking threads for file/DNS I/O |
| `FERRUM_POOL_SHARD_AMOUNT` | No | `0` (auto) | Shard count for hot-path `DashMap`s (connection pools, pending creations, RR counters, DNS cache, per-IP request counts, TCP connection-throttle counters, router prefix/regex caches, `response_caching` cache/Vary-index/predictor maps, and shared local/Redis-fallback rate-limiter token-state maps used by `rate_limiting`, `ai_rate_limiter`, `ws_rate_limiting`, `udp_rate_limiting`, GraphQL type/operation limits, and `grpc_method_router`). `0` auto-derives `next_power_of_two(max(64, num_cpus * 16))` (64 on small dev hosts, 256 on a 16-core box, 1024 on a 64-core box). Any positive value is rounded up to the next power of two. Tune up for hosts running 1M+ concurrent flows; tune down only under memory pressure |
| `FERRUM_MAX_CONNECTIONS` | No | `100000` | Max concurrent proxy connections; queues when full, `0` = unlimited |
| `FERRUM_MAX_REQUESTS` | No | `0` | Max concurrent in-flight requests/streams; `0` = unlimited |
| `FERRUM_MAX_CONCURRENT_REQUESTS_PER_IP` | No | `0` | Per-client-IP concurrent request cap; `0` disables |
| `FERRUM_PER_IP_CLEANUP_INTERVAL_SECONDS` | No | `60` | Cleanup interval for per-IP request counters |
| `FERRUM_CIRCUIT_BREAKER_CACHE_MAX_ENTRIES` | No | `10000` | Max circuit breaker cache entries |
| `FERRUM_STATUS_COUNTS_MAX_ENTRIES` | No | `200` | Max distinct HTTP status code counter entries |
| `FERRUM_TCP_LISTEN_BACKLOG` | No | `2048` | TCP listen backlog size (min 128); raise `net.core.somaxconn` to match |
| `FERRUM_ACCEPT_THREADS` | No | `0` (auto-detect) | Parallel accept() loops per proxy listener port via SO_REUSEPORT. `0` = CPU cores, `1` = single listener. Parallelizes kernel-level connection intake independently of worker threads. Unix only (Linux 3.9+, macOS, BSDs); non-Unix platforms warn and run one accept loop |
| `FERRUM_FRONTEND_H2_INITIAL_STREAM_WINDOW_SIZE` | No | `262144` | Frontend HTTP/2 per-stream flow-control window in bytes (256 KiB — conservative for untrusted clients; raise for benchmarking). Clamped to 65535..128 MiB |
| `FERRUM_FRONTEND_H2_INITIAL_CONNECTION_WINDOW_SIZE` | No | `2097152` | Frontend HTTP/2 connection-level flow-control window in bytes (2 MiB — conservative for untrusted clients; raise for benchmarking). Clamped to 65535..128 MiB |
| `FERRUM_FRONTEND_H2_MAX_FRAME_SIZE` | No | `16384` | Frontend HTTP/2 max frame size in bytes (RFC 9113 default). Clamped to 16384..1 MiB |
| `FERRUM_SERVER_HTTP2_MAX_CONCURRENT_STREAMS` | No | `1000` | Server-side HTTP/2 max concurrent streams per inbound connection |
| `FERRUM_SERVER_HTTP2_MAX_PENDING_ACCEPT_RESET_STREAMS` | No | `64` | Rapid-reset mitigation threshold for pending accept-reset streams |
| `FERRUM_SERVER_HTTP2_MAX_LOCAL_ERROR_RESET_STREAMS` | No | `256` | Rapid-reset mitigation threshold for locally reset streams |
| `FERRUM_WEBSOCKET_MAX_CONNECTIONS` | No | `20000` | Dedicated cap for upgraded WebSocket connections; `0` disables |
| `FERRUM_SHUTDOWN_DRAIN_SECONDS` | No | `30` | Graceful shutdown drain period; `0` skips draining |
| `FERRUM_STATUS_METRICS_WINDOW_SECONDS` | No | `30` | Rate window for admin `/status` metrics |

See [infrastructure_sizing.md](infrastructure_sizing.md) for detailed tuning guidance.

### Connection Pooling

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_POOL_WARMUP_ENABLED` | No | `true` | Pre-establish backend connections at startup after DNS warmup. Skipped for TCP/UDP stream proxies |
| `FERRUM_POOL_WARMUP_CONCURRENCY` | No | `500` | Maximum concurrent connection warmup attempts at startup |
| `FERRUM_POOL_CLEANUP_INTERVAL_SECONDS` | No | `30` | Cleanup sweep interval for all connection pools |
| `FERRUM_BACKEND_CAPABILITY_REFRESH_INTERVAL_SECS` | No | `86400` | Background interval for reproving backend HTTP/2, HTTP/3, and h2c capabilities |
| `FERRUM_GRPC_POOL_READY_WAIT_MS` | No | `1` | Time the gRPC pool waits for stream capacity before opening another backend connection |
| `FERRUM_POOL_MAX_IDLE_PER_HOST` | No | `64` | Maximum idle connections per backend host (min: 4, max: 1024) |
| `FERRUM_POOL_IDLE_TIMEOUT_SECONDS` | No | `90` | Seconds before idle connections are closed |
| `FERRUM_POOL_ENABLE_HTTP_KEEP_ALIVE` | No | `true` | Enable HTTP keep-alive for backend connection reuse |
| `FERRUM_POOL_ENABLE_HTTP2` | No | `true` | Enable HTTP/2 multiplexing when supported |
| `FERRUM_POOL_HTTP2_CONNECTIONS_PER_HOST` | No | CPU cores (2-8) | HTTP/2 connections per backend host |
| `FERRUM_POOL_TCP_KEEPALIVE_SECONDS` | No | `60` | TCP keep-alive interval in seconds |
| `FERRUM_POOL_HTTP2_KEEP_ALIVE_INTERVAL_SECONDS` | No | `30` | HTTP/2 keep-alive ping interval in seconds |
| `FERRUM_POOL_HTTP2_KEEP_ALIVE_TIMEOUT_SECONDS` | No | `45` | HTTP/2 keep-alive ping timeout in seconds |
| `FERRUM_POOL_HTTP2_INITIAL_STREAM_WINDOW_SIZE` | No | `8388608` | HTTP/2 per-stream flow-control window in bytes (8 MiB). Clamped to 65535..128 MiB |
| `FERRUM_POOL_HTTP2_INITIAL_CONNECTION_WINDOW_SIZE` | No | `33554432` | HTTP/2 connection-level flow-control window in bytes (32 MiB). Clamped to 65535..128 MiB |
| `FERRUM_POOL_HTTP2_ADAPTIVE_WINDOW` | No | `true` | Enable adaptive flow-control window sizing based on observed throughput |
| `FERRUM_POOL_HTTP2_MAX_FRAME_SIZE` | No | `1048576` | Maximum HTTP/2 frame payload in bytes (1 MiB). Clamped to 16384..1 MiB |
| `FERRUM_POOL_HTTP2_MAX_CONCURRENT_STREAMS` | No | `1000` | Max concurrent HTTP/2 streams per backend connection |

See [connection_pooling.md](connection_pooling.md) for the full configuration reference and pool warmup details.

### Router Cache

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_ROUTER_CACHE_MAX_ENTRIES` | No | `0` | Router lookup cache threshold per partition. The prefix partition stores prefix and negative matches; the regex/exact partition stores regex, exact-path, and path-param matches. `0` auto-scales as `max(10000, proxies × 3)` |

### Overload Management

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_OVERLOAD_CHECK_INTERVAL_MS` | No | `1000` | Resource pressure monitor interval; minimum 100ms |
| `FERRUM_OVERLOAD_FD_PRESSURE_THRESHOLD` | No | `0.80` | FD usage ratio above which keepalive is disabled |
| `FERRUM_OVERLOAD_FD_CRITICAL_THRESHOLD` | No | `0.95` | FD usage ratio above which new connections are rejected |
| `FERRUM_OVERLOAD_CONN_PRESSURE_THRESHOLD` | No | `0.85` | Connection usage ratio above which keepalive is disabled |
| `FERRUM_OVERLOAD_CONN_CRITICAL_THRESHOLD` | No | `0.95` | Connection usage ratio above which new connections are rejected |
| `FERRUM_OVERLOAD_REQ_PRESSURE_THRESHOLD` | No | `0.85` | Request usage ratio above which keepalive is disabled |
| `FERRUM_OVERLOAD_REQ_CRITICAL_THRESHOLD` | No | `0.95` | Request usage ratio above which new requests receive 503 |
| `FERRUM_OVERLOAD_LOOP_WARN_US` | No | `10000` | Event-loop latency warning threshold |
| `FERRUM_OVERLOAD_LOOP_CRITICAL_US` | No | `500000` | Event-loop latency threshold for rejecting new connections |

### Advanced Performance

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_ADAPTIVE_BUFFER_ENABLED` | No | `true` | Enable adaptive TCP/WebSocket tunnel copy buffer sizing |
| `FERRUM_ADAPTIVE_BATCH_LIMIT_ENABLED` | No | `true` | Enable adaptive UDP batch limit sizing |
| `FERRUM_ADAPTIVE_BUFFER_EWMA_ALPHA` | No | `300` | EWMA smoothing factor, clamped 1..999 |
| `FERRUM_ADAPTIVE_BUFFER_MIN_SIZE` | No | `8192` | Adaptive buffer floor in bytes |
| `FERRUM_ADAPTIVE_BUFFER_MAX_SIZE` | No | `262144` | Adaptive buffer ceiling in bytes |
| `FERRUM_ADAPTIVE_BUFFER_DEFAULT_SIZE` | No | `65536` | Initial adaptive buffer size before traffic data exists |
| `FERRUM_ADAPTIVE_BATCH_LIMIT_DEFAULT` | No | `6000` | Initial adaptive UDP batch limit |
| `FERRUM_TLS_OFFLOAD_THREADS` | No | `0` | Dedicated TLS handshake offload threads; `0` disables |
| `FERRUM_TCP_FASTOPEN_ENABLED` | No | `auto` | TCP Fast Open toggle: `auto`, `true`, or `false` |
| `FERRUM_TCP_FASTOPEN_QUEUE_LEN` | No | `256` | TCP Fast Open server queue length |
| `FERRUM_KTLS_ENABLED` | No | `auto` | Linux kTLS splice acceleration toggle |
| `FERRUM_IO_URING_SPLICE_ENABLED` | No | `auto` | Linux io_uring splice toggle |
| `FERRUM_UDP_GRO_ENABLED` | No | `auto` | Linux UDP GRO toggle; currently reserved/no-op |
| `FERRUM_UDP_GSO_ENABLED` | No | `auto` | Linux UDP GSO send batching toggle |
| `FERRUM_UDP_PKTINFO_ENABLED` | No | `auto` | Linux IP_PKTINFO/IPV6_PKTINFO reply-source optimization toggle |
| `FERRUM_SO_BUSY_POLL_US` | No | `0` | Linux SO_BUSY_POLL duration for latency-sensitive UDP sockets |

Core environment parsing lives in `src/config/env_config.rs`; early startup/pool settings use the same `FERRUM_*` names via conf-aware helpers.

## Backend Egress / SSRF Protection

The gateway dials backends, upstream targets, service-discovery results, and plugin endpoints (AI providers, log sinks, JWKS/OIDC, webhooks). On shared-cache egress paths, each resolved IP is screened against the backend egress policy on **every** fresh resolve and cache insertion, including stale/background refreshes, so a hostname that re-resolves to a denied address is rejected rather than cached or served. LDAP applies a stricter connection-establishment path: every connection/reconnection bypasses DNS caches, resolves both A and AAAA, rejects the complete answer if any candidate is denied, and rechecks each concrete candidate immediately before dialing while retaining the configured hostname for TLS/SNI verification.

The policy is composed from four `FERRUM_BACKEND_*` env vars and evaluated in this precedence (first match wins) for each resolved IP:

1. **`FERRUM_BACKEND_ALLOW_CIDRS`** — explicit allow; overrides everything below (the escape hatch).
2. **`FERRUM_BACKEND_DENY_CIDRS`** — explicit deny.
3. **Dangerous-range baseline** (`FERRUM_BACKEND_BLOCK_DANGEROUS_RANGES`, default `true`) — denies cloud-metadata/link-local, multicast, and unspecified/this-host ranges.
4. **`FERRUM_BACKEND_ALLOW_IPS`** mode — `both` allows; `private`/`public` filter on whether the IP is private/reserved.

### Default posture (no `FERRUM_BACKEND_*` set)

A fresh gateway runs `both` + baseline-on. It still reaches **loopback and RFC1918/ULA backends** (so mesh sidecars, same-host services, and internal upstreams work out of the box), but it is **not** an unrestricted SSRF bridge: egress to the cloud-metadata endpoints (`169.254.169.254` and the rest of `169.254.0.0/16`/`fe80::/10`, plus the AWS IPv6 IMDS host `fd00:ec2::254` and the Alibaba Cloud/ENS IMDS host `100.100.100.200`), multicast, and `0.0.0.0`/`::` is denied by default. A literal dangerous backend IP is also rejected at config-load time (proxy/upstream/plugin endpoints, on file/db loads and admin writes alike).

### Migration / deployment guidance

- **Internal-service deployments** (the common case): no change needed — loopback and RFC1918 backends keep working. If an internal backend lives in a normally-blocked range (rare), add it with `FERRUM_BACKEND_ALLOW_CIDRS`.
- **You genuinely need the metadata endpoint as a backend** (e.g. an IMDS proxy): set `FERRUM_BACKEND_ALLOW_CIDRS=169.254.169.254/32`. Prefer the narrowest CIDR.
- **Lock egress to the public internet** (egress-gateway style): set `FERRUM_BACKEND_ALLOW_IPS=public`. Carve out specific internal services with `FERRUM_BACKEND_ALLOW_CIDRS`.
- **Forbid a specific internal range** while otherwise allowing private backends: `FERRUM_BACKEND_DENY_CIDRS=10.0.0.0/8`.
- **Restore the legacy fully-open behaviour** (not recommended): `FERRUM_BACKEND_BLOCK_DANGEROUS_RANGES=false`. With `both` + no deny CIDRs this makes egress unrestricted and the gateway logs a startup warning to that effect.

The allow/deny CIDR lists accept comma-separated CIDRs or bare IPs (`10.0.0.0/8, 192.168.1.1, fc00::/7, ::1`); an invalid entry fails startup rather than silently failing open. The same policy is enforced by config validation, the DNS resolver, the connection pool, service discovery, and plugin endpoint screening.

### Known limitation: `rediss://` (TLS) Redis hostnames

The centralized rate-limiter's Redis endpoint is screened through the same policy: literal-IP `redis://`/`rediss://` endpoints are screened, and plaintext `redis://` hostnames are **pinned** to the gateway-resolved IP so the Redis client cannot re-resolve outside the cache. A **`rediss://` (TLS) endpoint specified as a hostname** is the one exception — it is screened on every resolve but **not pinned**, because the `redis` crate derives the TLS server name (SNI) from the URL host and offers no way to dial a chosen IP while presenting a separate server name. The Redis client therefore re-resolves the hostname itself at connect/reconnect time, leaving a narrow DNS-rebinding window between the gateway's screen and the client's dial. Exploiting it requires control of the operator's *own* Redis DNS (which already implies control of the gateway's resolver), and on any screen/resolve failure the rate limiter fails **closed** to the in-memory limiter rather than dialing unscreened. To remove the window entirely, use a literal-IP `rediss://` endpoint (e.g. `rediss://10.0.0.5:6380`) or a plaintext `redis://` hostname.

## Configuration File (`ferrum.conf`)

As an alternative to environment variables, the gateway supports a `ferrum.conf` configuration file for setting reasonable defaults. Environment variables **take precedence** over values in the conf file, allowing operators to define baseline configuration in the file and override specific values per deployment via env vars.

**File location:**
- Default: `./ferrum.conf` (current working directory)
- Override with the `FERRUM_CONF_PATH` environment variable (the only setting that must remain an env var)
- If the file does not exist at the default path, it is silently skipped

**Format:** Simple key-value pairs using the same `FERRUM_*` names as environment variables:

```conf
# Operating mode
FERRUM_MODE = file
FERRUM_FILE_CONFIG_PATH = /etc/ferrum/config.yaml
FERRUM_LOG_LEVEL = info

# Proxy ports
FERRUM_PROXY_HTTP_PORT = 8080
FERRUM_PROXY_HTTPS_PORT = 8443

# TLS hardening
FERRUM_TLS_MIN_VERSION = 1.3

# Quoted values for paths with spaces
FERRUM_FRONTEND_TLS_CERT_PATH = "/path/with spaces/cert.pem"
```

- Lines starting with `#` are comments
- Inline comments are supported: `KEY = value # comment`
- Values can be quoted with double or single quotes (quotes are stripped)
- Empty lines are ignored

A reference `ferrum.conf` with all available fields and descriptions is included in the repository root.

**Precedence order:** CLI flags (when using `ferrum-edge run` / `validate`) > environment variables > `ferrum.conf` > smart path/mode defaults > built-in defaults. See [cli.md](cli.md#configuration-precedence) for CLI override details. File-mode inference from a discovered or `--spec` path is a smart default and never overrides a `FERRUM_MODE` set by CLI, environment, or the selected settings file.

## File Mode Configuration Format

Configuration files can be YAML or JSON. See `tests/config.yaml` for a complete example.

```yaml
proxies:
  - id: "my-api"
    name: "My Backend API"
    listen_path: "/api/v1"
    backend_scheme: http
    backend_host: "backend-service"
    backend_port: 3000
    strip_listen_path: true
    preserve_host_header: false
    backend_connect_timeout_ms: 5000
    backend_read_timeout_ms: 30000
    backend_write_timeout_ms: 30000
    # Response body mode: "stream" (default) or "buffer"
    # response_body_mode: stream
    # Connection pooling settings (optional - override global defaults)
    pool_idle_timeout_seconds: 120
    auth_mode: single
    plugins:
      - plugin_config_id: "log-plugin"

consumers:
  - id: "user-1"
    username: "alice"
    credentials:
      keyauth:
        - key: "alice-api-key"
        - key: "alice-rotated-key"

plugin_configs:
  - id: "log-plugin"
    plugin_name: "stdout_logging"
    config: {}
    scope: global
    enabled: true
```

`backend_read_timeout_ms` defaults to `30000` (30 seconds). For HTTP and gRPC
proxies it has two roles: it bounds backend response reads, and it is the total
(not idle) deadline for collecting a client request body whenever retries or
body-processing policy require Ferrum to buffer that upload before dispatch.
Buffered uploads that take longer than the configured total deadline are
deliberately rejected with HTTP `408 Request Timeout` or gRPC
`DEADLINE_EXCEEDED`, even if the client is still making progress; increase the
value for legitimate slow buffered uploads. Streaming pass-through uploads are
unaffected. Set the value to `0` to disable both the backend read bound and this
buffered-upload collection deadline.

### Stream Proxy (TCP/UDP/DTLS)

Stream proxies use `listen_port` instead of `listen_path` and bind to dedicated ports:

Stream proxies route on `listen_port` and MUST NOT set `listen_path`.

```yaml
proxies:
  # TCP proxy with TLS origination to backend
  - id: "postgres-proxy"
    listen_port: 5432
    backend_scheme: tcps
    backend_host: "db.internal"
    backend_port: 5432

  # UDP proxy with DTLS encryption to backend
  - id: "iot-proxy"
    listen_port: 5684
    backend_scheme: dtls
    backend_host: "iot-backend.internal"
    backend_port: 5684
    backend_tls_verify_server_cert: false
    udp_idle_timeout_seconds: 120

  # Full DTLS e2e: DTLS client → gateway → DTLS backend
  - id: "secure-iot"
    listen_port: 5685
    backend_scheme: dtls
    backend_host: "secure-iot.internal"
    backend_port: 5684
    frontend_tls: true
    backend_tls_verify_server_cert: false
```

**Port validation:** Each `listen_port` must be unique across all stream proxies and must not conflict with gateway reserved ports (`FERRUM_PROXY_HTTP_PORT`, `FERRUM_PROXY_HTTPS_PORT`, `FERRUM_ADMIN_HTTP_PORT`, `FERRUM_ADMIN_HTTPS_PORT`, CP gRPC port). Ports set to `0` (disabled) are excluded from conflict checks. In database mode, the Admin API also probes OS-level port availability before accepting the config. See [tcp_udp_proxy.md](tcp_udp_proxy.md) for full documentation including per-mode behavior.

### Service Discovery

Upstreams can discover targets dynamically using a `service_discovery` block. Four providers are supported:

**DNS-SD** (DNS Service Discovery):
```yaml
upstreams:
  - id: "my-upstream"
    targets: []
    algorithm: round_robin
    service_discovery:
      provider: dns_sd
      dns_sd:
        service_name: "_http._tcp.my-service.local"
        poll_interval_seconds: 30
```

**Kubernetes**:
```yaml
upstreams:
  - id: "k8s-upstream"
    targets: []
    algorithm: least_connections
    service_discovery:
      provider: kubernetes
      kubernetes:
        namespace: "default"
        service_name: "my-service"
        port_name: "http"
        poll_interval_seconds: 15
```

**Consul**:
```yaml
upstreams:
  - id: "consul-upstream"
    targets:
      - host: "fallback.example.com"
        port: 8080
        weight: 1
    algorithm: round_robin
    service_discovery:
      provider: consul
      consul:
        address: "http://consul.internal:8500"
        service_name: "my-service"
        datacenter: "dc1"
        poll_interval_seconds: 10
        token: "consul-acl-token"
```

**Ferrum Mesh**:
```yaml
upstreams:
  - id: "mesh-payments"
    targets: []
    algorithm: round_robin
    service_discovery:
      provider: mesh
      mesh:
        service_name: "payments"
        namespace: "backend"   # optional; defaults to the upstream namespace
        port: 8080             # optional; defaults to the first mesh service port
        poll_interval_seconds: 5
        topology: sidecar      # optional; `ambient` (default, HBONE) or `sidecar` (SVID-mTLS)
```

The mesh provider reads the CP-delivered `mesh.services` and `mesh.workloads` snapshot already present in gateway DP config. It converts matching workload addresses into upstream targets tagged with `mesh.spiffe_id`, `mesh.namespace`, and the destination topology's mesh transport tag — `mesh.hbone=true` for `topology: ambient` (HBONE HTTP/2 CONNECT to the peer's `:15008` listener) or `mesh.mtls=true` for `topology: sidecar` (plain SVID-mTLS HTTP/2 to the peer sidecar's `:15006` inbound listener) — so the gateway-to-mesh bridge dispatches over the transport the destination actually serves (see `docs/mesh.md` → Gateway Mesh Service Discovery). Set `topology` to match the destination mesh; a mismatch fails closed at dispatch rather than silently downgrading.

Discovered targets are merged with any statically defined `targets`. If the provider is unreachable, the upstream keeps its last-known targets to maintain availability.

## Database Schema

When using Database or CP modes, Ferrum auto-creates the following tables on startup:

- **`proxies`** — Proxy route definitions (with `UNIQUE` constraint on `listen_path`)
- **`consumers`** — API consumer/user definitions
- **`plugin_configs`** — Plugin configurations (global, per-proxy, or proxy-group scoped)
- **`proxy_plugins`** — Many-to-many linking proxies to plugin configs
- **`upstreams`** — Upstream groups for load-balanced backends (targets stored as JSON, with algorithm and health check configuration)

See [migrations.md](migrations.md) for schema migration details.
