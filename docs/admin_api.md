# Admin API Reference

The Admin API provides full CRUD operations for managing Ferrum Edge configuration at runtime. It is available in **Database** and **Control Plane** modes (read/write) and **Data Plane** mode (read-only).

See also:
- [admin_read_only_mode.md](admin_read_only_mode.md) — Read-only mode configuration
- [admin_backup_restore.md](admin_backup_restore.md) — Backup and restore details
- [admin_batch_api.md](admin_batch_api.md) — Batch operations
- [admin_metrics.md](admin_metrics.md) — Metrics endpoint details
- [OpenAPI specification](../openapi.yaml) — Full API schema

## Authentication

Most endpoints require a valid HS256 JWT in the `Authorization: Bearer <token>` header, verified against `FERRUM_ADMIN_JWT_SECRET` (must be at least 32 characters). The observability surfaces have a tiered model:

| Endpoint | Unauthenticated | Authenticated |
| --- | --- | --- |
| `/live` | `{"status":"ok"}` (always; minimal liveness) | same |
| `/health`, `/status` | `status` + `ready` only, with the correct status code (200 / 503 starting or unavailable) | full diagnostics (mode, DB/pool, cached-config counts, polling degradation, mesh state, sanitized listener failures) |
| `/overload` | coarse `{level}` + status code (503 at critical) | full pressure/counter and sanitized listener-failure snapshots |
| `/metrics` | **401** unless the client IP is in `FERRUM_METRICS_ALLOWED_CIDRS` | 200 Prometheus text |

"Authenticated" here means **any** of: a valid admin JWT, a matching `FERRUM_METRICS_BEARER_TOKEN`, or a source IP within `FERRUM_METRICS_ALLOWED_CIDRS`. This lets Prometheus scrape with a dedicated token or from an allowlisted subnet without minting admin JWTs, while operational internals are not exposed by default. `/metrics/runtime` and `/charges` always require a full admin JWT (process/host diagnostics and customer/billing data respectively).

The whole admin listener can additionally be restricted at the TCP layer with `FERRUM_ADMIN_ALLOWED_CIDRS`.

Admin JWTs must include `iss`, `sub`, `exp`, `iat`, `nbf`, `jti`, and a string `role` claim. `iss` must match `FERRUM_ADMIN_JWT_ISSUER` (default `ferrum-edge`), and `nbf`/`exp` are validated. The `FERRUM_ADMIN_JWT_MAX_TTL` cap (default `3600` seconds) is enforced against verifier time, not just the claims, and counts the accepted clock-skew leeway (60 seconds) exactly once: `exp - iat` must be positive and within the maximum, `iat` must not be later than verifier time plus the leeway, `exp - now` must stay within the maximum plus that same leeway, and `exp` must still be in the future at verifier time (the cap path applies no expiry grace, so the skew allowance is not counted a second time at expiration). Effective maximum real validity is therefore `FERRUM_ADMIN_JWT_MAX_TTL + 60s`, and shifting `iat` and `exp` together into the future cannot extend a token's real lifetime beyond that bound. Setting `FERRUM_ADMIN_JWT_MAX_TTL=0` intentionally disables the lifetime cap; a configured value above `9223372036854775807` is rejected at startup as invalid rather than treated as unlimited. When `FERRUM_ADMIN_JWT_AUDIENCE` is set, tokens must also carry a matching `aud` claim. When unset (default), tokens without an `aud` claim are accepted, but tokens that carry `aud` are rejected per RFC 7519 §4.1.3 (no acceptable audience is configured) — if your token minter stamps `aud`, set `FERRUM_ADMIN_JWT_AUDIENCE` to that value.

### Per-namespace tenancy (`FERRUM_ADMIN_REQUIRE_NAMESPACE_CLAIM`)

By default, admin JWTs are **global**: the `X-Ferrum-Namespace` header is a routing selector, not an authorization boundary — any valid Operator/Admin token can address any namespace. On multi-namespace deployments (e.g. a CP with `FERRUM_CP_NAMESPACES="prod,staging"`), set `FERRUM_ADMIN_REQUIRE_NAMESPACE_CLAIM=true` to make namespace-scoped admin routes require the JWT to carry an `ns` claim authorizing the requested namespace, mirroring the CP↔DP gRPC plane's `FERRUM_CP_REQUIRE_NAMESPACE_CLAIM`:

- The `ns` claim accepts the same shapes as the gRPC plane: a single string (`"ns": "prod"`) or an array of strings (`"ns": ["prod", "staging"]`).
- A request whose `X-Ferrum-Namespace` (or the `ferrum` default when the header is omitted) is not in the token's `ns` set is rejected with `403 Forbidden`. With enforcement on, tokens without an `ns` claim are rejected on namespace-scoped routes — tenancy intent must be explicit.
- Enforcement covers the namespace-scoped resource surfaces: `/proxies`, `/consumers` (including credentials), `/plugins/config`, `/upstreams`, `/api-specs`, `/batch`, `/backup`, `/restore`, and `/audit`. Global surfaces (observability, `/cluster`, `/namespaces`, TLS management, backend capabilities, mesh introspection, `GET /plugins` type listing) are not tenant-selected and are unaffected.
- Malformed `ns` claims (non-string entries, empty strings) are rejected at authentication time regardless of the flag — a garbled tenancy claim never widens access.

With the flag off (default), behavior is unchanged and back-compatible.

| Role | Access |
| --- | --- |
| `viewer` | Read-only endpoints, including API spec metadata listing |
| `operator` | Read-only endpoints plus proxy, upstream, plugin config, backend capability refresh, TLS inventory/events/validation/forced reload, and mesh egress-scope test operations |
| `admin` | Full access, including consumers, credentials, raw API spec retrieval and mutations, TLS material and ACME state management, batch/restore, and audit logs |

Tokens without a valid `role` claim are rejected.

Generate a token:
```bash
# Using any JWT library; include the required claims and an explicit role.
# Example using Node.js jsonwebtoken:
node -e "const jwt=require('jsonwebtoken'); const now=Math.floor(Date.now()/1000); console.log(jwt.sign({iss:'ferrum-edge', sub:'admin', role:'admin', iat:now, nbf:now, exp:now+3600, jti:require('crypto').randomUUID()}, 'my-super-secret-jwt-key-at-least-32-chars'))"
```

## Liveness and Health Checks

### `/live` — liveness (unauthenticated, minimal)

```bash
curl http://localhost:9000/live
# Returns: {"status": "ok"}
```

`/live` is always unauthenticated and returns only `{"status":"ok"}` with a 200. It reveals no operational internals and is the recommended endpoint for load-balancer / Kubernetes **liveness** probes.

### `/health`, `/status` — readiness + diagnostics (tiered)

```bash
# Unauthenticated (LB / readiness probe): status + ready only.
curl http://localhost:9000/health
# Returns: {"status": "ok", "ready": true}     (503 with "starting" before ready)

# Authenticated: full diagnostics.
curl -H "Authorization: Bearer $TOKEN" http://localhost:9000/health
# Returns: {"status","timestamp","mode","database":{...},"admin_writes_enabled",
#           "ready","cached_config":{"proxy_count":...},"database_polling":{...},
#           "config_rejected":true,"mesh":{"egress_scope":{...}},
#           "listener_failures":{"failures_total":...}, ...}
```

Unauthenticated callers receive only `status` and `ready` (enough for a readiness probe) with the correct status code — 503 `"starting"` until the gateway is ready, 200 otherwise. The detailed diagnostics (DB type/pool stats, cached-config proxy/consumer counts, `database_polling` degradation, `config_rejected`, mesh state, sanitized listener failures) require an admin JWT, `FERRUM_METRICS_BEARER_TOKEN`, or a `FERRUM_METRICS_ALLOWED_CIDRS` source IP. In database mode the authenticated response includes `database_polling`; repeated rejected incremental deltas set `status: "degraded"` (also visible unauthenticated) while the gateway keeps serving the last known-good config. Both **database** and **cp** modes expose `database_polling.last_poll_completed_at` (updated on every normally completed poll outcome — empty success, rejection, or handled error — not on panic/abort/cancel) so operators can alert when the supervised poll task stops advancing. In **cp** mode, unexpected poll-task exit (panic/abort/unexpected completion — not ordinary shutdown) flips sticky `serving_degraded`, so `/health` returns 503 with `status: "unavailable"` and `ready: false`. In **database** mode the poll task is respawned after an unexpected exit while last-known-good config continues to serve.

In mesh mode, authenticated health detail includes
`mesh.egress_scope.sidecar_admitted_services` and
`mesh.egress_scope.sidecar_denied_services`. The authenticated `/overload`
snapshot also includes `node_waypoint_drops`, with monotonic counters for
missing/unknown socket-cookie metadata, missing pod/workload identity data,
unknown pods, and workload-hash mismatches. These fields are omitted from the
coarse unauthenticated responses.

In database **and control-plane** mode, if a **full** config load is rejected by the runtime-config validation contract (a reachable backend served a semantically-invalid snapshot — e.g. a partial/direct-DB write) the gateway keeps serving the last known-good config **and keeps the admin API writable**: `db_available` stays true because admin writes are the in-band repair path for the offending resource. Re-enabling writes is gated on any deferred schema migration applying first, so a reachable backend whose schema is still pending keeps writes blocked while `config_rejected` stays set. The rejection also skips failover (the same invalid snapshot lives on every replica). The authenticated `/health` detail then carries `config_rejected: true` and `status: "degraded"` (the boolean detail is authenticated-only; the coarse `degraded` status is also visible unauthenticated). The flag is sticky and clears only after an accepted authoritative **full** reload (an accepted incremental poll does not clear it). While the backend is later unreachable (`admin_writes_enabled` false) the `config_rejected` detail is suppressed so it never advertises the writable repair path during an outage, even though the underlying flag remains set. A genuine connectivity failure is unaffected and still flips `admin_writes_enabled` to false.

In **file** mode, if a SIGHUP reload candidate fails read, parse, validation, or apply, the gateway likewise keeps serving the last known-good config and raises the same `config_rejected` signal: authenticated `/health` reports `config_rejected: true` with `status: "degraded"` (boolean detail authenticated-only; coarse `degraded` also visible unauthenticated). File-mode admin stays read-only; operators repair by fixing the config file and reloading. The flag clears on the next Applied or Unchanged reload.

In **CP, DP, and mesh modes**, if a supervised serving-listener task exits with an error *after* the gateway became ready (the CP gRPC server; a DP proxy/admin HTTP/HTTPS/H3 listener; or a mesh traffic/admin listener), `/health` returns 503 with `status: "unavailable"` and `ready: false`. The same sticky path applies in **CP mode** when the database config poll task exits unexpectedly (panic/abort/unexpected completion — not ordinary shutdown). This is a **sticky** signal: it is set once and never cleared, so it survives a later readiness restore. Mesh authenticated `/health`/`/status` and `/overload` responses include `listener_failures` with `failures_total` and per-listener `listener`, `listen_port`, `kind`, and a deliberately sanitized `error`; raw error strings are not retained. Unauthenticated health/status responses remain exactly `status` plus `ready`, and unauthenticated overload remains `{level}`.

**Recommended split:** point liveness at `/live` and readiness at `/health`; route detailed diagnostics scraping through an authenticated path.

## TLS Inventory

List configured TLS material sources and parsed certificate metadata:

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:9000/admin/tls/inventory?limit=100"
```

The response is paginated and includes each source's non-secret provenance, material kind, load state, certificate subject/issuer/SANs, validity window, SHA-256 certificate fingerprint, and the runtime/config surfaces using it. Inline PEM values and private key bytes are redacted. Unsupported URI providers are listed with `state: "unsupported"` until their runtime loader is enabled.

This endpoint loads every configured source, including private keys (which are parse-checked and immediately dropped), so it performs real filesystem, Kubernetes, and secret-manager reads on each explicit request.

Exact `/metrics` never does that. It emits `ferrum_tls_cert_expiry_seconds` and `ferrum_tls_cert_not_before_seconds` from a cached, non-secret inventory snapshot and performs **zero** certificate, private-key, Kubernetes, HSM, or cloud-secret I/O on the scrape path. The snapshot is produced by a bounded, single-flight background refresh that reads only public certificate-family material (certificate, CA bundle, CRL) — private-key, JWKS, and OCSP sources are never materialized for metrics, and their entries report health from the owning validated config/reload state. A scrape whose snapshot is older than `FERRUM_TLS_INVENTORY_SNAPSHOT_TTL_SECONDS` (default 300, `0` disables the refresh) only *schedules* the refresh; it never waits on a provider. Validated rotation and reload outcomes mark the snapshot stale so the next scrape refreshes immediately. Freshness is exported explicitly as `ferrum_tls_inventory_snapshot_timestamp_seconds` with the configured bound `ferrum_tls_inventory_snapshot_max_age_seconds`; the certificate gauges are absent until the first snapshot is published.

TLS inventory, event listing, inline validation, and forced reload endpoints require an `operator` or `admin` token. Endpoints that create, replace, delete, import, finalize, or renew persisted TLS/ACME material require an `admin` token because they can alter private keys, certificate chains, trust bundles, revocation data, JWKS records, or ACME account-backed state.

Forced reload is an operational action rather than a persisted configuration
mutation, so `POST /admin/tls/rotate/{surface}` remains available in file, DP,
and mesh modes when authenticated with an `operator` or `admin` JWT.

## TLS Events

List recent source watcher rotations and failures:

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:9000/admin/tls/events?surface=proxy_https&limit=100"
```

The event log is bounded and persisted under `FERRUM_TLS_MANAGED_STORE_PATH` as `tls-events.json`, so recent rotation history survives process restarts. It records successful rotations, source load failures, and rebuild failures with non-secret source identifiers and fingerprints for non-key material. No-op refresh polls are not stored as events; they are counted in `/metrics` through `ferrum_tls_source_refresh_total`; rotation outcomes, source fetch latency, and bounded fetch failure reasons are exposed as `ferrum_tls_cert_rotations_total`, `ferrum_tls_source_fetch_duration_seconds`, and `ferrum_tls_source_fetch_failures_total`.

## TLS Forced Rotation

Ask active TLS source watchers to re-pull their configured sources immediately:

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  "http://localhost:9000/admin/tls/rotate/proxy_https"
```

Supported force-reload surfaces are `proxy_https`, `backend_tls`, `admin_https`, `dtls`, `database_tls`, `cp_grpc`, `dp_grpc`, `svid`, and `all` for every registered watcher plus the configured gateway SVID. Aliases `frontend`, `backend`, `admin`, `frontend_dtls`, `db`, `database`, `cp_grpc_tls`, `dp_grpc_tls`, and `gateway_svid` are accepted. Watcher-backed TLS reloads are enqueued and report success or failure asynchronously through `/admin/tls/events` and `/metrics`; `svid` reloads are validated synchronously and publish a backend SVID generation bump on success.

## TLS Validation

Validate PEM material without storing it:

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "cert_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
    "key_pem": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n"
  }' \
  http://localhost:9000/admin/tls/validate
```

`cert_pem` and `key_pem` must be submitted together. `ca_bundle_pem` and `crl_pem` can be validated independently. Private key bytes are never logged or persisted by this endpoint.

## ACME-Issued Certificates

Ferrum persists issued ACME certificates in the same TLS store directory used by managed TLS records. Imported records can be referenced from any TLS source field:

```bash
export FERRUM_FRONTEND_TLS_CERT_SOURCE="acme://certificates/edge-cert#cert"
export FERRUM_FRONTEND_TLS_KEY_SOURCE="acme://certificates/edge-cert#key"
```

List, import, replace, or delete ACME-issued records:

`GET/POST /admin/tls/acme/certificates`, `GET/PUT/DELETE /admin/tls/acme/certificates/{id}`

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "edge-cert",
    "domains": ["api.example.com"],
    "directory_url": "https://acme-v02.api.letsencrypt.org/directory",
    "cert_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
    "key_pem": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n"
  }' \
  http://localhost:9000/admin/tls/acme/certificates
```

Responses return non-secret certificate metadata, source URI, issuer, SANs, validity, fingerprint, ACME directory/account/order metadata, and timestamps. Private keys are persisted but never returned. Create, update, and delete operations ask active TLS source watchers to re-pull immediately; `DELETE` returns `409 Conflict` when the current runtime/config inventory still references the record.

ACME HTTP-01, TLS-ALPN-01, and DNS-01 order issue flows are available under:

`GET /admin/tls/acme/accounts`, `GET/POST /admin/tls/acme/orders`, `GET/DELETE /admin/tls/acme/orders/{id}`, `POST /admin/tls/acme/orders/{id}/finalize`, `POST /admin/tls/acme/renew/{cert_id}`

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "edge-order",
    "certificate_id": "edge-cert",
    "domains": ["api.example.com"],
    "directory_url": "https://acme-staging-v02.api.letsencrypt.org/directory",
    "contact": ["mailto:ops@example.com"],
    "terms_of_service_agreed": true,
    "challenge_type": "http01"
  }' \
  http://localhost:9000/admin/tls/acme/orders
```

Creating orders requires the optional `acme` Cargo feature. The `directory_url` is validated before any outbound ACME request to limit SSRF: it must be an absolute `https` URL with a host, and literal-IP hosts must be public addresses (loopback, RFC1918, link-local, ULA, and the `169.254.169.254` metadata address are rejected); a rejected URL returns `400 Bad Request`. The same check runs on `POST /admin/tls/acme/certificates` imports and on the auto-renewal path. Hostnames are not resolved by this check, so a hostname that points at a private IP is not blocked here — keep network-level egress controls in place. `challenge_type` defaults to `http01`; set it to `tls_alpn01` to prepare TLS-ALPN-01 challenge material or `dns01` to prepare DNS-01 TXT material. HTTP-01 responses include public key-authorization values and challenge paths. TLS-ALPN-01 responses include the SNI identifier, token, `acme-tls/1` ALPN protocol, and base64url SHA-256 digest embedded in the validation certificate's critical `acmeIdentifier` extension. DNS-01 responses include the identifier, token, TXT record name, and TXT value. While an order is `pending_challenges`, `ready`, or `processing`, proxy listeners serve HTTP-01 key authorizations at `/.well-known/acme-challenge/{token}` before normal route matching, and TLS listeners return the TLS-ALPN-01 validation certificate when the ClientHello offers only `acme-tls/1` and SNI matches an active challenge. DNS-01 TXT records must be published in authoritative DNS before finalization. Account credentials are persisted in the order store for follow-up ACME calls but are never returned.

`GET /admin/tls/acme/accounts` lists non-secret account identifiers, ACME directory URLs, order/certificate counts, whether resumable credentials exist, and last-seen timestamps. It merges credentials from order records and the dedicated `acme-accounts.json` account store, but never returns credential material.

After DNS points at the gateway and the HTTP-01 challenge path or TLS-ALPN-01 listener is externally reachable, or after DNS-01 TXT records are published, finalize the order:

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"poll_timeout_seconds": 90}' \
  http://localhost:9000/admin/tls/acme/orders/edge-order/finalize
```

Finalization marks the order's prepared HTTP-01, TLS-ALPN-01, or DNS-01 challenges ready with the ACME directory, waits for authorization/order readiness, finalizes the order, fetches the PEM certificate chain, persists it as the order's `certificate_id`, and asks active TLS source watchers to re-pull. The stored certificate can then be used through `acme://certificates/edge-cert#cert` and `acme://certificates/edge-cert#key`.

To force renewal for an existing ACME certificate record, create a replacement order:

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}' \
  http://localhost:9000/admin/tls/acme/renew/edge-cert
```

Ferrum reuses persisted account credentials from the latest order for that certificate when available. The request accepts the same `challenge_type` values as order creation. The response is a new order whose selected challenges must become reachable before calling `/admin/tls/acme/orders/{id}/finalize`.

Automatic renewal can be enabled with `FERRUM_ACME_AUTO_RENEW_ENABLED=true`. The scheduler reuses persisted account credentials, renews certificates inside `FERRUM_ACME_RENEW_WHEN_REMAINING_DAYS`, and finalizes HTTP-01/TLS-ALPN-01 renewals after Ferrum stores their challenge material. For DNS-01 renewals, set `FERRUM_ACME_DNS01_HOOK_COMMAND` to an executable that creates and cleans up provider TXT records; Ferrum passes the challenge through `FERRUM_ACME_DNS01_*` environment variables, waits `FERRUM_ACME_DNS01_PROPAGATION_SECONDS`, then finalizes the order.

## Managed TLS Records

Upload TLS material into Ferrum's file-backed managed store:

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "edge-cert",
    "name": "Edge certificate",
    "cert_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
    "key_pem": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n"
  }' \
  http://localhost:9000/admin/tls/certificates
```

Managed certificates, CA bundles, OCSP responses, CRLs, and JWKS documents are available under:

`GET/POST /admin/tls/certificates`, `GET/PUT/DELETE /admin/tls/certificates/{id}`

`GET/POST /admin/tls/ca-bundles`, `GET/PUT/DELETE /admin/tls/ca-bundles/{id}`

`GET/POST /admin/tls/crls`, `GET/PUT/DELETE /admin/tls/crls/{id}`

`GET/POST /admin/tls/ocsp-responses`, `GET/PUT/DELETE /admin/tls/ocsp-responses/{id}`

`GET/POST /admin/tls/jwks`, `GET/PUT/DELETE /admin/tls/jwks/{id}`

Record IDs are **globally unique** across those typed collections (one shared store map keyed by ID, not namespaced by kind). Create with `allow_overwrite=true` and every typed `PUT` require the existing record kind to match the route kind; a cross-kind collision returns `409 Conflict` with a stable error of the form `managed TLS record '{id}' already exists with kind {existing}, cannot overwrite with kind {requested}`. Typed `GET`/`DELETE` still reject a kind mismatch with `400 Bad Request`. Same-kind replacement is allowed even when the record is referenced: admission validates the new material before persistence, and TLS source watchers atomically activate or retain the previous runtime config.

Responses return non-secret metadata only: source URI, subject, issuer, SANs, validity, public-material fingerprint, counts, and timestamps. Private keys are persisted in the managed store but never returned. Configure the store directory with `FERRUM_TLS_MANAGED_STORE_PATH`; on Unix, the JSON store files are written with owner-only permissions.

Create, update, and delete operations ask active TLS source watchers to re-pull immediately. Surfaces without a live watcher still pick up managed records when their owning config/runtime is rebuilt.

Use managed records from any TLS source field:

```bash
export FERRUM_FRONTEND_TLS_CERT_SOURCE="managed://certificates/edge-cert#cert"
export FERRUM_FRONTEND_TLS_KEY_SOURCE="managed://certificates/edge-cert#key"
export FERRUM_FRONTEND_TLS_OCSP_RESPONSE_SOURCE="managed://ocsp-responses/edge-ocsp#ocsp"
export FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED=true
```

JWKS-capable plugin fields can reference `managed://jwks/{id}#jwks` once the plugin accepts `CertSource` JWKS material.

`DELETE` returns `409 Conflict` when the current runtime/config inventory still references the record.

## Pagination

Resource and TLS list endpoints — `GET /proxies`, `/consumers`, `/plugins/config`, `/upstreams`, `/namespaces`, and the ten `GET /admin/tls/*` list routes — return a paginated envelope `{ "data": [...], "pagination": { "offset", "limit", "total" } }` and accept `limit`/`offset` query parameters. An omitted `limit` applies the default of 100 (maximum 1000; `GET /backup` is the intentional full-export mechanism), `0` is coerced to the default, and representable unsigned 64-bit values above 1000 are capped. Malformed or negative values, limits beyond the unsigned 64-bit range, and offsets beyond `2^63 - 1` are rejected with `400`. The offset is retained as a 64-bit value on every target; for an in-memory collection, an offset too large for the target's address space is a valid request beyond the collection and returns an empty page.

`pagination.limit` reports the page size the server applied, not the number of items returned: an omitted `limit` reports 100 even when fewer rows exist.

Pagination is validated only by routes that consume it, after their authentication, namespace-claim, and role gates. A malformed `limit`/`offset` therefore never preempts the `401` or `403` the caller would otherwise receive, never affects the always-unauthenticated `/live` observability tier, and is ignored on non-paginated routes such as `/backup` and `/cluster`. On the paginated `GET` routes the check runs before the request body is read, so a malformed `limit`/`offset` returns `400` without buffering a body the read endpoint would never use. Route-specific ceilings narrower than the shared bounds — such as the `GET /audit` `offset` cap described below — are applied in that same pre-body check, so they also return `400` rather than a body-size `413`.

Two endpoints intentionally differ and document their own bounds below: `GET /audit` shares these bounds for `limit` but caps `offset` at `2^32 - 1`, and `GET /api-specs` uses a default of 50 and a maximum of 200. Both return their own `{ items, ..., next_offset }` envelope instead of `data`/`pagination`.

## Proxies

```bash
# List proxies (first page)
curl -H "Authorization: Bearer $TOKEN" http://localhost:9000/proxies

# Create a proxy
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "listen_path": "/new-api",
    "backend_scheme": "http",
    "backend_host": "backend",
    "backend_port": 3000,
    "strip_listen_path": true
  }' \
  http://localhost:9000/proxies

# Get a proxy
curl -H "Authorization: Bearer $TOKEN" http://localhost:9000/proxies/{proxy_id}

# Update a proxy
curl -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"listen_path": "/new-api", "backend_host": "new-backend", "backend_port": 4000, "backend_scheme": "http"}' \
  http://localhost:9000/proxies/{proxy_id}

# Delete a proxy
curl -X DELETE -H "Authorization: Bearer $TOKEN" http://localhost:9000/proxies/{proxy_id}
```

### Stream Proxy (TCP/UDP)

Stream proxies use `listen_port` instead of `listen_path`:

```bash
# Create a TCP stream proxy
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "listen_path": "",
    "listen_port": 5432,
    "backend_scheme": "tcp",
    "backend_host": "db.internal",
    "backend_port": 5432
  }' \
  http://localhost:9000/proxies
```

The Admin API validates `listen_port` at creation and update time:
- **409 Conflict** if the port is already used by another stream proxy
- **409 Conflict** if the port conflicts with a gateway reserved port (proxy HTTP/HTTPS, admin HTTP/HTTPS, or CP gRPC)
- **409 Conflict** if the port is already bound by another process on the host (OS-level probe)

In **CP mode**, the gateway reserved port and OS-level checks are skipped since stream proxies run on remote Data Plane nodes.

## Consumers

Consumer identity is one keyspace per namespace: `id`, `username`, and `custom_id` must all be mutually unique across every consumer in a namespace (a consumer whose own `custom_id` equals its own `id`/`username` is fine). Cross-field collisions — e.g. one consumer's `username` equalling another's `custom_id` — are rejected with `409 Conflict`, enforced both by the admission precheck and by a persistence-level unique constraint (`consumer_identity_index`), so concurrent writes cannot race a collision in. Consumer `id` values are scoped per namespace: the same id may exist in two namespaces.

`mtls_auth` credential identities remain exact and case-sensitive for non-DNS certificate fields. When an enabled `san_dns` policy is effective, the namespace also admits those identities under one ASCII case-folded DNS keyspace. Consumer, policy, and proxy-association mutations are serialized in the persistent backend, so a concurrent case variant or policy-activation race cannot commit ambiguity; an ordinary conflicting CRUD request returns `409 Conflict`. Namespace-fence contention is backend-independent: guarded mutation endpoints return `503 Service Unavailable`, `Retry-After: 1`, and `{"error":"Namespace mutation is temporarily unavailable; retry later"}` without exposing database topology or lock-owner details. Retry after the delay; a fence intentionally retained for an uncertain write requires operator recovery before retries can succeed.

If an out-of-band restore or manual database edit has already created DNS ambiguity, deletes remain repair-oriented. Ferrum permits a delete only when every post-delete ambiguous canonical identity and owner set is a subset of the pre-delete state. Removing an unrelated resource or one of the conflicting Consumers is therefore allowed, while deleting a policy or association that would activate a new collision remains `409 Conflict`.

```bash
# List consumers
curl -H "Authorization: Bearer $TOKEN" http://localhost:9000/consumers

# Create consumer
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "credentials": {"keyauth": [{"key": "my-key"}]}}' \
  http://localhost:9000/consumers

# Replace all credentials of a type (PUT replaces entirely and stores an array)
curl -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '[{"key": "new-api-key"}]' \
  http://localhost:9000/consumers/{consumer_id}/credentials/keyauth

# Append a credential for zero-downtime rotation (POST adds to array)
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"key": "rotated-api-key"}' \
  http://localhost:9000/consumers/{consumer_id}/credentials/keyauth

# Delete a specific credential by index (0-based)
curl -X DELETE -H "Authorization: Bearer $TOKEN" \
  http://localhost:9000/consumers/{consumer_id}/credentials/keyauth/0

# Delete all credentials of a type
curl -X DELETE -H "Authorization: Bearer $TOKEN" \
  http://localhost:9000/consumers/{consumer_id}/credentials/keyauth
```

Credential rotation workflow:
1. `POST .../credentials/keyauth` with the new key — both old and new are now active
2. Roll out the new key to all clients
3. `DELETE .../credentials/keyauth/0` to remove the old key

Max credentials per type is controlled by `FERRUM_MAX_CREDENTIALS_PER_TYPE` (default: 2).

Ordinary Consumer responses are a closed, fail-safe credential projection: they omit the entire `basicauth` credential type and every unknown/custom credential type, return only `identity` for `mtls_auth`, and replace each `keyauth.key`, `jwt.secret`, and `hmac_auth.secret` with the exact `[REDACTED]` marker. Extra fields on legacy known entries are dropped rather than echoed. Consumer audit diffs use the same closed projection (plus one stable marker for Basic credentials), so unknown/custom credential values are omitted there too. This response-only projection does not alter stored values: Consumer create/update and batch input still accept custom credential maps, and authenticated backup/restore preserves them unredacted for faithful recovery. Because that projection is closed, whole-Consumer `PUT` is non-destructive for the credential state it hides, so a read-modify-write round trip (GET a consumer, edit `acl_groups`, PUT the returned body) cannot silently destroy credentials. When a stored credential type the ordinary response does not emit at all — `basicauth`, any unknown/custom type, or an `mtls_auth` map whose entries the projection filtered out — is omitted from the request, the stored value is preserved; use `DELETE /consumers/{id}/credentials/{cred_type}` to remove it. If an `mtls_auth` map is only partially visible because some legacy entries or fields were filtered, submitting the exact projected array restores the complete stored map as well; supplying any different mTLS value remains an intentional wholesale replacement. Restored legacy-invalid hidden state fails validation rather than being silently deleted. Concretely, for the Basic case: When `basicauth` is omitted from the request, an existing Basic credential type is preserved; use `DELETE /consumers/{id}/credentials/basicauth` to remove it. That delete route accepts the five known types unconditionally and an unknown/custom type when the consumer actually stores it, so hidden types stay removable without opening a new credential-type namespace (an unknown type the consumer does not store returns `400`). A `keyauth`, `jwt`, or `hmac_auth` entry submitted as the exact `[REDACTED]` placeholder is restored from the stored entry at the same array index, so a round-tripped response cannot overwrite a live API key or shared secret with the placeholder string; entries carrying real values are written through, so rotation by `PUT` still works. For `jwt` and `hmac_auth` the restore uses the stored entry's canonical `secret` only, so a legacy row that still carries an ignored extra field such as `algorithm` does not fail an otherwise unrelated edit; `keyauth`, which has no single-field rule, is restored with every stored field. `[REDACTED]` is reserved for exactly this round trip: it is never accepted as a real `keyauth` `key`, `jwt` `secret`, or `hmac_auth` `secret` on any surface — create, whole-Consumer `PUT`, batch, restore, or the dedicated credential endpoints — and a placeholder submitted at an array index with no corresponding stored entry is rejected with `400` rather than stored, so the marker can never become live credential material. Credential type keys are likewise restricted at every write and restore boundary to one path-safe URI segment (1-64 ASCII letters, digits, underscores, or hyphens); keys that are empty or contain `/`, `%`, whitespace, control bytes, or other reserved URI characters are rejected, which guarantees that every stored credential type — including a hidden custom type only `PUT` preservation can create — remains addressable by `DELETE /consumers/{id}/credentials/{cred_type}`, a route that matches the raw path split on `/` without percent-decoding. Omitting a credential type the ordinary response does represent (`keyauth`, `jwt`, `hmac_auth`, `mtls_auth`) still removes it. The authenticated `/backup` endpoint is the only management response that intentionally returns unredacted Basic password hashes for faithful restoration. During active build-out, restore rejects legacy `basicauth` entries with extra fields: each entry must contain exactly one `password` or `password_hash` field.

The OpenAPI document models these wire differences with separate Consumer surface schemas: `ConsumerCreate` is the create/batch request shape (write-only credential inputs, including plaintext `basicauth` `password`, and no `[REDACTED]` values), `ConsumerUpdate` is the `PUT` request shape (identical to `ConsumerCreate` except that `keyauth`, `jwt`, and `hmac_auth` entries may also be the exact `[REDACTED]` placeholder, so the server's own redacted response validates as an update body), `Consumer` is the ordinary redacted response shape (`basicauth` absent; `keyauth.key`, `jwt.secret`, and `hmac_auth.secret` carry the exact `[REDACTED]` placeholder), and `ConsumerBackup`/`ConsumerRestore` are the unredacted backup/restore shapes documented in [docs/admin_backup_restore.md](admin_backup_restore.md). Every composed Consumer surface closes unknown top-level fields (`unevaluatedProperties: false`), matching runtime `Consumer` serde `deny_unknown_fields` on create, update, batch, restore, and file/CP-DP config deserialization (SQL/Mongo loaders construct Consumers from typed columns/documents rather than accepting free-form top-level JSON). Credential mutation request bodies use `ConsumerCredentialInput`, the union of the per-type input entry schemas. Dedicated credential `PUT`/`POST` path parameters advertise only `BuiltInCredentialType` (`basicauth`, `keyauth`, `jwt`, `hmac_auth`, `mtls_auth`), matching runtime `ALLOWED_CREDENTIAL_TYPES`; type-level `DELETE` keeps the broader path-safe `CredentialTypeName` so custom maps remain removable.

Consumer credential string maxima use Unicode character counts, matching OpenAPI `maxLength`: `basicauth.password`, `keyauth.key`, `hmac_auth.secret`, `jwt.secret`, and `mtls_auth.identity` are limited to 4096 characters and reject disallowed ASCII control bytes. HMAC secrets additionally require at least 32 non-whitespace characters. Consumer `jwt` credential entries support one key form: exactly one `secret` string (32-4096 characters) used for HS256 verification. Fields such as `algorithm`, `public_key`, `jwks`, and `jwks_uri` are rejected rather than ignored. RSA/EC/JWKS verification is configured through the separate `jwks_auth` plugin; it may map verified claims to a Consumer identity but does not read Consumer `jwt` credentials.

## Plugin Configs

```bash
# List available plugin types
curl -H "Authorization: Bearer $TOKEN" http://localhost:9000/plugins

# List plugin configs (first page)
curl -H "Authorization: Bearer $TOKEN" http://localhost:9000/plugins/config

# Create plugin config
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "plugin_name": "rate_limiting",
    "config": {"limit_by": "ip", "limits": [{"scope": "default", "requests_per_minute": 60}]},
    "scope": "global",
    "enabled": true
  }' \
  http://localhost:9000/plugins/config
```

Disabled plugin configs are stored without plugin-specific construction, so operators can stage configuration before runtime-only prerequisites are present. For example, `basic_auth` may be created or imported with `enabled: false` before `FERRUM_BASIC_AUTH_HMAC_SECRET` is provisioned. Enabling the config performs normal construction and fails closed unless the secret is present and at least 32 bytes.

Plugin-config reads by `viewer` and `operator` roles use the same redacted projection stored in admin audit diffs; `admin` reads remain raw. For `loki_logging`, the projection preserves only the endpoint scheme, host, and port, replaces the path/query, `authorization_header`, and every `custom_headers` value, and never returns URL-embedded or explicit credentials.

## Upstreams

```bash
# List upstreams (first page)
curl -H "Authorization: Bearer $TOKEN" http://localhost:9000/upstreams

# Create an upstream (load-balanced backend group)
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-backend-pool",
    "targets": [
      {"host": "backend1.example.com", "port": 8080, "weight": 5},
      {"host": "backend2.example.com", "port": 8080, "weight": 3}
    ],
    "algorithm": "weighted_round_robin",
    "health_checks": {
      "active": {
        "http_path": "/health",
        "interval_seconds": 10,
        "healthy_threshold": 3,
        "unhealthy_threshold": 3
      }
    }
  }' \
  http://localhost:9000/upstreams

# Get an upstream
curl -H "Authorization: Bearer $TOKEN" http://localhost:9000/upstreams/{upstream_id}

# Update an upstream
curl -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-backend-pool",
    "targets": [
      {"host": "backend1.example.com", "port": 8080, "weight": 5},
      {"host": "backend3.example.com", "port": 8080, "weight": 2}
    ],
    "algorithm": "round_robin"
  }' \
  http://localhost:9000/upstreams/{upstream_id}

# Delete an upstream
curl -X DELETE -H "Authorization: Bearer $TOKEN" http://localhost:9000/upstreams/{upstream_id}
```

Supported algorithms: `round_robin`, `weighted_round_robin`, `least_connections`, `least_latency`, `consistent_hashing`, `random`, `passthrough`.

To use an upstream with a proxy, set the proxy's `upstream_id` field. When set, the upstream's targets override the proxy's `backend_host`/`backend_port`. Each target may also specify an optional `path` field which overrides the proxy's `backend_path` when that target is selected.

## Backup & Restore

```bash
# Full backup — exports all proxies, consumers, plugins, upstreams (unredacted)
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:9000/backup > ferrum-backup.json

# Partial backup — only proxies and upstreams
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:9000/backup?resources=proxies,upstreams" > partial-backup.json

# Restore from backup (replaces config after taking a recovery snapshot)
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d @ferrum-backup.json \
  "http://localhost:9000/restore?confirm=true"
```

The backup output is directly compatible with `POST /batch` (additive) and `POST /restore` (full replacement). Before replacement, restore acquires a persistent namespace guard and snapshots the current namespace with a non-validating raw load from the primary, so an already-invalid-but-present config still snapshots and keeps rollback available while it is repaired. If that snapshot cannot be taken at all — a genuine database/connectivity failure — restore **aborts with `503` before deleting anything** and leaves the prior config intact (retry once the database is reachable). Database inserts are chunked into 1,000-record transactions for large-scale imports. Conditional mTLS DNS-identity uniqueness is checked under the same namespace-scoped datastore admission guard used by ordinary Consumer, plugin, proxy-association, upstream, and API-spec writes, so a concurrent admin process cannot race a batch/restore policy activation with a case-variant credential. Restore retains one persistent guard owner from before its snapshot through the clear and every import or compensating-replay batch. All non-owning namespace resource writers and replays fail closed for that full interval, so no concurrent resource can be lost merely because it was absent from the restore payload. The compensating replay intentionally does not apply newly introduced mTLS DNS admission to the old snapshot: otherwise a pre-existing ambiguity would be deleted successfully and then become impossible to restore. Normal batch/restore admission never receives this rollback-only bypass. The endpoint returns `500 Internal Server Error` with a `rollback` field (`completed` / `incomplete` / `not_needed` / `unknown_outcome`). `not_needed` means the clear definitively aborted atomically (SQL / replica-set MongoDB), so nothing was deleted and the prior config was retained without any re-import. An unknown MongoDB commit remains `unknown_outcome` with the guard retained even when immediate verification still sees the prior counts, because the clear can become visible later. API specs are admin-plane-only metadata outside the backup/restore payload: a successful restore deletes them, and a config rollback cannot recreate them. Re-submit original documents via `POST /api-specs`; use `GET /api-specs` to list specs currently stored in the namespace. Failed restores report the authoritative affected count in `api_specs_not_restored`.

See [admin_backup_restore.md](admin_backup_restore.md) for details.

## Audit Log

When `FERRUM_ADMIN_AUDIT_ENABLED=true`, successful admin mutations enqueue a database-backed audit event before the mutation response is returned. The response waits only for bounded queue enqueue, not durable database persistence. Audit persistence is best-effort after the mutation commits: if enqueue or persistence fails, Ferrum logs the failure and still returns the mutation result so operators do not retry an already-applied write. Partial `POST /batch` mutations that return `207 Multi-Status` emit an audit event when at least one resource was changed. Restore attempts that reach the delete/import phase emit an event; failed attempts record whether rollback completed or was incomplete. Each event includes an ID, timestamp, actor (`sub` claim), action, resource type, resource ID, namespace, and a JSON `diff` object with redacted consumer credentials and sensitive plugin configuration. Basic credential mutations remain visible by type and action, but every Basic value, entry field, shape, and count is replaced by one stable `[REDACTED]` marker before persistence. Loki plugin diffs preserve only the endpoint scheme/host/port and redact its path, query, authorization, and all custom-header values.

`GET /audit` requires an `admin` role token and supports `actor`, `action`, `resource_type`, `resource_id`, `start`, `end`, `limit`, and `offset` query parameters. `limit` follows the shared bounds (default 100, maximum 1000), and malformed or out-of-range values are rejected with `400`. The audit store indexes offsets as a 32-bit value, so `offset` is capped at `2^32 - 1` here rather than the `2^63 - 1` other list endpoints allow — a larger offset returns `400`. The audit response keeps its own `{ "items", "limit", "offset", "next_offset", "total" }` envelope. `next_offset` is always strictly greater than `offset`; it is `null` when no further page exists or the next cursor would exceed the 32-bit ceiling.

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:9000/audit?resource_type=proxy&resource_id=PROXY_ID"
```

## Cluster Status

The `/cluster` endpoint provides live CP/DP connection state. Available in all modes, but most useful in CP and DP modes.

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:9000/cluster
```

### CP Mode Response

Returns all currently connected Data Plane nodes and Mesh nodes. Each registry is independent: a node that subscribes to both `ConfigSync.Subscribe` (DP) and `MeshConfigSync.MeshSubscribe` (mesh) appears in both arrays with separate `connected_at` timestamps.

```json
{
  "mode": "cp",
  "connected_data_planes": 2,
  "data_planes": [
    {
      "node_id": "abc-123",
      "version": "0.9.0",
      "namespace": "ferrum",
      "status": "online",
      "connected_at": "2025-01-15T10:30:00Z",
      "last_sync_at": "2025-01-15T10:35:00Z"
    }
  ],
  "connected_mesh_nodes": 1,
  "mesh_nodes": [
    {
      "node_id": "mesh-789",
      "version": "0.9.0",
      "namespace": "ferrum",
      "status": "online",
      "connected_at": "2025-01-15T10:32:00Z",
      "last_heartbeat_at": "2025-01-15T10:34:30Z",
      "last_sync_at": "2025-01-15T10:35:00Z"
    }
  ]
}
```

- **`status`** is always `online` — disconnected DPs and mesh nodes are automatically removed from their registries when their gRPC stream drops. Mesh nodes also send lightweight `MeshSubscribe` heartbeats; the CP reaps entries that stop producing stream activity for 5 minutes.
- **`last_sync_at`** updates whenever the CP broadcasts a config update (full snapshot or delta) to that registry. DP and mesh broadcasts share the same database polling cycle, so the timestamps converge on every successful poll.
- **`last_heartbeat_at`** is mesh-only and updates whenever the CP produces a mesh stream item for that node: the initial snapshot, a config delta/full snapshot, or a heartbeat.

### DP Mode Response

Returns the connection status to the Control Plane:

```json
{
  "mode": "dp",
  "control_plane": {
    "url": "http://cp-host:50051",
    "status": "online",
    "is_primary": true,
    "connected_since": "2025-01-15T10:30:00Z",
    "last_config_received_at": "2025-01-15T10:35:00Z",
    "config_diverged": false,
    "config_diverged_since": null,
    "config_divergence_recoveries_total": 0
  }
}
```

- **`status`**: `online` when the gRPC stream to the CP is active, `offline` when disconnected (e.g., CP is down, DP is in backoff retry).
- **`is_primary`**: `true` when connected to the primary (first) CP URL, `false` when connected to a fallback CP (multi-CP failover).
- **`last_config_received_at`**: Timestamp of the last successfully *accepted* config update (full snapshot or delta) from the CP. Rejected resource deltas do not advance this stamp. `null` if no config has been accepted yet.
- **`config_diverged`**: Sticky operator signal set when a non-empty ConfigSync DELTA is rejected. Cleared only after an authoritative FULL_SNAPSHOT is accepted. Last-known-good config continues to serve while `true`.
- **`config_diverged_since`**: When sticky divergence was first raised (`null` when not diverged).
- **`config_divergence_recoveries_total`**: Count of divergence → FULL_SNAPSHOT recovery transitions.

### Database/File Mode Response

```json
{
  "mode": "database",
  "message": "Cluster status is only available in cp or dp modes"
}
```

## Metrics

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:9000/admin/metrics
```

Returns:
```json
{
  "mode": "database",
  "config_last_updated_at": "2025-01-15T10:30:00Z",
  "config_source_status": "online",
  "proxy_count": 5,
  "consumer_count": 10,
  "total_requests": 523401,
  "status_codes_total": {"200": 520000, "404": 2891, "429": 510},
  "requests_per_second": 150,
  "status_codes_per_second": {"200": 145, "404": 3, "429": 2},
  "metrics_window_seconds": 30
}
```

See [admin_metrics.md](admin_metrics.md) for the full metrics reference.

### Prometheus `/metrics` (gated)

The exact `/metrics` endpoint returns Prometheus text exposition for scrapers. **It is gated by default** — a scraper must present a valid admin JWT, a matching `FERRUM_METRICS_BEARER_TOKEN`, or originate from a `FERRUM_METRICS_ALLOWED_CIDRS` source IP. Without one of these, `/metrics` returns `401` with a `WWW-Authenticate: Bearer` header. Unauthenticated scraping is an explicit operator opt-in.

Safe Prometheus scrape configurations:

```yaml
# Option A — dedicated metrics bearer token (FERRUM_METRICS_BEARER_TOKEN=<token>)
scrape_configs:
  - job_name: ferrum-edge
    metrics_path: /metrics
    authorization:
      type: Bearer
      credentials: "<token>"          # or credentials_file: /etc/prometheus/ferrum.token
    static_configs:
      - targets: ["ferrum-admin:9000"]

# Option B — allowlist the Prometheus subnet (FERRUM_METRICS_ALLOWED_CIDRS=10.0.0.0/8)
#   then scrape with no credential. Combine with FERRUM_ADMIN_ALLOWED_CIDRS and/or
#   a NetworkPolicy so only the scrape network can reach the admin listener.
```

The output includes TLS inventory gauges `ferrum_tls_cert_expiry_seconds` and `ferrum_tls_cert_not_before_seconds` for loaded certificate sources — served from the cached non-secret inventory snapshot with the freshness pair `ferrum_tls_inventory_snapshot_timestamp_seconds` / `ferrum_tls_inventory_snapshot_max_age_seconds`, never by loading TLS material on the scrape path — plus `ferrum_tls_cert_rotations_total`, `ferrum_tls_source_refresh_total`, `ferrum_tls_source_fetch_duration_seconds`, and `ferrum_tls_source_fetch_failures_total` for background source watcher activity. It also exposes the admin/management-plane connection limiter: `ferrum_admin_active_connections` (gauge of admin connections in flight), `ferrum_admin_max_connections` (the configured `FERRUM_ADMIN_MAX_CONNECTIONS` cap, `0` = unlimited), and `ferrum_admin_rejected_connections_total{reason="max_connections"|"max_connections_per_ip"}` (admin connections dropped by the cap). In database mode it also includes bounded rejected-delta polling metrics such as `ferrum_database_delta_rejections_total`, `ferrum_database_delta_backoff_bucket`, `ferrum_database_delta_forced_full_reloads_total`, and `ferrum_database_delta_recoveries_total`. In mesh mode it also includes `ferrum_mesh_cert_expiry_seconds`, `ferrum_mesh_cert_rotation_failures_total`, `ferrum_mesh_ca_health`, `ferrum_mesh_trust_bundle_version`, `ferrum_mesh_config_last_received_timestamp_seconds`, and `ferrum_mesh_mtls_handshake_failures_total` alongside request RED metrics. Mesh RED and certificate series include SPIFFE identity labels — another reason the endpoint is gated by default; in Kubernetes, still put it behind a `NetworkPolicy` as defense in depth when workload identity inventory is sensitive.

### Runtime Metrics

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:9000/metrics/runtime
```

Returns one process-global JSON snapshot for host and gateway triage: process CPU and memory, file descriptors, ephemeral-port pressure, HTTP status windows, error classes, DNS outcomes, backend pool churn, TCP reset counts, bounded log counters, and overload state.

The response is cached briefly (`FERRUM_METRICS_RUNTIME_CACHE_MS`, default `1000`) to avoid amplifying sampler work under polling. Log counters count Ferrum project tracing events allowed by the output `FERRUM_LOG_LEVEL` / `RUST_LOG` filter, and the 1m/5m HTTP status windows can be disabled with `FERRUM_METRICS_STATUS_TRACKING_ENABLED=false` for maximum hot-path throughput.

## Charges

The `/charges` endpoint exposes per-consumer API usage charges tracked by the `api_chargeback` plugin. It requires the same admin JWT authentication as other sensitive admin endpoints.

Monetary samples convert the stored `u64` counter to IEEE-754 binary64 and
multiply it by the configured binary64 unit price (accepted rates are finite
and ≤ `1e288`). Counters above 2^53 follow normal binary64 rounding; Ferrum
applies no additional decimal or currency-subunit rounding. If export
arithmetic would produce a non-finite value, the endpoint returns **HTTP 500**
with `{"error":"<message>"}` for both Prometheus and JSON formats instead of
emitting JSON `null` or Prometheus `inf`.

```bash
# Prometheus text format (default)
curl -H "Authorization: Bearer $TOKEN" http://localhost:9000/charges

# JSON format
curl -H "Authorization: Bearer $TOKEN" http://localhost:9000/charges?format=json
```

**Prometheus format** returns counter families:
- `ferrum_api_chargeable_calls_total` — HTTP-family call counts with labels `consumer`, `proxy_id`, `proxy_name`, `status_code`, and `currency`. Ordinary HTTP uses the wire status; native gRPC and translated gRPC-Web use the final terminal `grpc-status` mapped to Ferrum's canonical effective HTTP status (for example `0→200`, `7→403`, `14→503`).
- `ferrum_api_charges_total` — HTTP per-call monetary charges with the same HTTP labels
- `ferrum_api_stream_connections_total` — stream session counts (TCP/TCP+TLS/UDP/DTLS proxies) with labels `consumer`, `proxy_id`, `proxy_name`, and `currency`
- `ferrum_api_stream_connection_charges_total` — stream per-session monetary charges with the same stream labels
- `ferrum_api_bytes_sent_total` / `ferrum_api_bytes_received_total` — bandwidth byte counters aggregated per `consumer`/`proxy_id`/`currency`/`protocol_family`
- `ferrum_api_bandwidth_charges_total` — bandwidth monetary charges, labelled with `direction="sent"`/`"received"` and `protocol_family="http"`/`"stream"`

All families include a `namespace` label when the plugin instance has a namespace.

**JSON format** returns a nested breakdown:
```json
{
  "currency": "USD",
  "generated_at": "2025-01-15T10:30:00Z",
  "consumers": {
    "alice": {
      "total_charges": 1.55,
      "total_calls": 150042,
      "per_call_charges": 1.50,
      "stream_connection_charges": 0.021,
      "bandwidth_charges": 0.029,
      "proxies": {
        "proxy-abc": {
          "proxy_name": "Payments API",
          "currency": "USD",
          "protocol_family": "http",
          "total_charges": 1.5105,
          "total_calls": 150000,
          "by_status": {
            "200": { "calls": 145000, "charges": 1.45 },
            "201": { "calls": 5000, "charges": 0.05 }
          },
          "bandwidth": {
            "bytes_sent": 1500000,
            "bytes_received": 4500000,
            "charge_sent": 0.0015,
            "charge_received": 0.009
          }
        },
        "tcp-edge": {
          "proxy_name": "TCP Edge",
          "currency": "USD",
          "protocol_family": "stream",
          "total_charges": 0.0397,
          "total_calls": 42,
          "by_status": {},
          "bandwidth": {
            "bytes_sent": 95000,
            "bytes_received": 184000,
            "charge_sent": 0.0095,
            "charge_received": 0.0092
          },
          "stream": {
            "connections": 42,
            "connection_charges": 0.021
          }
        }
      }
    }
  }
}
```

Each `api_chargeback` plugin instance owns its own `currency` and `namespace` (per global/proxy/proxy_group scope). The currency and namespace are recorded per proxy, so a process hosting multiple instances with different currencies reports each proxy under its own currency rather than a single last-writer-wins value. The top-level `currency` is the single currency in use, or `"mixed"` when instances disagree — read the per-proxy `currency` field in that case.

**`proxy_name` contract:** `proxy_name` is live display metadata for the stable `proxy_id` and is not part of the in-memory registry key, so a name-only reload keeps the accumulated counter values continuous. After an accepted configuration is published, both JSON and Prometheus resolve every active proxy ID through the same lock-free snapshot of that configuration's names; request completion order cannot change the exported label, so late traffic admitted under a retired generation cannot restore an old name. Because `proxy_name` is still a Prometheus label, a rename creates a controlled label transition at the accepted reload boundary; the new label carries the existing cumulative counter rather than restarting its in-memory value. Pricing changes still create distinct pricing-generation entries (price bits remain in the key), but overlapping entries collapse under the current published name. Retained rows for a deleted proxy fall back deterministically to their recorded metadata.

**Mixed-currency consumer totals:** Monetary values are never summed across currencies. When every proxy for a consumer shares one currency, the historical flat fields (`total_charges`, `per_call_charges`, `stream_connection_charges`, `bandwidth_charges`) remain numeric and reconcilable with that consumer's proxy rows. When a single consumer spans more than one currency, those flat monetary fields are `null` and a `charges_by_currency` map is emitted instead — one partition per currency with the same component fields. `total_calls` stays numeric because it is unitless. Billing integrations must treat `null` as "not a settlement total" (do not coerce to `0`) and invoice from `charges_by_currency` and/or per-proxy rows. Within each currency, `charges_by_currency[currency].total_charges` equals the sum of `proxies[*].total_charges` for proxies carrying that currency.

A proxy that serves both HTTP and stream traffic under one `proxy_id` reports `"protocol_family": "mixed"` and includes both a populated `by_status` map and a `stream` sub-object, so the per-family breakdown always reconciles with the totals. For gRPC/gRPC-Web, `by_status` is the effective billing status derived from the final client-visible terminal code; it does not overwrite the wire HTTP status in transaction logs. Missing, malformed, and unknown terminal codes fail closed to the `500` bucket.

**Multi-node deployments**: Each gateway node accumulates charges independently in memory. In CP/DP topologies, scrape `/charges` from every DP node with admin JWT credentials and aggregate externally. See [plugins.md](plugins.md#api_chargeback) for Prometheus scrape configuration examples.

## API Spec Management

Ferrum Edge can ingest an OpenAPI 2.0 (Swagger), 3.0.x, 3.1.x, or 3.2.x specification document and atomically provision a proxy, optional upstream, and proxy-scoped plugins as a single bundle. Specs are admin-plane-only metadata and the gateway runtime never reads them — submitting or updating a spec has no effect on in-flight requests. Authenticated `viewer`, `operator`, and `admin` tokens can list non-secret spec metadata. Retrieving an original spec document requires `admin` because it can contain sensitive upstream or plugin configuration that the normal Viewer/Operator resource responses redact. Creating, replacing, or deleting a spec also requires `admin`. See [docs/api_specs.md](api_specs.md) for the full extension contract, worked examples, and curl recipes.

**Endpoints at a glance:**

| Method | Path | Minimum role | Description |
|--------|------|--------------|-------------|
| `POST` | `/api-specs` | `admin` | Submit new spec; create proxy + upstream + plugins |
| `GET` | `/api-specs` | `viewer` | List spec metadata (paginated, no content) |
| `GET` | `/api-specs/{id}` | `admin` | Retrieve spec document (content negotiation + ETag) |
| `PUT` | `/api-specs/{id}` | `admin` | Replace spec; recreate spec-owned resources |
| `DELETE` | `/api-specs/{id}` | `admin` | Delete spec; cascade proxy + plugins + upstream |
| `GET` | `/api-specs/by-proxy/{proxy_id}` | `admin` | Look up spec by proxy ID |

### `POST /api-specs`

Submit an OpenAPI or Swagger document. The spec must include a `x-ferrum-proxy` extension at the root. Optional `x-ferrum-upstream` and `x-ferrum-plugins` extensions create additional resources. All created resources are tagged with the spec's `api_spec_id` by the server. Clients must omit `api_spec_id` from all three extensions; copied ownership tags return 422 on POST and PUT.

```bash
curl -X POST https://gateway/api-specs \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/yaml" \
  --data-binary @orders-api.yaml
```

Returns **201** with `{ id, proxy_id, content_hash, spec_version }` on success. The `Location` header points to the new spec. Returns **400** for parse failures, **409** if a spec already exists for the same proxy, **422** if resources fail validation, **413** if the body exceeds `FERRUM_ADMIN_SPEC_MAX_BODY_SIZE_MIB` (default 25 MiB).

### `GET /api-specs`

Returns paginated spec summaries (no spec content). The list includes Tier 1 metadata fields extracted at submit time (`description`, `contact_name`, `contact_email`, `license_name`, `license_identifier`, `tags`, `server_urls`, `operation_count`). The internal `resource_hash` is excluded.

Response shape: `{ "items": [...], "limit": N, "offset": N, "next_offset": N|null, "total": N }`. The `total` field is the count of all matching rows ignoring pagination — use it to render "showing X–Y of Z" in UIs.

`limit` defaults to 50 with a maximum of 200 here — stricter than the 100/1000 used by the other list endpoints — and `offset` is a 32-bit value. As elsewhere, malformed or negative `limit`/`offset` values are rejected with 400 rather than coerced to a default.

Supports filter and sort query parameters: `proxy_id` (exact), `spec_version` (prefix), `title_contains` (case-insensitive substring), `updated_since` (ISO-8601), `has_tag` (exact tag membership), `sort_by` (`updated_at`, `title`, `operation_count`, `created_at`; default `updated_at`), and `order` (`asc`/`desc`; default `desc`). Unknown `sort_by` or `order` values return 400.

```bash
curl "https://gateway/api-specs?limit=20&offset=0" \
  -H "Authorization: Bearer $JWT"

curl "https://gateway/api-specs?has_tag=public&spec_version=3.1&sort_by=title&order=asc" \
  -H "Authorization: Bearer $JWT"
```

### `GET /api-specs/{id}` and `GET /api-specs/by-proxy/{proxy_id}`

Return the raw spec document. Supports `Accept` header content negotiation (`application/json` ↔ `application/yaml`) and conditional GET via `If-None-Match` using the `ETag` (SHA-256 hex content hash). Returns **304 Not Modified** when the ETag matches.

```bash
# Retrieve as YAML (regardless of stored format)
curl https://gateway/api-specs/SPEC_ID \
  -H "Authorization: Bearer $JWT" \
  -H "Accept: application/yaml"

# Conditional GET
curl https://gateway/api-specs/SPEC_ID \
  -H "Authorization: Bearer $JWT" \
  -H "If-None-Match: \"abc123...\""

# Look up by proxy ID
curl https://gateway/api-specs/by-proxy/orders-proxy \
  -H "Authorization: Bearer $JWT"
```

### `PUT /api-specs/{id}`

Replaces the spec and recreates all **spec-owned** resources (those with `api_spec_id` matching this spec). Resources added manually to the same proxy via direct admin endpoints (`api_spec_id = null`) are not touched. `created_at` is preserved; `updated_at` and `content_hash` reflect the new document.

**Idempotent PUT**: if the submitted bundle produces the same resource hash as the stored one (e.g. only `info.description` changed), the proxy/upstream/plugin rows are left untouched — their `updated_at` does not advance and no polling or DP broadcast fires. The `api_specs` row is always updated. This makes PUT safe to call on every CI/CD deploy cycle.

### `DELETE /api-specs/{id}`

Deletes the spec and cascades:

- Spec-owned **proxy** is deleted → FK cascade removes its plugins (including any added manually after import).
- Spec-owned **upstream** is deleted if present. Upstreams without `api_spec_id` survive.
- Calling `DELETE /proxies/{id}` directly also removes the spec row via the `ON DELETE CASCADE` FK constraint.
- Before a direct delete of an API-spec-owned proxy, Ferrum re-reads the
  current upstream and every cascade plugin with ownership metadata intact.
  Hand-owned rows remain hand-owned; foreign API-spec ownership, missing rows,
  or an ownership/scope shape that atomic recovery cannot reproduce returns 400
  without deleting the proxy.
- If the cascade would leave an invalid aggregate plugin graph, the API returns
  422 with validation failures and no resources are deleted. Direct proxy or
  plugin-config deletion reports the equivalent precondition failure as 400.
- Before deletion, the complete compensation snapshot is checked for ownership
  and restorable plugin shape. Foreign API-spec ownership, a global plugin tied
  to or explicitly associated with the deleted proxy, a proxy-scoped association
  targeting another proxy, a proxy-group plugin carrying `proxy_id`, or an
  embedded proxy association naming a missing config returns the structured 422
  validation-failure response without deleting anything, leaving the malformed
  graph available for operator repair.
- If namespace admission is lost after the delete commits, SQL backends and
  replica-set MongoDB restore the upstream, proxy, all spec-owned and hand-owned
  plugins removed by the cascade, associations, spec row, and config-change
  records in one transaction. Valid proxy-scoped configs without a reverse
  proxy association are restored in that same transaction and remain
  unattached. Reference validation is limited to this recovered proxy graph, so
  unrelated malformed associations remain available for in-band repair. Route
  uniqueness, namespace-wide guarded plugin composition, mTLS identity policy,
  and referenced-upstream existence are still rechecked inside the restore
  transaction after any intervening writer; a conflict rolls the complete
  restore back. Recovery validation uses the same configured backend egress
  policy and real-IP header as normal admin plugin validation. Standalone
  MongoDB cannot provide that boundary, so compensation fails before writing
  and leaves the route deleted rather than publishing a partially protected
  proxy.

### Cascade and ownership summary

| Operation | Spec-owned resources | Hand-added resources |
|---|---|---|
| `POST /api-specs` | Created; tagged with `api_spec_id` | — |
| `PUT /api-specs/{id}` | Replaced (deleted + re-inserted) | Survive unchanged |
| `DELETE /api-specs/{id}` | Proxy + plugins deleted; spec-owned upstream deleted | Non-spec upstreams survive |
| `DELETE /proxies/{id}` | Spec row deleted by FK cascade | — |

### Mode behavior

| Mode | Write (`POST`/`PUT`/`DELETE`) | Read (`GET`) |
|---|---|---|
| `database` | Supported | Supported |
| `cp` | Supported — resources distributed to DPs via gRPC; spec stays on CP | Supported |
| `dp` | 503 (no database) | 503 (no database) |
| `file` | 403 (read-only) | 503 (no database) |

For the full extension contract, supported versions, validation rules, and worked examples, see [docs/api_specs.md](api_specs.md).

## Backend Capability Registry

Ferrum Edge classifies each HTTP-family backend target's protocol support (HTTP/1.1, HTTP/2 over TLS, HTTP/3, gRPC-over-TLS, h2c) at startup and on a periodic background refresh (`FERRUM_BACKEND_CAPABILITY_REFRESH_INTERVAL_SECS`, default 24h). The hot path consults this registry to decide whether to route plain HTTPS traffic through the native H3 pool, the direct HTTP/2 pool, or the generic reqwest path without per-request probing. See [CLAUDE.md — Backend Capability Registry](../CLAUDE.md) and [docs/http3.md](http3.md) for the underlying design.

Two JWT-authenticated endpoints let operators inspect and force-refresh the registry at runtime.

### `GET /backend-capabilities`

Returns every cached entry keyed by the deduplicated backend-target identity the registry uses internally (scheme + host + port + `dns_override` + CA + mTLS cert + mTLS key + verify flag, plus HBONE sidecar port for targets tagged `mesh.hbone=true`).

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:9000/backend-capabilities
```

Response:

```json
{
  "entries": [
    {
      "key": "https|api.example.internal|443||/etc/ferrum/ca.pem|||1",
      "plain_http": {
        "h1": "supported",
        "h2_tls": "supported",
        "h3": "supported"
      },
      "grpc_transport": {
        "h2_tls": "supported",
        "h2c": "unknown"
      },
      "hbone": "unsupported",
      "last_probe_at_unix_secs": 1714003200,
      "last_probe_error": null
    },
    {
      "key": "https|legacy.example.internal|443||||0",
      "plain_http": {
        "h1": "supported",
        "h2_tls": "unsupported",
        "h3": "unsupported"
      },
      "grpc_transport": {
        "h2_tls": "unsupported",
        "h2c": "unknown"
      },
      "hbone": "unknown",
      "last_probe_at_unix_secs": 1714003200,
      "last_probe_error": "H2/TLS downgraded after ALPN-negotiated HTTP/1.1 on request path"
    }
  ]
}
```

Field semantics:

- **`key`** — stable identity used by the router to look up the entry. Safe to match across responses to detect churn.
- **`plain_http.{h1, h2_tls, h3}`** — whether the native dispatch path for plain HTTP traffic may use HTTP/1.1 (always true for reachable HTTPS backends), the direct HTTP/2 pool (`h2_tls`), or the native HTTP/3 pool (`h3`). Values: `"supported"`, `"unsupported"`, or `"unknown"` (not yet probed). `"unknown"` and `"unsupported"` both cause the hot path to fall back through the reqwest HTTP/1.1+HTTP/2 client.
- **`grpc_transport.{h2_tls, h2c}`** — same semantics for gRPC. `h2c` is native gRPC over plaintext HTTP/2 prior-knowledge; rarely deployed.
- **`hbone`** — gateway-to-mesh HBONE support for upstream targets tagged `mesh.hbone=true`. `"supported"` means the gateway can open HTTP/2 CONNECT over SPIFFE mTLS to the sidecar port, `"unsupported"` skips the tunnel, and `"unknown"` is used when the target is not HBONE-tagged, the gateway has no SVID, or the probe has not completed.
- **`last_probe_at_unix_secs`** — epoch seconds of the most recent probe or live-traffic downgrade. Updates on every refresh AND on each live `mark_h2_tls_unsupported` / `mark_h3_unsupported` / `mark_hbone_unsupported` invocation.
- **`last_probe_error`** — human-readable error string set when the last classification update came from a live-traffic downgrade (ALPN mismatch, QUIC failure, HBONE capability-establishment failure) or from a genuine probe failure (TLS config error, connection error on an HTTPS backend). `null` when the most recent update classified the backend cleanly. Expected-unsupported outcomes (h2c on plaintext HTTP, H3 on most HTTPS backends, untagged HBONE, per-request HBONE CONNECT rejection) do NOT populate this field — only genuine errors / live downgrades do. An H3 probe failure against a target the registry had already classified `h3: supported` always populates it, including when a transient DNS/connect/refused/timeout class preserves the previous classification instead of downgrading it — that record is intentionally stale and the operator should see why.

Use cases:

- **Routing-decision debugging**: "Why did this H3-capable backend just fall back to reqwest?" → check `last_probe_error`.
- **Protocol-rollout monitoring**: poll after enabling H3 on a backend fleet to verify every target flipped to `h3: "supported"`.
- **Stale-cache auditing**: verify `last_probe_at_unix_secs` is within your expected refresh interval.

### `POST /backend-capabilities/refresh`

Force an immediate, synchronous classification pass over every HTTP-family backend in the current config. Blocks until every probe completes (bounded by `FERRUM_POOL_WARMUP_CONCURRENCY` parallelism + per-probe timeout).

This operational recovery endpoint is available in every proxy-serving mode,
including read-only file, DP, and mesh admin states. It does not persist a
configuration or database mutation and still requires a valid admin JWT.

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" http://localhost:9000/backend-capabilities/refresh
```

Response:

```json
{
  "status": "refreshed"
}
```

Use after:

- Deliberately toggling a backend's H3 / H2 support without waiting for the 24h timer.
- Rotating backend TLS material that the previous probe didn't see.
- Manually resolving an incident where the cache is known stale (e.g., backend came back online after a QUIC failure downgraded `h3` or an HBONE capability-establishment failure downgraded `hbone` to `unsupported`).

Because this endpoint is **synchronous**, callers can assert on the post-refresh state by immediately issuing `GET /backend-capabilities` afterward. Request body is ignored; no fields are required.

### No payload data exposed

The registry stores only protocol classifications and probe timestamps — never request bodies, credentials, TLS keys, or anything resembling user payload. Both endpoints are safe to expose in any environment where admin JWTs are issued.

### Related environment variables

- `FERRUM_BACKEND_CAPABILITY_REFRESH_INTERVAL_SECS` — periodic refresh cadence (default `86400`).
- `FERRUM_POOL_WARMUP_ENABLED` — when `true`, the initial classification runs synchronously during startup; when `false`, the gateway issues the first refresh in the background and reports ready before it completes (DP mode always gates readiness on first-refresh completion regardless).
- `FERRUM_POOL_WARMUP_CONCURRENCY` — parallelism cap for both startup and refresh probe passes.

## Node-Waypoint Identities (mesh `NodeWaypoint` topology)

The node-waypoint topology accepts traffic on behalf of many pods on the same node. Each pod's identity is enrolled into a per-resolver index keyed by Kubernetes pod UID; the eBPF data path records the socket cookie and original destination per outbound connection. `GET /node-waypoint/identities` exposes the live snapshot of that index so operators can answer "which pods is this waypoint actually serving?" without scraping eBPF maps.

The endpoint returns `404 Not Found` when the node-waypoint resolver is not installed on `ProxyState` — including all non-mesh modes and mesh modes other than `NodeWaypoint` topology. This avoids surfacing an empty stub list that could be mistaken for "no pods enrolled yet" on a sidecar/ambient/east-west/egress-gateway DP.

### `GET /node-waypoint/identities`

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:9000/node-waypoint/identities
```

Response:

```json
{
  "identity_count": 2,
  "cookies": {
    "orig_dst4": 17,
    "orig_dst6": 0
  },
  "identities": [
    {
      "pod_uid": "11111111-1111-1111-1111-111111111111",
      "spiffe_id": "spiffe://cluster.local/ns/default/sa/api",
      "workload_spiffe_hash": 12345678901234567890,
      "orig_dst4_cookies": 5,
      "orig_dst6_cookies": 0,
      "has_policy_scope": true
    },
    {
      "pod_uid": "22222222-2222-2222-2222-222222222222",
      "spiffe_id": "spiffe://cluster.local/ns/default/sa/billing",
      "workload_spiffe_hash": 9876543210987654321,
      "orig_dst4_cookies": 12,
      "orig_dst6_cookies": 0,
      "has_policy_scope": false
    }
  ]
}
```

Field semantics:

- `pod_uid` — hyphenated lowercase UUID matching the Kubernetes `metadata.uid` operators see in `kubectl get pod -o yaml`.
- `spiffe_id` — SPIFFE ID assigned to that pod's service account (`spiffe://{trust_domain}/ns/{namespace}/sa/{service_account}` by convention).
- `workload_spiffe_hash` — first 8 bytes of SHA-256 over the SPIFFE ID, big-endian as `u64`. Matches the value the eBPF `OrigDst{4,6}` map carries for cross-correlation with `node_agent` telemetry.
- `orig_dst4_cookies` / `orig_dst6_cookies` — number of socket cookies currently mapped to this pod via the IPv4 / IPv6 original-destination map. `0` means the pod is enrolled but has no in-flight outbound connection on that family.
- `has_policy_scope` — `true` iff a per-pod `PolicyScopeCache` is derived for this pod from the accepted mesh slice's workload metadata. When `false`, the pod's workload is not in the live slice generation, so mesh-authz **fails closed** (rejects with 403) if any namespace- or selector-scoped policy is configured; a mesh with only mesh-wide policies stays fully evaluable and falls through to mesh-wide-only.

`identities` is sorted by `pod_uid` so polling produces stable output. Entries with zero cookies are kept — enrolled-but-idle pods are operationally interesting (the cookie count answers "is this pod taking traffic?").

The endpoint is cold-path: it iterates the unified cookie-record map and identity map, then reads the policy-scope snapshot. Don't poll faster than a few times per second on a busy node.

## Service-Waypoint Services (mesh `ServiceWaypoint` topology)

The service-waypoint topology accepts HBONE traffic for services bound to one GAMMA waypoint. `GET /service-waypoint/services` exposes the currently installed slice projection so operators can answer "which services is this waypoint actually serving?" without inspecting raw Gateway API resources.

The endpoint returns `404 Not Found` when service-waypoint topology is not active, when no mesh slice has been installed yet, or when the installed slice has no `waypoint_name`. This avoids surfacing an empty stub list on unrelated sidecar/ambient/node-waypoint/east-west/egress DPs.

### `GET /service-waypoint/services`

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:9000/service-waypoint/services
```

Response:

```json
{
  "waypoint_name": "api-waypoint",
  "namespace": "default",
  "service_count": 2,
  "services": [
    {
      "namespace": "default",
      "name": "reviews",
      "ports": [8080],
      "workload_count": 3
    },
    {
      "namespace": "default",
      "name": "ratings",
      "ports": [8081],
      "workload_count": 1
    }
  ]
}
```

Field semantics:

- `waypoint_name` — the `FERRUM_MESH_WAYPOINT_NAME` / native `MeshSubscribe` binding name used to build this slice.
- `namespace` — the namespace of the installed mesh slice.
- `service_count` — number of services admitted into the slice for this waypoint.
- `services[].ports` — service ports from the admitted `MeshService`; port protocol metadata is intentionally omitted from this compact operability view.
- `services[].workload_count` — number of workload SPIFFE references behind that service in the installed slice.

`services` are returned in slice order. The payload exposes service names, namespaces, ports, and workload counts, but no request bodies, credentials, or backend TLS material.

## Mesh Service Graph (mesh mode)

`GET /mesh/service-graph` returns the live HTTP-family mesh service graph aggregated from the auto-injected `workload_metrics` plugin. It is JWT-authenticated and contains only identity, workload, protocol, and RED-counter metadata; request bodies, headers, and credentials are never stored.

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:9000/mesh/service-graph
```

Response:

```json
{
  "generated_at": "2026-05-17T16:30:00Z",
  "generated_at_unix_ms": 1779035400000,
  "edge_count": 1,
  "edges": [
    {
      "source_principal": "spiffe://cluster.local/ns/default/sa/frontend",
      "source_workload": "frontend",
      "source_namespace": "default",
      "source_app": "frontend",
      "source_service": "frontend",
      "destination_principal": "spiffe://cluster.local/ns/default/sa/reviews",
      "destination_workload": "reviews",
      "destination_namespace": "default",
      "destination_app": "reviews",
      "destination_service": "reviews",
      "request_protocol": "http",
      "connection_security_policy": "mutual_tls",
      "requests_total": 1250,
      "errors_total": 3,
      "duration_ms_total": 8420.5,
      "duration_ms_avg": 6.7364,
      "last_seen": "2026-05-17T16:29:58Z",
      "last_seen_unix_ms": 1779035398000
    }
  ]
}
```

The graph is node-local. In CP/DP or multi-replica mesh deployments, query each data plane and aggregate externally. The admin read path serves an `ArcSwap` snapshot, so frequent polling does not iterate live request counters.

## Mesh Egress Scope (mesh mode)

Two JWT-authenticated endpoints expose the live Sidecar egress scope for operability and pre-enforcement validation. They are mesh-only: requests return `404 Not Found` when no mesh slice has been installed (for example, during DP startup before the first CP push or when running on a non-mesh mode).

### `GET /mesh/egress-scope`

Returns the current workload's resolved egress scope: namespace, admitted services, admitted service-entries, admitted destination-rules, the deduplicated `known_destinations` host list used by the outbound registry, dry-run status, and admit/deny service and DestinationRule counts.

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:9000/mesh/egress-scope
```

Response (truncated):

```json
{
  "namespace": "alpha",
  "scope": {
    "sidecar_enforced": false,
    "dry_run": true,
    "sidecar_applied": false,
    "sidecar_admitted_services": 1,
    "sidecar_denied_services": 1,
    "sidecar_admitted_destination_rules": 1,
    "sidecar_denied_destination_rules": 0,
    "services": [
      {
        "namespace": "alpha",
        "name": "reviews",
        "hosts": ["reviews.alpha.svc.cluster.local"],
        "ports": [8080]
      }
    ],
    "destination_rules": [
      {"namespace": "alpha", "name": "reviews", "hosts": ["reviews.alpha.svc.cluster.local"], "ports": []}
    ],
    "known_destinations": ["reviews.alpha.svc.cluster.local:8080"]
  },
  "health": {
    "sidecar_admitted_services": 1,
    "sidecar_denied_services": 1
  }
}
```

**Disclosure surface**: the payload reveals the mesh topology shape the current workload can reach — service names, namespaces, hosts, ports, FQDN aliases. This is not secret traffic data (no bodies, headers, or credentials), but operators wiring this into long-running scrapers should still scope JWT issuance accordingly.

Returns `503 Service Unavailable` when proxy state is not yet available, `404 Not Found` when no active mesh egress scope has been installed.

### `POST /mesh/egress-scope/test`

Dry-runs a candidate destination against the current scope. Accepts a JSON object with `host` (required) and `port` (optional). Returns whether the destination is admitted by the resolved scope. Never mutates slice state.

Because this is a non-mutating diagnostic, it remains available in read-only
mesh and DP admin states with the standard admin JWT authentication.

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"host":"reviews.alpha.svc.cluster.local","port":8080}' \
  http://localhost:9000/mesh/egress-scope/test
```

Response:

```json
{
  "allowed": true,
  "decision": "admit",
  "host": "reviews.alpha.svc.cluster.local",
  "port": 8080,
  "dry_run": true
}
```

The handler memoises the resolved `OutboundRegistry` against the installed snapshot, so repeated calls do not re-parse `known_destinations` on every request.

Returns `503` when proxy state is unavailable, `404` when no active mesh egress scope, `400` when the body is not valid JSON / `host` is missing or empty / `port` is `0`.

### Related environment variables

- `FERRUM_MESH_SIDECAR_ENFORCED` — gates the slice-narrowing pass (default `false`).
- `FERRUM_MESH_SIDECAR_ENFORCED_DRY_RUN` — computes the scope and exposes it through these endpoints while leaving the slice unenforced.

## Mesh Remote Clusters (mesh mode)

### `GET /mesh/remote-clusters`

JWT-authenticated, mesh-only introspection of the data plane's view of multicluster east-west discovery. Operators previously inferred remote-cluster state only indirectly from `GET /mesh/config-drift` workload/service `resources` counts; this endpoint names the remote clusters directly and distinguishes "configured but never polled" from "not configured".

Two views are returned:

- `discovered` — remote clusters this DP has successfully polled over the native `MeshSubscribe` stream (cross-cluster endpoint discovery), keyed and sorted by `cluster_name`, each with per-cluster `workload_count` / `service_count`, the `fetched_at_unix_seconds` of the last successful poll, and the derived `age_seconds`. `age_seconds` measures time since the last successful **poll**, not the last endpoint **change**: a stable cluster whose endpoints have not changed still has its `fetched_at_unix_seconds` refreshed on every successful poll, so a healthy-but-static remote cluster does not look stale. This view is scoped to the **accepted** slice's configured remote clusters (matched by `cluster_name` and `trust_domain`): a cluster present in the discovery store but absent from the accepted config — e.g. left over from a slice the proxy rejected — is omitted, so an invalid slice never appears as live discovery. Empty when discovery is disabled (`FERRUM_MESH_REMOTE_DISCOVERY_POLL_INTERVAL_SECONDS` is `0`), no slice has been accepted, no remote cluster is trust-eligible, or no poll has succeeded yet.
- `configured` — remote clusters declared in the **accepted** slice's multicluster config: name, trust domain, network, and whether a control plane (`control_plane_configured`) / federation endpoint (`federation_endpoint_configured`) is set. Each carries a `discovered` flag cross-referencing the scoped `discovered` view, plus `outbound_trust_active`, `inbound_trust_active`, `trust_source`, and polled-bundle freshness when available so asymmetric trust and fail-closed bootstrap are visible.

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:9000/mesh/remote-clusters
```

Response:

```json
{
  "discovery_enabled": true,
  "discovered": [
    {
      "cluster_name": "remote-east",
      "trust_domain": "east.example.com",
      "network": "net2",
      "workload_count": 12,
      "service_count": 3,
      "fetched_at_unix_seconds": 1747595531,
      "age_seconds": 8
    }
  ],
  "configured": [
    {
      "cluster_name": "remote-east",
      "trust_domain": "east.example.com",
      "network": "net2",
      "control_plane_configured": true,
      "federation_endpoint_configured": true,
      "discovered": true,
      "outbound_trust_active": true,
      "inbound_trust_active": true,
      "trust_source": "polled",
      "trust_bundle_fetched_at_unix_seconds": 1747595530,
      "trust_bundle_age_seconds": 9
    },
    {
      "cluster_name": "remote-west",
      "trust_domain": "west.example.com",
      "control_plane_configured": false,
      "federation_endpoint_configured": true,
      "discovered": false,
      "outbound_trust_active": false,
      "inbound_trust_active": false,
      "trust_source": "blocked_pending_poll"
    }
  ]
}
```

**Disclosure surface**: the payload reveals the cross-cluster topology shape the DP participates in — remote cluster names, trust domains, networks, and per-cluster endpoint counts. It deliberately omits raw workload addresses, SPIFFE IDs, and the control-plane / federation URLs themselves (those are reported only as booleans), keeping the same sensitive detail that `/mesh/config-drift` keeps off `/metrics` behind the JWT.

Returns `404 Not Found` outside mesh mode (when the mesh runtime state is not wired into the admin API). In mesh mode with nothing configured or discovered yet, both lists are empty (a `200`, not a `404`) so dashboards can poll continuously across boot.

### Related environment variables

- `FERRUM_MESH_REMOTE_DISCOVERY_POLL_INTERVAL_SECONDS` — poll interval for cross-cluster endpoint discovery; `0` (default) disables it and forces `discovered` empty.
- `FERRUM_MESH_REMOTE_DISCOVERY_POLL_TIMEOUT_SECONDS` — per-poll request timeout (default `30`).

## Mesh Federation (mesh mode)

`GET /mesh/federation` is JWT-authenticated and mesh-only. It returns the currently cached cross-cluster SPIFFE trust bundles fetched by the federation poller — the poller hits each `MultiClusterConfig.remote_clusters[].federation_endpoint` at `FERRUM_MESH_FEDERATION_POLL_INTERVAL_SECONDS` and overlays the validated bundle on `TrustBundleSet.federated`. Each entry reports the originating cluster name, trust domain, endpoint URL, fetch timestamp, derived bundle age, and X.509/JWT authority counts. Returns `404` outside mesh mode or before any federation bundle has been cached. Raw workload addresses and bundle contents are never exposed.

## Mesh Runtime Overlay (mesh mode)

`GET /mesh/runtime-overlay` is JWT-authenticated and mesh-only. It returns the merged xDS RTDS runtime overlay built from every `envoy.service.runtime.v3.Runtime` layer the mesh xDS client has received: each layer's top-level fields are flattened into a single keyed map, with later layers overriding earlier ones on key conflicts. Values are typed (`number` → `f64`, `string` → UTF-8 string, etc.). Returns `404` only outside mesh mode or before the first proxy-accepted slice; an active mesh that has received no RTDS layers returns `200` with an empty overlay (matching `/mesh/egress-scope`), so dashboards/health checks can poll continuously.

## Mesh Policy Denies (mesh mode)

`GET /mesh/policy-denies/recent` is JWT-authenticated and mesh-only. It returns the top-N most recent `mesh_authz` deny events grouped by the `(rule, source, destination, reason)` tuple, for ad-hoc triage. The recorder is a process-singleton bounded FIFO ring (`FERRUM_MESH_POLICY_DENY_LOG_CAPACITY`, default `10000`) written only on the `mesh_authz` deny branch — allowed requests never touch it, and a denied request takes the recorder mutex once to push the event (so under a deny storm the cost is on the deny path, not on normal traffic). The endpoint reads a one-shot snapshot, filters to a recent `window`, groups by the 4-tuple, sorts by count descending, and truncates to `limit`. Identity / route / policy metadata only; no request bodies, headers, or credentials. Set `FERRUM_MESH_POLICY_DENY_LOG_CAPACITY=0` to disable the recorder (the endpoint still serves an empty `grouped` array).
