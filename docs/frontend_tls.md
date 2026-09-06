# Frontend TLS Configuration

This guide explains how to configure TLS (HTTPS) and mutual TLS (mTLS) for client connections to the Ferrum Edge.

## Overview

Ferrum Edge supports three modes of operation for client connections:

1. **HTTP** - Plain text connections (default)
2. **HTTPS** - Encrypted connections with server authentication
3. **mTLS** - Encrypted connections with mutual (server + client) authentication

## Environment Variables

### Server TLS (HTTPS)

Required for HTTPS mode:

```bash
# Server certificate (PEM format)
export FERRUM_FRONTEND_TLS_CERT_PATH="/path/to/server.crt"

# Server private key (PEM format)  
export FERRUM_FRONTEND_TLS_KEY_PATH="/path/to/server.key"

# Optional source overrides. These accept a path, file:// URI, or inline PEM.
export FERRUM_FRONTEND_TLS_CERT_SOURCE="file:///path/to/server.crt"
export FERRUM_FRONTEND_TLS_KEY_SOURCE="file:///path/to/server.key"
```

### Client Certificate Verification (mTLS)

Optional for mTLS mode:

```bash
# Client CA bundle for verifying client certificates
export FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH="/path/to/client-ca-bundle.pem"

# Optional source override for the client CA bundle
export FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_SOURCE="file:///path/to/client-ca-bundle.pem"
```

`*_SOURCE` values override their matching `*_PATH` values when both are set. They can be ordinary filesystem paths, `file://` URIs, inline PEM beginning with `-----BEGIN `, provider URIs, Kubernetes Secret URIs such as `k8s://edge/frontend#tls.crt`, ACME-issued records such as `acme://certificates/edge-cert#cert`, or admin-managed URIs such as `managed://certificates/edge-cert#cert` and `managed://ocsp-responses/edge-ocsp#ocsp`. Managed TLS record IDs are globally unique across certificates, CA bundles, CRLs, OCSP responses, and JWKS (not namespaced by collection); typed admin overwrite paths reject cross-kind ID collisions with `409 Conflict`. Frontend/admin server key sources can also use non-extractable RSA PKCS#11 keys when the binary is built with the `pkcs11` Cargo feature. Inline PEM is redacted in debug output. File/external-source-backed frontend/admin cert, key, client-CA, OCSP response, and CRL sources can be live-reloaded when `FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED=true`; inline PEM remains static until config reload.

PKCS#11 key sources use the token for TLS signing without exporting the private key:

```bash
export FERRUM_PKCS11_MODULE_PATH="/usr/lib/softhsm/libsofthsm2.so"
export FERRUM_PKCS11_PIN="token-user-pin"
export FERRUM_FRONTEND_TLS_CERT_SOURCE="file:///etc/ferrum/certs/frontend.crt"
export FERRUM_FRONTEND_TLS_KEY_SOURCE="pkcs11://edge-rsa?pin_env=FERRUM_PKCS11_PIN"
```

Use `?module=/path/to/pkcs11.so` or `?module_env=FERRUM_PKCS11_MODULE_PATH` to override the default module path per source, `?slot=` to pin a slot id, `?label=` to override the URI path selector, and `?id_hex=` to refine selection by key id. PKCS#11 support is currently RSA-only and available for frontend/Admin API server TLS keys plus backend mTLS client keys. See [pkcs11_tls.md](pkcs11_tls.md) for HSM deployment notes and the token-backed smoke test.

### Handshake Timeout

```bash
# Seconds allowed for a client to complete frontend TLS or DTLS negotiation.
# Default: 10. Set to 0 only when an upstream load balancer enforces an
# equivalent pre-handshake deadline.
export FERRUM_FRONTEND_TLS_HANDSHAKE_TIMEOUT_SECONDS=10
```

This timeout applies before HTTP header parsing begins, so it protects HTTPS,
WSS, gRPC-over-TLS, TCP+TLS stream listeners, and UDP+DTLS listeners from slow
or stalled handshakes. After TLS completes, HTTP requests are governed by
`FERRUM_HTTP_HEADER_READ_TIMEOUT_SECONDS`.

### Frontend Before Backend

For TLS/DTLS-terminating client-facing protocols, Ferrum completes frontend
crypto and admission before backend dispatch:

- HTTPS, HTTP/2-over-TLS, WSS, and gRPC-over-TLS complete the frontend TLS
  handshake before HTTP request routing or backend connection selection.
- Normal HTTP/3 completes the QUIC/TLS handshake before request routing.
- TCP+TLS stream proxies complete the frontend TLS handshake, then run
  `on_stream_connect`, before opening the backend TCP or TLS connection.
- UDP+DTLS stream proxies complete the frontend DTLS handshake, then run
  `on_stream_connect`, before creating the backend UDP or DTLS session.

Frontend handshake failures and stream plugin rejections are frontend setup
failures. They close the client side without dialing the backend or recording a
backend circuit-breaker failure.

The deliberate exception is operator-enabled HTTP/3 0-RTT early data
(`FERRUM_TLS_EARLY_DATA_METHODS`), which is disabled by default. When enabled
for HTTP/3 without frontend mTLS, Ferrum sets the QUIC TLS early-data size to
`u32::MAX` (quinn/rustls require `0` or `2^32-1`; a finite TLS byte cap is not
available on QUIC), permits only configured replay-safe methods, and forwards
`Early-Data: 1` so backends can apply their own replay policy. HTTPS/H1/H2
currently keep rustls 0-RTT disabled until per-request early-data state is
available, so the method allowlist does not enable a TCP TLS early-data byte cap
either.

0-RTT and frontend mTLS are mutually exclusive on the HTTP/3 listener. When
`FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH` is set, the H3 listener sets QUIC
rustls `max_early_data_size` to `0` and never takes quinn's 0.5-RTT accept path.
Accepting the connection before the peer's `Certificate` flight would leave
`peer_identity()` unknowable for the connection's lifetime, while accepting
client early data only after the full handshake would lose the replay-state
signal needed by the method gate. `FERRUM_TLS_EARLY_DATA_METHODS` is therefore
inert for HTTP/3 on such a listener (a startup warning says so); ordinary 1-RTT
H3 mTLS keeps working and `mtls_auth` / `spiffe_identity` receive the presented
client certificate.

## Configuration Scenarios

### 1. HTTP Only (Default)

No TLS configuration needed:

```bash
# Gateway starts with:
# - HTTP listener on port 8000 (configurable via FERRUM_PROXY_HTTP_PORT)
# - No HTTPS listener
./ferrum-edge run
```

### 2. HTTPS + HTTP (Dual Listeners)

Enable server TLS:

```bash
export FERRUM_FRONTEND_TLS_CERT_PATH="/etc/ssl/certs/gateway.crt"
export FERRUM_FRONTEND_TLS_KEY_PATH="/etc/ssl/private/gateway.key"

./ferrum-edge run
```

**What happens:**
- **HTTP listener** on port 8000 (configurable)
- **HTTPS listener** on port 8443 (configurable via FERRUM_PROXY_HTTPS_PORT)
- Gateway presents server certificate to HTTPS clients
- Clients verify server certificate using system trust store
- All HTTPS traffic is encrypted
- No client certificate required

### 3. mTLS + HTTP (Dual Listeners with Mutual Auth)

Enable server TLS + client verification:

```bash
export FERRUM_FRONTEND_TLS_CERT_PATH="/etc/ssl/certs/gateway.crt"
export FERRUM_FRONTEND_TLS_KEY_PATH="/etc/ssl/private/gateway.key"
export FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH="/etc/ssl/certs/client-ca-bundle.pem"

./ferrum-edge run
```

**What happens:**
- **HTTP listener** on port 8000 (configurable)
- **HTTPS/mTLS listener** on port 8443 (configurable)
- Gateway presents server certificate to HTTPS clients
- Gateway requires and verifies client certificates on HTTPS port
- Only clients with certificates from trusted CAs can connect to HTTPS port
- HTTP port remains unencrypted (can be blocked by firewall if needed)

## Architecture Benefits

### Separate Listeners vs Single Port

**Before (Single Port Approach):**
- Single listener trying to handle both HTTP and HTTPS
- TLS handshake failures for HTTP clients
- Port confusion and protocol mismatches
- Complex protocol detection logic

**After (Separate Listeners):**
- **Clear protocol separation** - HTTP on dedicated port, HTTPS on dedicated port
- **No handshake conflicts** - Each listener handles its protocol exclusively
- **Standard port conventions** - HTTP: 8000, HTTPS: 8443 (both configurable)
- **Better security posture** - Can block HTTP port in production
- **Easier load balancing** - Separate endpoints for different protocols
- **Simplified client configuration** - Clear URLs for each protocol

### Listener Management

```bash
# Startup logs show clear listener status:
Starting HTTP proxy listener on 0.0.0.0:8000
Starting HTTPS proxy listener on 0.0.0.0:8443
# OR
TLS not configured - HTTPS listener disabled
```

### Deployment Flexibility

**Development:**
```bash
# HTTP only for easy development
./ferrum-edge run
# Access: http://localhost:8000
```

**Staging:**
```bash
# Both HTTP and HTTPS for testing
export FERRUM_FRONTEND_TLS_CERT_PATH="./staging.crt"
export FERRUM_FRONTEND_TLS_KEY_PATH="./staging.key"
./ferrum-edge run
# Access: http://localhost:8000 AND https://localhost:8443
```

**Production (TLS-only, no plaintext):**
```bash
# Disable all plaintext listeners at the gateway level
export FERRUM_PROXY_HTTP_PORT=0      # Disable plaintext proxy
export FERRUM_ADMIN_HTTP_PORT=0      # Disable plaintext admin API

# TLS for proxy traffic
export FERRUM_FRONTEND_TLS_CERT_PATH="/prod/certs/gateway.crt"
export FERRUM_FRONTEND_TLS_KEY_PATH="/prod/certs/gateway.key"
export FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH="/prod/certs/client-ca.pem"

# TLS for admin API
export FERRUM_ADMIN_TLS_CERT_PATH="/prod/certs/admin.crt"
export FERRUM_ADMIN_TLS_KEY_PATH="/prod/certs/admin.key"

./ferrum-edge run
# Proxy: https://localhost:8443 only (mTLS required)
# Admin: https://localhost:9443 only
# No plaintext listeners bound — nothing to firewall
```

> **Tip**: Setting port to `0` prevents the listener from binding at all, which is more secure than relying on a firewall to block the port. The gateway logs `FERRUM_PROXY_HTTP_PORT=0 — plaintext HTTP proxy listener disabled` and `FERRUM_ADMIN_HTTP_PORT=0 — plaintext admin HTTP listener disabled` at startup to confirm.
> The same disable behavior applies to `FERRUM_PROXY_HTTPS_PORT=0` and `FERRUM_ADMIN_HTTPS_PORT=0` in every serving mode (database, file, CP, DP, and mesh) when TLS material is configured. See the `FERRUM_ADMIN_HTTPS_PORT` row in [configuration.md](configuration.md) for the full port-0 contract, including the config-level scope and the file-mode `ServeOptions` pre-bound exception.

## Use Cases

### HTTP Mode
- **Development environments** where encryption isn't needed
- **Internal networks** with trusted network segments
- **Testing and debugging** scenarios

### HTTPS Mode
- **Public-facing APIs** requiring encryption
- **Production environments** with security requirements
- **Compliance** with data protection regulations

### mTLS Mode
- **Enterprise APIs** with strict security requirements
- **Microservices** communication within trusted networks
- **Zero-trust architectures** where all connections must be authenticated
- **Financial services** and healthcare applications

## Certificate Requirements

### Server Certificate
- Must be in PEM format
- Should include the full certificate chain
- For frontend DTLS, certificates must be leaf-first. Ferrum transmits every
  configured certificate in order in DTLS 1.2 and 1.3 and validates the first
  certificate against the configured ECDSA P-256/P-384 private key.
- Common name (CN) or Subject Alternative Name (SAN) should match the gateway hostname
- Private key must be unencrypted (or gateway must have access to decryption key)

### Client CA Bundle
- Must be in PEM format
- Can contain one or multiple CA certificates
- All certificates in the bundle are trusted for client verification
- Bundle admission is atomic: every declared `CERTIFICATE` record must parse
  and be accepted as a trust root, or startup/reload rejects the complete
  candidate and keeps the last-known-good TLS configuration
- Clients must present certificates signed by one of these CAs

### Frontend DTLS Client-Certificate Refusal

When `FERRUM_DTLS_CLIENT_CA_CERT_PATH` / `_SOURCE` is configured, a UDP+DTLS
listener refuses two cases: a client chain the verifier cannot validate, and a
client that completes the handshake without presenting a verified certificate at
all (DTLS permits an empty `Certificate` message in response to a
`CertificateRequest`, so this is a distinct case, not the same one).

Both refusals happen **before the server's final flight is committed to the
wire**. Ferrum discards every record the DTLS engine has queued for that session
and only then emits the refusal alert, so under DTLS 1.2 the client never
receives the server `ChangeCipherSpec`+`Finished` and its handshake does not
complete — `openssl s_client -dtls1_2` reports a failed connection rather than an
established session that is dropped a moment later. Under DTLS 1.3 the server's
`Finished` belongs to a flight that necessarily precedes the client's
certificate, so that handshake cannot be made incomplete by the server; there the
alert is what tears the peer down. In both versions the refused session is never
delivered to the proxy, no application data is relayed, and no backend session is
created.

On a Ferrum-generated `MeshNodeWaypoint` DTLS listener the refusal alert leaves
from the same pinned reply source as the rest of the handshake, so a client that
addressed a Service ClusterIP sees it instead of discarding a record sourced from
a node address.

## Admin API TLS Configuration

The Admin API also supports separate HTTP and HTTPS listeners with the same architecture as the proxy listeners.

### Admin API Environment Variables

```bash
# Admin server certificates (for HTTPS)
export FERRUM_ADMIN_TLS_CERT_PATH="/etc/ssl/certs/admin.crt"
export FERRUM_ADMIN_TLS_KEY_PATH="/etc/ssl/private/admin.key"
export FERRUM_ADMIN_TLS_CERT_SOURCE="file:///etc/ssl/certs/admin.crt"
export FERRUM_ADMIN_TLS_KEY_SOURCE="file:///etc/ssl/private/admin.key"

# Admin client CA bundle (for mTLS)
export FERRUM_ADMIN_TLS_CLIENT_CA_BUNDLE_PATH="/etc/ssl/certs/admin-client-ca.pem"
export FERRUM_ADMIN_TLS_CLIENT_CA_BUNDLE_SOURCE="file:///etc/ssl/certs/admin-client-ca.pem"

# Admin ports (configurable)
export FERRUM_ADMIN_HTTP_PORT="9000"
export FERRUM_ADMIN_HTTPS_PORT="9443"

# Admin TLS no-verify (testing only)
export FERRUM_ADMIN_TLS_NO_VERIFY="true"

# Backend TLS no-verify (testing only)
export FERRUM_TLS_NO_VERIFY="true"

# JWT authentication (required)
export FERRUM_ADMIN_JWT_SECRET="change-me-to-a-32-character-admin-secret"
```

### Admin API Configuration Scenarios

#### **1. Admin HTTP Only (Default)**
```bash
./ferrum-edge run
# Admin HTTP: http://localhost:9000
# No Admin HTTPS
```

#### **2. Admin HTTP + HTTPS**
```bash
export FERRUM_ADMIN_TLS_CERT_PATH="/etc/ssl/certs/admin.crt"
export FERRUM_ADMIN_TLS_KEY_PATH="/etc/ssl/private/admin.key"
./ferrum-edge run
# Admin HTTP: http://localhost:9000
# Admin HTTPS: https://localhost:9443
```

#### **3. Admin HTTP + mTLS**
```bash
export FERRUM_ADMIN_TLS_CERT_PATH="/etc/ssl/certs/admin.crt"
export FERRUM_ADMIN_TLS_KEY_PATH="/etc/ssl/private/admin.key"
export FERRUM_ADMIN_TLS_CLIENT_CA_BUNDLE_PATH="/etc/ssl/certs/admin-client-ca.pem"
./ferrum-edge run
# Admin HTTP: http://localhost:9000
# Admin HTTPS/mTLS: https://localhost:9443 (client certs required)
```

#### **4. Admin HTTPS Only (No Plaintext)**
```bash
export FERRUM_ADMIN_HTTP_PORT=0  # Disable plaintext admin
export FERRUM_ADMIN_TLS_CERT_PATH="/etc/ssl/certs/admin.crt"
export FERRUM_ADMIN_TLS_KEY_PATH="/etc/ssl/private/admin.key"
./ferrum-edge run
# Admin HTTPS only: https://localhost:9443
# No HTTP listener — plaintext admin requests are impossible
```

#### **5. Admin HTTPS with No-Verify (Testing)**
```bash
export FERRUM_ADMIN_TLS_CERT_PATH="/etc/ssl/certs/admin.crt"
export FERRUM_ADMIN_TLS_KEY_PATH="/etc/ssl/private/admin.key"
export FERRUM_ADMIN_TLS_NO_VERIFY="true"
./ferrum-edge run
# Admin HTTP: http://localhost:9000
# Admin HTTPS: https://localhost:9443 (no cert verification)
```

### Admin API Security Notes

- **mTLS Support**: Admin API now supports client certificate verification
- **Custom CA Bundle**: Can use internal/private CAs for admin client verification
- **No-Verify Mode**: Available for testing (NEVER use in production)
- **JWT Required**: All admin endpoints require JWT authentication
- **Same Security**: HTTP and HTTPS endpoints have identical security requirements
- **Operating Modes**: Admin API available in Database and Control Plane modes only

### No-Verify Mode (Testing Only)

#### **Purpose**
The no-verify mode is designed for development, testing, and isolated environments where certificate verification is not practical. Outside production it remains an explicit opt-in that logs a loud warning. Under `FERRUM_MESH_PRODUCTION_MODE=true`, both `FERRUM_TLS_NO_VERIFY` and `FERRUM_ADMIN_TLS_NO_VERIFY` are **refused** by the shared `EnvConfig` validation path used by `ferrum-edge validate` and runtime startup (every mesh topology). FIPS enforce independently refuses them as well.

#### **Risks**
- **Security Risk**: Disables ALL certificate verification
- **Man-in-the-Middle**: Vulnerable to certificate spoofing attacks
- **Production Warning**: NEVER use in production environments — mesh production mode and FIPS enforce fail closed rather than warning

#### **Use Cases**
```bash
# Development with self-signed certificates
export FERRUM_ADMIN_TLS_NO_VERIFY="true"
export FERRUM_TLS_NO_VERIFY="true"

# Internal testing with custom CAs
export FERRUM_ADMIN_TLS_NO_VERIFY="true"

# Staging with temporary certificates
export FERRUM_ADMIN_TLS_NO_VERIFY="true"
```

#### **Warnings**
Gateway will log warnings when no-verify is enabled:
```
WARNING: Admin TLS configuration loaded with certificate verification DISABLED (testing mode)
WARNING: Backend TLS certificate verification DISABLED (testing mode)
```

## Example Certificate Setup

### Generate Self-Signed Certificates (Testing)

```bash
# Generate CA private key
openssl genrsa -out ca.key 4096

# Generate CA certificate
openssl req -new -x509 -days 365 -key ca.key -out ca.crt -subj "/CN=Test CA"

# Generate server private key
openssl genrsa -out server.key 2048

# Generate server CSR
openssl req -new -key server.key -out server.csr -subj "/CN=localhost"

# Sign server certificate with CA
openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt

# Generate client private key
openssl genrsa -out client.key 2048

# Generate client CSR
openssl req -new -key client.key -out client.csr -subj "/CN=Test Client"

# Sign client certificate with CA
openssl x509 -req -days 365 -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt

# Create client CA bundle (same as CA cert for self-signed)
cp ca.crt client-ca-bundle.pem
```

### Configure Gateway

```bash
export FERRUM_FRONTEND_TLS_CERT_PATH="./server.crt"
export FERRUM_FRONTEND_TLS_KEY_PATH="./server.key"
export FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH="./client-ca-bundle.pem"

./ferrum-edge run
```

### Test with Client Certificate

```bash
# Test with client certificate
curl --cert client.crt --key client.key https://localhost:8443/api/v1

# Test without client certificate (should fail)
curl https://localhost:8443/api/v1
```

## CRL Policy

`FERRUM_TLS_CRL_FILE_PATH` / `_SOURCE` supplies one PEM file that may hold many
`-----BEGIN X509 CRL-----` blocks. One policy governs every verifier that
consumes them — frontend and admin mTLS (HTTP/1.1, HTTP/2, HTTP/3, and TCP+TLS),
frontend DTLS, the mesh operator-CA and SPIFFE peer verifiers, rustls backend
server verification on the proxy data path, active HTTPS and gRPC health-check
probes, and the rustls LDAP / TCP / UDP / WebSocket logging sinks. Across those
surfaces there is no per-surface CRL setting and no way for one of them to run a
weaker posture than another. The surfaces the CRL source does not reach at all
are listed at the end of this section.

### What the verifier enforces

- **Full-chain revocation.** Every certificate in the chain rustls builds is
  checked, excluding the trust anchor itself. Revoking an issuing intermediate
  in a CRL signed by its own issuer stops the certificates that intermediate
  signed; it is not necessary to remove the intermediate's root from the trust
  bundle to make the revocation take effect.
- **Unknown revocation status is accepted.** A chain that no configured CRL is
  authoritative for still verifies. This is deliberate: a configured CRL list is
  the operator's list of issuers to police, not a completeness claim about every
  trusted anchor, and refusing uncovered chains would break every public-CA path
  the moment one private CRL is configured. If you need a chain policed, supply
  a CRL from its issuer.
- **CRL validity windows are enforced at handshake time.** A CRL whose
  `nextUpdate` has passed is an error, not a fallback to "no revocation data".
  A CRL that expires while the gateway is running therefore stops authorizing
  **new** handshakes on every surface it is installed on, without a reload and
  without a restart. Keep the CRL refreshed ahead of its own `nextUpdate`.
- **CRL refresh is a restart-blocking dependency.** The same refusal applies at
  **startup**, not only at reload: `FERRUM_TLS_CRL_FILE_PATH` /
  `FERRUM_TLS_CRL_SOURCE` is loaded during startup in every serving mode
  (database, file, cp, dp, mesh, node_agent) and an expired record fails that
  load, so the process exits instead of booting. A pod that restarts after
  `nextUpdate` — rolling deploy, node drain, OOM kill — does not come back, and
  a forgotten CRL refresh job is therefore a fleet-wide outage rather than a
  single-pod incident. This is deliberate (see
  [PRODUCTION_READINESS.md](../PRODUCTION_READINESS.md) → "Deliberate
  decisions"): booting with an expired CRL would serve without revocation
  enforcement for that issuer, which is fail-open. Two things are required of
  an operator: refresh the CRL before `nextUpdate`, and/or set
  `FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED=true` (and
  `FERRUM_BACKEND_TLS_LIVE_RELOAD_ENABLED=true` for backend surfaces) so a
  refreshed copy is adopted without a restart. Live reload is **off by
  default**, so without it the only way to pick up a new CRL is a restart —
  which the expired one blocks.
- **A lead-time warning is the advance signal.** Every accepted CRL source
  whose soonest `nextUpdate` falls within `FERRUM_TLS_CRL_EXPIRY_WARNING_DAYS`
  (default `30`, `0` disables) logs a `warn!` naming the redacted source id and
  the remaining days. The same knob covers stapled OCSP responses — one refresh
  loop, one deadline. The recurring signal is the Prometheus gauge
  `ferrum_tls_revocation_expiry_seconds{material_id,kind,source_kind}`, which
  the bundled chart alerts on as `FerrumGatewayRevocationMaterialExpiringSoon`
  (`metrics.alerts.revocationExpiringSeconds`, default 7 days).

### What admission enforces

Every path that loads CRLs — startup, `ferrum-edge validate`, config load, each
live reload, `POST /admin/tls/validate`, and managed CRL create/update — applies
the same temporal check before any candidate is published:

| Candidate | Result |
|-----------|--------|
| `thisUpdate` in the future | refused, "is not yet valid" |
| `thisUpdate` exactly now | admitted |
| `nextUpdate` absent | refused, "omits the required nextUpdate field" |
| `nextUpdate` in the future | admitted |
| `nextUpdate` exactly now, or in the past | refused, "has expired" |
| Not a parseable X.509 CRL | refused |

The boundaries are chosen to match rustls exactly (`now >= nextUpdate` is
expired), so a CRL that admission accepts is always one the handshake path can
still use. A missing `nextUpdate` is refused rather than treated as "never
expires": RFC 5280 §5.1.2.5 requires conforming issuers to emit it, and a record
that declares no expiry cannot have one enforced.

Admission is **atomic** over the whole source. If any record in a multi-CRL file
is malformed or outside its validity window, the entire candidate is refused;
Ferrum never publishes the usable subset, because doing so would silently drop
revocations the operator declared. At startup that is a hard failure. On a live
reload the refusal keeps the complete previous generation — verifier, generation
counter, semantic material, and every established session — in service, and is
counted as a rejected candidate so the refusal is observable rather than silent.

Refusal diagnostics carry the record index and the already-redacted source
display id only. CRL contents, issuer names, revoked serials, validity
timestamps, and secret source URIs are never logged.

### Surfaces CRLs do not reach

CRLs are not applied to the DP gRPC client’s verification of CP server
certificates or to reqwest-based plugin egress; those stacks do not expose a
compatible CRL configuration. The CP gRPC server does enforce the configured
CRL when verifying DP client certificates, including on live reload.
`kafka_logging` uses librdkafka/OpenSSL and maps the CRL source to `ssl.crl.location` instead.
Skip-verify health probes (`backend_tls_verify_server_cert: false` or
`FERRUM_TLS_NO_VERIFY`) skip CRL enforcement, matching the data-path skip-verify
contract. TCP and UDP probes perform no TLS handshake and are unaffected.

Verified **HTTPS and gRPC health-check probes** share this policy. They snapshot
the same admitted `SharedCrlList` generation backend data-path pools use when
each probe task is spawned. Backend TLS live reload stores a new generation
first, then restarts probes so replacement tasks load that exact snapshot. A
refused candidate keeps the previous generation, verifiers, and probe tasks in
service. See [backend_mtls.md](backend_mtls.md) for the backend-side reload
contract.

## Certificate Reload Behavior

Frontend proxy, Admin API, and frontend DTLS cert/key/client-CA/OCSP/CRL sources can opt in to live reload with `FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED=true`. Sources supplied as paths or `file://` URIs are polled by material byte fingerprint using `FERRUM_FRONTEND_TLS_WATCH_INTERVAL_SECONDS`. Provider URI sources (`vault://`, `aws://`, `azure://`, `gcp://`) are fetched through the matching secret-provider backend and polled with `FERRUM_SECRET_REFRESH_INTERVAL_SECONDS` unless the URI includes `?poll=` (for example, `vault://secret/data/edge#cert?poll=60s`). Kubernetes Secret URI sources (`k8s://namespace/secret#key`) also register a Kubernetes watch on the named Secret and queue an immediate reload when cert-manager or another controller updates it; polling remains the fallback and debounce. A `pkcs11://` frontend/admin key source is tracked by stable selector fingerprint so adjacent cert, client-CA, OCSP, and CRL rotations still reload; changing the HSM key behind the same URI requires a config/source change or restart. Each rebuild re-proves that the token key pairs with the rotated leaf certificate, so a rotation onto a mismatched pair fails the rebuild and the previous known-good `ServerConfig` stays published. Inline PEM remains static until config reload. Provider URI sources require the matching secret-provider Cargo feature and use the same credentials/configuration as the existing `_VAULT`, `_AWS`, `_AZURE`, and `_GCP` env-var suffixes.

Runtime source reads and provider resolutions for every TLS watcher share one
process-wide blocking executor. `FERRUM_TLS_SOURCE_MAX_BLOCKING_CONCURRENCY`
bounds admitted filesystem/provider work, and
`FERRUM_TLS_SOURCE_LOAD_TIMEOUT_SECONDS` bounds admission plus resolution. The
deadline cannot exceed the five-second shutdown cleanup budget. Expiry keeps
the last accepted generation; an unchanged outage increments refresh/failure
counters on every poll but records only its first fixed-class event, a changed
failure class, recovery, and a later regression. Event identities are bounded
digests and never contain source URIs, credentials, or provider payloads.

| Category | Environment Variables |
|----------|---------------------|
| **Frontend proxy live reload** | `FERRUM_FRONTEND_TLS_CERT_PATH` / `_SOURCE`, `FERRUM_FRONTEND_TLS_KEY_PATH` / `_SOURCE`, `FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH` / `_SOURCE`, `FERRUM_FRONTEND_TLS_OCSP_RESPONSE_SOURCE`, `FERRUM_TLS_CRL_FILE_PATH` / `_SOURCE` when any active source is file/provider/Kubernetes/managed-backed |
| **Admin API live reload** | `FERRUM_ADMIN_TLS_CERT_PATH` / `_SOURCE`, `FERRUM_ADMIN_TLS_KEY_PATH` / `_SOURCE`, `FERRUM_ADMIN_TLS_CLIENT_CA_BUNDLE_PATH` / `_SOURCE`, `FERRUM_ADMIN_TLS_OCSP_RESPONSE_SOURCE`, `FERRUM_TLS_CRL_FILE_PATH` / `_SOURCE` when any active source is file/provider/Kubernetes/managed-backed |
| **Frontend DTLS live reload** | `FERRUM_DTLS_CERT_PATH` / `_SOURCE`, `FERRUM_DTLS_KEY_PATH` / `_SOURCE`, `FERRUM_DTLS_CLIENT_CA_CERT_PATH` / `_SOURCE`, `FERRUM_TLS_CRL_FILE_PATH` / `_SOURCE` when any active source is file/provider/Kubernetes/managed-backed |
| **Backend TLS live reload** | `FERRUM_BACKEND_TLS_CLIENT_CERT_PATH` / `_SOURCE`, `FERRUM_BACKEND_TLS_CLIENT_KEY_PATH` / `_SOURCE`, `FERRUM_TLS_CA_BUNDLE_PATH` / `_SOURCE`, per-proxy/per-upstream backend TLS source fields, and `FERRUM_TLS_CRL_FILE_PATH` / `_SOURCE` |
| **Database TLS live reload** | `FERRUM_DB_TLS_CA_CERT_PATH` / `_SOURCE`, `FERRUM_DB_TLS_CLIENT_CERT_PATH` / `_SOURCE`, and `FERRUM_DB_TLS_CLIENT_KEY_PATH` / `_SOURCE` in database/CP modes when `FERRUM_DB_TLS_LIVE_RELOAD_ENABLED=true` |
| **CP gRPC TLS live reload** | `FERRUM_CP_GRPC_TLS_CERT_PATH` / `_SOURCE`, `FERRUM_CP_GRPC_TLS_KEY_PATH` / `_SOURCE`, and `FERRUM_CP_GRPC_TLS_CLIENT_CA_PATH` / `_SOURCE`, plus `FERRUM_TLS_CRL_FILE_PATH` / `_SOURCE` in CP mode |
| **DP gRPC TLS live reload** | `FERRUM_DP_GRPC_TLS_CA_CERT_PATH` / `_SOURCE`, `FERRUM_DP_GRPC_TLS_CLIENT_CERT_PATH` / `_SOURCE`, and `FERRUM_DP_GRPC_TLS_CLIENT_KEY_PATH` / `_SOURCE` in DP mode |
| **Loaded but static** | Inline frontend/admin/DTLS/backend/database/CP-gRPC/DP-gRPC sources |
| **Gateway SVID rotation** | `FERRUM_GATEWAY_SVID_*_PATH` / `_SOURCE`: file-backed sources are re-read once per second, provider URIs are re-fetched on `FERRUM_SECRET_REFRESH_INTERVAL_SECONDS` or the source's `?poll=`, and inline PEM stays static until config reload |

All TLS sources are validated at startup and config load time when their owning runtime is built. Certificate and CA bundles are atomic: Ferrum rejects the complete candidate if any declared `CERTIFICATE` record is malformed or any CA record cannot be admitted as a trust root; it never installs a usable subset. CRL sources are atomic on the same terms and are additionally checked against their own declared validity window — see [CRL Policy](#crl-policy). If any configured certificate, key, CA bundle, OCSP response, or CRL source is missing, unreadable, expired, not-yet-valid, mismatched, or contains invalid PEM data where PEM is expected, the gateway refuses to start or rejects the config reload. OCSP response sources must resolve to a DER response that passes the certificate-bound validation described in [Stapled OCSP Responses](#stapled-ocsp-responses). There is no silent fallback to unauthenticated or unencrypted connections. Client cert and key sources must always be configured as a pair.

Certificate/key PEM parsing is capped at 4 MiB per source and certificate
bundles at 4096 records. A configured client-CA is still fully admitted when a
testing-only no-verify mode disables use of its verifier. DTLS server identity
sources accept a complete leaf-first certificate chain. Ferrum admits every
declared record atomically, verifies the leaf against the configured private
key, and transmits the complete chain; it never publishes only a usable prefix.

The frontend/admin live-reload poller atomically swaps a validated `rustls::ServerConfig` for new handshakes. The frontend DTLS poller validates cert/key/optional client-CA/CRL inputs as one immutable generation, publishes that generation into shared reconcile state, and live-swaps it into every active DTLS server without rebinding the UDP socket. Stream-listener reconciliation resolves and fingerprints all TLS source material before it takes the listener-state lock; it compares and swaps only prepared keys/configs while locked and never awaits with that guard held. Cert/key-only rotation and additive client-trust changes leave established TLS/DTLS sessions on the config they negotiated with; an accepted client-trust narrowing retires the affected scope's client-certificate-authenticated sessions as described below. Subsequent sessions use the accepted generation. A failed or timed-out candidate keeps the complete previous generation in service on every listener and logs a warning without exposing PEM contents, secret URIs, or private material. Disabling `FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED` preserves static-until-restart behavior for all of these surfaces.

For backend HTTP-family TLS, keep `FERRUM_BACKEND_TLS_LIVE_RELOAD_ENABLED=true` to pick up in-place cert/key/CA/CRL source changes and to watch backend TLS sources added by later config reloads. Database TLS can opt in with `FERRUM_DB_TLS_LIVE_RELOAD_ENABLED=true` in database and CP modes. CP gRPC TLS swaps the server TLS slot for new handshakes when watched source bytes change. Every candidate reloads the configured CRL source; malformed, expired, or unavailable CRL material rejects the candidate and retains the last accepted slot. Existing CP gRPC streams are not retired by this reload; DP gRPC TLS reconnects the CP stream with fresh client-side TLS material.

### Stapled OCSP Responses

`FERRUM_FRONTEND_TLS_OCSP_RESPONSE_SOURCE` and
`FERRUM_ADMIN_TLS_OCSP_RESPONSE_SOURCE` supply DER bytes that Ferrum staples to
the served certificate. Those bytes are **validated against the certificate they
will be stapled to** before they are attached — for file, `file://`, inline,
provider URI, Kubernetes Secret, and `managed://` sources alike, and for both
the single-certificate frontend and the Gateway API multi-certificate frontend.
An invalid response fails the whole TLS load: the gateway refuses to start, or
the reload is rejected and the previous known-good `ServerConfig` keeps serving.
Ferrum never staples a response it could not validate and never serves a
partially applied generation.

A response is admitted only when all of the following hold.

| Check | Rejected when |
|---|---|
| Size | The DER exceeds 64 KiB. The bound is enforced before parsing. |
| Envelope | `responseStatus` is not `successful(0)`, or `responseType` is not `id-pkix-ocsp-basic`. |
| Encoding | The `BasicOCSPResponse`, `ResponseData`, `SingleResponse`, or `CertID` is malformed, carries trailing bytes, uses non-minimal DER length octets at an OCSP grammar boundary, explicitly encodes the `ResponseData.version` DEFAULT `v1` (DER omits a `DEFAULT` value) or declares any other version, contains no `SingleResponse`, or contains more than 64 `SingleResponse` entries. `ResponseData` and `SingleResponse` are consumed to their last byte: every `GeneralizedTime` (including `producedAt` and `revocationTime`) must use DER's exact `YYYYMMDDHHMMSSZ` form and decode successfully; timezone-less, explicit-offset, and fractional-second forms are refused. `nextUpdate [0]` and `singleExtensions [1]` may each appear at most once and only in that order, `responseExtensions [1]` at most once after `responses`, and any unknown, duplicate, misordered, or trailing element is refused. The `certStatus` CHOICE is checked as an encoding, not just a tag: `good [0]` and `unknown [2]` must be primitive and empty, and `revoked [1]` must be a well-formed `RevokedInfo`. Every field boundary is checked for ASN.1 class and primitive/constructed form as well as tag number, so a context-specific element reusing a universal tag number, a primitive `SEQUENCE`, or a constructed `OCTET STRING` is refused rather than decoded as the field it imitates. Primitive contents are then checked against their type-specific DER rules: OBJECT IDENTIFIER values (including ignored extension OIDs) must be a complete canonical encoding (nonempty, terminated base-128, no redundant leading `0x80` group); INTEGER and ENUMERATED values must be nonempty and minimal (one sign-protection `0x00` only when the next byte has its high bit set); a CertID serial must be nonnegative; `successful(0)` is the single content octet `0x00`; the signature BIT STRING must be octet-aligned (`unused_bits == 0`) and nonempty; and `AlgorithmIdentifier` parameters follow a field- and algorithm-specific profile. `CertID.hashAlgorithm` accepts absent or canonical NULL for digest identifiers (the two encodings RFC 4055 / RFC 5754 require receivers to handle), including unknown hash OIDs at the certificate-independent admin boundary — full certificate-bound validation still refuses an unsupported hash. `BasicOCSPResponse.signatureAlgorithm` applies the verifier-supported family instead of that digest rule: `ecdsa-with-SHA256` / `ecdsa-with-SHA384` and Ed25519 require absent parameters (RFC 5758 / RFC 8410), so a NULL that `x509_parser::verify_signature` would ignore is refused; RSA PKCS#1 (`sha*WithRSAEncryption`) requires the canonical NULL RFC 3279 and RFC 5754 specify when generating, so this strict-stapling policy rejects an omitted NULL that some receivers still accept; `rsassa-pss` requires present parameters parseable on the verification path (SHA-256/384/512, MGF1 with the same hash, saltLength equal to the hash output length, trailerField omitted, no trailing fields). This is not a complete RFC 4055 strictness claim. An unknown signature OID is refused at this grammar so it cannot be stored or served. |
| Extensions | An `Extensions` container is not a non-empty `SEQUENCE` of at most 32 well-formed `Extension`s (DER omits `critical` when `FALSE`), it repeats one extension OID (X.509 forbids a duplicate extension type, and Ferrum ignores supported non-critical extensions), or it carries a **critical** extension. Ferrum implements no OCSP response extension, so RFC 6960 §4.4 does not let it ignore a critical one; non-critical extensions are ignored after that strict parse. |
| Certificate binding | No `SingleResponse` `CertID` matches the served leaf's serial number together with the `issuerNameHash` and `issuerKeyHash` of the configured issuer, recomputed under the `CertID` hash algorithm (SHA-1, SHA-256, SHA-384, or SHA-512); a serial-matching entry uses an unsupported hash algorithm (the whole response fails closed even when another entry would match); or **more than one** entry matches, including duplicates that use different supported hash algorithms, because the status a strict client would select is then ambiguous. |
| Issuer availability | No certificate in the served chain is proven to have signed the leaf. A matching subject name is not enough: same-name candidates are scanned until one verifies the leaf's signature, and a self-issued leaf is accepted as its own issuer only when it is genuinely self-signed. |
| Carried certificates | The optional `certs` field carries more than 16 certificates or an entry that is not one complete, parseable X.509 `Certificate`. A malformed entry is refused even when it is unused — that is, even when the issuing CA signed the response directly or another carried certificate would authorize it. |
| Responder authorization | The signature does not verify against the issuing CA, and no certificate carried in the response is simultaneously named by the `ResponderID`, issued by that CA, currently valid, marked specifically with the `id-kp-OCSPSigning` extended key usage (`anyExtendedKeyUsage` does not substitute), permitted to sign by any `KeyUsage` it carries (an absent `KeyUsage` is accepted; a present one must include `digitalSignature`), and able to verify the signature. |
| Signature | `tbsResponseData` does not verify under the authorized responder's public key. |
| Validity window | `nextUpdate` is absent, `nextUpdate` is not after `thisUpdate`, `thisUpdate` is in the future, or `nextUpdate` is in the past. |
| Status | `certStatus` is `revoked` or `unknown`. |

**Clock-skew policy.** The two time bounds are widened by a fixed **5 minutes**
in the permissive direction, so the accepted window is
`thisUpdate - 5m <= now <= nextUpdate + 5m`. The allowance is not configurable:
it exists to absorb ordinary NTP drift between the responder and the gateway,
not to extend the life of a stale staple.

**`nextUpdate` is required.** RFC 6960 §2.4 makes an absent `nextUpdate` mean
"newer information is available at all times", which a cached, re-served staple
cannot satisfy, so such a response has no usable validity window and is refused.

**Revoked and unknown fail closed.** Ferrum refuses to serve them rather than
stapling them. A client that honours the staple would refuse the connection
anyway, and a reload must not be able to publish that state silently.

**Admin-managed records.** `POST`/`PUT /admin/tls/ocsp-responses` stores a
record before any certificate context exists, so it performs the
certificate-independent half only: the size bound, a successful
`id-pkix-ocsp-basic` envelope, and a well-formed `BasicOCSPResponse`. Storing a
record is therefore not a promise it can be served. The certificate-bound half
above runs when a frontend TLS configuration referencing
`managed://ocsp-responses/<id>#ocsp` is built, and a mismatch is refused there.

**Multi-certificate frontends.** A stapled response is bound to one
certificate, so a Gateway data plane staples it only when it serves exactly one
certificate; with several it is stapled to none and a warning is logged.

**Serving.** An accepted response is attached to the `CertifiedKey` the
listener serves, so a client receives it in the certificate message. The
single-certificate frontend and the single-entry SNI frontend share one
`rustls::ServerConfig` for HTTP/1.1 and HTTP/2, and the HTTP/3 listener rebuilds
a TLS 1.3-only config around **the same certificate resolver** rather than
reloading the material, so all three protocols serve the same validated bytes.
An `admin` HTTPS listener behaves identically.

**FIPS mode.** With `FERRUM_FIPS_MODE=enforce`, admission is narrower: the
`BasicOCSPResponse` signature, the served leaf's own signature, and every
certificate carried in `certs` must use `sha256/384/512WithRSAEncryption`,
`rsassa-pss` with SHA-256/384/512, `ecdsa-with-SHA256`, or `ecdsa-with-SHA384`
— `sha1WithRSAEncryption` and Ed25519 are refused — and every carried responder
certificate plus the issuer selected from the served chain must carry an
approved key (RSA 2048–8192, or ECDSA over P-256/P-384/P-521). The refusal is at
the response grammar, so a non-approved response cannot be stored through the
admin API either. `CertID` and `ResponderID` **key identifier** digests are
unaffected: RFC 6960 defines them over public issuer/responder material as a
selection key, and SHA-1 remains admitted there. See
[`docs/fips.md`](fips.md). Outside enforcement nothing changes, so ordinary
deployments keep interoperating with responders that still sign with SHA-1.

**Certificate binding is checked when the material is loaded, not per
handshake; freshness is re-checked hourly.** The full validity window above is
evaluated while the `ServerConfig` candidate is being built — at startup, at
config reload, and when a watched OCSP source's bytes change. In addition, a
background task re-evaluates the accepted `nextUpdate` of every served staple
**once an hour**, and retires a staple that has reached it.

The re-check interval is a fixed constant, not an environment variable. It is
not a policy choice — it is a bound on how long an expired staple could keep
being served — and an hour is far inside the shortest window any responder
issues, so a knob there would only be a way to disable the protection.

**Dropping is the safe state, not a fallback.** Serving a response past its
`nextUpdate` is strictly worse than serving none: a client that enforces staple
validity — a browser with OCSP checking on, or a peer honouring a must-staple
certificate — aborts the handshake outright on an expired response, whereas an
absent staple falls back to that client's own revocation behaviour. The
retirement is applied to the certificate resolver the listener already serves,
so it takes effect on the next handshake for HTTP/1.1, HTTP/2, HTTP/3 and
TCP+TLS at once, **whether or not `FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED` is
set**, and without rebuilding or re-reading anything. An `admin` HTTPS listener
behaves identically. The drop is logged as a `warn!` naming the redacted source,
and the TLS inventory entry for that source reports the retirement instead of
its stale `nextUpdate`, so the
`ferrum_tls_revocation_expiry_seconds{kind="ocsp"}` row for it stops being
exported rather than counting further and further negative for material nothing
staples.

**Refresh is still the operator's job.** Ferrum has **no OCSP responder
client**: nothing inside the gateway fetches a fresh response, so re-attaching
one is the operator's own fetch loop plus live reload. Refresh the OCSP source
before `nextUpdate` elapses: with
`FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED=true` a file or provider source is
re-read and re-validated as soon as its bytes change — including after a drop,
which the ordinary reload path repairs by building a new resolver carrying the
new response — and rewriting the source with a stale or otherwise invalid
response is rejected while the previous known-good material keeps serving.
Without live reload the only way to adopt a refreshed staple is a restart — and
a restart after `nextUpdate` is refused by the same admission check, exactly as
for CRLs above. A must-staple certificate has no working posture between the
drop and one of those two events; the drop does not create that gap, it only
stops hiding it behind a handshake failure the client blames on the response.

A staple inside `FERRUM_TLS_CRL_EXPIRY_WARNING_DAYS` of its `nextUpdate` logs a
`warn!` at load, re-logs it on **every hourly re-check** while it stays inside
the window — so the signal is not load-time only — and is exported as
`ferrum_tls_revocation_expiry_seconds{kind="ocsp"}` on the authenticated
`/metrics` surface.

**Diagnostics.** Rejections name the redacted source identifier and the
structural reason. They never contain certificate bytes, response bytes, private
material, or a secret source reference.

### Client-Trust Generations and Established-Transport Retirement

Live-reloading a CRL or a client-CA bundle rebuilds the verifier used for **new**
handshakes. That alone does not reach a connection that is already established:
without the mechanism described here, the holder of a pre-reload TLS connection
could keep opening new HTTP/2 and HTTP/3 request streams and new HTTP/1.1
keep-alive requests, and keep an active WebSocket, TCP+TLS, or UDP+DTLS session
running, under the trust decision the operator had just withdrawn.

Under `FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED=true`, Ferrum attaches a
**client-trust generation** to every established transport that authenticated
with a client certificate, and retires those transports when authority is
withdrawn.

**This is not certificate expiry.** A certificate reaching its own `notAfter` is
a different control with a different lifecycle. This section is about an operator
explicitly revoking a certificate or removing an issuing CA.

#### Trust domains

A generation is scoped to a listener family, never process-global, so one
listener's rotation cannot tear down another's sessions:

| Scope | Listeners | Material |
|-------|-----------|----------|
| `proxy_frontend` | Proxy HTTPS / HTTP-2 **and** TCP+TLS stream listeners | `FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH` + `FERRUM_TLS_CRL_FILE_PATH` |
| `proxy_h3` | The QUIC / HTTP-3 listener | the same operator material, published separately (see below) |
| `admin_https` | The Admin API HTTPS listener | `FERRUM_ADMIN_TLS_CLIENT_CA_BUNDLE_PATH` + `FERRUM_TLS_CRL_FILE_PATH` |
| `frontend_dtls` | Operator-owned UDP + DTLS listeners only | `FERRUM_DTLS_CLIENT_CA_CERT_PATH` + `FERRUM_TLS_CRL_FILE_PATH` |

Ferrum-generated mesh `NodeWaypoint` DTLS listeners deliberately join **no**
trust scope. Their identity and client-CA policy are published by the mesh
slice, not by the `FERRUM_DTLS_*` generation, and the live-swap path already
skips them for the same reason. An operator CRL or client-CA edit therefore
retires operator DTLS sessions only; it never tears down mesh datapath
sessions or counts them under `scope="frontend_dtls"`.

HTTP/3 keeps its own generation even though it serves the same material: the
QUIC endpoint applies a reload asynchronously (`Endpoint::set_server_config`
after the revision watch fires), so only the HTTP/3 listener can publish a
generation that is not already ahead of the verifier QUIC is handshaking with.

Because it applies reloads out of band, the HTTP/3 listener adopts **one whole
accepted candidate**: the reload pipeline publishes the `rustls::ServerConfig`,
the client-certificate verifier compiled into it, and the semantic identity of
exactly the client-CA bytes and CRLs behind that verifier as a single value, and
the listener installs and publishes both halves of it. The generation HTTP/3
reports therefore always describes the anchors and revocations its endpoint is
actually enforcing: an accepted CRL addition both retires the established HTTP/3
connections *and* is present in the verifier a reconnecting client meets. The
startup baseline works the same way — it is the identity of the load whose
config the endpoint was built with, not of a later re-read of the same sources.

In DP mode the control plane owns the active **server certificate** when it has
delivered Gateway TLS material, and the operator still owns **client trust**
(the client-CA bundle and CRL). An accepted operator CRL or client-CA reload
must not substitute the operator server certificate into the H1/H2/TCP slot
while that CP material is present. CP-delivered H1/H2/TCP (and TCP+TLS stream)
configs therefore keep the CP server certificate/resolver and bind
`ClientTrustScope::ProxyFrontend`'s live handshake wrapper, so a new connection
after the accepted reload uses only the new operator verifier — including an
additive CA overlap or a CRL unrevocation, which post-handshake revalidation
cannot admit on its own. The wrapper's CertificateRequest CA-name hints are
generation-neutral (empty): rustls then omits or does not constrain the
`certificate_authorities` hint, so a client that honors those names can still
present a certificate issued by a CA added after that CP `ServerConfig` was
built. The presented chain is verified only by the currently published
fail-closed operator verifier; empty hints do not broaden trust. HTTP/3 still
has to install the new trust through its asynchronous endpoint apply: the DP
publishes one accepted candidate that pairs the live CP server config with the
same accepted operator verifier and semantic identity, then wakes the QUIC
listener so `ProxyH3` installs that pair through its one rustls transaction
(live verifier → `Endpoint::set_server_config` → generation/fence). A refused
operator candidate never enters that slot and never replaces the live verifier,
so every family keeps its last-good verifier, config, generation, and sessions.
Clearing CP material restores the latest accepted operator candidate — not a
startup snapshot captured when CP material first arrived. This does not add
CP-delivered client-CA support.

A data plane may have **no operator server certificate at all**: with
`FERRUM_PROXY_HTTPS_PORT` enabled and no `FERRUM_FRONTEND_TLS_CERT_PATH` /
`FERRUM_FRONTEND_TLS_KEY_PATH`, the listener starts with an empty TLS slot and
CP-delivered Gateway material is the only server certificate it will ever serve.
Client trust is still operator-owned on that shape, so
`FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH` (plus `FERRUM_TLS_CRL_FILE_PATH`) is
loaded once at startup, arms `proxy_frontend` before the first accept, and is
live-reloaded under `FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED=true` exactly as it
is on an operator-certificate data plane. The verifier and the published
identity come from that one load, so what the listener enforces and what it
reports can never describe different material. An accepted client-CA or CRL
change installs the live verifier CP-delivered H1/H2 and TCP+TLS configs consult
on new handshakes, advances the generation that retires established
client-certificate transports, and re-pairs the live CP server config with the
new trust for HTTP/3 — all under one publication that a concurrent CP update
cannot interleave with. No operator server certificate is ever synthesized: the
server half of every published candidate is the CP's, and when CP withdraws its
material a node with no operator certificate clears the listener slot and
disables HTTP/3 rather than inventing one. The scope stays unarmed when no
client-CA source is configured (nothing on that listener can hold a withdrawable
credential, and an unrelated CRL must not make it fail or export protection
metrics) and when every configured client-trust source is inline material that
can never change. A configured-but-unloadable client-CA bundle fails startup
closed rather than serving CP material under an unknown trust baseline;
`ferrum-edge validate` exercises the same trust-only load as `run`. After the
watcher establishes its first source fingerprint, it reconciles once before
normal polling so a rotation between the accepted startup load and watcher
registration cannot be mistaken for already-applied material. A refused reload
keeps the complete last-good verifier, identity, generation, paired config, and
sessions.

The `frontend_dtls` scope reads its declared client-CA source **once** through
the shared `CertSource` abstraction, and derives both the DTLS trust anchors and
the published identity from those exact bytes. A `file://` path, inline PEM, or
a provider URI therefore all work for `FERRUM_DTLS_CLIENT_CA_CERT_PATH` /
`FERRUM_DTLS_CLIENT_CA_CERT_SOURCE`, the shared
`FERRUM_TLS_MAX_MATERIAL_SIZE_BYTES` ceiling applies, and diagnostics carry only
the redacted source label — never the configured value, which for an inline
source is itself certificate material.

Mesh inbound mTLS is deliberately **out of scope**. Its verifier is owned by
PeerAuthentication / SPIFFE trust-bundle reload, which is a separate trust plane
with its own rotation contract.

#### When a scope is armed

A scope is armed **only when the exact accepted candidate that listener family
installed actually performs verified client-certificate authentication**.
Concretely, `proxy_frontend` and `proxy_h3` arm only when
`FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH` is set (there is no frontend
no-verify switch; without that client-CA source the listener does not request
a client certificate). `admin_https` arms only with
`FERRUM_ADMIN_TLS_CLIENT_CA_BUNDLE_PATH` set and admin no-verify
(`FERRUM_ADMIN_TLS_NO_VERIFY`) off, and `frontend_dtls` only with
`FERRUM_DTLS_CLIENT_CA_CERT_PATH` set.

A listener that does no client-certificate authentication can never hold a
credential an operator could withdraw. It therefore:

- publishes no baseline and exports **none** of the series below, rather than
  reporting a protection with nothing to protect;
- tracks nothing per connection;
- keeps its existing kTLS and HTTP/3 0-RTT eligibility exactly as it is without
  live reload — arming is what declines the TCP+TLS kTLS handoff, and an unarmed
  listener never does.

The two rustls-level changes this control makes to a `ServerConfig` — the live
handshake verifier wrapper (whose CertificateRequest CA-name hints are
deliberately empty) and the suppression of TLS 1.3 session tickets and the
stateful session cache — are likewise applied **only where a client-trust
generation can actually be published**: an mTLS listener built without
`FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED` keeps its `certificate_authorities`
hints and its session resumption exactly as before. Suppressing resumption is
required once a withdrawal can land mid-life, because a session ticket does not
re-run client-certificate verification; where no generation can ever advance,
there is no withdrawn generation for a ticket to outlive. The one exception is
HTTP/3 under a data plane, whose reload channel is CP-delivered rather than
operator-file-driven: there the QUIC listener binds the wrapper whenever it has
a reload channel at all, which is the same condition under which it arms
`proxy_h3`.

Certificate/key-only live reload is unaffected on such a listener: it rotates
normally, simply without a trust generation. A listener's authentication mode is
fixed configuration and is not something live reload may change, so a reload
candidate that would drop client-certificate authentication on an armed surface
is refused outright and the complete last-good generation, verifier, and
sessions are retained.

#### What advances a generation, and what retires a connection

A candidate is summarized into a *semantic* identity — the set of client-CA
trust anchors, and the set of `(signer-key, serial)` revocations across every
CRL — rather than a byte hash of the source material. Each revoked serial is
scoped by a stable identity of the **CRL signing key**, not the issuer
distinguished name: two CA keys can share a subject DN and a leaf serial, and
hashing issuer DN with that serial would let a revocation under the second key
collide with the first and suppress `CrlChanged`. The signer is the uniquely
verified SubjectPublicKeyInfo from the accepted client-CA bundle (signature
verified; matching a DN is not enough; identical SPKIs are deduplicated). When
the signer is not in the accepted bundle, issuer DN and Authority Key
Identifier cannot prove its key identity: distinct keys can deliberately reuse
both. Ferrum therefore requires an unambiguous AKI but conservatively includes
the complete signed CRL in that issuer identity. A reissue from such an
outside-bundle signer retires established sessions; this availability cost
prevents colliding issuer metadata from suppressing a new revocation. A CRL
whose issuer cannot be identified conservatively is refused and the last-good
generation is retained. For signers whose SPKI is verified from the bundle, a
routine reissue with a fresh `thisUpdate` / `nextUpdate` / `crlNumber` and an
unchanged revocation set remains unchanged and does not churn sessions.

| Change | Generation | Established sessions |
|--------|-----------|----------------------|
| Server cert/key rotation only | unchanged | untouched |
| CRL re-issued, same revocation set, signer SPKI verified from bundle | unchanged | untouched |
| CRL re-issued, signer outside bundle | advances, fence moves | retired conservatively |
| CA **added** to the bundle (additive overlap rotation) | advances | untouched |
| Revocation **removed** from a CRL | advances | untouched |
| CA **removed** from the bundle | advances, fence moves | retired |
| Revocation **added** by a CRL | advances, fence moves | retired |
| Malformed / truncated / unreadable candidate | unchanged | untouched |

A refused candidate keeps the previous verifier, the previous generation, the
previous semantic material, and every live session, and is counted as a rejected
candidate so the refusal is observable rather than silent.

##### Revoking an intermediate CA stops the leaves it issued

Revocation is checked on **every non-trust-anchor certificate in the built
chain**, not only on the leaf a client presents. Revoking an intermediate CA in
a CRL its issuer signed therefore retires the scope's established
client-certificate sessions *and* refuses their reconnect: the retirement and
the enforcement agree.

The semantic identity above is still a superset of what the verifier rejects. It
summarizes *every* revoked serial in every CRL, because a CRL entry is an issuer
key plus a serial number and carries nothing that distinguishes an end-entity
serial from a CA serial. An entry naming a serial that no presented chain
contains therefore still retires sessions. That direction is the fail-closed
one: it can only end sessions that would have survived, never keep alive a
session that should have ended.

Removing the intermediate (or its issuing root) from the client-CA bundle
remains available and is still the broader instrument — it invalidates every
chain terminating at that anchor, including branches a CRL does not name. It
shows up in the table above as "CA **removed** from the bundle".

#### Retirement scope

When authority narrows, **every client-certificate-authenticated transport in
the changed scope** is retired — not only those whose chain or serial is
provably affected. This is deliberate and conservative: deciding per-connection
impact would mean re-running path building against each retained chain at
publish time, and an error there fails *open*. Precision is applied instead in
the semantic diff above, which refuses to retire anything unless authority
actually narrowed.

Anonymous TLS connections are never registered and never retired: with no
gateway-verified client certificate they hold no trust decision a CRL or
client-CA change can revoke. Plaintext listeners are untouched.

#### What retirement does, per protocol

| Transport | Behaviour |
|-----------|-----------|
| HTTP/1.1 keep-alive | The next request is refused with a fixed `401` before routing and plugins; the connection is closed at end of keep-alive via hyper's graceful shutdown. |
| HTTP/2 | New streams are refused with the same fixed `401` before routing and plugins, and the connection receives a `GOAWAY`. |
| Admin HTTPS (HTTP/1.1 or HTTP/2) | Identical: a request already buffered on the connection is refused with a fixed `401` JSON body before it enters admin routing, and the connection ends through hyper's graceful shutdown. The admin connection permit and the slowloris activity accounting release exactly once, on the paths that already own them. |
| HTTP/3 | The QUIC connection is closed with `H3_REQUEST_REJECTED` (`0x010B`); a request stream that was already ready is refused before its task is spawned. |
| gRPC | The pre-routing refusal is a `grpc-status: 16` (`UNAUTHENTICATED`) trailers-only response. |
| WebSocket (H1/H2/H3) | The session's stop arbiter terminates it with the bounded reason `trust_withdrawn`, through the same teardown as drain and maximum-lifetime stops. |
| TCP+TLS | The client leg fails with a bounded transport error, so byte counters, first-failure attribution, circuit-breaker classification, `on_stream_disconnect`, and the stream summary all complete exactly once through the existing relay paths. Between registration and the first relayed byte the client leg is not polled at all, so every post-admission wait — the `on_stream_connect` chain, the decrypted first-bytes read, DNS resolution, retry backoff, the backend dial with its TLS handshake and outbound PROXY framing, and the forward of an already-consumed decrypted prefix — additionally races the retirement fence and is **dropped** rather than finished. The `on_stream_connect` chain is interrupted promptly and lifecycle-balanced: an already-retired session starts no further hook, an in-flight hook future is dropped mid-poll, no later hook and no backend work runs, and the chain then releases every admission permit it took and settles the mesh opened/closed finalizer exactly once under the metadata the completed hooks left — the same bookkeeping a plugin rejection and the fault-injection peer-reset cancellation already perform, and that cancellation is unchanged. The buffered prefix is written through the same fence, so a withdrawal landing before the forward writes nothing and one racing a write parked on a full backend buffer abandons the remainder. The refusal is client-side and health-neutral: any claimed half-open probe slot is released neutrally and no circuit-breaker or passive-health failure is charged to the upstream. Its message is fixed and redacted — *frontend client trust withdrawn during setup, with no further backend bytes written* — because a withdrawal can land after a partially written outbound PROXY header or after the prefix forward already delivered its pre-withdrawal bytes; what the fence guarantees is that nothing further is written on the retired session's behalf. |
| UDP+DTLS | The session driver ends through the same break the shutdown path uses; the demux entry, the active-session counter, and its mirror all release exactly once. Queued application data is **not** flushed — the peer is no longer authorized. After a client-certificate session is registered, plaintext delivery to the proxy, the accepted-connection handoff, and UDP writes observe the same fail-closed retirement fence so a full channel cannot pin the session past withdrawal. The driver's fences stop the **driver**; the accepted connection carries the registered session with it, so the detached proxy handler is bound by the same decision. The accepted-session `on_stream_connect` chain is interrupted exactly as the TCP+TLS chain is — an already-retired session starts no hook, an in-flight hook future is dropped mid-poll, no later hook and no backend work runs, and the chain hands back every admission permit it took before releasing the session slot (there is no mesh opened/closed lifecycle on this path to finalize). Every post-admission backend-setup wait — DNS resolution, the backend UDP connect, and the backend DTLS handshake — additionally races the fence and is **dropped** rather than finished, and the fence is re-read synchronously immediately before backend success is recorded and before either relay task is spawned. Both relay directions carry the fence too: the client receive, every awaited per-datagram hook in either direction, the backend commit, the backend receive, and the client-facing send are each bounded, so a datagram received while the decision still stood cannot be committed from inside a hook that was pending when it was withdrawn. On retirement the supervisor aborts **and joins** both relay tasks through the existing bounded teardown; nothing is detached. The refusal is client-side and health-neutral: any claimed half-open probe slot is released neutrally, no circuit-breaker or passive-health failure is charged to the upstream, and the connection's fixed-cardinality fence counter is recorded exactly once however many of these boundaries observe the same withdrawal. Its message is fixed and redacted — *frontend client trust withdrawn during setup (DTLS session), with no further backend datagram forwarded* — because a withdrawal can land after datagrams already forwarded under the decision that was still standing. |

Because retirement runs through each transport's existing bounded teardown,
request guards, connection guards, permits, load-balancer and circuit-breaker
state, and accounting all complete exactly once.

**kTLS interaction.** A kernel-terminated TCP+TLS leg is spliced, so it has no
userspace poll seam at which a withdrawal could end the session. When a
listener's client-trust domain is armed, the optional kTLS handoff is therefore
declined **before the handshake**, while the socket is still pristine, and the
connection is relayed on the fence-aware buffered `rustls` path. Nothing is
refused and no authentication is skipped; only the optimization is declined, and
only in deployments that enabled frontend TLS live reload.

#### Race behaviour

On rustls surfaces (proxy HTTPS / HTTP-2 / TCP+TLS, admin HTTPS, HTTP/3), each
listener family owns exactly one client-trust scope. An accepted candidate is
published as **one rustls transaction for that singular scope**, and only after
every fallible rebuild has succeeded. That transaction holds the scope
publication lock continuously across: install the live handshake verifier,
execute the already-validated infallible config exposure/adoption (slot swap /
`Endpoint::set_server_config`), then publish that same candidate's material,
generation, fence, and session sweep. Installing a stricter verifier slightly
before its config is conservative — a stale config refuses withdrawn
credentials. Holding the lock across those steps is what keeps concurrent V2/V3
publications from serving verifier V3 with config/material V2 (or the converse).
A refused candidate never enters the transaction and never replaces the live
verifier. HTTP/3 remains independently owned and published by its own `ProxyH3`
scope; the HTTPS/H2 reload task never publishes H3's generation.

DTLS has no rustls live verifier. It keeps the distinct config-before-generation
order: the DTLS generation is published into every active `DtlsServer` first,
then the trust generation advances.

The DTLS driver also commits its internal accept handoff *before* draining the
server's queued final flight, so there is a short interval in which the proxy
handler exists while the peer has not yet seen the flight. That interval is
covered by the fence the accepted connection carries rather than by the
handoff's own race: a withdrawal landing inside it retires the session, the
handler starts no hook and no backend stage, and the driver still discards every
queued packet on a trust withdrawal. The existing client-certificate refusal
path — which returns *before* the flight is emitted, so a refused peer never
receives it — is unchanged.

Admission is the mirror image: a listener captures the generation first and
loads the configuration second. A connection can therefore capture a generation
that is *older* than the material it actually handshakes with — the conservative
direction, costing at most one unnecessary retirement for a connection
handshaking exactly across a withdrawal — but never a newer one, so none can
escape the fence. The TCP+TLS accept path is the exception to the ordering
itself — it snapshots the TLS configuration for a connection before reading the
generation, so it can hold a post-withdrawal generation beside a pre-withdrawal
configuration. Its outcome is unchanged, because every rustls surface also
re-verifies the presented chain against the live published verifier once the
handshake completes, and that verifier is installed before the generation
advances: a connection observing generation G meets a verifier at or newer than
G, so a credential withdrawn at or before G is refused there and one withdrawn
after G is caught by the fence. A connection being registered while a
publication sweeps is caught by a post-registration re-check against the same
fence, so it can neither escape nor repopulate the registry after the sweep.

The HTTP/3 revision channel is a wakeup, not a queue: several accepted
candidates can coalesce into one notification, and the sources can rotate again
between the wakeup and the rebuild. Neither can desynchronize what that endpoint
enforces from what it reports, because the candidate is taken as one value —
whichever candidate is installed is the candidate whose identity is published,
and one that arrives afterwards simply wakes the listener again.

#### Observability

All series are fixed-cardinality. Trust-specific dimensions (`scope`,
`outcome`, `reason`) use closed vocabularies: the scope set above, publication
outcomes `armed` / `unchanged` / `advanced` / `withdrawn`, and retirement
reasons `client_ca_withdrawn` and `crl_changed`. The rendered registry also
appends the standard configured `namespace` label — the same process-wide
namespace fragment every other Ferrum family carries, not a per-listener or
per-certificate dimension. No serial, subject, SAN, issuer name, key
identifier, SPKI digest, fingerprint, certificate path, or generation of any
secret appears in a metric label, a log line, or a client-visible error.

| Metric | Type | Meaning |
|--------|------|---------|
| `ferrum_frontend_client_trust_generation{scope}` | gauge | Generation currently in force |
| `ferrum_frontend_client_trust_withdrawal_generation{scope}` | gauge | Generation at which authority was last narrowed (`0` = never) |
| `ferrum_frontend_client_trust_tracked_connections{scope}` | gauge | Established client-certificate transports tracked for retirement |
| `ferrum_frontend_client_trust_publications_total{scope,outcome}` | counter | `armed` / `unchanged` / `advanced` / `withdrawn` |
| `ferrum_frontend_client_trust_rejected_candidates_total{scope}` | counter | Candidates refused; previous generation retained |
| `ferrum_frontend_client_trust_retired_connections_total{scope,reason}` | counter | Transports retired, by bounded reason |
| `ferrum_frontend_client_trust_fenced_total{scope}` | counter | Requests / streams refused at the admission fence |

`GET /metrics/runtime` carries the same state as `frontend_client_trust`, one
entry per armed scope.

Nothing is emitted, and nothing is tracked per connection, when no scope has
accepted client-trust material — which is the default posture with
`FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED` unset, and also the posture of any
listener family that does no client-certificate authentication (see
"When a scope is armed").

### Gateway API Multi-Certificate Serving (SNI)

A data plane that receives its frontend TLS material from a Kubernetes Gateway (`spec.listeners[].tls.certificateRefs`) can serve **many** certificates at once. This covers two shapes that used to be refused:

- one listener naming several `certificateRefs` (for example an RSA and an ECDSA leaf, or several hostnames);
- several Gateways in the **same namespace**, each owning its own Secret.

Every authorized certificate for the data plane's namespace is installed into one SNI-aware `rustls` certificate resolver:

1. **Declared listener match.** Exact listener `hostname` claims win first, followed by declared one-label wildcards. A declared name is authoritative: certificate-derived aliases from other listeners are never added as alternative signing candidates for it.
2. **Certificate SAN alias.** When no listener hostname claims the SNI, exact DNS SANs win over one-label wildcard SANs. `*.example.com` answers `a.example.com`, but not `a.b.example.com` and not bare `example.com` (RFC 6125).
3. **Fallback listener.** A ClientHello with no SNI, or an SNI no certificate covers, is answered from the namespace's deterministic default — the first catch-all listener (one with no `hostname`) when there is one, otherwise the first admitted listener. Gateway owners precede ListenerSet extensions, then older resources and complete listener-key order decide ties. Selection never fails a handshake merely for lack of a name match; it uses the fallback exactly as a single-certificate listener would. The decision is order-independent end to end: the Kubernetes controller's reconcile snapshot is deduplicated across served-version aliases (the preferred served version of one object wins: GA, then beta, then alpha, by Kubernetes version priority) and sorted by group, kind, namespace, and name before translation, so the same cluster state — including a stale watch store that still holds a deleted Gateway — always yields the same fallback winner. Such a stale Gateway is retired by the idle relist (`FERRUM_K8S_WATCH_IDLE_RELIST_SECS`) — but only once EACH served-version scope that held it (`Gateway` is watched under `v1` and `v1beta1`, each relisting on its own schedule) has relisted; every relist logs the objects it found missing, so the first such warning can precede the slot's retirement by up to one more window.

Each exact, wildcard, or fallback listener retains all of its certificate candidates in declared order and chooses the first signing key compatible with the ClientHello's offered signature schemes. This makes an RSA/ECDSA `certificateRefs` pair effective instead of silently pinning the first algorithm. If a name is claimed but none of its candidates is cryptographically compatible, the handshake fails closed rather than falling through to an unrelated listener's certificate.

ACME TLS-ALPN-01 validation still takes precedence over SNI selection, so `acme://` order validation is unaffected.

**Ownership and tenancy.** A certificate is owned by its **Gateway's** namespace, never the Secret's — a `ReferenceGrant` may authorize a Secret from elsewhere. The control plane filters the certificate set to the subscribing namespace before it leaves the CP, and the data plane re-applies the same filter on receipt, so a data plane can never observe or serve another namespace's certificate.

**Collision behavior.** Two listeners in one physical Gateway namespace that declare the **same** `hostname` with **different** certificates are a conflict. The winner is deterministic — Gateway owners precede ListenerSet extensions, then the older resource (by `creationTimestamp`), then complete listener-key order — and the loser fails closed: it serves no route traffic, so a hostname is never answered by an ambiguous certificate. Gateway losers keep their `Accepted`/`ResolvedRefs` status and report `Conflicted=True` with reason `HostnameConflict`; ListenerSet conflicts follow their attachment-status contract. Several `certificateRefs` on one listener are not a conflict, and two catch-all listeners are not either — they claim no name, so both stay served and selection falls back to each certificate's own SANs.

**Fail-closed loading.** A listener whose `certificateRefs` contains any reference that is missing, malformed, not a `kubernetes.io/tls` Secret, or not authorized by a `ReferenceGrant` is left entirely unmaterialized — never partially. At the data plane, if any certificate in the delivered set fails to load, parse, pair, or is expired, or if an explicit listener hostname is malformed, the whole snapshot is rejected and the previous configuration keeps serving.

**Rotation and deletion.** Each source carries a content digest (`k8s://<ns>/<secret>#tls.crt?sha256=…`), so a Secret update changes the snapshot and the control plane broadcasts it; the data plane rebuilds the resolver and swaps it atomically for new handshakes. In-flight sessions keep the configuration they negotiated. Deleting a Gateway or listener withdraws exactly its own certificates; when the last Gateway certificate for the namespace goes away, the data plane restores the operator's `FERRUM_FRONTEND_TLS_*` material if any was configured.

**Bounds.** At most 256 Gateway certificates are admitted per configuration snapshot and at most 4096 SNI names are indexed. Certificate admission is listener-atomic: if every `certificateRef` on one listener cannot fit, none of that listener's certificates or routes are materialized. The runtime indexes every explicit listener hostname before adding certificate-derived SAN aliases, so SAN-heavy certificates cannot displace a later listener's declared SNI mapping; only surplus SAN aliases are omitted at the name bound. A stapled OCSP response (`FERRUM_FRONTEND_TLS_OCSP_RESPONSE_SOURCE`) is bound to one certificate, so it is stapled only when the data plane serves exactly one Gateway certificate; with several it is not stapled to any and a warning is logged.

### TLS Inventory Visibility and Metrics

`GET /admin/tls/inventory` collects live: it loads every configured source on each request, including private keys (parse-checked and dropped immediately), so an operator request may reach the filesystem, the Kubernetes API, and secret managers.

Prometheus `/metrics` deliberately does not. Its `ferrum_tls_cert_expiry_seconds` / `ferrum_tls_cert_not_before_seconds` gauges are rendered from a cached, non-secret inventory snapshot, so a scrape performs **zero** certificate, private-key, Kubernetes, HSM, or cloud-secret I/O and never blocks on a secret provider (a Prometheus fleet cannot amplify a secret-backend incident, and an allowed scraper cannot drive private-key materialization outside the reload lifecycle).

The snapshot is produced off the request path by a bounded, single-flight background refresh:

- It reads only public certificate-family material — certificate, CA bundle, CRL. Private-key, JWKS, and OCSP sources are never materialized for metrics; those entries report health from the owning validated config/reload state (startup and every reload validate a source before adopting it, and a recorded watcher load/rebuild failure downgrades the entry without re-reading a byte).
- A scrape refreshes nothing itself. When the snapshot is older than `FERRUM_TLS_INVENTORY_SNAPSHOT_TTL_SECONDS` (default 300; `0` disables the refresh and leaves the gauges absent) the scrape only schedules the refresh, and at most one refresh runs process-wide at a time.
- Validated rotation and reload outcomes mark the snapshot stale, so a rotated certificate is picked up on the next scrape instead of at the end of the TTL window.
- Freshness is explicit: `ferrum_tls_inventory_snapshot_timestamp_seconds` carries the snapshot's collection time and `ferrum_tls_inventory_snapshot_max_age_seconds` carries the configured bound. Alert on `time() - ferrum_tls_inventory_snapshot_timestamp_seconds` exceeding that bound rather than assuming scrape-time collection.

### Backend Connection Pool and TLS Paths

For reqwest-based backend paths (HTTP/1.1, HTTP/2 via reqwest, HTTP/3 frontend-to-backend), each unique combination of `backend_tls_client_cert_path`, `backend_tls_client_key_path`, and `backend_tls_server_ca_cert_path` produces a **separate `reqwest::Client` pool entry**. Two proxies with different cert paths targeting the same backend host will not share connections. For rustls-based paths (gRPC pool, HTTP/2 direct pool), the TLS config is built per-connection rather than per-pool-entry, but the same isolation principle applies — different cert paths produce different TLS configurations.

## Security Best Practices

### Production Environments
1. **Use certificates from trusted CAs** for server certificates
2. **Implement proper certificate lifecycle management** (renewal, revocation)
3. **Use strong cryptographic algorithms** (RSA 2048+, ECDSA)
4. **Protect private keys** with appropriate file permissions
5. **Enable certificate revocation checking** when using CRLs or OCSP

### mTLS Considerations
1. **Limit client CA scope** to only necessary certificates
2. **Implement certificate expiration monitoring**
3. **Consider certificate short lifetimes** for enhanced security
4. **Document certificate issuance procedures**
5. **Plan for certificate compromise scenarios**

### Client-Certificate Authorization Lifetime

The TLS handshake proves the client certificate was valid **at handshake time**.
That is necessary but not sufficient for the gateway's authorization contract:
HTTP/2 and HTTP/3 multiplex new request streams over one transport connection
for a long time without repeating the handshake, HTTP/1.1 reuses a connection
for keep-alive requests, and a TCP+TLS stream session can stay open
continuously. Issue #3816 tracks that gap.

`mtls_auth` therefore enforces the leaf certificate's validity interval itself:

- **Unconditional leaf validity.** Every request re-checks the leaf's
  `notBefore` / `notAfter` window, independently of whether the optional
  `allowed_issuers` / `allowed_ca_fingerprints_sha256` constraints are
  configured. The default configuration (`cert_field` only) is covered. The
  existing CA/intermediate validity checks inside the issuer-constraint paths
  remain as defense in depth and cannot bypass this check.
- **Fail closed on unusable times.** A certificate whose validity interval
  cannot be represented as a coherent window — a malformed or overflowing ASN.1
  time, or an inverted `notAfter < notBefore` — is rejected outright, before any
  identity is extracted.
- **Boundaries are inclusive.** `notBefore` and `notAfter` themselves are inside
  the window, matching RFC 5280 "valid at" semantics. One second past `notAfter`
  is outside it.
- **The connection cache stays, but never caches a time-dependent decision.**
  HTTP/3 memoizes the expensive X.509 parse, path verification, and identity
  extraction once per plugin instance and transport connection. What is cached
  is the certificate-*invariant* result — the identity plus the validity window
  — never "this was valid". Every request re-checks the Unix window, and the
  first successful evaluation converts `notAfter` once to a monotonic Instant
  that later cache hits must return unchanged, so a wall-clock rollback cannot
  recreate a later deadline. A cached success becomes a fixed `401` the moment
  that retained Instant elapses. `ConsumerIndex` lookup likewise stays per
  request, so a consumer removed by a config reload stops being authorized
  immediately.
- **The client learns nothing.** The rejection body is a fixed
  `{"error":"Client certificate is not currently valid"}`. `notBefore`,
  `notAfter`, the observed time, the subject, the SAN, the serial, the
  fingerprint, and the DER are never echoed to the client and never logged or
  exported as a metric label.

A successful `mtls_auth` verification also publishes the leaf's `notAfter` as
the request's authoritative **credential deadline** on the shared,
protocol-neutral contract. That single value is what bounds:

- the WebSocket session deadline arbiter (earlier of certificate expiry and
  `FERRUM_WEBSOCKET_MAX_LIFETIME_SECONDS`), on H1 Upgrade, H2 Extended CONNECT,
  and H3 Extended CONNECT;
- generic HTTP/SSE, native gRPC, and gRPC-Web streaming bodies (see
  [Authorization Lifetime of an Admitted Stream](response_body_streaming.md#authorization-lifetime-of-an-admitted-stream));
- TCP+TLS and UDP+DTLS stream sessions, whose `on_stream_connect` admission runs
  exactly once and would otherwise leave a continuously active relay unbounded.

The deadline is converted to a **monotonic** instant once, at the first
successful evaluation, and that Instant is retained on the cached evaluation so
a wall-clock rollback cannot lengthen a later request on the same connection.
Relay traffic never refreshes it.

#### Kernel TLS and the stream authorization deadline

The optional Linux kernel-TLS (kTLS) fast path for terminating `tcp_tls`
listeners hands the socket to the kernel and relays with `splice(2)`. The
gateway no longer owns the byte stream at that point, so the userspace
authorization-deadline wrapper that bounds an admitted TCP+TLS session cannot be
installed — and once `dangerous_into_kernel_connection` has run there is no safe
conversion back to a userspace rustls session.

Eligibility is therefore decided **before the frontend handshake starts**, while
the socket is still pristine. A TLS-terminating TCP listener whose plugin chain
can admit an authenticated stream principal — today that means `mtls_auth` —
does not take the kTLS handoff at all. Such a connection stays on the ordinary
buffered rustls path, is relayed normally, and is bounded by the certificate
deadline exactly as described above. Nothing is refused and no authentication is
skipped; only the optional fast path is declined.

Listeners that cannot admit such a principal keep kTLS unchanged, alongside the
pre-existing refusals (opt-in off, TLS backend, decrypted first-bytes
inspection, TLS 1.3, and the cipher/kernel probes inside the handoff itself).

#### Expiry is not revocation

These are two different mechanisms and this document does not conflate them:

| Event | Effect on a NEW handshake | Effect on an ALREADY-ESTABLISHED session |
|-------|---------------------------|------------------------------------------|
| Client certificate reaches `notAfter` | Rejected at TLS verification | **Enforced.** New H1 keep-alive requests, new H2/H3 streams, and admitted HTTP/SSE/gRPC/gRPC-Web/WebSocket/TCP+TLS relays are terminated at the certificate deadline |
| `FERRUM_TLS_CRL_FILE_PATH` live-reloaded with a new revocation list | Applied — the rebuilt verifier rejects revoked certificates | **Enforced** when live reload is enabled and the accepted candidate actually adds a revocation. See [Client-Trust Generations](#client-trust-generations-and-established-transport-retirement). |
| `FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH` live-reloaded (CA rotation/removal) | Applied to new handshakes | **Enforced** on withdrawal (a CA disappeared). Additive CA overlap does not retire sessions. Same client-trust generation contract. |

Certificate expiry is a time bound on an admitted credential. Trust retirement is an operator withdrawing authority. They compose: a session can be ended by whichever fires first. A refused reload candidate keeps the previous verifier, generation, and live sessions.

### Per-Proxy CA Filtering with `mtls_auth`

The global `FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH` applies to all connections on the HTTPS listener — the TLS handshake happens before routing, so the gateway cannot know which proxy a request targets until after the handshake completes. The same source controls terminated TCP+TLS; UDP+DTLS uses the separate `FERRUM_DTLS_CLIENT_CA_CERT_PATH` / `_SOURCE`. When the client-CA source for a frontend is configured, Ferrum requires every client to present a certificate that validates to it. Without that source, the frontend does not request a client certificate, so an `mtls_auth` plugin will not have a certificate to authenticate.

For per-proxy CA restrictions, use the `mtls_auth` plugin's `allowed_issuers` and `allowed_ca_fingerprints_sha256` options. This gives you a two-layer approach:

1. **TLS layer (global)** — accepts any client cert signed by any CA in the truststore
2. **Plugin layer (per-proxy)** — verifies a cryptographic CA pin and/or a verified chain CA fingerprint matches the proxy's policy

```yaml
version: "1"
proxies:
  - id: "proxy-a"
    listen_path: "/internal/"
    backend_scheme: "https"
    backend_host: "internal-api.example.com"
    backend_port: 443
    auth_mode: "single"
    plugins:
      - plugin_config_id: "mtls-internal-only"
  - id: "proxy-b"
    listen_path: "/partner/"
    backend_scheme: "https"
    backend_host: "partner-api.example.com"
    backend_port: 443
    auth_mode: "single"
    plugins:
      - plugin_config_id: "mtls-partner-only"
consumers:
  - id: "internal-client"
    username: "internal-client"
    credentials:
      mtls_auth:
        - identity: "internal-client.example.com"
  - id: "partner-client"
    username: "partner-client"
    credentials:
      mtls_auth:
        - identity: "partner-client.example.com"
plugin_configs:
  - id: "mtls-internal-only"
    plugin_name: "mtls_auth"
    scope: "proxy"
    proxy_id: "proxy-a"
    enabled: true
    config:
      cert_field: "subject_cn"
      # Replace with the SHA-256 fingerprint of a verified intermediate/CA
      # certificate that clients present in their TLS chain.
      allowed_ca_fingerprints_sha256:
        - "0000000000000000000000000000000000000000000000000000000000000000"
  - id: "mtls-partner-only"
    plugin_name: "mtls_auth"
    scope: "proxy"
    proxy_id: "proxy-b"
    enabled: true
    config:
      cert_field: "subject_cn"
      allowed_ca_fingerprints_sha256:
        - "1111111111111111111111111111111111111111111111111111111111111111"
upstreams: []
```

For an issuer pin that also works with UDP+DTLS, use an `allowed_issuers` entry with descriptive `cn`/`o`/`ou` fields and a `ca_certificate_pem` containing exactly one CA certificate. Ferrum verifies the leaf signature path to that pinned key; issuer DN text alone is never trusted. DTLS exposes the complete presented chain to plugins, so this may pin a higher-level root when the client transmits the needed intermediates, matching HTTP/TCP TLS behavior.

`auth_mode: multi` does not provide a fallback for TLS handshake failures. A missing or untrusted client certificate is rejected before routing when the frontend client-CA bundle is configured. Multi-auth fallback applies only after a successful certificate-bearing handshake reaches the plugin pipeline.

## Troubleshooting

### Common Issues

#### TLS Handshake Failed
```bash
# Check certificate validity
openssl x509 -in server.crt -text -noout

# Check certificate chain
openssl s_client -connect localhost:8443 -showcerts
```

#### Client Certificate Rejected
```bash
# Verify client certificate is signed by trusted CA
openssl verify -CAfile client-ca-bundle.pem client.crt

# Check client certificate details
openssl x509 -in client.crt -text -noout
```

#### Certificate File Permissions
```bash
# Set appropriate permissions
chmod 600 server.key
chmod 644 server.crt
chmod 644 client-ca-bundle.pem
```

### Debug Logging

Enable debug logging to troubleshoot TLS issues:

```bash
export RUST_LOG=debug
./ferrum-edge run
```

Look for messages like:
- "TLS configuration loaded with client certificate verification"
- "TLS connection established with client certificate verification"
- "TLS handshake failed"

## TLS Policy Hardening

The gateway supports fine-grained control over TLS protocol versions, cipher suites, key exchange groups, and cipher order negotiation. These settings apply uniformly to **both inbound (frontend) and outbound (backend)** TLS connections across **all protocols**:

| Direction | Protocols |
|-----------|-----------|
| **Inbound** | Proxy HTTPS, Admin HTTPS, HTTP/3 (QUIC) listeners |
| **Outbound** | HTTP/1.1 and HTTP/2 backends (reqwest), hyper HTTP/2 pool, gRPC (grpcs://) backends, WebSocket (wss://) backends, TCP-TLS stream backends, HTTP/3 QUIC backends |

> **Note:** DTLS (UDP-TLS) uses `dimpl`, which has its own cipher negotiation independent of rustls. Since issue #4507 the version, cipher-suite and key-exchange-group settings are translated into that vocabulary and applied to every DTLS surface (frontend listener, live-reload rebuild, generated NodeWaypoint listeners, backend client) — see [DTLS and the TLS policy](tcp_udp_proxy.md#dtls-and-the-tls-policy) for the mapping and for the one dimension that does not carry over (`ECDHE-RSA-*` suites, which DTLS cannot authenticate). `FERRUM_TLS_PREFER_SERVER_CIPHER_ORDER` and `FERRUM_TLS_SESSION_CACHE_SIZE` remain rustls-only: they apply to inbound TCP/QUIC listeners and have no DTLS equivalent.

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `FERRUM_TLS_MIN_VERSION` | `1.2` | Minimum TLS version (inbound + outbound). Allowed: `1.2`, `1.3` |
| `FERRUM_TLS_MAX_VERSION` | `1.3` | Maximum TLS version (inbound + outbound). Allowed: `1.2`, `1.3` |
| `FERRUM_TLS_CIPHER_SUITES` | *(see defaults below)* | Comma-separated cipher suites (inbound + outbound) |
| `FERRUM_TLS_KEY_EXCHANGE_GROUPS` | *(see defaults below)* | Comma-separated key exchange groups (inbound + outbound). `FERRUM_TLS_CURVES` is accepted as an alias |
| `FERRUM_TLS_PREFER_SERVER_CIPHER_ORDER` | `true` | Server cipher preference for TLS 1.2 (inbound only) |
| `FERRUM_TLS_SESSION_CACHE_SIZE` | `4096` | Inbound stateful session cache for TLS 1.2 session IDs and HTTP/3 server 0-RTT sessions |

### Protocol Version Examples

```bash
# TLS 1.2 and 1.3 (default)
export FERRUM_TLS_MIN_VERSION="1.2"
export FERRUM_TLS_MAX_VERSION="1.3"

# TLS 1.3 only (strictest)
export FERRUM_TLS_MIN_VERSION="1.3"
export FERRUM_TLS_MAX_VERSION="1.3"

# TLS 1.2 only
export FERRUM_TLS_MIN_VERSION="1.2"
export FERRUM_TLS_MAX_VERSION="1.2"
```

**Note:** Setting `FERRUM_TLS_MIN_VERSION` higher than `FERRUM_TLS_MAX_VERSION` is an error and the gateway will refuse to start.

### Supported Cipher Suites

When `FERRUM_TLS_CIPHER_SUITES` is not set, the gateway uses secure AEAD-only defaults:

The default preference starts with AES-128-GCM. Operators that set `FERRUM_TLS_CIPHER_SUITES` keep their explicit order, so pinned cipher configurations are not affected by default-order changes.

**TLS 1.3 (always AEAD):**
| Name | Description |
|------|-------------|
| `TLS_AES_128_GCM_SHA256` | AES-128-GCM (default preference; secure and cheaper on the record path) |
| `TLS_AES_256_GCM_SHA384` | AES-256-GCM |
| `TLS_CHACHA20_POLY1305_SHA256` | ChaCha20-Poly1305 (fast on non-AES-NI hardware) |

**TLS 1.2 (ECDHE + AEAD only):**
| Name | Description |
|------|-------------|
| `ECDHE-ECDSA-AES128-GCM-SHA256` | ECDSA key exchange, AES-128-GCM (default preference) |
| `ECDHE-RSA-AES128-GCM-SHA256` | RSA key exchange, AES-128-GCM (default preference) |
| `ECDHE-ECDSA-CHACHA20-POLY1305` | ECDSA key exchange, ChaCha20-Poly1305 |
| `ECDHE-RSA-CHACHA20-POLY1305` | RSA key exchange, ChaCha20-Poly1305 |
| `ECDHE-ECDSA-AES256-GCM-SHA384` | ECDSA key exchange, AES-256-GCM |
| `ECDHE-RSA-AES256-GCM-SHA384` | RSA key exchange, AES-256-GCM |

No CBC or non-AEAD cipher suites are supported.

**Example — restrict to AES-256 only:**
```bash
export FERRUM_TLS_CIPHER_SUITES="TLS_AES_256_GCM_SHA384,ECDHE-ECDSA-AES256-GCM-SHA384,ECDHE-RSA-AES256-GCM-SHA384"
```

### Supported Key Exchange Groups (Curves)

When `FERRUM_TLS_KEY_EXCHANGE_GROUPS` is not set, the gateway uses `X25519` and `secp256r1`. `FERRUM_TLS_CURVES` is accepted as an alias for existing deployments; the canonical variable wins if both are set.

| Name | Aliases | Description |
|------|---------|-------------|
| `X25519` | — | Curve25519 (modern, fast, recommended) |
| `secp256r1` | `P-256`, `P256` | NIST P-256 (widely compatible) |
| `secp384r1` | `P-384`, `P384` | NIST P-384 (stronger, slower) |

Curve names are case-insensitive.

Hybrid post-quantum groups such as Kyber/X25519 are not exposed by the current rustls/ring provider used by Ferrum. `FERRUM_TLS_KEY_EXCHANGE_GROUPS` is the stable operator-facing control point; supported hybrid names can be added there when the upstream provider exposes them.

**Example — X25519 only:**
```bash
export FERRUM_TLS_KEY_EXCHANGE_GROUPS="X25519"
```

**Example — all supported curves:**
```bash
export FERRUM_TLS_KEY_EXCHANGE_GROUPS="X25519,secp256r1,secp384r1"
```

### Server Cipher Order

When `FERRUM_TLS_PREFER_SERVER_CIPHER_ORDER` is `true` (the default), the server's cipher suite preference takes priority over the client's during TLS 1.2 negotiation. This ensures the gateway's configured preference is selected regardless of client ordering. TLS 1.3 does not use this setting (server always selects).

```bash
# Let server choose (recommended, default)
export FERRUM_TLS_PREFER_SERVER_CIPHER_ORDER="true"

# Let client choose
export FERRUM_TLS_PREFER_SERVER_CIPHER_ORDER="false"
```

### Verifying TLS Policy

The gateway logs the active TLS policy at startup:

```
TLS policy: versions=["TLS 1.2", "TLS 1.3"], cipher_suites=["TLS13_AES_128_GCM_SHA256", ...], curves=["X25519", "SECP256R1"], prefer_server_order=true
```

You can also verify externally:

```bash
# Check negotiated protocol and cipher
openssl s_client -connect localhost:8443 -tls1_3

# List supported ciphers
openssl s_client -connect localhost:8443 -cipher 'ALL' -tls1_2
```

## Integration with Load Balancers

When using load balancers:

1. **TLS Termination at Load Balancer**: Configure HTTP mode on the gateway and include the load balancer in `FERRUM_TRUSTED_PROXIES` so its `X-Forwarded-Proto: https` preserves the browser-facing secure scheme
2. **TLS Pass-Through**: Configure HTTPS/mTLS mode on gateway
3. **Health Checks**: Ensure health checks work with your TLS configuration

## Performance Considerations

- **TLS Handshake Overhead**: Initial connections have higher latency
- **Session Resumption**: Enabled by default. TLS 1.3 normally uses stateless auto-rotating tickets; HTTP/3 uses the bounded stateful cache sized by `FERRUM_TLS_SESSION_CACHE_SIZE` when server 0-RTT is explicitly enabled on a non-mTLS listener, because rustls requires stateful resumption for early data. TLS 1.2 uses the same bound for its stateful session ID cache. Resumption is disabled on an mTLS listener whose client-trust scope can advance under `FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED=true`, so a ticket cannot outlive an accepted client-CA or CRL withdrawal; static mTLS listeners retain normal resumption. Resumption otherwise saves 1 RTT on reconnections. 0-RTT remains disabled by default because of replay risk.
- **Hardware Acceleration**: Consider for high-throughput scenarios
- **Certificate Size**: Smaller certificates improve performance

## Migration Guide

### From HTTP to HTTPS

1. Obtain server certificate and private key
2. Set `FERRUM_FRONTEND_TLS_CERT_PATH` and `FERRUM_FRONTEND_TLS_KEY_PATH`
3. Update client applications to use HTTPS URLs
4. Test thoroughly before production deployment

### From HTTPS to mTLS

1. Obtain or create client CA certificate
2. Set `FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH`
3. Issue client certificates to authorized clients
4. Update client applications to present certificates
5. Gradually enforce mTLS (start with optional, then required)

## ACME Auto-Renewal Requires Frontend TLS Live Reload

`FERRUM_ACME_AUTO_RENEW_ENABLED=true` renews certificates **into the ACME
certificate store**. Getting the renewed leaf in front of clients is a separate
step, and it is not automatic:

1. A successful renewal commits the new material under the lease fence and then
   asks every TLS surface that registered a *force-reload sender* to rebuild.
2. Only surfaces with a registered sender are notified; an unregistered surface
   is silently skipped.
3. The proxy HTTPS/H2/H3 and admin HTTPS surfaces register their sender
   **exclusively from inside the frontend live-reload watcher**, and that watcher
   is not built at all when `FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED` is `false`
   (its default).

With auto-renew on and live reload off, renewals therefore succeed in the logs
and in `acme-certificates.json` while every client keeps receiving the previous
leaf — until it expires and HTTPS fails with the correct certificate already on
disk.

Ferrum **refuses to start** in that configuration rather than serving it. When
`FERRUM_ACME_AUTO_RENEW_ENABLED=true` and any of `FERRUM_FRONTEND_TLS_CERT_SOURCE`,
`FERRUM_FRONTEND_TLS_KEY_SOURCE`, `FERRUM_ADMIN_TLS_CERT_SOURCE`, or
`FERRUM_ADMIN_TLS_KEY_SOURCE` resolves to an `acme://` URI, startup and
`ferrum-edge validate` fail unless `FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED=true`.
The message names both variables and the offending source. Either set the
live-reload flag, or turn auto-renew off and renew out of band. The admin HTTPS
listener has no live-reload flag of its own: it shares
`FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED` with the proxy frontend.

A file-backed, `managed://`, or provider-URI serving source is unaffected — the
ACME scheduler does not renew it — and so is a deployment that simply leaves
`FERRUM_ACME_AUTO_RENEW_ENABLED=false`.

Gateway-API multi-certificate listeners are outside this check: their
certificates arrive in the control-plane config snapshot and the data plane
rebuilds the whole SNI resolver on each delivery, so they never depend on the
force-reload registry.

As a residual safety net for anything the startup check cannot see (a surface
registered later, or a sender that has since closed), a renewal that commits new
material but reaches no surface logs a `warn!` naming the certificate; a renewal
that does reach one logs the accepted surfaces at `info!`.

## Managed TLS And ACME Across Multiple Replicas

Admin-managed TLS records (`managed://`), ACME certificates/orders/accounts
(`acme://`), and the ACME renewal claims all live as JSON documents under
`FERRUM_TLS_MANAGED_STORE_PATH`. Several gateway instances may share that
directory.

### Deployment contract

- **Shared writable volume — supported.** Point every replica's
  `FERRUM_TLS_MANAGED_STORE_PATH` at the same directory on a filesystem that
  supports POSIX advisory locks (`flock`) — a local volume, a
  `ReadWriteMany` block/POSIX volume, or a host path shared by co-located
  pods. Reads are revalidated against the file on every access and writes are
  serialized read-modify-writes, so replicas see each other's records and
  interleaved updates never overwrite one another.
- **Per-replica (unshared) storage — single-writer only.** With per-pod
  volumes there is no shared state to coordinate: a record uploaded through
  replica A simply does not exist on replica B, and B can reject a config that
  A can serve. Run exactly one instance with admin mutations and auto-renew
  enabled, or move to a shared volume.
- **Network filesystems without working advisory locks** (some NFS setups)
  are not supported: mutual exclusion depends on `flock`, and without it the
  store degrades to the unsafe whole-file-rewrite behaviour.

### What is coordinated

| Concern | Mechanism |
| --- | --- |
| Cross-instance visibility | Every read revalidates the document against the file's replacement identity and re-reads on change. `managed://` / `acme://` source polling (`FERRUM_SECRET_REFRESH_INTERVAL_SECONDS`, or a per-source `?poll=`) therefore picks up another replica's rotation through the ordinary reload path. |
| Read availability | Reads never wait on the writer lock. Publication is fsync + atomic replacement of the destination (`rename(2)` on Unix; `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING \| MOVEFILE_WRITE_THROUGH` on Windows), so a reader observes one complete generation or the other and its next read detects the newer one. The destination is never unlinked first, so it is never observably absent — an absent store document reads as an empty one. Challenge lookups and admin reads cannot be stalled by a slow writer. |
| Runtime isolation of blocking work | Every mutation is a synchronous read-modify-write that can wait on the advisory lock for up to `FERRUM_TLS_STORE_LOCK_TIMEOUT_SECONDS`. Admin managed-TLS/ACME writes, account-credential mirroring, failed-order persistence, and every lease operation (acquire, heartbeat, fenced commit, refresh, release) therefore run on the blocking pool, never on a Tokio worker, so a contended or wedged shared volume cannot stall request serving. A write that cannot be driven to a conclusion is reported as a server error, never as success. Reads stay on the runtime because they take no lock. |
| Lost-update prevention | Each mutation takes an exclusive advisory lock on a sidecar `.<file>.lock`, re-reads the authoritative document under that lock, applies the change, and republishes atomically. Create-without-overwrite and cross-kind ID conflicts are evaluated against authoritative state, so a concurrent create returns `409` rather than silently replacing another instance's record. |
| Single renewer | Before renewing a certificate, an instance must win that certificate's claim in `tls-leases.json`. Exactly one holder is granted at a time — a live claim excludes *every* other acquirer, including one presenting the same instance identity — so two replicas cannot create duplicate orders or collide on challenge state. The claim is what excludes a second renewer; a persisted in-flight order never is. Every due certificate goes through the claim attempt first, and the authoritative order is read only by the winner. |
| Ownership for the whole operation | The winner heartbeats its claim at a third of the TTL for as long as the renewal runs, and every stretch of external work (account/order calls, the DNS-01 publication hook, the propagation wait, authorization polling, finalization, certificate download, and the DNS-01 *cleanup* hook) is cancelled if the claim is lost — so a superseded instance never retracts `_acme-challenge` records the new owner is about to revalidate. The cleanup hook additionally *refreshes* the claim under the lease store's own lock before it starts, rather than relying on the heartbeat having already published the loss: a takeover lands in the table before any beat has had a reason to notice it, and a retraction that is ready to run would otherwise complete inside that gap. Refreshing rather than merely re-reading also means the hook starts on a full TTL — a claim confirmed with a sliver of lifetime left could legally expire and be taken over between the check and the hook's first poll. A refresh that cannot be granted (taken over, expired, or a store error) abandons the renewal. |
| Fenced store commits | Each account/order/certificate write runs *while the lease table's exclusive lock is held*, after re-verifying holder, fence, and liveness under that lock. Acquisition and takeover block on the same lock, so a superseded instance cannot land a stale write alongside the new owner's — a before/after ownership check would detect that race but could not undo it. Final renewal publication persists the already-CA-valid order as `Valid` first and always attempts the certificate store second inside that same lease fence, even when the order write fails. The lease document itself is never rewritten by a commit, so a target-store error propagates without disturbing any holder's claim. The lock is held only across the synchronous write(s), never across a network call, hook, or sleep. Both writes succeed: reload is requested and the renewal counts as renewed. Order succeeds and certificate fails: no reload; prior material remains due; the now-`Valid` order does not block a later retry. Order fails and certificate succeeds: new material is authoritative and reload is requested, but the renewal is still reported as failed; the published certificate's exact non-empty `order_url` is durable completion evidence so a matching stale `Pending`/`Ready`/`Processing` order is not treated as active on a later scan. Both fail: no reload and an explicit combined failure (that storage-outage case may remain fail-closed). Lease loss before entering the fence performs neither write. |
| Crash recovery | A claim carries `expires_at` (`FERRUM_ACME_RENEWAL_LEASE_TTL_SECONDS`) and a monotonic fence. A dead holder runs no heartbeat, so the claim expires and another replica takes over; the dead holder's fence is stale, so it can no longer renew or release the claim if it comes back. The successor then **resumes that holder's authoritative persisted order** rather than skipping the certificate or ordering it again, including the window after the prior holder's finalize request already landed: the certificate key and CSR are generated during preparation and persisted with the order, so a `processing` or `valid` order is retrieved and paired with that key instead of being finalized a second time — see "Resuming a crashed renewer's order" below. |
| Fail-closed ambiguity | A lock that cannot be taken within `FERRUM_TLS_STORE_LOCK_TIMEOUT_SECONDS`, a malformed value for that setting, an unreadable, unparseable, or **oversized** document, an unreadable lease table, or any heartbeat error is an error. Admin mutations fail, HTTP-01/TLS-ALPN-01 challenges are not served from stale state, and the renewal is abandoned rather than run twice. A store that is merely *missing* is a successful empty store — that is a real answer, not a failure — but a store that cannot be opened or parsed is never reported as an empty one. Oversized candidate writes fail before rename and leave the previous authoritative generation intact. |
| Durable-state bounds | Each shared JSON document is capped by `FERRUM_TLS_STORE_MAX_DOCUMENT_BYTES` (bounded read through `limit+1`, serialize-then-reject before publication). Managed creates stop at `FERRUM_TLS_MANAGED_MAX_RECORDS`; ACME certificate/account creates stop at `FERRUM_TLS_ACME_MAX_CERTIFICATES` / `FERRUM_TLS_ACME_MAX_ACCOUNTS` while overwrite/delete remain available. Terminal ACME order history is pruned under the exclusive mutation to `FERRUM_TLS_ACME_TERMINAL_ORDER_HISTORY` per certificate and never removes pending/ready/processing orders, finalization material needed for crash recovery, current certificates, or active account credentials. `tls-events.json` is bounded before buffering/parsing and compacted atomically to its configured capacity. Leases keep their existing expiry retention under the common byte ceiling. Fixed-cardinality metrics (`ferrum_tls_store_*`) expose bytes/counts/prunes/refusals without IDs, domains, paths, or accounts. |
| Oversized-file recovery | Quarantine or replace the oversized document with a known-good backup from the shared volume. Do not truncate live material in place and do not empty a store that still holds active certificates or recoverable ACME finalization packages. Diagnostics and metrics stay secret-safe. |

### Resuming a crashed renewer's order

An ACME renewal persists its order before it can finish it. A holder that dies
after that fenced write — but before the final certificate/order publication —
leaves an authoritative order behind in `pending_challenges`, `ready`, or
`processing`. Its claim then expires and a successor takes over.

The successor **finishes that same order**. It never treats the leftover record
as a reason to skip the certificate (which would wedge renewal permanently,
since the record outlives the claim that produced it) and never creates a second
order with the CA:

- **The finalization material is generated first and persisted with the order.**
  The certificate private key and the CSR are produced during *preparation* —
  before the order is created with the CA and before the fenced order upsert —
  and are stored in the order record. This is what makes the post-finalize crash
  window recoverable at all. The ACME client's own convenience finalization
  generates a key *inside* the finalize call and only hands it back after the
  finalize POST has already succeeded, so a renewer that dies in that window
  would leave the CA issuing a certificate whose only matching key died with the
  process — and RFC 8555 does not allow a second finalize for an order that has
  left `ready`, so the successor could not re-key it either. Ferrum therefore
  finalizes with the persisted CSR and publishes against the persisted key.
- **Completion follows the CA's current state, not Ferrum's last-persisted one.**
  The order is re-fetched from the directory after the account is restored, and:
  - `pending` — each challenge endpoint is validated; a challenge that is still
    `pending` is notified ready once, while a challenge already `processing` or
    `valid` is left alone (a crashed holder can leave the order pending with a
    challenge already in flight), an `invalid` challenge fails closed, and the
    order is polled to `ready` under `FERRUM_ACME_RENEW_POLL_TIMEOUT_SECONDS`,
    then finalized once;
  - `ready` — exactly one finalize request is sent, carrying the persisted CSR;
    no key or CSR is ever generated at this point;
  - `processing` — the crashed renewer's finalize already landed, so **no second
    finalize is sent**; the certificate is polled for and paired with the
    persisted key;
  - `valid` — likewise no finalize; the certificate is retrieved and paired with
    the persisted key;
  - `invalid`, or an unusable/malformed state, fails closed.
- **Missing or corrupt material fails closed.** A resumable order that no longer
  carries a usable key/CSR is not completed, not replaced with a second CA
  order, and never re-keyed after the fact. Usability is checked before any
  directory request: the package must contain exactly one parseable private key;
  multiple keys or malformed trailing PEM input are rejected. The CSR DER must
  consume its entire input and verify its proof-of-possession signature, the
  private-key public SPKI must match the CSR SPKI, and the CSR DNS SAN set must
  exactly match the order's normalized domains (including wildcards; non-DNS
  SANs and duplicate/ambiguous names fail closed). It fails before the DNS-01
  hook or any directory request runs, and the record is left intact for
  inspection. Renewal diagnostics may identify the order, while the Admin API
  uses a fixed `400`; neither describes the material. The
  persisted finalization key and CSR never appear in a log, an error, a `Debug`
  rendering, or an Admin response: the material is deliberately absent from
  `AcmeOrderSummary` (so the Admin order shape and `openapi.yaml` are unchanged
  by it) and its `Debug` is a fixed placeholder. Existing authenticated order
  summaries continue to expose the documented challenge-setup fields; account
  credentials remain excluded.
- **Retention is tied to resumability.** The material is dropped in the same
  write that sets the order `Valid`, which is exactly when the order stops being
  resumable (`Valid` is terminal, so a later scan plans a fresh order with fresh
  material). All four partial-publication outcomes stay recoverable: the two
  where the order write lands reach `Valid` and no longer need it, and the two
  where the order write fails never touch the stored record, so a still-active
  order keeps the material its successor needs.

- **Claim first, decide second.** The per-certificate claim is attempted for
  every due certificate. Only after winning it is the latest authoritative order
  re-read. A replica that is not the renewer is turned away by lease denial and
  never selects an order at all.
- **Completed work is still recognised.** If the published certificate's exact,
  non-empty `order_url` matches the leftover order, that order is finished work
  (the material-published-but-`Valid`-write-failed case above) and a fresh order
  is planned instead. A different URL, an empty URL, a missing URL, or a missing
  certificate record is not completion evidence.
- **The order's own challenge type is used**, inferred from the challenge
  records it actually carries — not from whatever
  `FERRUM_ACME_RENEWAL_CHALLENGE_TYPE` is set to now. Exactly one non-empty
  challenge family is required; no families or more than one is an explicit
  failure and the order is left untouched. Diagnostics name the order id only,
  never a token, key authorization, or account credential.
- **HTTP-01 and TLS-ALPN-01 need nothing republished.** The shared challenge
  resolvers answer out of the order store for any order still in an active
  status, so the prior renewer's tokens keep being served while the successor
  polls for completion.
- **DNS-01 is re-presented through the hook.** Those records live in the
  operator's DNS provider, so the successor republishes the stored challenges
  with `FERRUM_ACME_DNS01_HOOK_COMMAND`, honours
  `FERRUM_ACME_DNS01_PROPAGATION_SECONDS`, and runs the same lease-guarded
  cleanup afterwards. **A resumed DNS-01 order therefore requires the DNS hook
  to still be configured.** If it is not, the order is skipped explicitly — it
  is not deleted, not marked complete, and not counted as renewed — and the
  certificate stays due until a hook is configured again.
- **Losing the claim mid-resume abandons the work** at exactly the points a
  newly prepared renewal does: no further store writes, no DNS cleanup, no
  reload.

Order age is deliberately not consulted. Lease ownership plus persisted state is
the whole recovery authority.

### Operational notes

- Store files (including `tls-leases.json` and the `.lock` sidecars) are
  created with owner-only permissions on Unix. The lease table holds only
  instance identities and timestamps — no certificates, keys, or account
  credentials.
- `FERRUM_TLS_STORE_INSTANCE_ID` pins a stable, attributable identity for this
  replica's claims (for example the pod name). It does **not** let a restarting
  replica reclaim its own still-live claim: a live claim excludes every
  acquirer, because two processes can legitimately present the same identity
  (a duplicated setting, or an overlapping rolling replacement) and letting the
  newcomer in would start a second renewal while the first is still mid-ACME.
  A restarted replica waits out the previous claim's expiry, which is the same
  path a crash takes. The value is validated, never sanitized: an empty,
  overlong (>128 characters), or otherwise disallowed value fails startup of
  the store rather than being silently folded onto another identity. Permitted
  characters are `A-Z a-z 0-9 - _ . :`. Leave the setting unset for a generated
  per-process identity, which is always valid and always distinct.
- `FERRUM_ACME_RENEWAL_LEASE_TTL_SECONDS` no longer has to cover a whole ACME
  cycle, because the heartbeat extends the claim while the renewal runs; it has
  to cover one heartbeat interval (a third of the TTL) plus scheduling slack,
  and it is how long a *crashed* holder's certificate stays unrenewable. Note
  that the TTL by itself guarantees nothing: ACME does not fence side effects
  for Ferrum, so a renewal that outran a static TTL would previously have
  overlapped with its successor. Continuous maintenance plus
  cancel-on-loss — not the TTL value — is what bounds overlap.
- **DNS-01 hook cancellation stops the process Ferrum started, not its
  descendants.** A DNS-01 hook is a child process, and cancelling the renewal
  cancels it: the hook is spawned with kill-on-drop, so losing the claim
  terminates the running hook instead of leaving it free to publish or retract
  `_acme-challenge` records the new owner depends on. That guarantee covers the
  **direct child**. A hook that forks detached descendants — a backgrounded
  provider client, a shell wrapper that returns before its work finishes — is
  outside Ferrum's reach on every supported platform, because only the hook
  itself can put that work in a process group or job object. Write hooks that
  do their work in the foreground; if a hook must spawn background work, make
  it idempotent and safe to interleave with another replica performing the same
  publication.
- **An abandoned renewal releases its claim off the runtime.** Normal
  completion settles the heartbeat and then awaits the release, so the claim is
  observably free when the renewal returns. An *abandoned* renewal — an early
  return, a panic, a cancelled scheduler — cannot await anything, so the release
  is handed to the blocking pool instead of running inline; a lock-taking
  release on a Tokio worker would park that worker for up to
  `FERRUM_TLS_STORE_LOCK_TIMEOUT_SECONDS`. If it cannot be scheduled at all the
  claim is simply not released and lapses at `expires_at`, which is the same
  path a crash takes. Never releasing is safe; stalling the runtime is not.
- Managed TLS and ACME admin endpoints use the non-topology admin write gate
  (read-only mode and database-unavailable) only. They deliberately do not
  acquire a config-database write-topology pin and are not gated by
  `FERRUM_DB_FAILOVER_ALLOW_WRITES`: these stores are independent of the
  configuration database, and slow ACME network work must not defer database
  failover or failback.
