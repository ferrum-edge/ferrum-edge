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
The no-verify mode is designed for development, testing, and isolated environments where certificate verification is not practical.

#### **Risks**
- **Security Risk**: Disables ALL certificate verification
- **Man-in-the-Middle**: Vulnerable to certificate spoofing attacks
- **Production Warning**: NEVER use in production environments

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

## Certificate Reload Behavior

Frontend proxy, Admin API, and frontend DTLS cert/key/client-CA/OCSP/CRL sources can opt in to live reload with `FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED=true`. Sources supplied as paths or `file://` URIs are polled by material byte fingerprint using `FERRUM_FRONTEND_TLS_WATCH_INTERVAL_SECONDS`. Provider URI sources (`vault://`, `aws://`, `azure://`, `gcp://`) are fetched through the matching secret-provider backend and polled with `FERRUM_SECRET_REFRESH_INTERVAL_SECONDS` unless the URI includes `?poll=` (for example, `vault://secret/data/edge#cert?poll=60s`). Kubernetes Secret URI sources (`k8s://namespace/secret#key`) also register a Kubernetes watch on the named Secret and queue an immediate reload when cert-manager or another controller updates it; polling remains the fallback and debounce. A `pkcs11://` frontend/admin key source is tracked by stable selector fingerprint so adjacent cert, client-CA, OCSP, and CRL rotations still reload; changing the HSM key behind the same URI requires a config/source change or restart. Each rebuild re-proves that the token key pairs with the rotated leaf certificate, so a rotation onto a mismatched pair fails the rebuild and the previous known-good `ServerConfig` stays published. Inline PEM remains static until config reload. Provider URI sources require the matching secret-provider Cargo feature and use the same credentials/configuration as the existing `_VAULT`, `_AWS`, `_AZURE`, and `_GCP` env-var suffixes.

| Category | Environment Variables |
|----------|---------------------|
| **Frontend proxy live reload** | `FERRUM_FRONTEND_TLS_CERT_PATH` / `_SOURCE`, `FERRUM_FRONTEND_TLS_KEY_PATH` / `_SOURCE`, `FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH` / `_SOURCE`, `FERRUM_FRONTEND_TLS_OCSP_RESPONSE_SOURCE`, `FERRUM_TLS_CRL_FILE_PATH` / `_SOURCE` when any active source is file/provider/Kubernetes/managed-backed |
| **Admin API live reload** | `FERRUM_ADMIN_TLS_CERT_PATH` / `_SOURCE`, `FERRUM_ADMIN_TLS_KEY_PATH` / `_SOURCE`, `FERRUM_ADMIN_TLS_CLIENT_CA_BUNDLE_PATH` / `_SOURCE`, `FERRUM_ADMIN_TLS_OCSP_RESPONSE_SOURCE`, `FERRUM_TLS_CRL_FILE_PATH` / `_SOURCE` when any active source is file/provider/Kubernetes/managed-backed |
| **Frontend DTLS live reload** | `FERRUM_DTLS_CERT_PATH` / `_SOURCE`, `FERRUM_DTLS_KEY_PATH` / `_SOURCE`, `FERRUM_DTLS_CLIENT_CA_CERT_PATH` / `_SOURCE`, `FERRUM_TLS_CRL_FILE_PATH` / `_SOURCE` when any active source is file/provider/Kubernetes/managed-backed |
| **Backend TLS live reload** | `FERRUM_BACKEND_TLS_CLIENT_CERT_PATH` / `_SOURCE`, `FERRUM_BACKEND_TLS_CLIENT_KEY_PATH` / `_SOURCE`, `FERRUM_TLS_CA_BUNDLE_PATH` / `_SOURCE`, per-proxy/per-upstream backend TLS source fields, and `FERRUM_TLS_CRL_FILE_PATH` / `_SOURCE` |
| **Database TLS live reload** | `FERRUM_DB_TLS_CA_CERT_PATH` / `_SOURCE`, `FERRUM_DB_TLS_CLIENT_CERT_PATH` / `_SOURCE`, and `FERRUM_DB_TLS_CLIENT_KEY_PATH` / `_SOURCE` in database/CP modes when `FERRUM_DB_TLS_LIVE_RELOAD_ENABLED=true` |
| **CP gRPC TLS live reload** | `FERRUM_CP_GRPC_TLS_CERT_PATH` / `_SOURCE`, `FERRUM_CP_GRPC_TLS_KEY_PATH` / `_SOURCE`, and `FERRUM_CP_GRPC_TLS_CLIENT_CA_PATH` / `_SOURCE` in CP mode |
| **DP gRPC TLS live reload** | `FERRUM_DP_GRPC_TLS_CA_CERT_PATH` / `_SOURCE`, `FERRUM_DP_GRPC_TLS_CLIENT_CERT_PATH` / `_SOURCE`, and `FERRUM_DP_GRPC_TLS_CLIENT_KEY_PATH` / `_SOURCE` in DP mode |
| **Loaded but static** | Inline frontend/admin/DTLS/backend/database/CP-gRPC/DP-gRPC sources |
| **SVID file rotation** | `FERRUM_GATEWAY_SVID_*_PATH` / `_SOURCE` when all three sources are file-backed |

All TLS sources are validated at startup and config load time when their owning runtime is built. Certificate and CA bundles are atomic: Ferrum rejects the complete candidate if any declared `CERTIFICATE` record is malformed or any CA record cannot be admitted as a trust root; it never installs a usable subset. If any configured certificate, key, CA bundle, OCSP response, or CRL source is missing, unreadable, expired, not-yet-valid, mismatched, or contains invalid PEM data where PEM is expected, the gateway refuses to start or rejects the config reload. OCSP response sources must resolve to non-empty DER bytes. There is no silent fallback to unauthenticated or unencrypted connections. Client cert and key sources must always be configured as a pair.

Certificate/key PEM parsing is capped at 4 MiB per source and certificate
bundles at 4096 records. A configured client-CA is still fully admitted when a
testing-only no-verify mode disables use of its verifier. DTLS server identity
sources accept a complete leaf-first certificate chain. Ferrum admits every
declared record atomically, verifies the leaf against the configured private
key, and transmits the complete chain; it never publishes only a usable prefix.

The frontend/admin live-reload poller atomically swaps a validated `rustls::ServerConfig` for new handshakes. The frontend DTLS poller swaps the active DTLS server material for new DTLS sessions. Existing TLS/DTLS sessions keep the config they negotiated with. A failed reload keeps the previous config in service and logs a warning without exposing PEM contents.

For backend HTTP-family TLS, keep `FERRUM_BACKEND_TLS_LIVE_RELOAD_ENABLED=true` to pick up in-place cert/key/CA/CRL source changes and to watch backend TLS sources added by later config reloads. Database TLS can opt in with `FERRUM_DB_TLS_LIVE_RELOAD_ENABLED=true` in database and CP modes. CP gRPC TLS swaps the server TLS slot for new handshakes when watched source bytes change; DP gRPC TLS reconnects the CP stream with fresh client-side TLS material.

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

> **Note:** DTLS (UDP-TLS) uses `dimpl` which has its own cipher negotiation independent of rustls. These TLS policy settings do not affect DTLS connections. `FERRUM_TLS_PREFER_SERVER_CIPHER_ORDER` and `FERRUM_TLS_SESSION_CACHE_SIZE` only apply to inbound listeners.

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
- **Session Resumption**: Enabled by default. TLS 1.3 normally uses stateless auto-rotating tickets; HTTP/3 uses the bounded stateful cache sized by `FERRUM_TLS_SESSION_CACHE_SIZE` when server 0-RTT is explicitly enabled on a non-mTLS listener, because rustls requires stateful resumption for early data. TLS 1.2 uses the same bound for its stateful session ID cache. Resumption saves 1 RTT on reconnections. 0-RTT remains disabled by default because of replay risk.
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
