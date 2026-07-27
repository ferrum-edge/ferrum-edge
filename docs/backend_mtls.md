# Backend mTLS Configuration

This document explains how to configure backend mutual TLS (mTLS) authentication in Ferrum Edge.

## Overview

Backend mTLS allows the gateway to authenticate itself to backend services using client certificates. This is commonly used when backend services require certificate-based authentication.

## Configuration

### Global Environment Variables

Set these environment variables to configure client certificates and CA verification for all backend connections:

```bash
# Path to CA bundle for backend TLS verification (overrides system trust store)
export FERRUM_TLS_CA_BUNDLE_PATH="/path/to/ca-bundle.pem"

# Optional source override for the CA bundle. Source values accept a path,
# file:// URI, or inline PEM beginning with -----BEGIN .
export FERRUM_TLS_CA_BUNDLE_SOURCE="file:///path/to/ca-bundle.pem"

# Path to client certificate file (PEM format)
export FERRUM_BACKEND_TLS_CLIENT_CERT_PATH="/path/to/client-cert.pem"

# Optional source override for the client certificate
export FERRUM_BACKEND_TLS_CLIENT_CERT_SOURCE="file:///path/to/client-cert.pem"

# Path to client private key file (PEM format)  
export FERRUM_BACKEND_TLS_CLIENT_KEY_PATH="/path/to/client-key.pem"

# Optional source override for the client private key. With the pkcs11 Cargo
# feature, this may be a non-extractable RSA token key.
export FERRUM_BACKEND_TLS_CLIENT_KEY_SOURCE="file:///path/to/client-key.pem"
# export FERRUM_BACKEND_TLS_CLIENT_KEY_SOURCE="pkcs11://backend-rsa?pin_env=FERRUM_PKCS11_PIN"

# Disable backend TLS certificate verification (testing only)
export FERRUM_TLS_NO_VERIFY="true"
```

When both a `_PATH` and `_SOURCE` variable are set, `_SOURCE` wins and the startup warning names only the variable names, not the material. Inline PEM is redacted in debug output and hashed in backend pool keys so private-key bytes are not logged or embedded in cache identifiers.

### Custom CA Bundles

The `FERRUM_TLS_CA_BUNDLE_PATH` allows you to specify custom Certificate Authority (CA) bundles for backend TLS verification. This is useful for:

- **Enterprise Environments**: When backend services use certificates from private CAs
- **Development**: Using self-signed certificates in testing environments
- **Security**: Fine-grained control over trusted CAs beyond system defaults
- **Compliance**: Meeting regulatory requirements for certificate validation

**How it works:**
- The CA bundle is loaded when a connection pool entry is first created for a proxy
- Works with all backend protocols: HTTP/1.1, H2, HTTP/3, gRPC, WebSocket (wss://), and TCP/TLS
- Per-proxy `backend_tls_server_ca_cert_path` takes priority over the global `FERRUM_TLS_CA_BUNDLE_PATH` / `FERRUM_TLS_CA_BUNDLE_SOURCE`

**CA Trust Fallback Chain:**

The gateway resolves backend CA trust in the following order:

1. **Proxy-specific CA** (`backend_tls_server_ca_cert_path`) — verify with **only** that CA. Webpki/system roots are excluded to prevent public CAs from being trusted alongside your internal CA.
2. **Global CA bundle** (`FERRUM_TLS_CA_BUNDLE_PATH` / `FERRUM_TLS_CA_BUNDLE_SOURCE`) — verify with **only** the global CA. Same exclusivity as proxy-specific.
3. **Neither set** — verify with **bundled webpki roots** (secure default). The gateway does **not** skip verification when no CA is configured.
4. **Explicit opt-out** — `backend_tls_verify_server_cert: false` on a per-proxy basis, or `FERRUM_TLS_NO_VERIFY=true` globally, skips all certificate verification. These are the **only** ways to disable verification and should never be used in production.

**CA exclusivity**: When a custom CA is configured, it is the sole trust anchor. This prevents a backend pinned to an internal CA from being MITMed via any publicly-trusted certificate. If you need both internal and public CAs trusted, combine them into a single PEM bundle file.

No-verify changes handshake verification only. Ferrum still materializes and
atomically validates any explicitly declared custom CA for HTTP-family, gRPC
health-probe, DTLS, LDAP, TCP logging, and WebSocket logging clients. An empty,
malformed, or unusable selected bundle is therefore a configuration error even
when verification is disabled.

> **Trust roots — backend proxy path.**
> The proxy backend path (HTTP/1.1, H2, HTTP/3, gRPC, WebSocket, TCP/TLS) builds its trust store in-house from `webpki-roots`'s `TLS_SERVER_ROOTS` and hands the resulting `rustls::ClientConfig` to reqwest via `use_preconfigured_tls(...)`. That means the "no custom CA" fallback always uses bundled webpki on every platform — Linux, macOS, and Windows — regardless of OS keychain contents. Only the `FERRUM_TLS_CA_BUNDLE_PATH` / `_SOURCE` or per-proxy CA paths can change which roots the gateway trusts for backend traffic.

> **Trust roots — internal helper clients.**
> A few internal-helper reqwest clients (active health-check probes, plugin outbound HTTP via `PluginHttpClient`, the `spec_expose` plugin) do not preconfigure TLS. As of reqwest 0.13 those clients use `rustls-platform-verifier`, which resolves trust roots from the **OS keychain on macOS/Windows** and falls through to bundled webpki on Linux. For containerised production deploys (the supported target) behaviour is identical to pre-0.13. Operators running the gateway locally on macOS/Windows will see helper-client TLS verified against their OS keychain unless a `FERRUM_TLS_CA_BUNDLE_PATH` / `_SOURCE` or per-plugin CA is configured (in which case the custom CA replaces the trust store wholesale, per the exclusivity rule above).

Backends using certificates from public CAs work out of the box with no CA configuration. Backends using internal or self-signed certificates require either a proxy-specific or global CA bundle.

**CA Bundle Format:**
```bash
# Multiple CAs can be combined in one file
cat ca1.pem ca2.pem ca3.pem > ca-bundle.pem

# Or create a single file with multiple certificates
cat > ca-bundle.pem << EOF
-----BEGIN CERTIFICATE-----
# First CA certificate
-----END CERTIFICATE-----

-----BEGIN CERTIFICATE-----
# Second CA certificate  
-----END CERTIFICATE-----
EOF
```

Custom CA and client-certificate bundles are admitted atomically. Every
declared `CERTIFICATE` record must parse, every custom CA record must be usable
as a trust root, and a selected custom bundle must contain at least one
certificate. A failure rejects the complete startup/reload candidate; Ferrum
never installs only the surviving subset, and existing live pools/health
clients keep their last-known-good generation. Shared PEM admission limits each
certificate/key source to 4 MiB and each certificate bundle to 4096 records so
provider- or file-controlled input cannot drive unbounded parsing work.

### Per-Proxy Configuration

You can also configure mTLS on a per-proxy basis in your configuration files:

```yaml
proxies:
  - id: "secure-api"
    listen_path: "/api"
    backend_scheme: "https"
    backend_host: "secure-backend.example.com"
    backend_port: 443
    # Proxy-specific mTLS configuration (overrides global)
    backend_tls_client_cert_path: "/path/to/proxy-specific-cert.pem"
    backend_tls_client_key_path: "/path/to/proxy-specific-key.pem"
```

## Configuration Priority

1. **Proxy-specific configuration** takes priority over global settings
2. **Global environment variables** are used when proxy doesn't have specific mTLS config
3. **No mTLS** is applied when neither is configured

## Certificate Requirements

- **Format**: PEM encoded
- **Certificate**: X.509 certificate chain in leaf-first order. DTLS 1.2 and
  1.3 transmit the complete configured client chain.
- **Private Key**: Unencrypted private key (RSA or ECDSA), or a `pkcs11://` RSA signer URI when Ferrum is built with the `pkcs11` feature
- **Sources**: File paths and `file://` URIs must be readable by the gateway process; inline PEM must contain the full PEM block

## Usage Examples

### Example 1: Global mTLS Configuration

```bash
# Set global mTLS certificates
export FERRUM_BACKEND_TLS_CLIENT_CERT_PATH="/etc/ssl/certs/gateway-client.pem"
export FERRUM_BACKEND_TLS_CLIENT_KEY_PATH="/etc/ssl/private/gateway-client-key.pem"

# Start gateway
./ferrum-edge run
```

### Example 2: Mixed Configuration

```bash
# Set global mTLS for most backends
export FERRUM_BACKEND_TLS_CLIENT_CERT_PATH="/etc/ssl/certs/default-client.pem"
export FERRUM_BACKEND_TLS_CLIENT_KEY_PATH="/etc/ssl/private/default-client-key.pem"

# Configure specific proxy with different certificates
cat > config.yaml << EOF
proxies:
  - id: "public-api"
    listen_path: "/public"
    backend_host: "public-api.example.com"
    # Uses global mTLS settings
    
  - id: "secure-api"  
    listen_path: "/secure"
    backend_host: "secure-api.example.com"
    # Override with specific certificates
    backend_tls_client_cert_path: "/etc/ssl/certs/secure-client.pem"
    backend_tls_client_key_path: "/etc/ssl/private/secure-client-key.pem"
EOF

./ferrum-edge run --mode file --spec config.yaml
```

## Testing

The gateway includes comprehensive tests for mTLS functionality:

```bash
# Run mTLS tests
cargo test --test backend_mtls_tests

# Run specific test
cargo test test_backend_mtls_global_config -- --nocapture
```

## Troubleshooting

### Common Issues

1. **Certificate File Not Found**
   ```
   Error: Failed to read client certificate from /path/to/cert.pem: No such file or directory
   ```
   **Solution**: Ensure certificate files exist and are readable by the gateway process.

2. **Invalid Certificate Format**
   ```
   Error: Failed to parse client certificate/key: invalid PEM format
   ```
   **Solution**: Verify certificates are in PEM format and not corrupted.

3. **Certificate/Key Mismatch**
   ```
   Error: Failed to parse client certificate/key: private key does not match certificate
   ```
   **Solution**: Ensure the private key matches the certificate.

4. **Backend Certificate Verification**
   ```
   Error: TLS handshake failed: certificate verification failed
   ```
   **Solution**: The backend may not trust the client certificate. Ensure the backend is configured to accept the client certificate.

### Debug Tips

1. **Enable Debug Logging**
   ```bash
   RUST_LOG=debug ./ferrum-edge run
   ```

2. **Test Certificate Loading**
   ```bash
   # Test if certificates can be loaded
   openssl x509 -in /path/to/cert.pem -text -noout
   openssl rsa -in /path/to/key.pem -check
   ```

3. **Verify Backend mTLS Configuration**
   Use tools like `openssl s_client` to test mTLS against the backend:
   ```bash
   openssl s_client -connect backend.example.com:443 \
     -cert /path/to/cert.pem \
     -key /path/to/key.pem
   ```

## Security Considerations

1. **File Permissions**: Protect private key files with appropriate permissions (600 or 400).
2. **Key Storage**: Consider using hardware security modules (HSMs) for production environments. Backend mTLS client keys can use `pkcs11://` RSA signer URIs when Ferrum is built with the `pkcs11` feature; see [pkcs11_tls.md](pkcs11_tls.md).
3. **Certificate Rotation**: Keep `FERRUM_BACKEND_TLS_LIVE_RELOAD_ENABLED=true` so backend cert/key/CA/CRL source changes are validated, backend CRLs are refreshed, HTTP-family backend pools are cleared, and active health checks restart with the rotated material.
4. **Monitoring**: Monitor certificate expiration and renewal.

### Operational Contract for Backend TLS Sources

Ferrum Edge loads backend TLS material from the configured sources and can refresh the HTTP-family backend pools when watched source bytes change:

- **Backend client certs, backend client keys, backend CA bundles, and CRLs** are validated at config load time and then loaded into protocol-specific backend TLS configs when those connection pools are created.
- **Config reload** updates routing and resources. Backend TLS live reload is the mechanism for in-place source byte changes at the same path or URI.

This matters in Kubernetes and similar environments:

- A mounted `Secret`, `ConfigMap`, CSI certificate volume, or sidecar-managed shared volume can update files at the same path while the Pod is still running.
- With `FERRUM_BACKEND_TLS_LIVE_RELOAD_ENABLED=true` (default), Ferrum watches backend TLS cert/key/CA/CRL sources, validates the active backend TLS configs on changed bytes, refreshes the backend CRL slot, clears HTTP-family backend client pools, and restarts active health checks. Existing in-flight backend requests keep their current connections; new backend connections rebuild from the rotated material.
- The backend watcher recollects sources from the current gateway config on each pass. After a file-mode SIGHUP reload, database poll, or CP/DP config push adds or replaces backend TLS source URIs, those new sources are watched without restarting Ferrum.
- Watched backend TLS sources include global backend mTLS env vars, per-proxy settings, per-upstream settings, and direct-backend `mesh_route_dispatch.rules[].destination.backend_tls` overrides.
- If you disable backend TLS live reload, treat in-place backend certificate rotation as requiring a **rolling redeploy / rolling restart** of Ferrum pods.

Recommended practice:

- Store TLS materials in Kubernetes `Secret` objects or your preferred cert delivery mechanism.
- Update the Secret or mounted files as usual.
- Keep backend TLS live reload enabled for file/provider/Kubernetes/managed-backed sources, or trigger a **rolling restart** of the Deployment/StatefulSet after rotation if you intentionally disable it.

Admin-managed backend certificate resources can be referenced with `managed://` source URIs. Managed TLS IDs are globally unique across material kinds; typed admin create-with-overwrite and PUT reject cross-kind collisions with `409 Conflict`. Same-kind updates request active TLS source reload watchers immediately and keep existing `managed://` references valid.

## Implementation Details

The mTLS implementation uses:

- **reqwest**: HTTP client with TLS support
- **rustls**: TLS library for secure connections
- **Connection Pooling**: mTLS clients are pooled and reused efficiently
- **Override Logic**: Proxy-specific settings override global environment variables

### Connection Pool Behavior

- **Fail-fast on bad certificates**: All backend TLS certificate sources — both global env vars (`FERRUM_BACKEND_TLS_CLIENT_CERT_PATH` / `_SOURCE`, `FERRUM_BACKEND_TLS_CLIENT_KEY_PATH` / `_SOURCE`, `FERRUM_TLS_CA_BUNDLE_PATH` / `_SOURCE`, `FERRUM_TLS_CRL_FILE_PATH` / `_SOURCE`) and per-proxy fields (`backend_tls_client_cert_path`, `backend_tls_client_key_path`, `backend_tls_server_ca_cert_path`) — are validated at startup and config load time when they are file-backed, inline PEM, provider-backed (`vault://`, `aws://`, `azure://`, `gcp://`), Kubernetes Secret-backed (`k8s://namespace/secret#key`), admin-managed (`managed://certificates/id#cert`, `managed://certificates/id#key`, `managed://ca-bundles/id`, `managed://crls/id`), or PKCS#11-backed (`pkcs11://label?...`) for client keys. Provider URI sources require the matching secret-provider Cargo feature and use the same credentials/configuration as the existing `_VAULT`, `_AWS`, `_AZURE`, and `_GCP` env-var suffixes. Kubernetes sources use the default `kube` client environment. Managed sources are stored under `FERRUM_TLS_MANAGED_STORE_PATH`. PKCS#11 key sources require the `pkcs11` Cargo feature and a token RSA key matching the configured selector, and that key must also be proven to pair with the configured client certificate before the backend client identity is published; see [pkcs11_tls.md](pkcs11_tls.md). If any configured source is missing, unreadable, unsupported by the current build, unreachable, or contains invalid/corrupt material, the gateway **refuses to start** or rejects the config reload. There is no silent fallback to unauthenticated connections or to webpki-only verification when a configured CA source fails to load. Cert and key sources must always be configured as a pair; setting one without the other is a validation error. CA and CRL sources are independent — you can set just a CA to verify a server without presenting client identity.
- **TLS source deduplication**: When multiple proxies share the same cert/key/CA/CRL source values, each unique source is parsed only once during validation. This avoids redundant disk I/O and PEM parsing at config load time.
- **Pool-per-cert-source**: Each unique combination of `backend_tls_client_cert_path`, `backend_tls_client_key_path`, and `backend_tls_server_ca_cert_path` produces a **separate connection pool entry** per protocol. Inline PEM values are represented by a SHA-256 source component instead of the raw PEM; PKCS#11 values use the URI selector as the non-secret pool key component:
  - **HTTP/1.1 + H2** (`ConnectionPool`): separate `reqwest::Client` instances keyed by `host:port:protocol:dns_override:ca_path`
  - **HTTP/3** (`Http3ConnectionPool`): separate `rustls::ClientConfig` + QUIC endpoints per proxy
  - **gRPC** (`GrpcConnectionPool`): separate `rustls::ClientConfig` + H2 senders per target
  - **HTTP/2 direct** (`Http2ConnectionPool`): separate `rustls::ClientConfig` + H2 senders per target
  - **TCP/TLS**: separate `rustls::ClientConfig` cached per listener lifecycle
  - **WebSocket (wss://)**: `rustls::ClientConfig` built per connection (no persistent pool)

  Two proxies pointing at the same backend host but with different cert sources will **not** share connections. This is required because `reqwest::Client` and `rustls::ClientConfig` bake TLS identity and root certificates in at build time. Changing a proxy's cert sources in a config reload creates a new pool entry on the next request; the old pool entry is eventually evicted by idle timeout.
- File-backed sources are read at validation time (startup/config load) and when the connection pool entry is first created. Inline PEM sources are materialized directly from the configured value. Subsequent requests reuse the cached client.
- Replacing the contents of a watched cert/key/CA/CRL file at the **same path** refreshes already-built HTTP-family backend TLS configs when backend TLS live reload is enabled. If you disable it, use a process restart, Kubernetes rolling redeploy, or an effective config change that produces a new pool key to pick up in-place rotations.
- If certificate source loading or parsing fails at request time (e.g., file deleted after startup), the request fails with an error. This behavior is consistent across all backend protocols (HTTP/1.1, H2, and HTTP/3). The gateway continues running and serves other proxies normally.
- Connection reuse respects the original mTLS configuration

## Testing with Self-Signed Certificates

### No-Verify Mode (Testing Only)

For development and testing environments where certificate verification is not practical, you can disable backend TLS verification:

```bash
export FERRUM_TLS_NO_VERIFY="true"
```

**⚠️ Security Warning**: No-verify mode disables ALL certificate verification and should NEVER be used in production environments.

**Use Cases:**
- **Development**: Testing with self-signed backend certificates
- **Staging**: Temporary environments with invalid certificates
- **Internal Networks**: Isolated environments where verification is not needed

**Gateway Behavior:**
- Logs warning: "Backend TLS certificate verification DISABLED (testing mode)"
- Accepts any certificate (including self-signed and expired)
- Still uses TLS encryption, just skips verification

For development and testing, you can generate self-signed certificates:

```bash
# Generate private key
openssl genrsa -out client-key.pem 2048

# Generate certificate signing request
openssl req -new -key client-key.pem -out client.csr

# Generate self-signed certificate
openssl x509 -req -days 365 -in client.csr -signkey client-key.pem -out client-cert.pem

# Clean up CSR
rm client.csr
```

## Migration from Previous Versions

If upgrading from a version without mTLS support:

1. No breaking changes - existing configurations continue to work
2. Add environment variables or proxy configuration as needed
3. Test with non-production backends first
4. Monitor logs for certificate-related errors

## Performance Impact

- **Certificate Loading**: One-time cost per client creation
- **Connection Pooling**: Minimal impact after initial setup
- **TLS Handshake**: Slightly increased due to client certificate verification
- **Memory**: Small increase due to certificate storage in connection pool

Overall performance impact is minimal when connection pooling is enabled.
