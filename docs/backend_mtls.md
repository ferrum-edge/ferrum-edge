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

# Path to client certificate file (PEM format)
export FERRUM_BACKEND_TLS_CLIENT_CERT_PATH="/path/to/client-cert.pem"

# Path to client private key file (PEM format)  
export FERRUM_BACKEND_TLS_CLIENT_KEY_PATH="/path/to/client-key.pem"

# Disable backend TLS certificate verification (testing only)
export FERRUM_TLS_NO_VERIFY="true"
```

### Custom CA Bundles

The `FERRUM_TLS_CA_BUNDLE_PATH` allows you to specify custom Certificate Authority (CA) bundles for backend TLS verification. This is useful for:

- **Enterprise Environments**: When backend services use certificates from private CAs
- **Development**: Using self-signed certificates in testing environments
- **Security**: Fine-grained control over trusted CAs beyond system defaults
- **Compliance**: Meeting regulatory requirements for certificate validation

**How it works:**
- The CA bundle is loaded when a connection pool entry is first created for a proxy
- Works with all backend protocols: HTTP/1.1, H2, HTTP/3, gRPC, WebSocket (wss://), and TCP/TLS
- Per-proxy `backend_tls_server_ca_cert_path` takes priority over the global `FERRUM_TLS_CA_BUNDLE_PATH`

**CA Trust Fallback Chain:**

The gateway resolves backend CA trust in the following order:

1. **Proxy-specific CA** (`backend_tls_server_ca_cert_path`) — verify with **only** that CA. Webpki/system roots are excluded to prevent public CAs from being trusted alongside your internal CA.
2. **Global CA bundle** (`FERRUM_TLS_CA_BUNDLE_PATH`) — verify with **only** the global CA. Same exclusivity as proxy-specific.
3. **Neither set** — verify with **webpki/system roots** (secure default). The gateway does **not** skip verification when no CA is configured.
4. **Explicit opt-out** — `backend_tls_verify_server_cert: false` on a per-proxy basis, or `FERRUM_TLS_NO_VERIFY=true` globally, skips all certificate verification. These are the **only** ways to disable verification and should never be used in production.

**CA exclusivity**: When a custom CA is configured, it is the sole trust anchor. This prevents a backend pinned to an internal CA from being MITMed via any publicly-trusted certificate. If you need both internal and public CAs trusted, combine them into a single PEM bundle file.

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

### Per-Proxy Configuration

You can also configure mTLS on a per-proxy basis in your configuration files:

```yaml
proxies:
  - id: "secure-api"
    listen_path: "/api"
    backend_protocol: "https"
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
- **Certificate**: X.509 certificate chain
- **Private Key**: Unencrypted private key (RSA or ECDSA)
- **Files**: Must be readable by the gateway process

## Usage Examples

### Example 1: Global mTLS Configuration

```bash
# Set global mTLS certificates
export FERRUM_BACKEND_TLS_CLIENT_CERT_PATH="/etc/ssl/certs/gateway-client.pem"
export FERRUM_BACKEND_TLS_CLIENT_KEY_PATH="/etc/ssl/private/gateway-client-key.pem"

# Start gateway
./ferrum-edge
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

./ferrum-edge --mode file --config config.yaml
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
   RUST_LOG=debug ./ferrum-edge
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
2. **Key Storage**: Consider using hardware security modules (HSMs) for production environments.
3. **Certificate Rotation**: Implement regular certificate rotation procedures. **Note:** Ferrum Edge does not watch certificate files for changes or reload them dynamically. **No TLS surface supports hot reload — not frontend, not backend, not admin, not DTLS, not gRPC.** All TLS certificate files are read from disk either at process startup or when the connection pool entry for a proxy is first created. A config reload (SIGHUP, database poll, or gRPC sync) refreshes routing, plugins, consumers, and upstreams but does **not** re-read any TLS certificate files from disk for existing connection pool entries. To pick up rotated certificates, you must **restart the gateway process**. In Kubernetes, a rolling restart after a Secret update is the standard approach.
4. **Monitoring**: Monitor certificate expiration and renewal.

## Implementation Details

The mTLS implementation uses:

- **reqwest**: HTTP client with TLS support
- **rustls**: TLS library for secure connections
- **Connection Pooling**: mTLS clients are pooled and reused efficiently
- **Override Logic**: Proxy-specific settings override global environment variables

### Connection Pool Behavior

- **Fail-fast on bad certificates**: All TLS certificate files — both global env var paths (`FERRUM_BACKEND_TLS_CLIENT_CERT_PATH`, `FERRUM_BACKEND_TLS_CLIENT_KEY_PATH`, `FERRUM_TLS_CA_BUNDLE_PATH`) and per-proxy paths (`backend_tls_client_cert_path`, `backend_tls_client_key_path`, `backend_tls_server_ca_cert_path`) — are validated at startup and config load time. If any configured cert file is missing, unreadable (permission denied), or contains invalid/corrupt PEM data, the gateway **refuses to start** (or rejects the config reload). There is no silent fallback to unauthenticated connections or to webpki-only verification when a configured CA file fails to load. Cert and key paths must always be configured as a pair; setting one without the other is a validation error. CA paths are independent — you can set just a CA to verify a server without presenting client identity.
- **TLS path deduplication**: When multiple proxies share the same cert/key/CA file paths, each unique file is parsed only once during validation. This avoids redundant disk I/O and PEM parsing at config load time.
- **Pool-per-cert-path**: Each unique combination of `backend_tls_client_cert_path`, `backend_tls_client_key_path`, and `backend_tls_server_ca_cert_path` produces a **separate connection pool entry** per protocol:
  - **HTTP/1.1 + H2** (`ConnectionPool`): separate `reqwest::Client` instances keyed by `host:port:protocol:dns_override:ca_path`
  - **HTTP/3** (`Http3ConnectionPool`): separate `rustls::ClientConfig` + QUIC endpoints per proxy
  - **gRPC** (`GrpcConnectionPool`): separate `rustls::ClientConfig` + H2 senders per target
  - **HTTP/2 direct** (`Http2ConnectionPool`): separate `rustls::ClientConfig` + H2 senders per target
  - **TCP/TLS**: separate `rustls::ClientConfig` cached per listener lifecycle
  - **WebSocket (wss://)**: `rustls::ClientConfig` built per connection (no persistent pool)

  Two proxies pointing at the same backend host but with different cert paths will **not** share connections. This is required because `reqwest::Client` and `rustls::ClientConfig` bake TLS identity and root certificates in at build time. Changing a proxy's cert paths in a config reload creates a new pool entry on the next request; the old pool entry is eventually evicted by idle timeout.
- Certificate files are read from disk both at validation time (startup/config load) and when the connection pool entry is first created. Subsequent requests reuse the cached client.
- If certificate file reading or parsing fails at request time (e.g., file deleted after startup), the request fails with an error. This behavior is consistent across all backend protocols (HTTP/1.1, H2, and HTTP/3). The gateway continues running and serves other proxies normally.
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
