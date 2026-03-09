# Backend mTLS Configuration

This document explains how to configure backend mutual TLS (mTLS) authentication in Ferrum Gateway.

## Overview

Backend mTLS allows the gateway to authenticate itself to backend services using client certificates. This is commonly used when backend services require certificate-based authentication.

## Configuration

### Global Environment Variables

Set these environment variables to configure client certificates and CA verification for all backend connections:

```bash
# Path to CA bundle for backend TLS verification (overrides system trust store)
export FERRUM_BACKEND_TLS_CA_BUNDLE_PATH="/path/to/ca-bundle.pem"

# Path to client certificate file (PEM format)
export FERRUM_BACKEND_TLS_CLIENT_CERT_PATH="/path/to/client-cert.pem"

# Path to client private key file (PEM format)  
export FERRUM_BACKEND_TLS_CLIENT_KEY_PATH="/path/to/client-key.pem"
```

### Custom CA Bundles

The `FERRUM_BACKEND_TLS_CA_BUNDLE_PATH` allows you to specify custom Certificate Authority (CA) bundles for backend TLS verification. This is useful for:

- **Enterprise Environments**: When backend services use certificates from private CAs
- **Development**: Using self-signed certificates in testing environments  
- **Security**: Fine-grained control over trusted CAs beyond system defaults
- **Compliance**: Meeting regulatory requirements for certificate validation

**How it works:**
- The CA bundle is loaded once at gateway startup
- It's used for ALL backend connections (global configuration only)
- It supplements or replaces the system trust store
- Works with HTTP/HTTPS and WebSocket (wss://) connections

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
./ferrum-gateway
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

./ferrum-gateway --mode file --config config.yaml
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
   RUST_LOG=debug ./ferrum-gateway
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
3. **Certificate Rotation**: Implement regular certificate rotation procedures.
4. **Monitoring**: Monitor certificate expiration and renewal.

## Implementation Details

The mTLS implementation uses:

- **reqwest**: HTTP client with TLS support
- **rustls**: TLS library for secure connections
- **Connection Pooling**: mTLS clients are pooled and reused efficiently
- **Override Logic**: Proxy-specific settings override global environment variables

### Connection Pool Behavior

- Clients with different mTLS configurations are pooled separately
- Certificate loading happens once per client creation
- Failed certificate loading prevents client creation (fallback to no mTLS)
- Connection reuse respects the original mTLS configuration

## Testing with Self-Signed Certificates

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
