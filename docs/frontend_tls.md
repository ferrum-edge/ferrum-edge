# Frontend TLS Configuration

This guide explains how to configure TLS (HTTPS) and mutual TLS (mTLS) for client connections to the Ferrum Gateway.

## Overview

Ferrum Gateway supports three modes of operation for client connections:

1. **HTTP** - Plain text connections (default)
2. **HTTPS** - Encrypted connections with server authentication
3. **mTLS** - Encrypted connections with mutual (server + client) authentication

## Environment Variables

### Server TLS (HTTPS)

Required for HTTPS mode:

```bash
# Server certificate (PEM format)
export FERRUM_PROXY_TLS_CERT_PATH="/path/to/server.crt"

# Server private key (PEM format)  
export FERRUM_PROXY_TLS_KEY_PATH="/path/to/server.key"
```

### Client Certificate Verification (mTLS)

Optional for mTLS mode:

```bash
# Client CA bundle for verifying client certificates
export FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH="/path/to/client-ca-bundle.pem"
```

## Configuration Scenarios

### 1. HTTP Only (Default)

No TLS configuration needed:

```bash
# Gateway starts with:
# - HTTP listener on port 8000 (configurable via FERRUM_PROXY_HTTP_PORT)
# - No HTTPS listener
./ferrum-gateway
```

### 2. HTTPS + HTTP (Dual Listeners)

Enable server TLS:

```bash
export FERRUM_PROXY_TLS_CERT_PATH="/etc/ssl/certs/gateway.crt"
export FERRUM_PROXY_TLS_KEY_PATH="/etc/ssl/private/gateway.key"

./ferrum-gateway
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
export FERRUM_PROXY_TLS_CERT_PATH="/etc/ssl/certs/gateway.crt"
export FERRUM_PROXY_TLS_KEY_PATH="/etc/ssl/private/gateway.key"
export FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH="/etc/ssl/certs/client-ca-bundle.pem"

./ferrum-gateway
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
./ferrum-gateway
# Access: http://localhost:8000
```

**Staging:**
```bash
# Both HTTP and HTTPS for testing
export FERRUM_PROXY_TLS_CERT_PATH="./staging.crt"
export FERRUM_PROXY_TLS_KEY_PATH="./staging.key"
./ferrum-gateway
# Access: http://localhost:8000 AND https://localhost:8443
```

**Production:**
```bash
# HTTPS/mTLS only, block HTTP at firewall
export FERRUM_PROXY_TLS_CERT_PATH="/prod/certs/gateway.crt"
export FERRUM_PROXY_TLS_KEY_PATH="/prod/certs/gateway.key"
export FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH="/prod/certs/client-ca.pem"
./ferrum-gateway
# Access: https://localhost:8443 (mTLS required)
# Firewall blocks port 8000
```

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
- Common name (CN) or Subject Alternative Name (SAN) should match the gateway hostname
- Private key must be unencrypted (or gateway must have access to decryption key)

### Client CA Bundle
- Must be in PEM format
- Can contain one or multiple CA certificates
- All certificates in the bundle are trusted for client verification
- Clients must present certificates signed by one of these CAs

## Admin API TLS Configuration

The Admin API also supports separate HTTP and HTTPS listeners with the same architecture as the proxy listeners.

### Admin API Environment Variables

```bash
# Admin server certificates (for HTTPS)
export FERRUM_ADMIN_TLS_CERT_PATH="/etc/ssl/certs/admin.crt"
export FERRUM_ADMIN_TLS_KEY_PATH="/etc/ssl/private/admin.key"

# Admin client CA bundle (for mTLS)
export FERRUM_ADMIN_TLS_CLIENT_CA_BUNDLE_PATH="/etc/ssl/certs/admin-client-ca.pem"

# Admin ports (configurable)
export FERRUM_ADMIN_HTTP_PORT="9000"
export FERRUM_ADMIN_HTTPS_PORT="9443"

# Admin TLS no-verify (testing only)
export FERRUM_ADMIN_TLS_NO_VERIFY="true"

# Backend TLS no-verify (testing only)
export FERRUM_TLS_NO_VERIFY="true"

# JWT authentication (required)
export FERRUM_ADMIN_JWT_SECRET="your-secret-key"
```

### Admin API Configuration Scenarios

#### **1. Admin HTTP Only (Default)**
```bash
./ferrum-gateway
# Admin HTTP: http://localhost:9000
# No Admin HTTPS
```

#### **2. Admin HTTP + HTTPS**
```bash
export FERRUM_ADMIN_TLS_CERT_PATH="/etc/ssl/certs/admin.crt"
export FERRUM_ADMIN_TLS_KEY_PATH="/etc/ssl/private/admin.key"
./ferrum-gateway
# Admin HTTP: http://localhost:9000
# Admin HTTPS: https://localhost:9443
```

#### **3. Admin HTTP + mTLS**
```bash
export FERRUM_ADMIN_TLS_CERT_PATH="/etc/ssl/certs/admin.crt"
export FERRUM_ADMIN_TLS_KEY_PATH="/etc/ssl/private/admin.key"
export FERRUM_ADMIN_TLS_CLIENT_CA_BUNDLE_PATH="/etc/ssl/certs/admin-client-ca.pem"
./ferrum-gateway
# Admin HTTP: http://localhost:9000
# Admin HTTPS/mTLS: https://localhost:9443 (client certs required)
```

#### **4. Admin HTTPS with No-Verify (Testing)**
```bash
export FERRUM_ADMIN_TLS_CERT_PATH="/etc/ssl/certs/admin.crt"
export FERRUM_ADMIN_TLS_KEY_PATH="/etc/ssl/private/admin.key"
export FERRUM_ADMIN_TLS_NO_VERIFY="true"
./ferrum-gateway
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
export FERRUM_PROXY_TLS_CERT_PATH="./server.crt"
export FERRUM_PROXY_TLS_KEY_PATH="./server.key"
export FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH="./client-ca-bundle.pem"

./ferrum-gateway
```

### Test with Client Certificate

```bash
# Test with client certificate
curl --cert client.crt --key client.key https://localhost:8443/api/v1

# Test without client certificate (should fail)
curl https://localhost:8443/api/v1
```

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

The global `FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH` applies to all connections on the HTTPS listener — the TLS handshake happens before routing, so the gateway cannot know which proxy a request targets until after the handshake completes.

For per-proxy CA restrictions, use the `mtls_auth` plugin's `allowed_issuers` and `allowed_ca_fingerprints_sha256` options. This gives you a two-layer approach:

1. **TLS layer (global)** — accepts any client cert signed by any CA in the truststore
2. **Plugin layer (per-proxy)** — verifies the cert's issuer DN and/or chain CA fingerprints match the proxy's policy

```yaml
# Proxy A: only accepts certs from Internal Services CA
- id: "proxy-a"
  listen_path: "/internal/"
  auth_mode: single
  plugins:
    - plugin_config_id: "mtls-internal-only"

# Plugin config: mtls-internal-only
- id: "mtls-internal-only"
  name: "mtls_auth"
  config:
    cert_field: "subject_cn"
    allowed_issuers:
      - cn: "Internal Services CA"

# Proxy B: accepts certs from either Internal or Partner CAs
- id: "proxy-b"
  listen_path: "/partner/"
  auth_mode: single
  plugins:
    - plugin_config_id: "mtls-internal-and-partner"

# Plugin config: mtls-internal-and-partner
- id: "mtls-internal-and-partner"
  name: "mtls_auth"
  config:
    cert_field: "subject_cn"
    allowed_issuers:
      - cn: "Internal Services CA"
      - cn: "Partner Portal CA"
```

This approach works with `auth_mode: multi` — if the mTLS check fails, the gateway tries the next auth plugin (e.g., JWT, API key).

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
./ferrum-gateway
```

Look for messages like:
- "TLS configuration loaded with client certificate verification"
- "TLS connection established with client certificate verification"
- "TLS handshake failed"

## TLS Policy Hardening

The gateway supports fine-grained control over TLS protocol versions, cipher suites, key exchange groups, and cipher order negotiation. These settings apply globally to all inbound TLS listeners (proxy and admin).

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `FERRUM_TLS_MIN_VERSION` | `1.2` | Minimum TLS version. Allowed: `1.2`, `1.3` |
| `FERRUM_TLS_MAX_VERSION` | `1.3` | Maximum TLS version. Allowed: `1.2`, `1.3` |
| `FERRUM_TLS_CIPHER_SUITES` | *(see defaults below)* | Comma-separated list of cipher suites (OpenSSL naming) |
| `FERRUM_TLS_CURVES` | *(see defaults below)* | Comma-separated list of key exchange groups |
| `FERRUM_TLS_PREFER_SERVER_CIPHER_ORDER` | `true` | When `true`, server cipher preference is used during TLS 1.2 negotiation |

### Protocol Version Examples

```bash
# TLS 1.2 and 1.3 (default)
export FERRUM_TLS_MIN_VERSION="1.2"
export FERRUM_TLS_MAX_VERSION="1.3"

# TLS 1.3 only (strictest)
export FERRUM_TLS_MIN_VERSION="1.3"
export FERRUM_TLS_MAX_VERSION="1.3"

# TLS 1.2 only (legacy compatibility)
export FERRUM_TLS_MIN_VERSION="1.2"
export FERRUM_TLS_MAX_VERSION="1.2"
```

**Note:** Setting `FERRUM_TLS_MIN_VERSION` higher than `FERRUM_TLS_MAX_VERSION` is an error and the gateway will refuse to start.

### Supported Cipher Suites

When `FERRUM_TLS_CIPHER_SUITES` is not set, the gateway uses secure AEAD-only defaults:

**TLS 1.3 (always AEAD):**
| Name | Description |
|------|-------------|
| `TLS_AES_256_GCM_SHA384` | AES-256-GCM (strongest) |
| `TLS_AES_128_GCM_SHA256` | AES-128-GCM |
| `TLS_CHACHA20_POLY1305_SHA256` | ChaCha20-Poly1305 (fast on non-AES-NI hardware) |

**TLS 1.2 (ECDHE + AEAD only):**
| Name | Description |
|------|-------------|
| `ECDHE-ECDSA-AES256-GCM-SHA384` | ECDSA key exchange, AES-256-GCM |
| `ECDHE-RSA-AES256-GCM-SHA384` | RSA key exchange, AES-256-GCM |
| `ECDHE-ECDSA-AES128-GCM-SHA256` | ECDSA key exchange, AES-128-GCM |
| `ECDHE-RSA-AES128-GCM-SHA256` | RSA key exchange, AES-128-GCM |
| `ECDHE-ECDSA-CHACHA20-POLY1305` | ECDSA key exchange, ChaCha20-Poly1305 |
| `ECDHE-RSA-CHACHA20-POLY1305` | RSA key exchange, ChaCha20-Poly1305 |

No CBC or non-AEAD cipher suites are supported.

**Example — restrict to AES-256 only:**
```bash
export FERRUM_TLS_CIPHER_SUITES="TLS_AES_256_GCM_SHA384,ECDHE-ECDSA-AES256-GCM-SHA384,ECDHE-RSA-AES256-GCM-SHA384"
```

### Supported Key Exchange Groups (Curves)

When `FERRUM_TLS_CURVES` is not set, the gateway uses `X25519` and `secp256r1`.

| Name | Aliases | Description |
|------|---------|-------------|
| `X25519` | — | Curve25519 (modern, fast, recommended) |
| `secp256r1` | `P-256`, `P256` | NIST P-256 (widely compatible) |
| `secp384r1` | `P-384`, `P384` | NIST P-384 (stronger, slower) |

Curve names are case-insensitive.

**Example — X25519 only:**
```bash
export FERRUM_TLS_CURVES="X25519"
```

**Example — all supported curves:**
```bash
export FERRUM_TLS_CURVES="X25519,secp256r1,secp384r1"
```

### Server Cipher Order

When `FERRUM_TLS_PREFER_SERVER_CIPHER_ORDER` is `true` (the default), the server's cipher suite preference takes priority over the client's during TLS 1.2 negotiation. This ensures the strongest cipher is selected regardless of client ordering. TLS 1.3 does not use this setting (server always selects).

```bash
# Let server choose (recommended, default)
export FERRUM_TLS_PREFER_SERVER_CIPHER_ORDER="true"

# Let client choose
export FERRUM_TLS_PREFER_SERVER_CIPHER_ORDER="false"
```

### Verifying TLS Policy

The gateway logs the active TLS policy at startup:

```
TLS policy: versions=["TLS 1.2", "TLS 1.3"], cipher_suites=["TLS13_AES_256_GCM_SHA384", ...], curves=["X25519", "SECP256R1"], prefer_server_order=true
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

1. **TLS Termination at Load Balancer**: Configure HTTP mode on gateway
2. **TLS Pass-Through**: Configure HTTPS/mTLS mode on gateway
3. **Health Checks**: Ensure health checks work with your TLS configuration

## Performance Considerations

- **TLS Handshake Overhead**: Initial connections have higher latency
- **Session Resumption**: Configure for better performance
- **Hardware Acceleration**: Consider for high-throughput scenarios
- **Certificate Size**: Smaller certificates improve performance

## Migration Guide

### From HTTP to HTTPS

1. Obtain server certificate and private key
2. Set `FERRUM_PROXY_TLS_CERT_PATH` and `FERRUM_PROXY_TLS_KEY_PATH`
3. Update client applications to use HTTPS URLs
4. Test thoroughly before production deployment

### From HTTPS to mTLS

1. Obtain or create client CA certificate
2. Set `FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH`
3. Issue client certificates to authorized clients
4. Update client applications to present certificates
5. Gradually enforce mTLS (start with optional, then required)
