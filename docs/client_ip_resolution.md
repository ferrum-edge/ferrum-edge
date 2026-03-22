# Client IP Resolution

When Ferrum Gateway sits behind load balancers, CDNs, or reverse proxies, the TCP socket address is the proxy's IP -- not the real client's. This guide explains how to configure the gateway to accurately and securely resolve the originating client IP.

## Table of Contents

- [How It Works](#how-it-works)
- [Configuration](#configuration)
- [Security Model](#security-model)
- [Deployment Examples](#deployment-examples)
- [How Client IP Is Used](#how-client-ip-is-used)
- [Troubleshooting](#troubleshooting)

## How It Works

The gateway uses a three-step process to resolve the real client IP:

1. **Check authoritative header** (optional): If `FERRUM_REAL_IP_HEADER` is set (e.g., `CF-Connecting-IP`), the gateway checks that header first. This is only trusted when the direct connection comes from a trusted proxy.

2. **Walk `X-Forwarded-For` right-to-left**: Parse the XFF header into a list of IPs. Starting from the rightmost entry, skip any IP that matches a trusted proxy CIDR. The first non-trusted IP is the real client.

3. **Fall back to socket IP**: If no XFF header is present, all XFF entries are trusted proxies, or no trusted proxies are configured, the TCP socket address is used.

### Why right-to-left?

A malicious client can prepend arbitrary IPs to the `X-Forwarded-For` header:

```
X-Forwarded-For: 1.1.1.1, <real-client-ip>
                 ^^^^^^^   ^^^^^^^^^^^^^^^^
                 attacker   added by your
                 injected   load balancer
```

Only the **rightmost** entries -- those appended by your own infrastructure -- are trustworthy. Walking right-to-left and skipping known proxies ensures you find the first IP that wasn't added by your own infrastructure.

## Configuration

| Environment Variable | Default | Description |
|---|---|---|
| `FERRUM_TRUSTED_PROXIES` | *(empty)* | Comma-separated list of trusted proxy CIDRs and/or IPs |
| `FERRUM_REAL_IP_HEADER` | *(none)* | Optional authoritative header name for client IP |

### `FERRUM_TRUSTED_PROXIES`

A comma-separated list of IP addresses and CIDR ranges that represent your trusted proxy infrastructure. Supports IPv4 and IPv6.

```bash
# Private network ranges (common for internal load balancers)
FERRUM_TRUSTED_PROXIES="10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"

# Specific proxy IPs
FERRUM_TRUSTED_PROXIES="10.0.1.50,10.0.1.51"

# Mixed IPv4 and IPv6
FERRUM_TRUSTED_PROXIES="10.0.0.0/8,fd00::/8,::1"
```

**When this is empty (default)**, the `X-Forwarded-For` header is completely ignored and the TCP socket IP is always used. This is the secure default for edge deployments where the gateway faces the internet directly.

### `FERRUM_REAL_IP_HEADER`

Some CDNs and proxies set a single authoritative header containing the real client IP. When configured, this header is checked first before falling back to the XFF walk.

```bash
# Cloudflare
FERRUM_REAL_IP_HEADER="CF-Connecting-IP"

# nginx (with realip module)
FERRUM_REAL_IP_HEADER="X-Real-IP"

# AWS CloudFront
FERRUM_REAL_IP_HEADER="CloudFront-Viewer-Address"

# Akamai
FERRUM_REAL_IP_HEADER="True-Client-IP"
```

**Security note**: This header is only trusted when the direct TCP connection comes from a trusted proxy (as defined by `FERRUM_TRUSTED_PROXIES`). If a client connects directly and sends this header, it is ignored.

## Security Model

The client IP resolution follows these security principles:

1. **Secure by default**: With no configuration, XFF headers are ignored entirely. The socket IP is the only source of truth.

2. **Direct connections ignore XFF**: If the TCP connection does NOT come from a trusted proxy CIDR, the `X-Forwarded-For` header is ignored regardless of its contents. This prevents IP spoofing by clients connecting directly.

3. **Right-to-left walk prevents injection**: Even when XFF is trusted, the algorithm walks from right to left, skipping only known proxy IPs. An attacker who prepends fake IPs cannot influence the resolved client IP.

4. **Authoritative header gated on trust**: The `FERRUM_REAL_IP_HEADER` is only honored when the connection comes from a trusted proxy.

### Attack Scenarios Handled

| Scenario | Behavior |
|---|---|
| Client connects directly (no proxy), sends fake XFF | XFF ignored; socket IP used |
| Client behind proxy prepends fake IP to XFF | Right-to-left walk returns the real client IP (added by your proxy) |
| Client behind proxy sends fake `CF-Connecting-IP` | Header ignored because the direct connection isn't from a trusted proxy |
| All XFF entries are trusted proxy IPs | Falls back to socket IP |
| XFF contains unparseable garbage entries | Stops at the first unparseable entry (conservative) |

## Deployment Examples

### Edge Deployment (No Proxy)

The gateway faces the internet directly. No configuration needed.

```bash
# Socket IP is always the real client IP
# (default behavior)
```

### Behind a Single Load Balancer

```
Client (203.0.113.50) → AWS ALB (10.0.1.100) → Gateway
```

```bash
FERRUM_TRUSTED_PROXIES="10.0.0.0/8"
```

Result: The gateway sees socket IP `10.0.1.100` (trusted), reads XFF `203.0.113.50`, and resolves client IP as `203.0.113.50`.

### Behind Cloudflare + Internal Load Balancer

```
Client (198.51.100.23) → Cloudflare (173.245.49.1) → Internal LB (10.0.0.1) → Gateway
```

```bash
# Cloudflare IP ranges + internal network
FERRUM_TRUSTED_PROXIES="173.245.48.0/20,103.21.244.0/22,103.22.200.0/22,103.31.4.0/22,141.101.64.0/18,108.162.192.0/18,190.93.240.0/20,188.114.96.0/20,197.234.240.0/22,198.41.128.0/17,162.158.0.0/15,104.16.0.0/13,104.24.0.0/14,172.64.0.0/13,131.0.72.0/22,10.0.0.0/8"

# Use Cloudflare's authoritative header for best accuracy
FERRUM_REAL_IP_HEADER="CF-Connecting-IP"
```

Result: Gateway checks `CF-Connecting-IP: 198.51.100.23` (connection is from trusted `10.0.0.1`), resolves client IP as `198.51.100.23`.

### Behind nginx Reverse Proxy

```
Client (192.0.2.10) → nginx (172.16.0.5) → Gateway
```

```bash
FERRUM_TRUSTED_PROXIES="172.16.0.0/12"
FERRUM_REAL_IP_HEADER="X-Real-IP"
```

### Kubernetes with Ingress Controller

```
Client → Cloud LB → Ingress Controller (Pod Network) → Gateway (Pod)
```

```bash
# Trust the pod network and cloud LB ranges
FERRUM_TRUSTED_PROXIES="10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
```

### Docker Compose Example

```yaml
services:
  gateway:
    image: ferrum-gateway:latest
    environment:
      FERRUM_MODE: file
      FERRUM_FILE_CONFIG_PATH: /config/gateway.yaml
      # Trust the Docker bridge network
      FERRUM_TRUSTED_PROXIES: "172.17.0.0/16,10.0.0.0/8"
      FERRUM_REAL_IP_HEADER: "X-Real-IP"
```

## How Client IP Is Used

The resolved client IP (`ctx.client_ip`) is used throughout the gateway:

| Feature | How IP Is Used |
|---|---|
| **IP Whitelisting / Blacklisting** | `access_control` plugin checks `client_ip` against allow/block lists |
| **IP Restriction** | `ip_restriction` plugin enforces allow-first or deny-first IP policies |
| **Rate Limiting** | When `limit_by="ip"` (default), rate limit key is `ip:{client_ip}` |
| **Load Balancer Hashing** | `client_ip` used as hash key for consistent upstream selection |
| **Transaction Logging** | `client_ip` included in all log entries and transaction summaries |
| **X-Forwarded-For (outbound)** | Real client IP appended to XFF when proxying to backends |

## Troubleshooting

### Client IP is always the load balancer's IP

**Cause**: `FERRUM_TRUSTED_PROXIES` is not set.

**Fix**: Set it to include your load balancer's IP/CIDR range.

### Client IP is wrong / shows an attacker-injected IP

**Cause**: Your proxy infrastructure IPs are not in the trusted list, so the XFF walk stops at the wrong position.

**Fix**: Ensure ALL proxy hops between the client and the gateway are listed in `FERRUM_TRUSTED_PROXIES`.

### Rate limiting doesn't work correctly behind a proxy

**Cause**: Without trusted proxy configuration, all requests appear to come from the same IP (the proxy), so rate limits apply to the proxy IP rather than individual clients.

**Fix**: Configure `FERRUM_TRUSTED_PROXIES` so each client gets its own rate limit bucket.

### XFF header is not being set on backend requests

The gateway always sets the `X-Forwarded-For` header when proxying to backends, using the resolved client IP. If the header was already present, the client IP is appended; otherwise a new header is created.
