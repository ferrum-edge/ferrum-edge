# Client IP And Original Scheme Resolution

When Ferrum Edge sits behind load balancers, CDNs, or reverse proxies, the TCP socket address and transport scheme describe the nearest proxy hop rather than necessarily describing the browser-facing request. This guide explains how to configure the gateway to resolve the originating client IP and original HTTP-family scheme accurately and securely.

## Table of Contents

- [How It Works](#how-it-works)
- [Original Request Scheme](#original-request-scheme)
- [Configuration](#configuration)
- [Security Model](#security-model)
- [Deployment Examples](#deployment-examples)
- [How Client IP Is Used](#how-client-ip-is-used)
- [Troubleshooting](#troubleshooting)

## How It Works

The gateway uses a three-step process to resolve the real client IP:

1. **Check authoritative header** (optional): If `FERRUM_REAL_IP_HEADER` is set (e.g., `CF-Connecting-IP`), the gateway checks that header first. This is only trusted when the direct connection comes from a trusted proxy. The header is read as **all of its field-lines**, and exactly one field-line holding exactly one value is accepted. Accepted values are parsed as a single `IpAddr`, or as an `ip:source-port` socket address for headers such as CloudFront's `CloudFront-Viewer-Address`, and normalized before use.

2. **Walk `X-Forwarded-For` right-to-left**: If the configured real-IP header is absent, parse the XFF header into a list of IPs. Starting from the rightmost entry, skip any IP that matches a trusted proxy CIDR. The first non-trusted IP is the real client.

3. **Fall back to socket IP**: If the configured real-IP header is present but empty, duplicated across field-lines, not valid UTF-8, malformed, comma-separated, or sent by an untrusted peer, the TCP socket address is used — and `X-Forwarded-For` is **not** consulted as a fallback, because it is the weaker source the operator chose to override. The socket address is also used when no XFF header is present, all XFF entries are trusted proxies, or no trusted proxies are configured.

### The authoritative header must be overwritten, not appended

`FERRUM_REAL_IP_HEADER` names an **overwrite-only** contract. A proxy that preserves the client's copy of the header and appends its own leaves two field-lines on the wire:

```
X-Real-IP: 203.0.113.50      <- attacker-supplied, preserved by the proxy
X-Real-IP: 198.51.100.23     <- appended by your proxy
```

Ferrum refuses to guess which line is authoritative: any count other than exactly one is rejected in either field order, identical duplicates included, and the request is accounted to the direct socket address. This is a fail-closed guard, not a substitute for correct upstream configuration — configure the hop in front of Ferrum to **overwrite** (nginx `proxy_set_header X-Real-IP $remote_addr;`, or the CDN's own authoritative header, which CDNs overwrite by contract). If you cannot guarantee overwrite behavior, leave `FERRUM_REAL_IP_HEADER` unset and rely on the `X-Forwarded-For` walk, which is append-aware by design.

The same verdict holds on HTTP/1.1, HTTP/2, and HTTP/3, and whether or not request headers have been materialized for plugins.

### Why right-to-left?

A malicious client can prepend arbitrary IPs to the `X-Forwarded-For` header:

```
X-Forwarded-For: 1.1.1.1, <real-client-ip>
                 ^^^^^^^   ^^^^^^^^^^^^^^^^
                 attacker   added by your
                 injected   load balancer
```

Only the **rightmost** entries -- those appended by your own infrastructure -- are trustworthy. Walking right-to-left and skipping known proxies ensures you find the first IP that wasn't added by your own infrastructure.

## Original Request Scheme

Ferrum also accepts an original browser-facing `http` or `https` scheme from `X-Forwarded-Proto`, but only when the direct peer is in `FERRUM_TRUSTED_PROXIES`:

- A singleton value is an overwrite-only assertion from the direct trusted proxy.
- A comma-separated or multi-field value is a safely appended chain. Ferrum accepts it only when its entry count matches `X-Forwarded-For`, validates the trusted XFF suffix, and selects the scheme aligned with the first untrusted XFF entry. This chooses the browser-facing value rather than the scheme of the hop nearest Ferrum.
- A missing, malformed, unrecognized, or misaligned chain is ignored, preserving the scheme of Ferrum's accepted frontend transport.

For example, `X-Forwarded-For: 203.0.113.50, 172.16.1.1` and `X-Forwarded-Proto: http, https` received from trusted `10.0.0.1` resolve to original scheme `http`: the rightmost `https` describes the CDN-to-LB hop, not the browser request. The accepted original scheme drives authentication URLs, secure-cookie ownership, request-authority default-port normalization, and the canonical `X-Forwarded-Proto` and RFC 7239 `Forwarded` metadata regenerated for backends.

## Configuration

| Environment Variable | Default | Description |
|---|---|---|
| `FERRUM_TRUSTED_PROXIES` | *(empty)* | Comma-separated trusted proxy CIDRs/IPs for client IP and original-scheme resolution |
| `FERRUM_REAL_IP_HEADER` | *(none)* | Optional authoritative header name for client IP |

### `FERRUM_TRUSTED_PROXIES`

A comma-separated list of IP addresses and CIDR ranges that represent your trusted proxy infrastructure. Supports IPv4, IPv6, and IPv4-mapped IPv6 forms (`::ffff:10.0.0.0/104`, which matches the equivalent IPv4 rule).

**The list is parsed strictly.** Every entry must be a valid IP or CIDR, and empty, trailing, or doubled comma segments are rejected:

```bash
FERRUM_TRUSTED_PROXIES="10.0.0.0/8,192.168.0.0/33"   # rejected: /33 is not a valid IPv4 prefix
FERRUM_TRUSTED_PROXIES="10.0.0.0/8,"                 # rejected: trailing comma
FERRUM_TRUSTED_PROXIES=""                            # valid: the secure default
```

A malformed entry fails `ferrum-edge validate` and fails startup **before any listener binds**; a partially parsed trust set is never installed, and a running gateway keeps its last-known-good boundary. Skipping the bad entry would be a silent security change, not a lenient one: the mistyped hop stops being trusted, so every client behind it collapses onto that hop's socket address for `ip_restriction`, GeoIP, bot/client attribution, per-IP rate and concurrency keys, and logs. A deny-only IP policy then stops seeing the abusive client addresses entirely.

```bash
# Private network ranges (common for internal load balancers)
FERRUM_TRUSTED_PROXIES="10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"

# Specific proxy IPs
FERRUM_TRUSTED_PROXIES="10.0.1.50,10.0.1.51"

# Mixed IPv4 and IPv6
FERRUM_TRUSTED_PROXIES="10.0.0.0/8,fd00::/8,::1"
```

**When this is empty (default)**, `X-Forwarded-For` and `X-Forwarded-Proto` are ignored. The TCP socket IP and Ferrum's accepted frontend transport remain authoritative. This is the secure default for edge deployments where the gateway faces the internet directly.

### `FERRUM_REAL_IP_HEADER`

Some CDNs and proxies set a single authoritative header containing the real client IP. When configured, this header is checked first; if the header is absent, the gateway falls back to the XFF walk.

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

**Security note**: This header is only trusted when the direct TCP connection comes from a trusted proxy (as defined by `FERRUM_TRUSTED_PROXIES`). If a client connects directly and sends this header, the socket IP is kept rather than falling through to `X-Forwarded-For`.

The effective header name is gateway-owned client-attribution state. Ferrum rejects any `correlation_id.header_name` (including a custom plugin correlation-capability claim) that matches it case-insensitively, preventing correlation processing from replacing the backend-visible attribution header. In CP/DP deployments this is an enforced cluster setting: every DP advertises its effective value during config subscription, and the CP refuses to distribute configuration when the value is missing or differs. Configure the same value (or no value) on every CP and DP.

Values must contain exactly one parseable IP address or one parseable socket address whose host is an IP. Whitespace is trimmed, accepted values are normalized with Rust's `IpAddr` formatter, and any source port is discarded before the value is used in plugin context, rate-limit keys, and logs. For example, `2001:0db8:0000::0001` is stored as `2001:db8::1`, and CloudFront's `198.51.100.10:46532` is stored as `198.51.100.10`.

## Security Model

The client IP resolution follows these security principles:

1. **Secure by default**: With no configuration, XFF headers are ignored entirely. The socket IP is the only source of truth.

2. **Direct connections ignore XFF**: If the TCP connection does NOT come from a trusted proxy CIDR, the `X-Forwarded-For` header is ignored regardless of its contents. This prevents IP spoofing by clients connecting directly.

3. **Right-to-left walk prevents injection**: Even when XFF is trusted, the algorithm walks from right to left, skipping only known proxy IPs. An attacker who prepends fake IPs cannot influence the resolved client IP.

4. **Authoritative header gated on trust and singular**: The `FERRUM_REAL_IP_HEADER` is only honored when the connection comes from a trusted proxy **and** the request carries exactly one field-line with exactly one value. If the configured header is present but rejected, the socket IP remains the source of truth and `X-Forwarded-For` is not consulted.

5. **Forwarded scheme is correlated or overwritten**: A trusted proxy may overwrite `X-Forwarded-Proto` with one original value. If proxies append values, the scheme list must align with the validated XFF chain; Ferrum rejects malformed or misaligned chains instead of guessing from the nearest hop.

6. **The trust list itself is strict**: `FERRUM_TRUSTED_PROXIES` must parse in full. Invalid configuration fails validation and startup rather than installing a partial trust boundary.

### Attack Scenarios Handled

| Scenario | Behavior |
|---|---|
| Client connects directly (no proxy), sends fake XFF | XFF ignored; socket IP used |
| Client behind proxy prepends fake IP to XFF | Right-to-left walk returns the real client IP (added by your proxy) |
| Client behind proxy sends fake `CF-Connecting-IP` | Header ignored because the direct connection isn't from a trusted proxy; socket IP used |
| CloudFront sends `CloudFront-Viewer-Address: 198.51.100.10:46532` | Source port is discarded; client IP is `198.51.100.10` |
| Trusted proxy sends empty, malformed, non-UTF-8, or comma-separated real-IP header | Socket IP used; XFF not consulted |
| Proxy preserves the client's real-IP header and appends its own (two field-lines) | Both lines rejected in either order; socket IP used; XFF not consulted |
| Typo in `FERRUM_TRUSTED_PROXIES` (e.g. `/33`, junk, stray comma) | Configuration rejected; `validate` and startup fail before listeners bind |
| All XFF entries are trusted proxy IPs | Falls back to socket IP |
| XFF contains unparseable garbage entries | Stops at the first unparseable entry (conservative) |
| Trusted proxy overwrites XFP with one `http` or `https` value | Value becomes the original request scheme |
| Trusted proxies append aligned XFF `client, proxy` and XFP `http, https` | Original scheme resolves to `http` at the client boundary |
| Appended XFP is malformed or does not align with XFF | Forwarded scheme ignored; accepted frontend transport scheme retained |

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
    image: ferrum-edge:latest
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
| **IP Whitelisting / Blacklisting** | `ip_restriction` plugin checks `client_ip` against allow/deny lists |
| **IP Restriction** | `ip_restriction` plugin enforces allow-first or deny-first IP policies |
| **Rate Limiting** | When `limit_by="ip"` (default), rate limit key is `ip:{client_ip}`. `consumer` and `spiffe_identity` modes fall back to this IP key when their identity is absent |
| **Load Balancer Hashing** | `client_ip` used as hash key for consistent upstream selection |
| **Transaction Logging** | `client_ip` included in all log entries and transaction summaries |
| **X-Forwarded-For (outbound)** | Outbound XFF chain built per standard `proxy_add_x_forwarded_for` semantics (see below) |
| **Forwarded (outbound, RFC 7239)** | `for=` carries the resolved client IP when `FERRUM_ADD_FORWARDED_HEADER` is enabled; client-supplied `Forwarded` is discarded so only the gateway-owned element reaches backends |

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

The gateway always sets the `X-Forwarded-For` header when proxying to backends, using standard `proxy_add_x_forwarded_for` semantics: the immediate socket peer is appended to the inbound chain. When there is no inbound XFF but the resolved client IP differs from the peer (a trusted proxy supplied `FERRUM_REAL_IP_HEADER`), the generated chain is seeded with the resolved client first. The same chain shape is produced on the HTTP/1.1, HTTP/2, and HTTP/3 frontends:

| Deployment shape | Inbound XFF | Outbound XFF |
|---|---|---|
| No proxy in front | — | `client-peer` |
| Trusted LB forwarding XFF | `…, client` | `…, client, lb-peer` |
| Trusted LB sending only a real-IP header | — | `resolved-client, lb-peer` |
| Untrusted peer (headers ignored) | any | `peer` |

The resolved client IP itself always travels in the RFC 7239 `Forwarded` header (`for=`) when `FERRUM_ADD_FORWARDED_HEADER` is enabled, and in `ctx.client_ip` for plugins, rate limiting, and logging.
