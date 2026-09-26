# Authentication & ACL Functional Testing

This document describes the end-to-end functional tests for authentication, access control, and multi-auth flows.

## Overview

`tests/functional/functional_auth_acl_test.rs` validates the authentication and authorization pipeline across the auth plugins. Its main test, `test_auth_acl_comprehensive`, runs the 40 numbered cases below, covering:

- **Key Auth**: API key authentication via header and query parameter
- **Basic Auth**: Username/password authentication with HMAC-SHA256 password hashes
- **JWT Auth**: HS256-signed token authentication with per-consumer secrets
- **HMAC Auth**: HMAC-signed request authentication with a `Date` freshness window
- **Access Control (ACL)**: Consumer allow/deny lists for authorization
- **Multi-Auth mode**: First-success-wins across multiple auth plugins
- **Consumer CRUD lifecycle**: Credential management and its effect on live auth

The same file also holds focused tests: `test_access_control_allows_jwks_authenticated_identity_when_enabled`, `test_basic_auth_plus_acl`, `test_jwt_auth_plus_acl`, `test_hmac_auth_plus_acl`, `test_hmac_v2_backend_sees_exactly_one_mutation_for_a_replayed_request`, and `test_hmac_v2_content_digest_forwards_original_body`.

## Running the Test

### Prerequisites

- Rust toolchain
- A buildable gateway binary (the shared `TestGateway` harness runs `cargo build --bin ferrum-edge` unless `FERRUM_SKIP_GATEWAY_BUILD=1`)

### Execute the Test

```bash
# Run the auth/ACL functional test
cargo test --test functional_tests functional_auth_acl -- --ignored --nocapture

# Run all functional tests (includes auth/ACL)
cargo test --test functional_tests -- --ignored --nocapture
```

### Expected Duration

The test takes approximately 60 seconds:
- ~20s for binary compilation (if not cached)
- ~4s for gateway startup and initial config load
- ~20s for setup (consumers, plugin configs, proxies, DB poll)
- ~16s for test execution (including DB poll waits for CRUD tests)

## Test Architecture

### Setup Flow

The test follows a specific ordering to satisfy database foreign key constraints:

1. **Start gateway** in database mode with a temporary SQLite database (via `TestGateway`)
2. **Create consumers** (alice, bob, charlie) with various credential types
3. **Create bare proxies** (9 proxies, no plugin associations yet)
4. **Create plugin configs** with `proxy_id` FK referencing existing proxies
5. **Update proxies** to add `plugins` array (populates `proxy_plugins` junction table)
6. **Wait for DB poll** (4 seconds) to load all config into the gateway

### Consumers

| Consumer | Credentials | Purpose |
|----------|-------------|---------|
| alice | keyauth + basicauth + jwt + hmac_auth | Multi-credential consumer for all auth types |
| bob | keyauth | Single-credential consumer for key auth + ACL tests |
| charlie | keyauth | Consumer used for ACL deny/block testing |

### Proxies and Plugin Configurations

| Proxy | Path | Auth Mode | Plugins | Purpose |
|-------|------|-----------|---------|---------|
| proxy-keyauth | `/keyauth` | single | key_auth (header) | Key auth via X-API-Key header |
| proxy-basicauth | `/basicauth` | single | basic_auth | Basic auth (username:password) |
| proxy-jwtauth | `/jwtauth` | single | jwt_auth | JWT token authentication |
| proxy-hmacauth | `/hmacauth` | single | hmac_auth | HMAC-signed request auth |
| proxy-keyauth-acl-allow | `/keyauth-acl-allow` | single | key_auth + access_control | ACL with allowed_consumers list |
| proxy-keyauth-acl-deny | `/keyauth-acl-deny` | single | key_auth + access_control | ACL with disallowed_consumers list |
| proxy-multiauth | `/multiauth` | **multi** | jwt_auth + key_auth | Multi-auth: JWT or API key |
| proxy-keyauth-query | `/keyauth-query` | single | key_auth (query) | Key auth via query parameter |
| proxy-multiauth-acl | `/multiauth-acl` | **multi** | jwt_auth + key_auth + access_control | Multi-auth with ACL |

## Test Cases

### Key Auth Tests (Tests 1-5)

| # | Test | Request | Expected |
|---|------|---------|----------|
| 1 | Valid API key (header) | `X-API-Key: alice-api-key-...` | 200 OK |
| 2 | Invalid API key | `X-API-Key: wrong-key` | 401 `{"error":"Invalid API key"}` |
| 3 | Missing API key | No X-API-Key header | 401 `{"error":"Missing API key"}` |
| 4 | Different consumer (bob) | `X-API-Key: bob-api-key-...` | 200 OK |
| 5 | Query param lookup | `?apikey=alice-api-key-...` | 200 OK |

### Basic Auth Tests (Tests 6-10)

| # | Test | Request | Expected |
|---|------|---------|----------|
| 6 | Valid credentials | `Authorization: Basic base64(alice:alice-password-123)` | 200 OK |
| 7 | Wrong password | `Authorization: Basic base64(alice:wrong-password)` | 401 |
| 8 | Unknown user | `Authorization: Basic base64(unknownuser:...)` | 401 |
| 9 | Missing header | No Authorization header | 401 |
| 10 | Wrong scheme | `Authorization: Bearer some-token` | 401 |

### JWT Auth Tests (Tests 11-16)

| # | Test | Request | Expected |
|---|------|---------|----------|
| 11 | Valid token | Bearer JWT(sub=alice, secret=alice-jwt-secret) | 200 OK |
| 12 | Expired token | Bearer JWT(exp=now-300s) | 401 |
| 13 | Wrong secret | Bearer JWT(signed with wrong key) | 401 |
| 14 | Unknown consumer | Bearer JWT(sub=nonexistent-user) | 401 |
| 15 | Missing token | No Authorization header | 401 |
| 16 | Malformed token | `Bearer not.a.valid.jwt` | 401 |

### HMAC Auth Tests (Tests 17-21)

| # | Test | Request | Expected |
|---|------|---------|----------|
| 17 | Valid signature | HMAC-SHA256 over the `ferrum-hmac-v1` signing string | 200 OK |
| 18 | Wrong secret | Signature computed with wrong key | 401 |
| 19 | Missing Date header | No Date header (freshness check) | 401 |
| 20 | Unknown consumer | `username="nonexistent"` | 401 |
| 21 | Missing auth header | No Authorization header | 401 |

### Access Control (ACL) Tests (Tests 22-27)

The `access_control` plugin supports both consumer-username and group-based rules.
Consumers declare group membership via the `acl_groups` field; the plugin checks
`allowed_groups` / `disallowed_groups` against those groups. Deny always wins over allow.

| # | Test | ACL Config | Consumer | Expected |
|---|------|-----------|----------|----------|
| 22 | Allow list — allowed | `allowed_consumers: [alice, bob]` | alice | 200 OK |
| 23 | Allow list — allowed | `allowed_consumers: [alice, bob]` | bob | 200 OK |
| 24 | Allow list — blocked | `allowed_consumers: [alice, bob]` | charlie | 403 |
| 25 | Deny list — allowed | `disallowed_consumers: [charlie]` | alice | 200 OK |
| 26 | Deny list — blocked | `disallowed_consumers: [charlie]` | charlie | 403 |
| 27 | Deny list — allowed | `disallowed_consumers: [charlie]` | bob | 200 OK |

#### Group-based ACL (unit-tested)

| Scenario | ACL Config | Consumer `acl_groups` | Expected |
|----------|-----------|----------------------|----------|
| Group allow — match | `allowed_groups: [engineering]` | `[engineering]` | 200 OK |
| Group allow — no match | `allowed_groups: [engineering]` | `[marketing]` | 403 |
| Group deny — match | `disallowed_groups: [banned]` | `[engineering, banned]` | 403 |
| Group deny — no match | `disallowed_groups: [banned]` | `[engineering]` | 200 OK |
| Group deny beats username allow | `allowed_consumers: [alice], disallowed_groups: [banned]` | alice, `[banned]` | 403 |
| Group allow + username allow (OR) | `allowed_consumers: [admin], allowed_groups: [engineering]` | alice, `[engineering]` | 200 OK |

### Multi-Auth Mode Tests (Tests 28-32)

Multi-auth mode executes auth plugins sequentially; first success stops iteration.

| # | Test | Credentials Provided | Expected |
|---|------|---------------------|----------|
| 28 | JWT succeeds first | Valid JWT token | 200 OK (JWT identifies consumer) |
| 29 | API key fallback | Valid API key only | 200 OK (key_auth identifies consumer) |
| 30 | Bob via API key only | Bob's API key (no JWT creds) | 200 OK |
| 31 | No credentials | Nothing | 401 (all plugins fail) |
| 32 | All invalid | Bad JWT + bad API key | 401 (all plugins fail) |

### Multi-Auth + ACL Combined Tests (Tests 33-35)

| # | Test | Auth | ACL Config | Expected |
|---|------|------|-----------|----------|
| 33 | Alice via JWT (allowed) | Valid JWT | `allowed_consumers: [alice]` | 200 OK |
| 34 | Alice via API key (allowed) | Valid API key | `allowed_consumers: [alice]` | 200 OK |
| 35 | Bob (blocked by ACL) | Valid API key | `allowed_consumers: [alice]` | 403 |

### Consumer CRUD Lifecycle Tests (Tests 36-40)

| # | Test | Action | Expected |
|---|------|--------|----------|
| 36 | Credentials redacted | GET consumer | `basicauth` omitted |
| 37 | List consumers | GET /consumers | Array with >= 3 consumers |
| 38 | Delete credential | DELETE credential, then auth | 401 (key no longer valid) |
| 39 | Re-add credential | PUT new credential, then auth | 200 OK (new key works) |
| 40 | Delete consumer | DELETE while ACL still names `bob` is 409; drop the username, then DELETE; auth | 409 then 204; 401 + admin 404 |

## Environment Variables

| Variable | Value | Purpose |
|----------|-------|---------|
| `FERRUM_MODE` | `database` | Operating mode |
| `FERRUM_ADMIN_JWT_SECRET` | `test-admin-jwt-secret-key-1234567890` | JWT signing secret for admin API |
| `FERRUM_ADMIN_JWT_ISSUER` | `ferrum-edge-auth-test` | JWT issuer claim |
| `FERRUM_DB_TYPE` | `sqlite` | Database type |
| `FERRUM_DB_URL` | `sqlite:<temp>/test.db?mode=rwc` | Database connection string |
| `FERRUM_DB_POLL_INTERVAL` | `2` | Database poll interval (seconds) |
| `FERRUM_PROXY_HTTP_PORT` | (random) | Proxy HTTP port |
| `FERRUM_ADMIN_HTTP_PORT` | (random) | Admin API HTTP port |
| `FERRUM_LOG_LEVEL` | `info` | Logging level |
| `FERRUM_BASIC_AUTH_HMAC_SECRET` | `test-hmac-server-secret-0123456789abcdef` | HMAC-SHA256 server secret for basic auth password verification (≥32 bytes) |

## Key Implementation Details

### Auth Mode Behavior

**Single mode** (default): Auth plugins execute sequentially. First failure immediately rejects the request.

**Multi mode**: Auth plugins execute sequentially. Each failure is recorded but execution continues. First success (consumer identified) stops iteration. If all fail, the last rejection is returned.

### Plugin Execution Order

Plugins execute by priority (lower = first):

1. `jwt_auth` (priority 1100) — JWT token verification
2. `key_auth` (priority 1200) — API key lookup
3. `basic_auth` (priority 1300) — Username/password verification
4. `hmac_auth` (priority 1400) — HMAC signature verification
5. `access_control` (priority 2000) — Consumer authorization (runs in authorize phase, after auth)

### Consumer Credential Types

| Credential Type | Storage Key | Lookup Method |
|----------------|-------------|---------------|
| `keyauth` | `{"key": "..."}` | `ConsumerIndex::find_by_api_key()` |
| `basicauth` | `{"password_hash": "..."}` | `ConsumerIndex::find_by_username()` |
| `jwt` | `{"secret": "..."}` | `ConsumerIndex::find_by_identity()` |
| `hmac_auth` | `{"secret": "..."}` | `ConsumerIndex::find_by_identity()` |

### HMAC Signing String

The `/hmacauth` proxy uses `signing_profile: ferrum-hmac-v1` (with `allow_unsafe_replayable_v1: true`). The signature is computed over:

```text
ferrum-hmac-v1\n{NAMESPACE}\n{USERNAME}\n{AUTHORITY}\n{METHOD}\n{PATH}\n{QUERY}\n{DATE}\n{DIGEST_HEADER_VALUE}
```

`ferrum-hmac-v2` appends a trailing `{NONCE}` field. The test helpers are in `tests/common/hmac_helpers.rs`; see [`hmac_auth`](plugins.md#hmac_auth) for the field definitions.

### JWT Token Notes

- `jwt_auth` uses the configurable `leeway_secs` (default `0`, max `300`) for expiration validation
- The expired token test uses a -300 second offset, so it stays expired under any allowed leeway
- Consumer lookup uses the `sub` claim by default (configurable via `consumer_claim_field`)

## References

- [Database Mode Functional Testing](functional_testing_database.md) — CRUD and routing tests
- [Plugin Execution Order](plugin_execution_order.md) — Plugin priority and lifecycle phases
- [Admin API Reference](../openapi.yaml) — Full API specification
