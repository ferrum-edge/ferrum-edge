# Agent 19 — Adversarial security launch-readiness review

Investigation only. No production code changes.

| Field | Value |
| --- | --- |
| SHA | `bf05855f8429e466511610f9072f666b45cd309a` (`origin/main`, `bf05855f8 Merge pull request #4319`) |
| Agent | Ferrum Edge Launch-Readiness Agent 19 |
| Ports | `127.0.0.1:22800` proxy, `127.0.0.1:22801` admin, `127.0.0.1:22810/22811` echo backends |
| Prefix | `fe-agent-19-` |
| Compile | `CXX=g++ CC=gcc CARGO_BUILD_JOBS=1 RUSTFLAGS='-C debuginfo=0' cargo --config 'build.rustc-wrapper=""' build --jobs 1 --bin ferrum-edge` — **pass** (15m 09s) |
| Verdict | **FAIL** |

## Verdict

Two HTTP/1 admission gaps are live on `bf05855f`:

1. HTTP/1.1 requests without a `Host` header are not rejected (RFC 9112 §3.2.2 MUST 400). A Host-less request to a catch-all path is routed and forwarded.
2. The documented CL+TE smuggling reject is order-dependent. `Content-Length` then `Transfer-Encoding` is 400; `Transfer-Encoding` then `Content-Length` is accepted and forwarded.

Other charter surfaces (H2/H3 framing guards, secret redaction, observability defaults, CORS construction, header/body/slowloris ceilings) are fail-closed or already tracked.

## Duplicate search

Security-labeled issues were listed first (open + recently closed). Semantic search covered smuggling, Host/authority, JWT/`_FILE` redaction, PERMISSIVE mTLS, metrics 401, CORS, max-request budgets, and the named overlap clusters.

| Cluster | Status | Why not this RCA |
| --- | --- | --- |
| Non-ASCII auth (#4063, #4060) | Closed | Plugin header decoding, not HTTP/1 Host admission |
| WAF SSRF (#3936, #3935, #3934) | Closed | Default WAF query/body rules, not gateway framing |
| NodeWaypoint UDP (#3861, #3286, #4021, #3858) | Closed | Ambient UDP identity/steering, not HTTP parsers |
| Destructive Admin API (#4177) | Closed | Mesh config-revision reset audit, not parser/defaults |
| Admin audit namespace (#4284) | Open | Global-route audit namespace, not Host/TE framing |
| Request buffering (#4153) | Closed | Body-limit `0` fail-closed + aggregate budget |
| H2 idle/header bounds (#4152) | Closed | H2 sniff/window timeouts |
| H3 unbounded frames (#4261) | Closed | QUIC stream payload accumulation |
| CORS credentials (#4269, #4296) | Closed | Origin reflection / metadata rewrite |
| Trailers forging `#x-consumer-*` (#4148) | Closed | Trailer sanitization, not CL/TE or Host |

No open or closed issue described HTTP/1.1 missing-`Host` admission or TE.CL order-dependent CL+TE bypass.

## Method

- Static review of `check_protocol_headers`, `check_host_authority_consistency`, hop-by-hop strip, admin observability, JWT/`_FILE` redaction, CORS construction, and resource-limit defaults.
- Light compile of `ferrum-edge` at the recorded SHA.
- File-mode live probes on `127.0.0.1:22800/22801` against two echo backends (`fe-agent-19-host-app` on `:22810`, `fe-agent-19-catchall` on `:22811`). Config: `artifacts/agent-19/configs/host-and-catchall.yaml`.
- HTTP-message-level requests only. No exploit payloads, no unauthorized-access PoCs.
- Targeted `unit_tests` filter `protocol_validation_` (not unfiltered `cargo test`).

## 1. HTTP/1 smuggling / parser differential — FAIL

`check_protocol_headers()` (`src/proxy/mod.rs`) runs before routing and is the documented smuggling boundary. Live results:

| Case | Wire shape (sanitized) | Observed | Posture |
| --- | --- | --- | --- |
| CL.TE | `Content-Length` then `Transfer-Encoding: chunked` | **400** `Request contains both Content-Length and Transfer-Encoding headers` | Fail-closed |
| TE.CL | `Transfer-Encoding: chunked` then `Content-Length` | **200** forwarded to `host-app` | **Fail-open vs documented reject** |
| Duplicate conflicting CL | two `Content-Length` values | **400** (hyper close, empty body) | Fail-closed |
| Duplicate same CL | (unit only) | allowed / coalesced | RFC 9110 §8.6 compliant |
| Multiple TE / `chunked, identity` / `identity`+CL | extra or unknown TE | **400** (hyper) | Fail-closed |
| TE-only `chunked` | valid HTTP/1.1 | **200** | Expected |
| HTTP/1.0 + TE | TE on 1.0 | **400** | Fail-closed |
| Duplicate Host | two `Host` fields | **400** `Request contains multiple Host headers` | Fail-closed |
| Missing Host, origin-form `/` | no `Host`, host-scoped route only | **404** (not 400) | **Spec miss** |
| Missing Host, catch-all path | `GET /catchall` no `Host` | **200** to catch-all backend | **Fail-open** |
| Absolute-form vs Host | `GET http://evil.example/` + `Host: app.example` | **200** to `host-app`; backend sees origin-form `/` | Fail-closed for forwarding |
| Absolute-form, no Host | `GET http://app.example/` | **200** to `host-app` (URI authority used) | Same as sending that Host |
| obs-fold | folded continuation line | **400** | Fail-closed (hyper) |
| Control byte in header value | `0x01` in field value | **400** | Fail-closed (hyper) |
| `Host :` (space before colon) | invalid field line | **400** | Fail-closed |
| `Host:\t` (HTAB after colon) | OWS | **200** | Valid OWS |
| Connection-nominated `X-Internal-Token` | `Connection: x-internal-token` | **200**; token **absent** from backend header names | Fail-closed |

### Finding A — HTTP/1.1 missing Host

**Observed.** RFC 9112 §3.2.2 requires 400 for any HTTP/1.1 request that lacks `Host`. Ferrum does not check this. `check_protocol_headers` only rejects *multiple* Host values. Routing uses `raw_header_get("host").or_else(uri.authority)` (`src/proxy/mod.rs` ~29399). When both are absent, `request_host` is `None` and `RouterCache::search_route_table` skips exact/wildcard host tiers and falls through to catch-all (`src/router_cache.rs` ~1917–2014).

Live: `GET / HTTP/1.1` with no Host → 404 (host-scoped `/` did not match). `GET /catchall HTTP/1.1` with no Host → 200, backend marker `catchall`.

**Expected.** HTTP/1.1 without `Host` is 400 before routing. Catch-all routes must not be reachable by omitting Host.

**RCA.** Admission never implements the RFC 9112 missing-Host MUST. Host-based ACLs / vhost isolation are bypassable whenever a catch-all (empty `hosts`) route exists for that path.

### Finding B — TE.CL order-dependent CL+TE reject

**Observed.** Documented guard: HTTP/1 messages with both `Content-Length` and `Transfer-Encoding` are 400. Live CL.TE matches that body. Live TE.CL is 200 and reaches the configured backend.

**Expected.** Either header order is a protocol violation and is rejected the same way.

**RCA.** Hyper's HTTP/1 parser removes `Content-Length` when `Transfer-Encoding` is already present (RFC 9112 “TE overrides CL”) *before* `check_protocol_headers` runs. The application guard therefore sees TE-only and allows the request. CL.TE still presents both names in the `HeaderMap`, so the guard fires.

Ferrum reconstructs the backend request (hop-by-hop / TE strip, new framing). That reduces classic gateway-to-backend desync. The residual is a parser differential with any frontend that still honors CL on a TE.CL message, and a hole in the gateway's own documented reject.

Sanitized TE.CL request:

```
POST / HTTP/1.1
Host: app.example
Transfer-Encoding: chunked
Content-Length: <decimal>
```

Sanitized CL.TE request (rejected):

```
POST / HTTP/1.1
Host: app.example
Content-Length: <decimal>
Transfer-Encoding: chunked
```

## 2. H2 / H3 pseudo-headers, connection headers, authority, path, frames — PASS

| Control | Evidence | Posture |
| --- | --- | --- |
| H2/H3 `Transfer-Encoding` | `check_protocol_headers` rejects; unit + functional coverage | Fail-closed |
| H2/H3 `TE` other than `trailers` | token walk + empty-list reject | Fail-closed |
| Host / `:authority` disagreement | `check_host_authority_consistency` on H2/H3 only; case/dot/default-port normalized | Fail-closed |
| Multiple Host on H2/H3 | consistency helper rejects before routing | Fail-closed |
| Connection-specific / hop-by-hop | stripped inbound (backend) and outbound (client); H3 final strip after plugins | Fail-closed |
| Path normalization | `canonicalize_policy_path` before routing/plugins (GHSA-69xf-42xm-4w4f) | Fail-closed |
| H2 frame / header list | `frontend_h2_max_frame_size`, `max_header_list_size`, stream/connection windows | Bounded |
| H3 field section | `SETTINGS_MAX_FIELD_SECTION_SIZE` + 431; prior OOM (#4261) closed | Bounded |
| CONNECT | H1 CONNECT rejected except WebSocket; H2 Extended CONNECT only `:protocol=websocket` | Fail-closed |

H2 connection-specific headers are also rejected by the `h2` crate as protocol errors before the service sees them. No new H2/H3 admission hole found on this SHA.

## 3. Secret handling — PASS

| Control | Evidence | Posture |
| --- | --- | --- |
| Admin JWT `validate_exp` | `src/admin/jwt_auth.rs` sets `validate_exp = true` and `validate_nbf = true`; required `iss/sub/exp/iat/nbf/jti` | Fail-closed |
| DB/CP secret floor | `FERRUM_ADMIN_JWT_SECRET` ≥ 32 chars; short/invalid settings are `VerificationFailed`, not “unset” | Fail-closed |
| File-mode generated secret | `src/modes/file.rs` mints a random secret only on `NotConfigured`; log is `Admin JWT not configured, generating a random read-only secret; admin endpoints will reject externally minted tokens` | Secret not logged |
| Live file-mode log | captured on `:22801` startup; placeholder/redaction path only, no secret bytes | Pass |
| `_FILE` / external secret redaction | `redact_external_secret_values` + structured log-record rewrite; `tests/unit/secrets/redaction_tests.rs` | Fail-closed |
| Admin JWT never minted | module docs and implementation validate only | Pass |

`JwtConfig` derives `Debug` and contains `secret`. `JwtManager` does not derive `Debug` and is the type held in admin state. No production log site prints `JwtConfig`. Residual hygiene only; not filed.

## 4. Resource exhaustion — PASS (documented residuals)

| Limit | Default | Live / code |
| --- | --- | --- |
| `FERRUM_MAX_HEADER_SIZE_BYTES` | 32768 | 431 on overflow (H1/H2/H3 functional coverage) |
| `FERRUM_MAX_HEADER_COUNT` | 100 | 431; `0` disables (documented) |
| `FERRUM_MAX_REQUEST_BODY_SIZE_BYTES` | 10 MiB | enforced; `#4153` closed fail-closed-on-0 |
| `FERRUM_HTTP_HEADER_READ_TIMEOUT_SECONDS` | 10 | slowloris / incomplete header timeout; `0` disables |
| `FERRUM_MAX_CONNECTIONS` | 100000 | logged at startup (`Connection limit: 100000`) |
| `FERRUM_MAX_REQUESTS` | **0 = unlimited** | documented in `docs/configuration.md` |
| `FERRUM_MAX_CONCURRENT_REQUESTS_PER_IP` | **0 = disabled** | documented |
| `FERRUM_ADMIN_MAX_CONNECTIONS` | 1024 | after CIDR, before TLS |
| `FERRUM_ADMIN_MAX_CONNECTIONS_PER_IP` | **0 = disabled** | documented (LB/monitor source) |

Unbounded request concurrency is an operator-tuned residual, not a silent fail-open. Header/body/slowloris ceilings are on by default. Not filed as a new issue.

## 5. Unsafe defaults — PASS

| Surface | Default | Evidence |
| --- | --- | --- |
| PERMISSIVE mTLS | Istio UNSET → PERMISSIVE | Translator fail-closed on unknown mode; EgressGateway escalates PERMISSIVE to require a cert; PERMISSIVE with no trust anchor is explicit `PermissiveNoTrustAnchor` + warn, not silent STRICT→PERMISSIVE |
| `/live` | unauthenticated `{"status":"ok"}` | live 200 |
| `/health`, `/status` | unauthenticated `{status, ready}` only | live `{"status":"ok","ready":true}`; full body JWT/token/CIDR gated |
| `/overload` | unauthenticated `{level}` | live `{"level":"normal"}` |
| `/metrics` | 401 | live 401 + `WWW-Authenticate: Bearer` text |
| CORS | `allowed_origins` required | empty/missing origins fail construction; `*` + credentials drop-credentials; universal prefix/regex + credentials refused (#4269) |

## Overlap note

Symptoms around non-ASCII auth, WAF SSRF, NodeWaypoint UDP, protocol-error classification, and destructive Admin API were reviewed. Those clusters have their own RCAs and do not explain the HTTP/1 Host or TE.CL gaps.

## Issues filed

- https://github.com/ferrum-edge/ferrum-edge/issues/4390 — HTTP/1.1 missing Host not rejected
- https://github.com/ferrum-edge/ferrum-edge/issues/4391 — TE.CL bypasses CL+TE smuggling reject

## Reproduce (sanitized)

File mode, `artifacts/agent-19/configs/host-and-catchall.yaml`, proxy `127.0.0.1:22800`.

Missing Host (expect 400, observed 200 on catch-all path):

```
GET /catchall HTTP/1.1
```

TE.CL (expect 400, observed 200):

```
POST / HTTP/1.1
Host: app.example
Transfer-Encoding: chunked
Content-Length: <decimal>
```

CL.TE (expect 400, observed 400):

```
POST / HTTP/1.1
Host: app.example
Content-Length: <decimal>
Transfer-Encoding: chunked
```

## Artifacts

- `artifacts/agent-19/configs/catchall.yaml`
- `artifacts/agent-19/configs/host-and-catchall.yaml`
- `artifacts/agent-19/echo_backend.py`
- `artifacts/agent-19/live_probe.py`
- `artifacts/agent-19/live-results-host-and-catchall.json`
