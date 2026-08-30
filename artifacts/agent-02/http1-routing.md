# Launch-readiness report: HTTP/1.1 routing, normalization, headers, bodies, errors

**Agent:** Ferrum Edge Launch-Readiness Agent 02  
**Scope:** Investigation only (no production code changes)  
**SHA tested:** `bf05855f8429e466511610f9072f666b45cd309a` (`origin/main` as of 2026-08-30; matches expected `bf05855f` or newer)  
**Binary:** `target/debug/ferrum-edge` version `0.9.0` (`x86_64-unknown-linux-gnu`)  
**Compile:** `CXX=g++ CC=gcc CARGO_BUILD_JOBS=1 RUSTFLAGS='-C debuginfo=0' cargo --config 'build.rustc-wrapper=""' build --jobs 1 --bin ferrum-edge` — finished in 15m 14s  
**Ports:** `127.0.0.1:21100` (proxy HTTP), `21101` (admin HTTP), origins `21110–21114`, refused `21122`, blackhole `192.0.2.1:21123`. Resource prefix `fe-agent-02-`.  
**Mode:** file-mode reverse proxy, local HTTP origins, raw-byte clients  
**Harness:** `artifacts/agent-02/run_http1_matrix.py` → `artifacts/agent-02/results.json`  
**Verdict:** **PASS** (66/66 matrix rows; hot-zone regressions #4025 / #4053 / #4054 / #4055 hold). One residual contract gap at the HTTP/1.1 parser boundary (empty 400 bodies) — tracked below, not a smuggling hole.

---

## Method

1. Fetched `origin/main` and recorded `bf05855f8429e466511610f9072f666b45cd309a`.
2. Re-read `docs/routing.md`, `docs/request_path_canonicalization.md`, `docs/error_classification.md`, `src/proxy/headers.rs`, `check_protocol_headers`, and hot-zone issues/PRs **#4025 / #4068**, **#4053 / #4075**, **#4054 / #4075**, **#4055 / #4074**.
3. Searched open+closed issues/PRs for `[Launch readiness][HTTP1]`, hop-by-hop, CL/TE smuggling, Allow/405, 414/431. No prior open HTTP1 launch-readiness issue existed.
4. Built `ferrum-edge` (jobs=1). Did **not** run unfiltered `cargo test` / `unit_tests`.
5. Started file-mode gateway + local origins. Drove raw HTTP/1.1 (including hostile bytes). Scraped `stdout_logging` access lines and tracing `error_class` / `error_kind`.

Gateway JSON envelopes are `{"error":"..."}` + `application/json`. RFC 7807 `application/problem+json` is claimed only for `openapi_validator`, not gateway-built rejects.

---

## Hot-zone regressions (retested, not duplicated)

| Issue | PR | Claim | SHA `bf05855f` result |
|---|---|---|---|
| [#4025](https://github.com/ferrum-edge/ferrum-edge/issues/4025) | [#4068](https://github.com/ferrum-edge/ferrum-edge/pull/4068) merged `3c88f7f73` | 405 MUST carry `Allow` | **HOLD.** POST `/getonly` → `405` `{"error":"Method Not Allowed"}` `Allow: GET`. TRACE/CONNECT use static `Allow: GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS`. |
| [#4053](https://github.com/ferrum-edge/ferrum-edge/issues/4053) | [#4075](https://github.com/ferrum-edge/ferrum-edge/pull/4075) merged `cd5066104` | HTTPS-to-plaintext is `tls_error`, not `connection_refused` | **HOLD.** Access log `error_class=tls_error`, tracing `error_kind=tls_error`. Public pair remains `502` / `X-Gateway-Error: connection_failure` / `{"error":"Backend unavailable"}` (pre-wire). |
| [#4054](https://github.com/ferrum-edge/ferrum-edge/issues/4054) | [#4075](https://github.com/ferrum-edge/ferrum-edge/pull/4075) | Backend FIN before complete body is `connection_closed` | **HOLD.** `502` `X-Gateway-Error: backend_error` `{"error":"Backend response body read failed"}`, access log `error_class=connection_closed`. |
| [#4055](https://github.com/ferrum-edge/ferrum-edge/issues/4055) | [#4074](https://github.com/ferrum-edge/ferrum-edge/pull/4074) merged `3ab50ddd` | `backend_write_timeout_ms` terminates POST when origin never reads | **HOLD when the write actually stalls.** 8 MiB POST to accept-and-sleep origin → `504` @ 810 ms, `X-Gateway-Error: backend_timeout`, `error_class=read_write_timeout`. **Nuance:** 2 MiB on this kernel fits localhost TCP buffers, so write idle does not fire and the request waits on `backend_read_timeout_ms` (original 2 MiB repro is environment-dependent). |

Comments with this SHA were posted on the four issues.

---

## Matrix (66 rows; negatives included)

| ID | Charter | Case | Expected | Observed | Verdict | Notes |
|---|---|---|---|---|---|---|
| R01 | 1 routing | Exact path `=/healthz` | 200 backend `/rid/exact/...` | 200 `path=/rid/exact/healthz` | PASS | |
| R02 | 1 routing | Exact does not prefix-match `/healthz/live` | 404 `Not Found` | 404 `{"error":"Not Found"}` | PASS | negative |
| R03 | 1 routing | Longest prefix `/api/v1` beats `/api` | 200 `/rid/apiv1/...` | 200 `path=/rid/apiv1/users` | PASS | |
| R04 | 1 routing | Shorter prefix `/api` | 200 `/rid/api/...` | 200 `path=/rid/api/health` | PASS | |
| R05 | 1 routing | Regex `~/users/{uid}/orders` full match | 200 `/rid/regex` | 200 `path=/rid/regex` | PASS | |
| R06 | 1 routing | Regex does not match `/users/42/orders/pending` | 404 (auto `$`) | 404 `{"error":"Not Found"}` | PASS | negative |
| R07 | 1 routing | Exact host `api.example.com` + `/tier` beats wildcard | 200 `/rid/tier-exact` | 200 `path=/rid/tier-exact/x` | PASS | overlapping same `listen_path` |
| R08 | 1 routing | Wildcard `*.example.com` + `/tier` | 200 `/rid/tier-wild` | 200 `path=/rid/tier-wild/x` | PASS | |
| R09 | 1 routing | Wildcard does not match apex `example.com` | 404 | 404 `{"error":"Not Found"}` | PASS | negative |
| R10 | 1 routing | Host-only fallback on `api.example.com` | 200 `/rid/hostonly` | 200 `path=/rid/hostonly/anything-else` | PASS | |
| R11 | 1 routing | Path-pinned `/api/v2` beats host-only | 200 `/rid/pinned` | 200 `path=/rid/pinned/items` | PASS | |
| R12 | 1 routing | Host-only `fallback.example.com` any path | 200 `/rid/fallback` | 200 `path=/rid/fallback/no/such/prefix` | PASS | |
| R13 | 1 routing | Unmatched path | 404 | 404 `{"error":"Not Found"}` | PASS | negative |
| R14 | 1 routing | `allowed_methods: [GET]` admits GET | 200 | 200 `path=/rid/getonly` | PASS | |
| R15 | 1 / #4025 | POST to GET-only | 405 + `Allow: GET` | 405 `Allow: GET` `{"error":"Method Not Allowed"}` | PASS | |
| R16 | 1 routing | TRACE | 405 + static Allow, no TRACE/CONNECT | 405 `Allow: GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS` | PASS | negative |
| P01 | 2 path | strip empty suffix `/strip` | backend `/` | 200 `path=/` | PASS | |
| P02 | 2 path | strip `/strip/foo` | backend `/foo` | 200 `path=/foo` | PASS | |
| P03 | 2 path | `backend_path` `/bprefix/foo` | `/internal/foo` | 200 `path=/internal/foo` | PASS | |
| P04 | 2 path | encoded slash `/echo/a%2Fb` | 400, no smuggle | 400 `encoded path separator` | PASS | negative |
| P05 | 2 path | encoded dot `/echo/a/%2e%2e/b` | 400 | 400 `encoded dot segment` | PASS | negative |
| P06 | 2 path | literal `/echo/a/../b` | 400 | 400 `dot segment` | PASS | negative |
| P07 | 2 path | duplicate slashes `/echo//foo` | 200, not a dot segment | 200 `path=/echo//foo` | PASS | |
| P08 | 2 path | query `/echo?x=1&y=two` | query preserved | 200 `path=/echo?x=1&y=two` | PASS | |
| P09 | 2 path | pchar decode `/%61dmin` | `/echo/admin` | 200 `path=/echo/admin` | PASS | |
| P10 | 2 path | percent UTF-8 `/echo/caf%C3%A9` | 400 unrepresentable | 400 `unrepresentable percent-escape` | PASS | negative |
| P11 | 2 path | literal UTF-8 `/echo/café` | 200; forwarded spelling may be `%C3%A9` | 200 `path=/echo/caf%C3%A9` | PASS | matches canonicalization docs |
| P12 | 2 / 414 | path > 8192 | 414 | 414 URL-length JSON | PASS | negative |
| P13 | 2 path | exact `=/healthz?ready=true` | still matches | 200 `/rid/exact/healthz?ready=true` | PASS | |
| H01 | 3 headers | hop-by-hop not forwarded | no Connection/Keep-Alive/TE/Upgrade/Proxy-Connection | 200; `X-Keep` survived | PASS | |
| H02 | 3 headers | `Connection: X-Sensitive` | `X-Sensitive` stripped | 200; not present on origin | PASS | anti-smuggle |
| H03 | 3 headers | `preserve_host_header=false` | Host rewritten to backend | Host `127.0.0.1` (port 80 omitted) | PASS | RFC default-port |
| H04 | 3 headers | `preserve_host_header=true` | client Host forwarded | `preserve.example.com` | PASS | |
| H05 | 3 headers | duplicate Host | 400 JSON | 400 `multiple Host headers` | PASS | negative; handler-layer JSON |
| H06 | 3 headers | Host case `API.EXAMPLE.COM` | exact-host route | 200 `/rid/tier-exact/x` | PASS | |
| H07 | 3 headers | obsolete line folding | reject / no smuggle | 400 | PASS | negative |
| H08 | 3 / 431 | single header 20 KiB | 431 | 431 `x-big` exceeds 16384 | PASS | negative; name escaped, not a secret |
| B01 | 4 bodies | Content-Length POST | body intact | 200 | PASS | |
| B02 | 4 bodies | chunked POST | decoded and forwarded | 200; backend hop re-chunked by reqwest | PASS | TE on origin is new-hop framing |
| B03 | 4 bodies | empty CL=0 | body_len 0 | 200 | PASS | |
| B04 | 4 bodies | identity POST (no CL/TE) | empty body | 200 body_len 0 | PASS | |
| B05 | 4 bodies | 1 MiB POST | 200 under 10 MiB cap | 200 body_len 1048576 | PASS | |
| B06 | 4 / 413 | declared CL 12_000_000 | 413 before upload | 413 `Request body exceeds maximum size` | PASS | negative |
| B07 | 4 / smuggle | CL + TE | 400 JSON | 400 both CL and TE | PASS | negative; handler-layer JSON |
| B08 | 4 / smuggle | two conflicting CL | 400 | 400 **empty body** | PASS | fail-closed; envelope gap |
| B09 | 4 bodies | HTTP/1.0 + TE | 400 | 400 **empty body** | PASS | fail-closed; envelope gap |
| B10 | 4 / #4054 | origin FIN mid-body | 502 + `connection_closed` | 502 `backend_error` + log `connection_closed` | PASS | |
| B11 | 4 bodies | client early close mid-POST | gateway stays up | subsequent GET 200 | PASS | |
| E01 | 5 errors | 404 envelope | JSON, not problem+json, no secret leak | 404 `{"error":"Not Found"}` | PASS | Bearer secret not echoed |
| E02 | 5 errors | 400 path + secret in path/header | fixed JSON, no echo | 400 encoded-separator; secret absent | PASS | |
| E03 | 5 / 7807 | gateway envelopes | `{error:...}` not problem+json | `application/json` on 404/405/502 | PASS | 7807 not claimed here |
| E04 | 5 / 502 | unbound origin | 502 `connection_failure` | 502 + log `connection_refused` | PASS | |
| E05 | 5 / #4053 | HTTPS→HTTP origin | log `tls_error` | 502 `connection_failure` + log `tls_error` | PASS | public token is pre-wire pair |
| E06 | 5 / 504 | stall after response headers | 504 @ ~800 ms | 504 @ 804 ms `backend_timeout` / `read_write_timeout` | PASS | |
| E07 | 5 / 504 | stall after partial body | 504 | 504 @ 804 ms | PASS | |
| E08 | 5 / #4055 | 8 MiB POST, origin never reads | 504 write idle | 504 @ 810 ms `backend_timeout` / `read_write_timeout` | PASS | |
| E09 | 5 / 502 | connect timeout `192.0.2.1` | 502 ~800 ms | 502 @ 804 ms log `connection_timeout` | PASS | |
| T01 | 6 / slowloris | header stall, timeout=2s | close (docs) or 408 | close @ 2002 ms; **no 408** | PASS | documented as close |
| T02 | 6 timeouts | `/live` after battery | 200 | 200 `{"status":"ok"}` | PASS | |
| X01 | 1 routing | CONNECT | 405 | 405 `CONNECT method is not allowed` | PASS | negative |
| X02 | 2 path | double-encoding `%252F` | 400 | 400 `double-encoded percent-escape` | PASS | negative |
| X03 | 2 path | encoded NUL `%00` | 400 | 400 `encoded control character` | PASS | negative |
| X04 | 3 headers | client `X-Forwarded-For: 8.8.8.8` | gateway-owned XFF | origin sees `127.0.0.1` | PASS | |
| X05 | 5 / 414 | long URL marker | 414 must not echo marker | 414 length only | PASS | |
| X06 | 5 errors | latin-1 `0xE9` in target | 400 fail-closed | 400 **empty body** | PASS | parser-layer; UTF-8 café is 200 (P11) |
| X07 | 4 / #4055 | 2 MiB never-read | no write-idle 504 within 2s on this kernel | transport wait @ 2203 ms | PASS | observational nuance |

**66 rows.** Negatives: R02, R06, R09, R13, R16, P04–P06, P10, P12, H05, H07, H08, B06–B09, X01–X03, X06.

Not exercised (no cheap, safe trigger on this range): **503** (overload / circuit-breaker-open). **408** is not a gateway JSON envelope; slowloris is a transport close (`read header from client timeout`).

---

## Access-log `error_class` (stdout_logging)

| Path | Status | `error_class` | Matches docs? |
|---|---|---|---|
| `/echo/huge` | 413 | `request_body_too_large` | yes |
| `/tfin` | 502 | `connection_closed` | #4054 yes |
| `/tconn` | 502 | `connection_refused` | yes |
| `/tlsbe` | 502 | `tls_error` | #4053 yes |
| `/tread` | 504 | `read_write_timeout` | yes |
| `/tstall` | 504 | `read_write_timeout` | yes |
| `/twrite` (8 MiB) | 504 | `read_write_timeout` | #4055 yes |
| `/thang` | 502 | `connection_timeout` | yes |
| `/echo/early` | 502 | `request_error` | client abort mid-body; catch-all is acceptable |

---

## Findings

### Hold (not new issues)

Routing precedence in `docs/routing.md` is deterministic on the wire: exact path > longest prefix > regex (same host tier); exact host > wildcard > catch-all; host-only is last inside a host group. Path canonicalization rejects encoded separators, dot segments (literal and encoded), double-encoding, controls, and unrepresentable escapes with **fixed non-echoing JSON**. Hop-by-hop + Connection-nominated stripping works. CL+TE is rejected in-handler with JSON. Size limits 413/414/431 hold. Timeouts: connect, read, write-stall, and header-read all bound.

### Residual contract gap (one distinct root cause)

**Parser-layer HTTP/1.1 400s omit the JSON envelope** that `check_protocol_headers` / policy-path rejects emit.

| Input | Status | Body | Log |
|---|---|---|---|
| Two `Content-Length` values | 400 | empty (`content-length: 0`) | `invalid content-length parsed` |
| HTTP/1.0 + `Transfer-Encoding` | 400 | empty | `unexpected transfer-encoding parsed` |
| latin-1 `0xE9` in request-target | 400 | empty | (connection error) |
| Two `Host` headers (contrast) | 400 | `{"error":"Request contains multiple Host headers"}` | handler path |
| CL + TE (contrast) | 400 | `{"error":"Request contains both Content-Length and Transfer-Encoding headers"}` | handler path |

Still fail-closed (no smuggle). Clients and tests that key off `{"error":...}` / `X-Gateway-Error` see an inconsistent 400 surface. Filed: [#4393](https://github.com/ferrum-edge/ferrum-edge/issues/4393).

### Not bugs

- RFC 7807: not claimed for gateway-built errors.
- Slowloris: `FERRUM_HTTP_HEADER_READ_TIMEOUT_SECONDS` documents **close**, not 408.
- 2 MiB write-timeout: kernel buffering; 8 MiB proves the watermark. Operators who need a bound after a fully-buffered upload must also set `backend_read_timeout_ms`.
- Host `127.0.0.1` without `:21110`: default port 80 omitted.

---

## Issue / PR actions

- Comments: [#4025](https://github.com/ferrum-edge/ferrum-edge/issues/4025#issuecomment-5467742701), [#4053](https://github.com/ferrum-edge/ferrum-edge/issues/4053#issuecomment-5467742772), [#4054](https://github.com/ferrum-edge/ferrum-edge/issues/4054#issuecomment-5467742812), [#4055](https://github.com/ferrum-edge/ferrum-edge/issues/4055#issuecomment-5467742886).
- New issue: [#4393](https://github.com/ferrum-edge/ferrum-edge/issues/4393) parser-layer empty 400 envelope.
- Artifacts PR: [#4395](https://github.com/ferrum-edge/ferrum-edge/pull/4395).

---

## Reproduction (local)

```bash
# after building ferrum-edge
export FE_AGENT_02_SHA=$(git rev-parse HEAD)
python3 artifacts/agent-02/run_http1_matrix.py
# config: artifacts/agent-02/fe-agent-02.yaml
# results: artifacts/agent-02/results.json
```

All listeners stay on `127.0.0.1:21100-21199`. Prefix every resource `fe-agent-02-`.
