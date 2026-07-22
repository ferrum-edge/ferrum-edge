# Web Application Firewall (WAF)

The `waf` plugin performs content-pattern threat detection on HTTP-family
traffic (HTTP/1.1, HTTP/2, HTTP/3, gRPC-over-HTTP). It inspects request
metadata and bodies — and, optionally, responses — against a curated rule pack
plus any custom rules you supply. It can also inspect raw TCP streams and
UDP/DTLS datagrams when a [`stream`](#stream-tcpudp-inspection) block is
configured.

## Scope: what the WAF does and does not do

The WAF is deliberately scoped to **payload and metadata inspection**. Other
concerns are handled by dedicated layers and the WAF does not duplicate them:

| Concern | Handled by |
| --- | --- |
| Request smuggling (CL/TE conflicts, duplicate Content-Length) | core proxy `check_protocol_headers()` + hyper strict parsing |
| Header/URI/body size limits | `FERRUM_MAX_*` env vars, `request_size_limiting` |
| Authentication / authorization | auth plugins, `access_control`, `mesh_authz`, `opa` |
| Rate limiting / flooding | `rate_limiting`, `*_rate_limiting` |
| Schema / contract validation | `body_validator`, `openapi_validator` |
| Bot / IP / geo filtering | `bot_detection`, `ip_restriction`, `geo_restriction` |
| Backend SSRF allow/deny | `FERRUM_BACKEND_ALLOW_IPS` + `FERRUM_BACKEND_ALLOW_CIDRS` / `FERRUM_BACKEND_DENY_CIDRS` (metadata/link-local/multicast blocked by default) |
| Response security headers | `security_headers` |

The WAF focuses on injection and disclosure signatures: SQLi, NoSQLi, command
injection, XSS, SSTI, JNDI/Log4Shell, path traversal, LFI, RFI, SSRF, XXE,
deserialization, prototype pollution, and (response-side) sensitive-data
leakage.

## Operating modes and enforcement posture

Two independent controls decide whether a matched rule **blocks** or only
**logs**:

- `mode` — the global switch: `enforce`, `monitor`, or `disabled`.
- per-rule **action** — `enforce`, `monitor`, or `disabled`.

A request is rejected only when a matched rule's effective action is `enforce`
**and** the global mode is `enforce`.

### Default rules ship monitor-only — and how to enforce them

The built-in rule pack ships with every rule set to `monitor`. This is a safe
default: deploy the WAF, watch what it flags, then enforce deliberately. It
also means `mode: enforce` **alone does not block anything** — you must opt
rules into enforcement. There are three ways:

1. **`default_rule_action`** — bulk-set the action of every built-in rule.
   `default_rule_action: "enforce"` enforces the whole pack (still subject to
   `paranoia_level`; see below). `rule_modes` overrides still win per rule.
2. **`rule_modes`** — set the action of individual rules by id:
   `{"FE-SQLI-001": "enforce"}`.
3. **anomaly scoring** — keep rules in `monitor` and block on the aggregate
   score (see [Anomaly scoring](#anomaly-scoring)).

Because the loud/broad rules are gated behind `paranoia_level >= 2` (see
below), the recommended starting posture for active blocking is:

```json
{ "mode": "enforce", "default_rule_action": "enforce", "paranoia_level": 1 }
```

This enforces only the low-false-positive core of the rule pack.

## Paranoia levels

`paranoia_level` (1–4, default 1) gates which rules are active. Each rule has a
`paranoia_min`; rules above the configured level are compiled out entirely.
Higher levels add broader, noisier signatures that catch more attacks at the
cost of more false positives. Loud rules retuned to `paranoia_min: 2` or `3`
(see below) are inactive at the default level 1.

## Decode / normalization

Attackers hide payloads behind encodings a raw-byte scan never sees. Before
matching request and response bodies, the WAF also scans **decoded variants**:

- JSON / JavaScript unicode escapes — `\uXXXX`, `\u{...}`, `\xXX`
- HTML entities — `&lt;`, `&#60;`, `&#x3c;`
- Percent-encoding and `+`-as-space (form bodies)
- a fully layered decode for stacked encodings

So a `<script>` written as `<script>`, `&lt;script&gt;`, or
`%3Cscript%3E` in a body is still caught by the script-tag rule. Decoding is
content-type-agnostic (an attacker controls the declared `Content-Type`), and
bounded to a small number of variants. Query values are percent-decoded before
matching as well.

The layered decode runs a bounded number of rounds (a cost guard against
decompression-style blowups), so double- and triple-stacked encodings are fully
reduced but a payload stacked deeper than the cap is not. Rather than silently
forwarding such a body, the WAF raises the `encoding_evasion` signal
(`FE-ENCODING-001`) for it — the same rule that flags URL double-encoding. The
overlong-UTF8 (`FE-ENCODING-002`), double-encoding, and null-byte
(`FE-ENCODING-001`) markers are likewise checked against request and response
**bodies**, not just the URL/path, so an overlong-encoded body payload that
lossy percent-decoding cannot recover to its literal character is still flagged
as an evasion attempt.

Note that body marker detection is a heuristic: a benign body that legitimately
contains a literal encoded marker (e.g. `code=SAVE50%25`, a `%00` in free text,
or `%c0%ae` in a paste) can raise `FE-ENCODING-001` or `FE-ENCODING-002`.
This is why both rules default to **Monitor** (they record `waf.rule_hits`
metadata rather than blocking) even when the WAF is in `enforce` mode —
operators opt a rule into blocking explicitly via `rule_modes` once they have
confirmed it is clean for their traffic.

## Rule targets

A rule's `target` selects what it inspects. Use a string for targets that need
no extra fields, or an object with `type` (and target-specific fields).

Canonical targets: `header_names`, `header_values` (optionally scoped with a
non-empty `names` list), `query_keys`, `query_values`, `cookies`, `url_path`,
`full_url`, `method`, `body_text`, `body_json_path` (object form only: requires
a non-empty dotted `path`), `response_headers`, `response_body`.

Runtime aliases map onto those targets: `request_headers` → `header_values`,
`request_query` → `query_values`, `request_path` → `url_path`,
`request_url` → `full_url`, `request_method` → `method`, and
`request_body` → `body_text`. `path` is valid only on `body_json_path`;
`names` is valid only on `header_values` / `request_headers`.

`match_kind` is one of `regex` (default), `literal`, `contains`, `equals`,
`luhn` (credit-card checksum; body targets only), or `cidr` (IP membership).

## Built-in rule pack

Rule ids are stable; reference them in `rule_modes`, `disabled_default_rules`,
and `rule_overrides`. Categories:

| Category | Rules | Notes |
| --- | --- | --- |
| `sqli` | FE-SQLI-001..005 | UNION/tautology/stacked are level 1; comment-token (004) and SQLSTATE (005) are level 2 |
| `nosqli` | FE-NOSQL-001 (operator key), FE-NOSQL-002 (bracket operator, L2) | |
| `command_injection` | FE-CMD-001..003 | shell-substitution (003) is level 2 |
| `jndi_injection` | FE-JNDI-001-{B,Q,H}, FE-JNDI-002-{B,Q,H} | **Log4Shell**; direct lookup is Critical/level 1 across body, query, and header; nested-obfuscation is level 2 |
| `rce` | FE-SPRING4SHELL-001-{B,Q} | class-loader manipulation (CVE-2022-22965) |
| `prototype_pollution` | FE-PROTO-001 (`__proto__`), FE-PROTO-002 (`constructor.prototype`, L2) | |
| `ldap_injection` | FE-LDAP-001..002 | |
| `xpath_injection` | FE-XPATH-001, FE-XPATH-002 (L3, low value) | |
| `ssti` | FE-SSTI-001 (broad, L2), FE-SSTI-002 (arithmetic probe, L1), FE-SSTI-003 (Java/Spring EL, L2) | |
| `xss` | FE-XSS-001..005 plus `-B`/`-Q` body/query mirrors | script-tag and js-URL now cover both query and body |
| `path_traversal` | FE-PATHTRAV-001..003, FE-PATHTRAV-001-B | now covers request bodies, not just the URL |
| `lfi` / `rfi` | FE-LFI-001(+ -B), FE-RFI-001 (L2) | |
| `ssrf` | FE-SSRF-001(+ -Q), FE-SSRF-002(+ -Q) | metadata/private-IP and dangerous schemes across body and query |
| `xxe` | FE-XXE-001 | external-entity markers; no longer trips on `<!DOCTYPE html>` |
| `deserialization` | FE-DESER-001..003 | Java / .NET / PHP markers |
| `header_anomaly` | FE-HEADER-001..003 | control chars, method-override, header-borne injection (L2) |
| `cookie_attack` | FE-COOKIE-001, FE-COOKIE-002 (Info, L3) | |
| `encoding_evasion` / `parameter_pollution` / `method_abuse` | FE-ENCODING-001..002, FE-HPP-001, FE-METHOD-001 | |
| stack trace / db error / source / fingerprint disclosure | FE-RESP-* | response-side; requires `response_inspection` |
| `data_leak` | FE-DATA-LEAK-001..006 | credit card (Luhn), AWS/Stripe/GitHub keys, JWT (L2), private key |

Disable the whole pack with `include_default_rules: false`, or selected rules
with `disabled_default_rules: ["FE-..."]`.

## Anomaly scoring

Per-rule enforcement is binary, which makes broad rules unsafe to enforce
individually. Scoring lets weak signals accumulate and block in aggregate while
each rule stays `monitor`:

```json
{
  "scoring": {
    "enabled": true,
    "block_threshold": 7,
    "weights": { "info": 0, "low": 2, "medium": 3, "high": 5, "critical": 10 }
  }
}
```

When enabled, every matched rule contributes its severity weight (or a per-rule
`score` override) to a request total. If the total reaches `block_threshold`
and the global mode is `enforce`, the request is rejected with
`waf.block_reason = "score"`. Hard per-rule `enforce` still blocks immediately
when the global mode is `enforce`.
The total is recorded in `waf.score` metadata regardless of mode.

## Per-rule overrides and exemptions

`rule_overrides` tunes individual rules — **including built-ins** — without
forking the rule pack. Attach false-positive filters, scope to paths, raise
paranoia, change severity/score, or set a per-rule `action`:

```json
{
  "rule_overrides": {
    "FE-RFI-001": { "fp_filters": ["^https://cdn\\.example\\.com/"], "paranoia_min": 1 },
    "FE-SQLI-001": { "action": "enforce" },
    "FE-XSS-001": { "conditions": { "paths": ["/api/*"] } }
  }
}
```

Per-rule `action: "enforce"` only blocks when global `mode` is also
`enforce`; with `mode: "monitor"` the match is logged but allowed.

For per-rule `conditions.paths`, plain strings are exact matches, trailing `*`
means prefix match, and leading `~` means the remaining text is compiled as the
operator-authored regex. Regex conditions are evaluated with Rust regex
`is_match`, so they may match anywhere in the path unless the pattern itself is
anchored (for example `~^/api/`). This preserves existing scoped protections
such as `~api` matching `/api/v1` and `/v1/api-keys`.

`global_exemptions` short-circuits the entire WAF for matching requests, so keep
the entries tight — an over-broad `paths` entry silently disables the WAF on
unintended routes:

- `paths` — exact, `prefix*`, or `~regex`. All three match from the **start** of
  the path: a non-wildcard entry is an exact full-path match, `prefix*` is a
  prefix match, and `~regex` is start-anchored (an implicit leading `^`). So
  `~/internal/` exempts only paths beginning with `/internal/`, not every path
  containing it. Use `~^/a|^/b` for alternation, or `~.*pattern` if you really
  need a floating substring match.
- `methods`, `consumers`, `ips` (CIDR)
- `header_present` — suppress rules when a header is present/equal
- `fp_capture_filters` — suppress any matched value matching these patterns
  (these match anywhere in the value by design and are **not** anchored)

## Custom rules

```json
{
  "custom_rules": [
    {
      "id": "ACME-1",
      "category": "custom",
      "severity": "high",
      "target": { "type": "body_json_path", "path": "user.bio" },
      "match_kind": "contains",
      "pattern": "<script",
      "action": "enforce",
      "paranoia_min": 1,
      "fp_filters": ["<script type=\"application/ld\\+json\">"],
      "conditions": { "methods": ["POST"], "paths": ["/profile*"] }
    }
  ]
}
```

## Body and response inspection

Request-body inspection is on by default for `POST`/`PUT`/`PATCH` with an
inspectable `Content-Type` (`body_methods`, `body_content_types`). Multipart and
binary bodies are opt-in (`inspect_multipart`, `inspect_binary_body`).

Response inspection is **off by default**. Enable `response_inspection` (and
`response_body_inspection` for body rules) to run the disclosure and
data-leak rules.

`max_scan_bytes` (default 1 MiB) bounds how much of a body is scanned.
`on_body_too_large` decides what happens when a body exceeds it:

- `scan_truncated` (default) — scan the first `max_scan_bytes`, flag truncation
- `skip` — do not scan
- `block` — reject when enforcing (fail closed; for high-assurance routes set
  `max_scan_bytes` at or above `FERRUM_MAX_REQUEST_BODY_SIZE_BYTES`)

`scan_budget_ms` bounds total scan time; `on_scan_timeout` (`allow`, `block`,
`log_and_allow`) decides the outcome when the budget is exceeded.

For a pristine backend `text/event-stream`, request `Accept` and internal
streaming markers cannot bypass response-body policy. Because an unbounded
stream cannot be truncated and scanned before headers are committed,
`on_body_too_large` supplies the explicit disposition: `skip` allows it
uninspected; `block` rejects in enforce mode; and `scan_truncated` rejects when
an enforcing response-body rule or anomaly-scoring policy would otherwise claim
inspection, while monitor-only policy records and allows it. With metadata
logging enabled, WAF writes `waf.response_stream_uninspectable=true` plus either
`waf.action=stream_uninspected` or `waf.action=blocked` and
`waf.block_reason=unbounded_response_stream`. `on_scan_timeout` does not apply
because no bounded scan starts. Missing, ambiguous, or later-relabeled response
types are never treated as proven SSE; the ordinary WAF content-type eligibility
rules still apply, including release of types outside the configured scan scope.

### Detection limits

A few detections trade exhaustiveness for bounded, attacker-resistant cost.
These are deliberate and documented so operators can layer additional controls
where the residual risk matters:

- **Luhn / credit-card scan (`FE-DATA-LEAK-001`)** caps a single *contiguous*
  digit run at 4096 digits. The run-length cap prevents quadratic Luhn work on
  an attacker-supplied page-long digit run. As a consequence, a valid card
  number embedded **after** more than 4096 unbroken digits in one run (where the
  only separators are spaces, dashes, or dots, which do not break the run) is
  not detected. Real card data is not preceded by thousands of digits, so this
  bounds cost without affecting normal leak detection; treat it as a known gap
  only against deliberately crafted padding. The cap is the
  `MAX_LUHN_DIGIT_RUN_SCAN` constant in `src/plugins/waf/scan.rs`.
- **Layered body decode** peels a bounded number of stacked encoding rounds (see
  *Decode / normalization*). Encodings stacked deeper than the cap are not
  decoded to their literal payload, but the body is flagged with the
  `encoding_evasion` signal instead of passing silently.

## Stream (TCP/UDP) inspection

Beyond HTTP-family traffic, the WAF can inspect raw TCP streams and UDP/DTLS
datagrams via the optional `stream` config block. It is **off unless
configured**: without a `stream` block the plugin stays HTTP-only and never
attaches to stream proxies. Two capabilities, both governed by the global
`mode` (`enforce` blocks, `monitor` records only):

- **`tcp_require_tls`** — reject a TCP connection whose opening bytes are not a
  TLS ClientHello (validated down to the handshake message type, not just the
  record header). A transport-shape guard for ports that must only carry TLS. It
  inspects raw wire bytes, so it applies to plain TCP and `passthrough` proxies;
  on TLS-terminating frontends the completed handshake already proved the
  transport, so it is a no-op there. The opening TLS record + handshake-type
  prefix is reassembled across fragmented reads (non-destructively, bounded by
  `FERRUM_FRONTEND_TLS_HANDSHAKE_TIMEOUT_SECONDS`), so a ClientHello split across
  TCP segments still classifies correctly. It **fails closed**: if the prefix
  never completes before the deadline (idle peek timeout / EOF) the connection is
  rejected in `enforce`, so a client cannot stall the peek and then send plaintext.
- **`signatures`** — byte-pattern (regex) matching over **plaintext application
  bytes**. Each signature has an `id`, a `pattern`, and optional `severity`
  (default `medium`) and `action` (`enforce` default / `monitor` / `disabled`).

```json
{
  "name": "waf",
  "config": {
    "mode": "enforce",
    "stream": {
      "tcp_require_tls": false,
      "signatures": [
        { "id": "STREAM-SQLI-1", "pattern": "(?i)union\\s+select", "severity": "high", "action": "enforce" }
      ]
    }
  }
}
```

What gets scanned, by proxy type:

| Proxy | Opening bytes seen by signatures |
| --- | --- |
| Plain TCP (`tcp`) | the first segment, in cleartext |
| TLS-terminating (`tcp_tls`) | the first **decrypted** application bytes (re-encrypted to the backend) |
| Plain UDP (`udp`) | each datagram payload |
| DTLS-terminating (`dtls`) | each **decrypted** datagram payload (re-encrypted to the backend) |
| Passthrough (`passthrough: true`) | **not L7-scanned** — the gateway never decrypts; only `tcp_require_tls` applies |

Limitations and behavior to know:

- **Inspection disables zero-copy.** Reading plaintext for L7 scanning is
  incompatible with the kTLS-splice fast path, so a TLS-terminating TCP proxy
  with stream inspection falls back to a userspace relay for inspected
  connections. Plain-TCP proxies are peeked non-destructively and keep splice.
- **First bytes only — best-effort, evadable by splitting.** TCP scanning
  inspects the opening segment the client sends (the first readable chunk, up to
  4 KiB) once, before the backend is dialed — not the full byte stream. If an
  L7-inspectable TCP stream produces no opening bytes before the bounded capture
  deadline, stream signatures fail closed in `enforce` mode when an
  enforce-action signature is configured (one whose hidden match could not be
  ruled out), so an idle client cannot wait out inspection and then send
  unchecked first bytes. A monitor-only signature set never blocks a present
  match, so it is allowed through on missing bytes too. A determined
  attacker can still evade a signature by splitting after a benign prefix: send
  bytes that do not match, wait for the gateway to forward them and connect, then
  send the malicious remainder, which is relayed without a rescan. Treat stream
  signatures as a cheap opening-payload filter for opportunistic/automated
  probes, not a replacement for inspection at the backend. UDP scanning is
  per-datagram (each datagram is scanned whole).
- **Server-first plaintext protocols are incompatible with `inspect_tcp`
  signatures in `enforce` mode.** The first-byte capture runs *before the backend
  is dialed*, so for protocols where the server speaks first (MySQL, PostgreSQL,
  SMTP, FTP, Redis-with-greeting, many DB wire protocols) the client sends
  nothing until it receives the server banner — which never arrives in the
  capture window because the backend is not connected yet. The peek elapses at
  the deadline, no first bytes are captured, and the fail-closed rule above
  rejects **every** connection (`waf.block_reason=first_bytes_unavailable`).
  Because `inspect_tcp` defaults to `true` whenever a `stream` block has
  signatures, putting enforce-action SQLi signatures in front of MySQL blocks all
  traffic. In front of a server-first protocol, use `tcp_require_tls` for
  transport-shape enforcement, keep the signatures non-blocking (global `monitor`
  mode or every signature's `action: monitor`), or set `inspect_tcp: false`.
- **TCP blocks** reject before any backend is dialed and ride the stream
  transaction summary as `waf.action=blocked`. **UDP blocks** are a silent
  datagram `Drop` (standard UDP behavior). Both transports record `waf.*` on the
  stream transaction summary for every hit — blocked or monitored — via
  `log_to_metadata` (on by default), so matches are observable in the transaction
  log without enabling `log_to_stdout`. Across a UDP/DTLS session, hits **merge**:
  matched rule ids accumulate, `waf.severity` keeps the highest seen, and a
  `blocked` action is never downgraded by a later monitored datagram. The one
  exception is a hit on the **opening** UDP datagram that is blocked before a
  session is established: there is no session summary to attach to, and emitting a
  per-datagram summary for a spoofable, sessionless datagram would be a log-flood
  amplifier, so those blocks surface only on the opt-in `log_to_stdout` channel.
- By default only client→backend traffic is inspected; set `inspect_response`
  to also scan backend→client datagrams.

## Observability

WAF activity is reported through transaction logs only — never the
`/metrics` endpoint. This is deliberate: the Prometheus endpoint is scraped
broadly and is not a place to expose matched rule ids and block outcomes,
which would let an unauthenticated caller use the gateway as a WAF oracle.
Rule ids and outcomes belong in the access/transaction log, which is
access-controlled and shipped to a SIEM.

When `log_to_metadata` is true (default), every WAF-evaluated request carries
`waf.*` fields in its transaction summary `metadata`, emitted by whatever
logging sinks are configured (stdout, http, tcp, kafka, loki, …):
`waf.rule_hits`, `waf.target`, `waf.severity`, `waf.score`, `waf.action`
(`blocked` / `monitored` / `clean`), `waf.first_blocking_rule`,
`waf.block_reason`, `waf.would_block_reason`, `waf.paranoia`, plus
`waf.scan_truncated` / `waf.scan_timed_out`. Blocked requests reject before
backend dispatch and still produce a transaction summary carrying these
fields, so blocks are visible in the same per-request log line as allowed
traffic.

`waf.block_reason` names why a request was blocked: `rule`, `score`, or
`body_too_large` for HTTP-family traffic, and `tcp_require_tls`,
`first_bytes_unavailable`, or `signature` for stream (TCP/UDP) traffic. Stream
inspection additionally records `waf.would_block_reason` (the same stream value
set) on `monitor`-mode connections that *would* have blocked under `enforce`,
so enforce-mode impact stays directly countable before you switch modes — in
particular the server-first `first_bytes_unavailable` false-positive risk noted
above, whose would-blocks carry no `waf.rule_hits` to infer from.

`log_to_stdout` additionally emits a dedicated structured `warn!`
(`target: "waf"`) per matched rule, independent of any logging plugin.

The per-request anomaly score is carried in `waf.score`. Run in `monitor`
first, watch the logs for `waf.action="monitored"` volume and which rules
fire, then switch to `enforce`.

## Configuration reference

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `mode` | enum | `enforce` | `enforce` / `monitor` / `disabled` |
| `default_rule_action` | enum | _(unset)_ | bulk action for built-ins; `rule_modes` overrides win |
| `paranoia_level` | int 1–4 | `1` | activate rules with `paranoia_min <= level` |
| `request_inspection` | bool | `true` | scan request metadata |
| `request_body_inspection` | bool | `true` | scan request bodies |
| `response_inspection` | bool | `false` | scan response headers |
| `response_body_inspection` | bool | `false` | scan response bodies |
| `include_default_rules` | bool | `true` | load the built-in pack |
| `disabled_default_rules` | string[] | `[]` | built-in ids to drop |
| `rule_modes` | map | `{}` | per-rule action by id |
| `rule_overrides` | map | `{}` | per-rule fp_filters/conditions/paranoia_min/severity/score/action |
| `custom_rules` | object[] | `[]` | additional rules |
| `scoring` | object | _(off)_ | anomaly scoring (see above) |
| `global_exemptions` | object | _(none)_ | request short-circuits |
| `scan_budget_ms` | int | `50` | total scan-time budget (0 = unbounded) |
| `on_scan_timeout` | enum | `log_and_allow` | `allow` / `block` / `log_and_allow` |
| `max_scan_bytes` | int | `1048576` | body scan cap |
| `on_body_too_large` | enum | `scan_truncated` | `scan_truncated` / `skip` / `block` |
| `body_methods` | string[] | `[POST,PUT,PATCH]` | methods whose bodies are scanned |
| `body_content_types` | string[] | see code | inspectable content types |
| `inspect_multipart` | bool | `false` | scan multipart bodies |
| `inspect_binary_body` | bool | `false` | scan bodies with unknown/binary type |
| `disallowed_methods` | string[] | `[]` | methods flagged by FE-METHOD-001 |
| `reject_status_code` | int 400–599 | `403` | status for blocked requests |
| `reject_content_type` | string | `application/json` | blocked-response content type |
| `reject_body` | string | `{"error":"Forbidden"}` | blocked-response body |
| `log_to_metadata` | bool | `true` | write `waf.*` metadata |
| `log_to_stdout` | bool | `false` | structured per-hit warning |
| `stream` | object | _(off)_ | raw TCP/UDP inspection (see [Stream inspection](#stream-tcpudp-inspection)) |

### `stream` block

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `tcp_require_tls` | bool | `false` | reject TCP whose opening bytes aren't a TLS ClientHello (raw-wire proxies only) |
| `inspect_tcp` | bool | `true` | run signatures over TCP opening bytes |
| `inspect_udp` | bool | `true` | run signatures over UDP/DTLS datagrams |
| `inspect_response` | bool | `false` | also scan backend→client datagrams |
| `signatures` | object[] | `[]` | byte-pattern rules: `id`, `pattern`, `severity?`, `action?` |
