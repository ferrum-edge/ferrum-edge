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
| Missing or empty HTTP/1.1 `Host` (RFC 9112 §3.2.2) | core proxy `check_protocol_headers()` (HTTP/1.0 and absolute-form URI authority are not rejected; HTTP/2/3 `:authority` is `check_host_authority_consistency()`) |
| HTTP/1.1 absolute-form request-target authority disagreeing with `Host` (RFC 9112 §3.2.1) | core proxy `check_protocol_headers()` (shared `host_authority_disagreement()` comparison with the HTTP/2/3 rule; HTTP/1.0 is out of scope) |
| Request smuggling (CL/TE conflicts, duplicate Content-Length) | bounded proxy-frontend HTTP/1 wire framing guard + core proxy `check_protocol_headers()` + Hyper parsing |
| Missing both HTTP/2 and HTTP/3 `:authority` and `Host` (RFC 9113 §8.3.1 / RFC 9114 §4.3.1) | core proxy `check_host_authority_consistency()` (`:authority`-only and Host-only remain valid; Extended CONNECT is `:authority`-only) |
| Header/URI/body size limits | `FERRUM_MAX_*` env vars, `request_size_limiting` |
| Authentication / authorization | auth plugins, `access_control`, `mesh_authz`, `opa` |
| Rate limiting / flooding | `rate_limiting`, `*_rate_limiting` |
| Schema / contract validation | `body_validator`, `openapi_validator` |
| Bot / IP / geo filtering | `bot_detection`, `ip_restriction`, `geo_restriction` |
| Backend SSRF allow/deny | `FERRUM_BACKEND_ALLOW_IPS` + `FERRUM_BACKEND_ALLOW_CIDRS` / `FERRUM_BACKEND_DENY_CIDRS` (metadata/link-local/multicast blocked by default) |
| Response security headers | `security_headers` |

On plaintext and TLS proxy frontends, HTTP/1 requests that carry both
`Content-Length` and `Transfer-Encoding` are rejected with `400` and the client
connection is closed, independently of field order or casing. Enforcement
starts in the proxy frontend I/O adapter, which observes each bounded raw
request head before Hyper applies transfer-coding precedence, and finishes in
the shared `check_protocol_headers()` rejection path before routing. The admin
and injector HTTP listeners do not use this adapter. HTTP/2 and HTTP/3 do not
use this wire observer; their existing protocol-specific TE validation is
unchanged.

The WAF focuses on injection and disclosure signatures: SQLi (including blind
time-delay, catalog enumeration, and error-based extraction), NoSQLi, command
injection, XSS, SSTI, JNDI/Log4Shell, Shellshock, OGNL/Struts, PHP and Node.js
code injection, path traversal, LFI, RFI, SSRF, XXE, deserialization gadgets,
prototype pollution, HTTP response splitting, restricted-file probing,
executable uploads, and (response-side) sensitive-data leakage.

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

1. **`default_rule_action`** — bulk-set the action of built-in rules that
   inherit it. `default_rule_action: "enforce"` enforces the low-false-positive
   core of the pack (still subject to `paranoia_level`; see below). Heuristic
   encoding-evasion rules (`FE-ENCODING-001`, `FE-ENCODING-002`) stay
   **monitor** under that bulk switch; only an explicit per-rule `rule_modes`
   or `rule_overrides.action` entry promotes them. Other `rule_modes` overrides
   still win per rule.
2. **`category_modes`** — set the action of every built-in rule in a
   category: `{"xss": "enforce", "ldap_injection": "disabled"}`. Categories
   are the backticked keys in the `Category` column of the
   [rule pack](#built-in-rule-pack) table (for example `sqli`,
   `path_traversal`, `http_response_splitting`, `stack_trace`); an unknown
   category is rejected. Naming an opt-in category (for example
   `encoding_evasion`) promotes its rules, unlike the bulk switch. Custom
   rules keep their own `action`.
3. **`rule_modes`** — set the action of individual rules by id:
   `{"FE-SQLI-001": "enforce"}`.
4. **anomaly scoring** — keep rules in `monitor` and block on the aggregate
   score (see [Anomaly scoring](#anomaly-scoring)).

Action precedence for a built-in rule, lowest first: `default_rule_action`,
`category_modes`, `rule_overrides.<id>.action`, `rule_modes`.
`rule_overrides.<id>.action` sets the action of a rule that is already enforced
by level; only `rule_modes: enforce` promotes a rule above `paranoia_level`
(including a [detection-band](#detection-paranoia-level) rule). An override's
`enforce` leaves a band rule monitor-only and a rule above both levels
compiled out, and the bulk controls (`default_rule_action`, `category_modes`)
promote neither.

Because the loud/broad rules are gated behind `paranoia_level >= 2` (see
below), the recommended starting posture for active blocking is:

```json
{ "mode": "enforce", "default_rule_action": "enforce", "paranoia_level": 1 }
```

This enforces only the low-false-positive core of the rule pack. Encoding
heuristics remain monitor-only under this posture; promote them with
`rule_modes` after confirming they are clean for your traffic.

### Strict configuration admission

Every fixed-shape WAF object rejects unknown keys **before** defaults apply:
top-level config, `scoring`, each `custom_rules[]` entry, object-form `target`,
`conditions`, `global_exemptions`, `stream`, each `stream.signatures[]` entry,
and each `rule_overrides[<id>]` value. A typo such as `default_rule_actoin`,
`conditions.path`, `global_exemptions.header_presnt`, or `stream.tcp_require_tsl`
fails construction so Admin, file, database, CP/DP, and reload paths keep
last-known-good configuration under the plugin's `FailClosed` policy.

Intentionally open maps (operator-defined keys) remain open and are not closed
by a blanket `additionalProperties: false` on the map itself:

| Map | Why it stays open |
| --- | --- |
| `rule_modes` | keys are rule ids |
| `category_modes` | keys are built-in rule categories (validated against the pack at construction) |
| `rule_overrides` | keys are rule ids; **values** are fixed-shape and closed |
| `conditions.headers` | keys are header names |
| `global_exemptions.header_present` | keys are header names |

`scoring.weights` accepts only the severity names `info` / `low` / `medium` /
`high` / `critical`.

`mode: enforce` is rejected at construction when no reachable enforcement path
remains after `default_rule_action`, `rule_modes`, `rule_overrides`,
`disabled_default_rules`, custom rules, paranoia filtering, and the request /
response inspection toggles. Built-in rules are monitor-only unless opted in, so
`mode: enforce` with only the default pack is not admitted unless one of the
separate enforcement paths below is configured. `mode: monitor`
with zero enforcing rules remains valid. Anomaly scoring (`scoring.enabled`) and
stream transport guards (`stream.tcp_require_tls`, enforce-action
`stream.signatures`) are separate enforcement paths and satisfy admission
without per-rule `action: enforce` when their corresponding inspection surface
is enabled. `on_body_too_large: block` is also a reachable enforcement path
when a body inspection hook can run: it rejects oversize governed HTTP bodies
and WebSocket application messages under `mode: enforce` even if every rule
stays monitor-only. `fail_closed` (the default), `scan_truncated`, and `skip`
do not count, because they cannot reject unless some other enforcing body
policy already exists. An empty `body_methods` does not remove this path:
client-to-backend WebSocket messages ignore `body_methods` and still apply the
cap. `on_unlisted_content_type: block` counts the same way when the
request-body hook can run and some HTTP request body can be unlisted, which
needs at least one `body_methods` entry and not both `inspect_multipart` and
`inspect_binary_body` (see
[Bodies outside the scan scope](#bodies-outside-the-scan-scope-on_unlisted_content_type));
its `fail_closed` does not.

## Paranoia levels

`paranoia_level` (1–4, default 1) gates which rules are active. Each rule has a
`paranoia_min`; rules above the configured level are compiled out entirely.
Higher levels add broader, noisier signatures that catch more attacks at the
cost of more false positives. Loud rules retuned to `paranoia_min: 2` or `3`
(see below) are inactive at the default level 1.

### Detection paranoia level

Raising `paranoia_level` blind is risky: the new rules block before you know
what they flag. `detection_paranoia_level` (1–4, default = `paranoia_level`)
runs the higher level in **detection-only** mode first, like CRS's
`detection_paranoia_level`:

```json
{ "mode": "enforce", "default_rule_action": "enforce",
  "paranoia_level": 1, "detection_paranoia_level": 2 }
```

Rules with `paranoia_level < paranoia_min <= detection_paranoia_level` are
compiled and scanned but:

- are always `monitor`, whatever `default_rule_action`, `category_modes`, or
  `rule_overrides.<id>.action` say. Only an explicit `rule_modes: {"<id>":
  "enforce"}` promotes one to a normal enforcing rule (no longer
  detection-only, so the rest of this list stops applying to it), exactly as
  it force-compiles a rule above `detection_paranoia_level`. An override's
  `enforce` never promotes, so raising the detection level never changes what
  blocks;
- contribute **zero** to anomaly scoring;
- never make a body policy "enforcing", so they cannot trigger
  `on_body_too_large: fail_closed`, `on_scan_timeout: fail_closed`, a
  WebSocket close, or a fail-closed representation claim, and they do not
  satisfy `mode: enforce` admission (the configuration-level `block`
  dispositions are the exception; see below);
- report through their own metadata: `waf.detection_rule_hits` (comma-joined
  ids) and `waf.detection_paranoia`. They are **not** added to
  `waf.rule_hits`, `waf.target`, or `waf.severity`, and a request whose only
  hits are detection-only keeps `waf.action=clean`, so dashboards built on
  the blocking posture are undisturbed. `log_to_stdout` events carry
  `action=detection_only`.

Detection-band body rules still cause request/response bodies (and WebSocket
messages) to be buffered and scanned, so budget for that scan cost while the
band is active.

A band body rule **turns on body inspection for its direction**, and the
dispositions that refuse by configuration rather than by a rule verdict then
apply to that direction. This is deliberate and fails closed: the WAF does not
track which rules enabled a direction, and an operator who asked for `block`
gets `block` on every body it inspects:

- in `mode: enforce`, `on_body_too_large: block` rejects an oversize request
  or response body, or an oversize WebSocket message;
- in `mode: enforce`, `on_unlisted_content_type: block` rejects a non-empty
  unlisted request body;
- `on_scan_timeout: block`, which does not depend on `mode`, rejects an
  over-budget body scan;

exactly as they would with a monitor-only body rule. This only changes
behavior when the band supplies the first body rule in a direction (for
example a custom-only pack whose one body rule sits in the band, or a response
band rule while `response_body_inspection` is on and no other response-body
rule is active). The `fail_closed` variants of these settings are unaffected,
since band rules never make a body policy enforcing; use them (the default for
`on_body_too_large`) while you measure a band if configuration-level refusals
are not wanted yet. `detection_paranoia_level` below `paranoia_level` is
rejected.

## Decode / normalization

Attackers hide payloads behind encodings a raw-byte scan never sees. Before
matching request and response bodies, the WAF also scans **decoded variants**:

- UTF-16LE / UTF-16BE and UTF-32LE / UTF-32BE request and response bodies
  admitted by the direction's body content-type gates, using an explicit
  `charset`, a byte-order mark, or an undeclared wide-text prefix signature
  (bare `utf-16` / `utf-32` without a BOM tries both endiannesses)
- JSON / JavaScript string escapes — `\uXXXX`, `\u{...}`, `\xXX`, and the
  single-character escapes `\n`, `\t`, `\r`, `\f`, `\b`, `\v`, `\/`, `\"`,
  `\'`, `\\`. A JSON parser resolves these before the application sees the
  value, so `{"q":"1 union\tselect …"}` reaches a SQL sink as
  `union<TAB>select`, `\"1\"=\"1` as `"1"="1`, and `file:\/\/\/etc\/passwd`
  as `file:///etc/passwd`. `\\` is one backslash, exactly as the parser reads
  it; the layered decode still reduces a deliberate double escape
  (`\\u003c` → `\u003c` → `<`) one layer per round. A `body_json_path` value
  has already been through the JSON parser, so only its `\uXXXX` / `\u{...}` /
  `\xXX` escapes are decoded again; `C:\new` in a parsed value stays a
  backslash and an `n`. A run of backslashes halves each round, but that
  collapse alone never counts as an unreduced layer for the `FE-ENCODING-001`
  residual described below, so multiply-stringified JSON, UNC paths, and regex
  or LaTeX source are not flagged. A `\uXXXX` / `\u{...}` / `\xXX` escape
  behind a run of backslashes of any length does count when it decodes to ASCII
  punctuation, a space, or a control character, because later decodes reach
  it however deep it is stacked.
- HTML entities — `&lt;`, `&#60;`, `&#x3c;`
- Percent-encoding — `%XX`, the IIS / classic ASP and JavaScript `unescape()`
  form `%uXXXX` (`%u003cscript%u003e`), and `+`-as-space (form bodies), in one
  pass: only a literal `+` is a space, so `%2B` and `%u002B` decode to `+`
- a fully layered decode for stacked encodings, scanned after its last round
  and after the round before it: the last round turns every `+` into a space,
  so a double-encoded `%252B` is scanned both as `+` (an application that
  decodes twice) and as a space

So a `<script>` written as `\u003cscript\u003e`, `&lt;script&gt;`,
`%3Cscript%3E`, or `%u003cscript%u003e` in a body is still caught by the
script-tag rule. The layered escape decoders are content-type-agnostic (an
attacker controls the declared `Content-Type`) and bounded to a small number of
variants.

UTF-16 / UTF-32 transcoding does **not** decide whether a body is
scanned. The `body_content_types`, `inspect_multipart`, and
`inspect_binary_body` gates run first and remain authoritative; a charset or
BOM never admits an otherwise excluded body. UTF-8 bodies are scanned in place;
a UTF-16 or UTF-32 view is allocated only within the `max_scan_bytes` bound.

- UTF-32 BOMs (`FF FE 00 00` little-endian, `00 00 FE FF` big-endian) are
  checked **before** the 2-byte UTF-16 BOMs. `FF FE 00 00` is ambiguous (it is
  also a UTF-16LE BOM followed by `U+0000`, which is how a backend without
  UTF-32 support reads it), so unless the charset names the UTF-32 family,
  **both** readings are scanned along with the raw/lossy view. A UTF-32
  charset (`utf-32`, `utf-32le`, `utf-32be`) settles the width. `00 00 FE FF`
  is unambiguous.
- Bare `charset=utf-16` / `charset=utf-32` with no BOM does not assume an
  endianness (IANA leaves it unspecified; unlike WHATWG, Ferrum does not
  default to little-endian): both little- and big-endian decodes are scanned,
  plus the raw/lossy view.

Without a charset or BOM, inference requires a four-byte prefix containing
one non-NUL ASCII UTF-32 unit or two non-NUL ASCII UTF-16 units in the
corresponding NUL positions. Interior NULs alone do not select a decoder.
The prefix selects a width; both endians and the raw/lossy text are scanned
within the existing two-wide-view cap. Ordinary UTF-8 and binary data without
that prefix gain no transcoded view. An explicit charset retains its existing
resolution policy.

Raw/lossy text and its bounded transformations are always retained, including
when a declaration resolves one wide view. Requests and responses share the
same raw-byte, wide-text, layered decoding,
encoding-special, Luhn, and CIDR pipeline, including packs with only encoding
specials. Response decoding uses the final response Content-Type before
transport compression. Rule conditions, false-positive filters, per-rule modes,
body size limits, and scan budgets still apply. HTTP responses that omit a body
(HEAD and bodyless statuses) remain outside body inspection; response inspection
must still be enabled. Request JSON-path rules retain their scalar-local
normalization policy.

Wide decoding is **lossy**. A malformed code unit — a length that is not a
multiple of the code-unit size, an unpaired surrogate, or a UTF-32 unit in
`U+D800..=U+DFFF` or above `U+10FFFF` — is replaced by `U+FFFD` and decoding
continues, matching what browsers (`TextDecoder`), the JVM
(`new String(bytes, "UTF-16LE")`), and .NET (`Encoding.Unicode`) do. Refusing
the whole view instead would let one hostile byte — for example a
`charset=utf-16le` body with its last byte removed — disable body-text
inspection while the backend still parsed the payload. This mirrors the lossy
UTF-8 path.

When the declared charset and the BOM **disagree** (for example
`charset=utf-16le` on a body prefixed with the UTF-16BE mark `FE FF`), both
readings are scanned: the declaration-honouring reading decodes the whole
body including the BOM bytes — which is what a backend trusting
`Content-Type` sees, reading `FE FF` as the noncharacter `U+FFFE` — and the
BOM-honouring reading decodes the body after the mark. The raw/lossy view is
kept as well, so a mismatched declaration cannot hide the payload.

The full WHATWG UTF-16LE label set is recognized, not just `utf-16le` /
`utf16le`: `unicode`, `unicodefeff`, `ucs-2`, `iso-10646-ucs-2`, and
`csunicode` all transcode. `unicodefffe` remains UTF-16BE.

A body that declares a charset the WAF cannot transcode at all records
**FE-ENCODING-001** instead of being scanned as ASCII cover text. These
encodings can represent ASCII payloads in bytes that no rule matches — UTF-7
writes `<script>` as `+ADw-script+AD4-`. The flagged families are UTF-7
(`utf-7`, `unicode-1-1-utf-7`, `csunicode11utf7`), the ISO-2022 escape-shift
encodings (`iso-2022-jp`, `iso-2022-kr`, `iso-2022-cn`, `csiso2022jp`,
`csiso2022kr`), `hz-gb-2312`, and EBCDIC (`ibm037`, `cp037`, `ibm500`,
`cp500`, `ibm1047`, `cp1047`, `ebcdic-cp-us`). The list is explicit, so
single-byte ASCII-superset charsets (`iso-8859-1`, `windows-1252`,
Shift_JIS, GBK, Big5) are unaffected. FE-ENCODING-001 is opt-in-enforce, so
this reports by default and blocks only when the rule is set to `enforce`;
the raw/lossy scan still runs alongside it.

Query matching is per decoded parameter value, not the raw whole URI. Query
**values** (each `&`/`=`-split component — never the structural delimiters,
and never the request path) run through that same bounded layered
percent-decode before matching, including reserved octets such as `%2f` /
`%2F` and `+`-as-space. Path canonicalization still refuses encoded
separators; that contract is not applied to query payload. Each value is
scanned as the percent-decoded form plus the same bounded layered variants,
so stacked percent / HTML-entity / unicode encodings cannot evade query
rules (including PATHTRAV/LFI canonical mirrors and the level-1 SSRF-Q
mirrors). At most three decode rounds are applied; deeper stacks are not
fully reduced and are flagged as `encoding_evasion` on the raw URL/body
rather than being decoded indefinitely. Decoding is inspection-only: the
original query bytes are forwarded unchanged.

Cookie values are scanned **both** as sent and as decoded. Frameworks disagree
about cookies: the Servlet API and Go's `net/http` hand the application the raw
octets, while PHP (`urldecode`, so `+` is a space), Express `cookie-parser`
(`decodeURIComponent`), and Rails unescape them first. Each `name=value` crumb
is therefore matched raw and beside its percent-decoded views — `%XX`,
`%uXXXX`, `+` as a space, and the bounded layered percent decode — so
`pref=%3Cscript%3E` and `lang=en%0d%0aSet-Cookie:…` reach the cookie rules. A
crumb holding both `%` and `+` is also matched percent-decoded with `+` kept,
as Express reads it, so `x=%27+alert(1)+%27` is seen as `'+alert(1)+'` as
well as `' alert(1) '`. Express `cookie-parser` runs `JSON.parse` on a value
starting with `j:`, so such a crumb is also matched with its `\uXXXX` /
`\u{...}` / `\xXX` escapes and its `\"`, `\'`, `\/`, `\\` escapes resolved.
Like Express, the WAF finds that value by splitting the raw crumb at its first
`=`, so an encoded `=` in the name (`a%3Db=j:…`) does not hide it. The JSON
control escapes (`\n`, `\t`, …) and HTML entities are not cookie encodings,
so a `j:` JSON cookie whose string holds `\n` is not read as a line feed. The
header is split on `;` before decoding, so an encoded `%3B` cannot forge an
extra crumb. As with queries, decoding is inspection-only.

The layered decode runs a bounded number of rounds (a cost guard against
decompression-style blowups), so double- and triple-stacked encodings are fully
reduced but a payload stacked deeper than the cap is not. Rather than silently
forwarding such a body, the WAF raises the `encoding_evasion` signal
(`FE-ENCODING-001`) for it — the same rule that flags URL double-encoding. The
signal fires when the value still holds a percent (`%XX`, `%uXXXX`) or HTML
entity layer after the cap, or, behind a backslash run of any length, a
`\uXXXX` / `\u{...}` escape of any ASCII character (letters included) or a
control character, or a `\xXX` escape of ASCII punctuation, a space, or an
ASCII control character. No JSON or JavaScript serializer writes ASCII as a
`\u` escape, so a deep `\u0073elect` is evasion in itself, while `\xXX` is
ordinary literal text in Windows paths, regex source, and hex dumps. Three
kinds of stack are deliberately not flagged: runs of the single-character
escapes (`\n`, `\"`, `\\`, …), which are ordinary in multiply-stringified
JSON; `\u` escapes of non-ASCII characters (`\u00e9` in a name); and `\x`
escapes of letters, digits, or C1 bytes (`\x64` or `bin\x86\Release` in a
Windows path). The overlong-UTF8 (`FE-ENCODING-002`), double-encoding, and
null-byte (`FE-ENCODING-001`) markers are likewise checked against request and
response **bodies**, not just the URL/path, so an overlong-encoded body payload that
lossy percent-decoding cannot recover to its literal character is still flagged
as an evasion attempt.

Note that body marker detection is a heuristic: a benign body that legitimately
contains a literal encoded marker (e.g. `code=SAVE50%25`, a `%00` in free text,
or `%c0%ae` in a paste) can raise `FE-ENCODING-001` or `FE-ENCODING-002`.
This is why both rules default to **Monitor** (they record `waf.rule_hits`
metadata rather than blocking) even under the recommended `mode: enforce` +
`default_rule_action: enforce` posture — operators opt a rule into blocking
explicitly via `rule_modes` (or `rule_overrides.action`) once they have
confirmed it is clean for their traffic. Global `mode: monitor` or `disabled`
still dominates: a promoted encoding rule only logs in monitor mode and is
not evaluated when the plugin is disabled. `waf.action` / `waf.score` /
stdout `action=` fields report that compile-time effective disposition.

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
Semantics:

| Kind | Matching |
| --- | --- |
| `regex` | Operator-authored Rust regex. Case sensitivity follows the pattern; use `(?i)…` when you need folding. |
| `literal` | Case-sensitive Unicode substring. `EVIL-LITERAL` does not match `evil-literal`; the value need not equal the whole field (unlike `equals`). |
| `contains` | Case-insensitive substring (same substring semantics as `literal`, but folded). |
| `equals` | Case-insensitive full-value match (anchored; does not prefix-match). |
| `luhn` | Valid credit-card Luhn checksum on digit runs (body targets only). |
| `cidr` | IP membership test. |

## Built-in rule pack

Rule ids are stable; reference them in `rule_modes`, `disabled_default_rules`,
and `rule_overrides`. Categories:

| Category | Rules | Notes |
| --- | --- | --- |
| `sqli` | FE-SQLI-001..009 plus FE-SQLI-001-B..004-B, FE-SQLI-006-B..010-B, and FE-SQLI-001-C..003-C | UNION/tautology/stacked (001–003) are level 1 across decoded query values and admitted request bodies; body mirrors use the exact query patterns. Those three accept either whitespace **or a bounded inline `/*…*/` comment** between SQL tokens, so `UNION/**/SELECT` and `;/**/DROP` are caught at level 1; the tautology rule also accepts an unspaced `\|\|` (`1'\|\|1=1`). The comment body is bounded, so a comment longer than the bound falls through to the comment-token catch-alls: 004 (query) and 004-B (body) are both level 2. SQLSTATE (005) is body-only level 2. Level 1 also covers blind time-delay probes (006: `SLEEP(n)`, `pg_sleep`, `BENCHMARK`, `WAITFOR DELAY`, Oracle `dbms_pipe`), catalog enumeration (007: `information_schema.`, `pg_catalog.`, `sqlite_master`, MSSQL `sys*` tables), error-based and out-of-band functions (008: `extractvalue`, `updatexml`, `load_file`, `INTO OUTFILE`, `xp_cmdshell`, `utl_http`), and quoted-string tautologies (009: `' or 'a'='a`, unspaced `'or'1'='1`). Because `like` is an English word, a 009 `like` comparison counts only when its right-hand string is injection-shaped: it opens with a `%` / `_` wildcard (`' or 'a' like '%`), it is left open for the application's closing quote (the value ends inside it, or a JSON string closes it: `' or 'a' like 'a`), or an SQL comment follows it, optionally after closing parentheses, a `;`, or a `LIMIT n` clause (`' or 'a' like 'a'--`, `' or 'a' like 'a')--`, `' or 'a' like 'a' limit 1--`). Prose with quoted words, such as `'soda' or 'pop' like 'grandma'`, stays clean. In 006, `sleep(n)` counts only after SQL-shaped context (a quote, `(`, `,`, `;`, `=`, `\|`, `&`, an SQL keyword, the start of the value, or a number that opens the value or directly follows a quote or `&`, followed by an arithmetic, comparison, or bitwise operator: `1-sleep(5)`, `'1*sleep(5)`), so method calls such as `time.sleep(1)`, `a-sleep(5)`, and `room 1-sleep(5)` stay clean. That context still matches source code (`foo(); sleep(1);`, `x = sleep(5)`, `benchmark(1000, fn)`), so the exact body mirror 006-B is level 2. Level-1 body coverage is 010-B: `sleep(n)` only after an SQL keyword (`AND`, `OR`, `SELECT`, `WHERE`, `ORDER BY`, …), after a closing quote and an SQL operator (`'+sleep(5)+'`, `'\|\|sleep(5)`), or as a branch of `IF(…, sleep(n), …)`; three unquoted shapes: a later `ORDER BY` / `GROUP BY` item, with whitespace or a bounded inline comment as the separator (`ORDER BY 1,sleep(5)`, `ORDER/**/BY 1/**/,sleep(5)`); a value that is nothing but a number, an arithmetic, comparison, or bitwise operator, and the call (`"1-sleep(5)"`, `"1=sleep(5)"`), opening the body, a quoted string, or an `&`-separated field and ending at the closing quote, `&`, the end of the body, or an SQL comment (`--`, `#`, `/*`); and a form pair whose whole value is the call, optionally behind that number and operator (`id=sleep(5)`, `id=1-sleep(5)`), opening the body or following `&` and ending at `&`, the end of the body, or an SQL comment (`--`, `#`, `/*`); `BENCHMARK` only around an SQL function (`MD5(`, `SHA1(`, a subquery); and `pg_sleep`, `WAITFOR DELAY`, and the Oracle calls as in 006. 010-B favours precision because the level-2 006-B is its backstop: it leaves `x = sleep(5)`, compact code such as `x=1+sleep(5)` inside a string, a spreadsheet formula such as `"=2*sleep(1)"`, `foo(); sleep(1);`, `time.sleep(1)`, a delay call followed by more SQL (`id=sleep(5) and 1=1`, `{"id":"1-sleep(5) and 1=1"}`), and a JSON string whose whole value is `sleep(5)` clean; the level-2 006-B claims those last two shapes. 008 counts `load_file` only as a bare call on what MySQL reads — a quoted absolute or UNC path, a hex literal (`0x2f65…` or `X'2f65…'`), either of those behind a charset introducer (`_latin1'/etc/passwd'`, `_binary 0x2f65…`), or a `CHAR(` / `CONCAT(` / `CONCAT_WS(` / `UNHEX(` / `FROM_BASE64(` expression, optionally after whitespace or a bounded inline comment (`load_file(/**/'/etc/passwd')`) — so `def load_file(path):` and `loader.load_file(…)` stay clean. A user-variable argument (`load_file(@v)`) is not matched, because Ruby writes `load_file(@path)` as ordinary code. The `-C` mirrors apply 001–003 to cookie values. The Cookie header is split into crumbs on `;` before matching, so no raw crumb carries the stacked-statement `;` that 003-C needs: it fires on a percent-encoded `%3B` (`id=1%3BDROP%20TABLE%20users`) through the decoded cookie views. |
| `nosqli` | FE-NOSQL-001 (operator key), FE-NOSQL-002 (bracket operator, L2) | |
| `command_injection` | FE-CMD-001..004, FE-CMD-005-{Q,B} | shell-substitution (003) is level 2. 004 (query, L1) catches command execution without a classic `;cmd` chain: a backtick or `$(` subshell; a CR/LF separator followed by a Windows tool in all-lower or all-upper case (`whoami`, `IPCONFIG`), or in any case (`cmd.exe` and PowerShell resolve commands case-insensitively) when it carries `.exe` or takes a flag (`PowerShell -nop`, `Certutil /urlcache`), and PowerShell also before `iex` / `invoke-` (`%0APowershell IEX(…)`); a mixed-case `Whoami`, `Ipconfig`, `Certutil`, or `Systeminfo` also counts when it ends the value (`%0AWhoami`) or is followed by a shell operator, but a bare mixed-case `PowerShell` / `Pwsh` runs no command and does not; a lower-case Unix tool; or a short lower-case command (`cat`, `id`, `sh`, `bash`) that ends the value, takes a flag, path, or quoted argument, or is followed by a shell operator — `;`, `\|`, `&`, `<`, `>`, or a backtick directly against the word (`cat\|nc`), `&&` / `\|` / `\|\|` / `;` / a backtick after a space, a `#` comment against the word or after a space that ends the value or is followed by a non-digit (`%0Aid%23`, `%0Aid%20%23`, the form a POSIX shell treats as a comment), a spaced `&` that ends the value (`%0Aid%20%26`), or a redirect onto a path, descriptor, or variable (`cat > /tmp/x`); `;`/`\|`/`&&` before a reconnaissance tool that never names a list item (`whoami`, `ifconfig`, `certutil`, `mkfifo`, …); `&&`/`\|\|` before a tool that can (`uname`, `busybox`, `powershell`, `pwsh`, `id`, `ls`, `sleep`, `ping`), or `;`/`\|` before one only when it takes a flag, path, or quoted argument, redirects, or chains again; `;`/`\|` before an argument shape a list never has (`busybox nc`/`wget`/`sh`/`ash`/`telnet`, `socat tcp:`/`udp:`/`exec:`/`-`, `ncat`/`netcat`/`nc` with a host and port); and `$IFS`. 004 does not fire on delimited lists (`tags=linux;bash`, `tags=windows;powershell`, `skills=bash\|pwsh`, `fields=id\|uname`) or multi-line prose (`Order%0AID: 123`, `%0ACat food`, a line starting `PowerShell is …` or `PowerShell - …`, a list or table row naming a bare `PowerShell` (`Skills:%0APython%0APowerShell`, `%0APowerShell \| Windows`), a numbered item such as `%0Acat #1`, `%0Acat & dog` or `%0Acat &amp; dog`), but the older level-1 001 still matches a list item that is one of its command words (`tags=linux;bash`, `tags=windows;powershell`, `q=dogs\|cat`); disable or scope FE-CMD-001 where such lists are expected. The cost is that a bare `x;uname` at the end of a value is not matched, because it cannot be told apart from a list. 005 flags explicit interpreter invocation (`/bin/sh`, `cmd /c`, `powershell -enc`, `sh -c`, `python -c`) at level 1 in query values and level 2 in bodies, where deployment APIs carry scripts. |
| `jndi_injection` | FE-JNDI-001-{B,Q,H}, FE-JNDI-002-{B,Q,H} | **Log4Shell**; direct lookup is Critical/level 1 across body, query, and header; nested-obfuscation is level 2 |
| `rce` | FE-SPRING4SHELL-001-{B,Q}, FE-SHELLSHOCK-001-{H,Q,QV}, FE-OGNL-001-{B,Q,H}, FE-PHP-001-{Q,B}, FE-PHP-002-{Q,B}, FE-NODE-001-{Q,B} | Spring4Shell class-loader manipulation (CVE-2022-22965). Shellshock (CVE-2014-6271) is Critical/level 1 and anchored to the **start** of a header value or query key/value — the position bash actually imports — so `function() {` in ordinary text never matches. OGNL (Apache Struts 2, including the CVE-2017-5638 `Content-Type` vector) is Critical/level 1 across body, query, and header. PHP code injection (`<?php`, `eval($_POST…)`, `system('…')`) and Node.js execution (`require('child_process')`, `process.mainModule`, `constructor.constructor('…')`) are level 1 in query values and level 2 in bodies, where code-hosting APIs carry source. PHP stream wrappers (`php://input`, `phar://`, `zip://`, `data://text/plain`) are level 1 in query values (002-Q) and level 2 in bodies (002-B), where PHP source reads its own request body through `file_get_contents('php://input')`. |
| `prototype_pollution` | FE-PROTO-001/002 plus FE-PROTO-{001,002}-{Q,QV} | Body `__proto__` is level 1 and body `constructor.prototype` is level 2. The level-1 `-Q`/`-QV` mirrors scan decoded keys/values for `__proto__` and `constructor[prototype]`. |
| `ldap_injection` | FE-LDAP-001..002 | |
| `xpath_injection` | FE-XPATH-001, FE-XPATH-002 (L3, low value) | |
| `ssti` | FE-SSTI-001 (broad, L2), FE-SSTI-002 (arithmetic probe, L1), FE-SSTI-003 (Java/Spring EL, L2) | |
| `xss` | FE-XSS-001..005 plus `-B`/`-Q`/`-C` body/query/cookie mirrors, FE-XSS-006-{Q,B} | script-tag and script-URL cover query, body, and cookie values. The script-URL rule (002) tolerates the ASCII tab/LF/CR that browsers delete inside a URL (`java&#x09;script:`, `jav%0Aascript:`) and covers `vbscript:`; a real space (`java script:`) is prose, not a scheme. 006 flags active-content elements (`<svg`, `<iframe`, `<object`, `<embed`, `<base`, `<meta`, `<math>`, frames) at level 1 in query values and level 2 in bodies, where rich-text APIs carry markup. |
| `path_traversal` | FE-PATHTRAV-001..003, FE-PATHTRAV-001-{B,C} | FE-PATHTRAV-001..003 (FullUrl) also scan percent-decoded query values (including `%2f`); 001-B covers request bodies and 001-C cookie values. Category labels do not select scan targets. |
| `lfi` / `rfi` | FE-LFI-001(+ -B), FE-RFI-001 (L2) | FE-LFI-001 (FullUrl) also inspects canonical query values; 001-B covers bodies. The `lfi` label itself does not. |
| `ssrf` | FE-SSRF-001(+ -Q), FE-SSRF-002(+ -Q), FE-SSRF-003-{Q,B} (L2) | metadata/private-IP and dangerous schemes; **level 1** across body and decoded query values (not the raw whole URI). Same dotted-IPv4 / cloud-metadata / `file|gopher|dict|jar|ldap://` claims as the body rules. Metadata endpoints are the IMDS address `169.254.169.254`, the AWS ECS credential endpoint `169.254.170.2`, the AWS IPv6 IMDS `fd00:ec2::254`, Alibaba Cloud's `100.100.100.200`, and `metadata.google.internal`. FE-SSRF-003 is **level 2** and needs a URL scheme in front, because development tooling legitimately passes `http://localhost:…` around. It covers `localhost` and `localhost.`, `0`, `0.0.0.0`, short dotted loopback (`127.1`, `127.0.1`), mixed dotted hex/octal (`0x7f.1`), and bracketed IPv6 (`[::1]`, `[::ffff:127.0.0.1]`, `[fe80::…]`). A host written as a single decimal, hex, or octal integer (`2130706433`, `0x7f000001`, `017700000001`) matches whatever address it encodes, loopback or not: legitimate URLs do not spell hosts that way, and the encoded address is exactly what the dotted-quad rules cannot see. |
| `xxe` | FE-XXE-001 | external-entity markers; does not trip on `<!DOCTYPE html>` |
| `deserialization` | FE-DESER-001..005 | Java (base64 `rO0AB` or hex `aced0005`) / .NET BinaryFormatter / PHP serialized markers; unsafe YAML type tags (004: PyYAML `!!python/object/apply`, SnakeYAML CVE-2022-1471 gadgets, Psych `!ruby/object`); and polymorphic JSON type discriminators naming a gadget namespace (005: Fastjson/Jackson `@type`/`@class` in `com.sun.`, `java.net.`, `org.apache.`, …, and Json.NET `$type` in `System.Windows.Data.ObjectDataProvider`, …). 005 also matches the Fastjson autoType bypass spellings (`"Lcom.sun…;"`, `"LLcom…;;"`, `"[com.sun…"`) and Jackson's `WRAPPER_ARRAY` form, `["com.sun…", {…}]`, which has no discriminator key. Spring is matched only by its gadget packages (`org.springframework.aop.`, `beans.`, `context.`, `jndi.`, `transaction.`, `expression.`, `jdbc.`, `jms.`, `jmx.`, `remoting.`, `scripting.`, `web.context.support.`), so Spring Session / Spring Security JSON — `"@class":"org.springframework.security…"`, `WRAPPER_ARRAY` `["org.springframework.security…",{…}]`, `["java.util.ArrayList",[…]]`, `["java.lang.Long",1]` — stays clean. The `WRAPPER_ARRAY` form also counts with a string argument (double-quoted and possibly holding a `'`, or single-quoted and possibly holding a `"`) when the array is exactly `[class, string]` and the first element ends in a capitalised class name — the CVE-2017-17485 payload `["org.springframework.context.support.FileSystemXmlApplicationContext","http://…/spel.xml"]` — outside the `java.*` and .NET namespaces, so a pair of package names, a longer class list, a Maven coordinate, and a JDK value type such as `["java.net.URL","https://…"]` stay clean. JSON-LD `"@type": "Product"` and application-owned type names stay clean. |
| `header_anomaly` | FE-HEADER-001..003 | control chars, method-override, header-borne injection (L2) |
| `cookie_attack` | FE-COOKIE-001, FE-COOKIE-002 (Info, L3) | |
| `encoding_evasion` / `parameter_pollution` / `method_abuse` | FE-ENCODING-001..002, FE-HPP-001, FE-METHOD-001 | encoding heuristics stay monitor under bulk `default_rule_action: enforce`; HPP and method-abuse inherit bulk enforce |
| `http_response_splitting` | FE-CRLF-001 | a decoded CR/LF in a query value followed by a response header name (`Set-Cookie:`, `Location:`, …) or a status line — the shape that splits a response when an application reflects the value into a header (redirect targets, download names). Level 1. |
| `restricted_file` | FE-RESTRICTED-001, FE-RESTRICTED-002 (L2) | matched on the **canonical** path, so `/%2egit/config` is `/.git/config`. 001 (level 1) covers version-control metadata (`.git/`, `.svn/`, `.hg/`), dotenv files, `.htaccess`/`.htpasswd`, credential stores (`.aws/`, `.ssh/`, `.docker/`, `.kube/`, `.npmrc`, `.netrc`, `.pgpass`, `id_rsa`), shell histories, `.DS_Store`, `web.config`, and `wp-config.php` together with its backup and editor-swap copies (`wp-config.php.bak`, `wp-config.php~`, `.wp-config.php.swp`). `.well-known`, `.github`, and `.gitignore` are not matched. 002 (level 2) covers backup, swap, and dump artifacts (`.bak`, `.old`, `.swp`, `.sql`, `.sqlite`, trailing `~`), which some sites publish legitimately. |
| `file_upload` | FE-UPLOAD-001 | a `filename` / `filename*` parameter on a multipart `Content-Disposition` line (the charset and language-tag prefix of a `filename*` value is skipped whatever its length or content, as lenient parsers do, as long as it holds no quote, `;`, or line break — `UTF-8'en'shell.php`, `ISO-8859-1''shell.php`, `UTF-8'en_US'shell.php` — and a percent-encoded name such as `shell%2Ephp` is matched through the decoded body view) naming a server-executable script (`.php`, `.phtml`, `.phar`, `.jsp`, `.aspx`, `.ashx`, `.cgi`, `.shtml`, `.htaccess`, …), including double extensions such as `shell.php.jpg` and the spellings Windows/IIS and C-backed handlers reduce to `shell.php`: a trailing dot or space, the `::$DATA` stream suffix, and a raw or `%00` NUL. A form or JSON field that merely names a file (`filename=index.php`) is not matched. Level 1, but multipart bodies are only scanned when `inspect_multipart` is enabled. |
| `stack_trace` / `database_error` / `source_disclosure` / `fingerprinting` | FE-RESP-STACK-001..003, FE-RESP-DB-001, FE-RESP-SOURCE-001, FE-RESP-FP-001 | response-side; requires `response_inspection` |
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
`score` override) to **that WAF instance's** request total. If the instance
total reaches its own `block_threshold` and the global mode is `enforce`, the
request is rejected with `waf.block_reason = "score"` and
`waf.scoring_instance` set to the blocking plugin-config identity. Hard per-rule
`enforce` still blocks immediately when the global mode is `enforce`.

**One response is scored once.** Phases that run exactly once per request — the
request metadata scan, the final request body scan, and the `after_proxy`
response-header scan — accumulate. The two authoritative **final client-visible**
phases (response headers, response body) do not: the response pipeline can run
them a second time over a revised representation of the same response, for
example when `mcp_gateway` re-frames a JSON-RPC answer as a POST-attached
`text/event-stream` body after those phases first closed. A re-run **replaces**
that phase's previous contribution instead of adding to it, so a response that
legitimately passed at `6` under a threshold of `10` is not refused at `12`
purely because its bytes were re-wrapped. Independent request-phase scores are
untouched, and a revised representation that genuinely trips more (or heavier)
rules scores higher than its predecessor and still blocks. The header phase
additionally skips a map it has already scanned, so only a map that actually
changed is rescored.

### Multi-instance ownership

Ferrum allows multiple scoped `waf` instances on one proxy. Anomaly scores are
**not** shared across instances:

- Each instance accumulates only its own rule hits across request metadata,
  final request body, response headers, and final response body.
- Each instance compares its private total against its own `block_threshold` and
  weights. Individually sub-threshold policies never reject merely because their
  arithmetic sum would cross another instance's threshold.
- Transaction metadata keeps ownership explicit:
  - `waf.instances.<plugin-config-id>.score` — per-instance running total
  - `waf.instance_scores` — deterministic sorted `id=score,...` aggregate when
    more than one scoring-enabled instance contributed on the request
  - `waf.score` — emitted only when a single instance scored (single-policy
    compatibility); omitted when multiple instances contributed so totals are
    never silently conflated
  - `waf.scoring_instance` — identity of the instance that crossed its score
    threshold

Those identities are the configured `plugin_configs[].id` in file, database, CP,
and DP modes. File/DB/CP/DP construction never substitutes a process-local
`standalone-<n>` label for a configured instance; that fallback exists only for
direct constructors that have no resource id (tests and similar callers).
Resource-id admission already rejects commas, equals signs, and other
delimiter-breaking characters, so `waf.instance_scores` (`id=score,...`) and
`waf.instances.<id>.score` stay unambiguous. Duplicate `(namespace, id)` plugin
configs are refused at config load.

Cross-instance aggregation is intentionally unsupported. If you want one
combined scoring policy, configure a single WAF instance (or one shared
`proxy_group`-scoped instance) rather than attaching multiple scoring-enabled
WAFs to the same proxy.

The per-instance total is recorded in the metadata fields above regardless of
mode.

## Per-rule overrides and exemptions

`rule_overrides` tunes individual rules — **including built-ins** — without
forking the rule pack. Attach false-positive filters, scope to paths, raise
paranoia, change severity/score, set a per-rule `action`, or exclude named
fields (see [Field exclusions](#field-exclusions)). Per-rule
`fp_filters` are unanchored regular expressions evaluated against the **complete
inspected target value** after the rule matcher finds a hit — for example the
full query value, header value, or `body_json_path` scalar string — not merely
the substring that satisfied `contains`/`regex`/…. A body carrying non-UTF-8
bytes is filtered too: the filter (and `global_exemptions.fp_capture_filters`)
sees the same lossy text view the wide-charset path uses, with invalid bytes
replaced by `U+FFFD`, so binary and legacy-encoded content is suppressed on the
same terms as text:

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
`enforce`; with `mode: "monitor"` the match is logged but allowed. It sits
below `rule_modes` in precedence. `rule_overrides.<id>.action` sets the action
of a rule that is already enforced by level; only `rule_modes: enforce`
promotes a rule above `paranoia_level` (including a
[detection-band](#detection-paranoia-level) rule). An override that raises
`paranoia_min` above `paranoia_level` together with `action: enforce` keeps
the rule dormant until `paranoia_level` reaches it.

### Field exclusions

The most common false positive is one rule firing on one field that
legitimately carries its pattern — a CMS `html` parameter full of markup, a
`redirect` parameter holding a URL, a repeated `ids` parameter. Disabling the
rule or scoping it away with `conditions` also drops its coverage of every
other field. `exclude` removes only the named fields from one rule (CRS-style
target exclusions):

```json
{
  "rule_overrides": {
    "FE-XSS-001":      { "exclude": { "query_params": ["html"] } },
    "FE-PATHTRAV-001": { "exclude": { "query_params": ["relpath"] } },
    "FE-HPP-001":      { "exclude": { "query_params": ["ids"] } },
    "FE-JNDI-001-H":   { "exclude": { "headers": ["x-template-preview"] } },
    "ACME-COOKIE-1":   { "exclude": { "cookies": ["prefs"] } }
  }
}
```

- `query_params` — names compared after one percent-decode (`%68tml` is
  `html`), exactly as a query parser delivers them; case-sensitive. Applies to
  `query_keys` / `query_values` rules and to `full_url` rules. A whole-URL
  match cannot be attributed to one pair, so a `full_url` rule with
  exclusions re-runs its own matcher over the URL rebuilt without the excluded
  pairs, and the hit counts only if it still matches. `FE-HPP-001` drops the
  excluded pairs before comparing duplicates, and the URL-side encoding
  heuristics judge the rebuilt URL.
- `headers` — header names, case-insensitive. Applies to `header_names`,
  `header_values`, and `response_headers` rules.
- `cookies` — cookie names (the text before `=` in the raw crumb),
  case-sensitive. Applies to `cookies` rules, including their scans of the
  crumb's percent-decoded views: the name always comes from the raw crumb, so
  an encoded `prefs%3D=…` is not the `prefs` cookie.

The exclusion boundary is the WAF's own split: query pairs on `&` only (as
CRS and current query parsers split them) and cookie crumbs on `;` only.
With `html` excluded, `html=x;evil=…` is one `html` pair to the WAF, so the
excluding rule skips all of it, while a backend that also splits a query on
`;` (Go before 1.17, older Python `parse_qs`) reads a second parameter,
`evil`. The same applies to a legacy cookie parser that also splits on `,`.
Every other rule still inspects that value; if such a backend sits behind the
WAF, keep exclusions narrow or rely on `fp_filters` instead.

Every other rule still inspects an excluded field, and the excluding rule
still inspects every other field. Exclusions must fit the rule: naming
`cookies` on a query rule, or any field on a path, method, or body rule, is
rejected at construction (bodies are scanned as whole documents; narrow body
rules with `fp_filters`, `conditions`, or a `body_json_path` custom rule
instead). An `exclude` object must name at least one field and rejects
unknown keys.

For per-rule `conditions.paths`, plain strings are exact matches, trailing `*`
means prefix match, and leading `~` means the remaining text is compiled as the
operator-authored regex. Regex conditions are evaluated with Rust regex
`is_match`, so they may match anywhere in the path unless the pattern itself is
anchored (for example `~^/api/`). This preserves existing scoped protections
such as `~api` matching `/api/v1` and `/v1/api-keys`.

Conditions are matched against the canonical request path
([request_path_canonicalization.md](request_path_canonicalization.md)), so a
value that is not itself canonical could never match and would leave its rule
silently inactive. Construction therefore rejects one: an exact or `prefix*`
value may not contain a percent escape, a `\`, a `.`/`..` segment, or a
non-final empty segment (`/api//admin`), and a `~regex` value may not contain a
percent escape. A request whose path carries a `;` parameter only reaches the
WAF on a proxy with `allow_path_parameters: true`; there the parameter is part
of the path conditions see (`/admin;x/users` is not `/admin/users`).

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
- `header_present` — suppress rules when a header is present/equal. **Clients
  choose their own headers**: an entry keyed on a header the client can send
  (for example `x-internal-scan`) lets any caller switch the WAF off for their
  request. Key it only on a header that a trusted component in front of the
  gateway always strips or overwrites — Ferrum's own `request_transformer`
  runs in `before_proxy`, after the WAF has decided, so it cannot protect
  this — or exempt authenticated callers via `consumers` instead. The same
  caution applies to per-rule `conditions.headers`.
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

The `fp_filters` entry above is a regex, not a literal substring. Escape
metacharacters as needed (`\\+` in JSON config for a literal `+` in
`application/ld+json`). After the `contains` matcher hits on the selected
`user.bio` string, the filter is checked against that **entire** bio value; a
JSON-LD `<script type="application/ld+json">…</script>` block therefore
suppresses the hit while an ordinary `<script>…</script>` payload still blocks.

## Body and response inspection

Request-body inspection is on by default for `POST`/`PUT`/`PATCH` with an
inspectable `Content-Type` (`body_methods`, `body_content_types`). Multipart and
binary bodies are opt-in (`inspect_multipart`, `inspect_binary_body`).

The `Content-Type` is matched on its lowercased base media type with parameters
stripped. RFC 6839 structured-syntax suffixes map onto their base family and
re-check the same allowlist: a base type ending in `+json` is treated as
`application/json`, and one ending in `+xml` as `application/xml` /`text/xml`.
So `application/vnd.api+json`, `application/ld+json`,
`application/merge-patch+json` and `application/json-patch+json` are inspected
whenever `application/json` is in `body_content_types`, and
`application/atom+xml` or `application/soap+xml` whenever either
`application/xml` or `text/xml` is. This matters because mainstream backends
(Spring's `MappingJackson2HttpMessageConverter`, ASP.NET Core's
`SystemTextJsonInputFormatter`) parse `application/*+json` as JSON, so without
the suffix rule one header token would defeat every body rule.

The suffix rule reuses the configured allowlist rather than adding hidden types:
if you remove `application/json` from `body_content_types`, `+json` types are
excluded too, and a plugin configured with only `text/plain` inspects neither.
`text/json` is in the default allowlist as an explicit entry, since it carries no
suffix to key off.

### Bodies outside the scan scope: `on_unlisted_content_type`

The `Content-Type` a client declares is attacker-controlled, and many backends
parse a body without consulting it: a Go handler that `json.Unmarshal`s the
raw body, Flask's `get_json(force=True)`, a framework with a default body
parser. Relabelling a JSON injection payload as `application/octet-stream`,
`text/csv`, or sending it with no `Content-Type` at all used to skip every
body rule silently. `on_unlisted_content_type` decides what happens to a
request body whose type is outside the scan scope — not in
`body_content_types` (including the `+json` / `+xml` suffix mapping), a
multipart body while `inspect_multipart` is off, or a missing/unknown type
while `inspect_binary_body` is off:

| Value | Non-empty unlisted body |
| --- | --- |
| `allow` (default) | forwarded uninspected, as before |
| `fail_closed` | rejected when an enforcing request-body policy applies to this request (an applicable `action: enforce` body rule, or anomaly scoring over one), so an enforcing rule cannot be sidestepped by relabelling; otherwise forwarded and recorded |
| `block` | rejected while `mode: enforce` — a strict allowlist of inspectable types |

The decision is exact: when a value could refuse the request, the WAF asks the
gateway to buffer that body and decides over the **finalized** backend-visible
headers and the actual bytes, so an empty upload always passes and an HTTP/2
or HTTP/3 body sent without `Content-Length` is still caught. Bodies that
could not be refused keep the streaming path.

Scope: the setting governs **HTTP request bodies only** — HTTP/1.1, HTTP/2,
HTTP/3, native gRPC, and gRPC-Web requests — and among those only:

- methods listed in `body_methods` (so `body_methods: []` turns it off, and
  `block` then no longer satisfies `mode: enforce` admission);
- requests no `global_exemptions` entry short-circuits;
- instances whose request-body hook runs at all (request and request-body
  inspection on, with an active request-body rule or `FE-ENCODING-001` /
  `FE-ENCODING-002` enabled).

Response bodies are never governed by it, and WebSocket messages carry no
`Content-Type` and are always scanned.

Because a refusing configuration reads the whole body before it rejects, a
large or long-running upload receives the rejection (`reject_status_code`,
default `403`) only at end of stream (memory
stays bounded by `FERRUM_MAX_REQUEST_BODY_SIZE_BYTES`), and a client-streaming
or bidirectional gRPC call may wait for its deadline instead. `on_body_too_large:
skip` does not avoid this buffering for unlisted bodies: it only skips oversize
bodies the WAF would otherwise scan.

A rejection sets `waf.action=blocked`, `waf.block_reason=content_type`, and
`waf.body_uninspected=content_type`. A body that is recorded but not refused
(`mode: monitor`, or `fail_closed` in enforce mode with no enforcing body
policy applicable to the request) carries `waf.body_uninspected=content_type`
without the block fields. Those bodies are not buffered: they are recorded
from the request's declared framing (`Content-Length` > 0 or
`Transfer-Encoding`), so an HTTP/2 or HTTP/3 body sent without
`Content-Length` is **not** recorded. Staging the setting in `monitor` first
shows which routes carry unlisted bodies, but undercounts such clients.

Under `mode: enforce`, `block` is itself a reachable admission enforcement
path when the request-body hook can run (as above), `body_methods` is not
empty, and at least one content type is left unscanned. With both
`inspect_multipart` and `inspect_binary_body` on, every body is scanned; with
`body_methods: []`, no HTTP request body is governed. Either way `block` can
never fire, and it does not satisfy admission (the configuration is still
accepted when some other enforcement path exists). `fail_closed` never
satisfies admission.

Before switching to `block` or `fail_closed`, list every type your backends
legitimately accept: add them to `body_content_types` (scanned as text), turn
on `inspect_multipart` for uploads, or exempt upload-only routes with
`global_exemptions`. gRPC (`application/grpc`, `application/grpc+proto`),
gRPC-Web (`application/grpc-web`, `application/grpc-web+proto`,
`application/grpc-web-text`), `application/protobuf`, and image bodies are
unlisted by default, so a non-empty one is refused under `block`, and under
`fail_closed` wherever an enforcing request-body policy applies (for example
with `default_rule_action: enforce` or anomaly scoring), unless the type is
listed or the route exempted. Every gRPC call has a non-empty body (each
message carries a 5-byte frame header), and a refused native gRPC call receives
the rejection mapped to a gRPC status (`PERMISSION_DENIED` for the default
`403`). The JSON codecs are the exception: `application/grpc+json` and
`application/grpc-web+json` map to the JSON family through their `+json`
suffix, so they are **scanned** as JSON whenever `application/json` is in
`body_content_types`, not refused as unlisted.
Bodies on methods outside `body_methods` (for example a `GET` with a body)
are not governed; add the method to `body_methods` if a backend reads such
bodies.

Response inspection is **off by default**. Enable `response_inspection` (and
`response_body_inspection` for body rules) to run the disclosure and
data-leak rules.

`max_scan_bytes` (default 1 MiB) bounds how much of a body is scanned. A body
whose length is exactly `max_scan_bytes` is scanned in full; only a strictly
larger body is oversize. `on_body_too_large` decides what happens then:

- `fail_closed` (default) — reject when that direction carries an enforcing body
  policy, otherwise scan the first `max_scan_bytes` and flag truncation
- `scan_truncated` — explicit compatibility opt-out: always scan only the first
  `max_scan_bytes` and forward the complete body
- `skip` — do not scan
- `block` — reject every oversize governed body when enforcing, regardless of
  which rules enforce

**Why the default fails closed.** Prefix-only inspection is not a body control.
A client can pad an upload with `max_scan_bytes` of benign bytes and place an
enforced SQLi/XSS/traversal/SSRF/custom-rule payload in the unscanned suffix; a
compromised backend can do the same with disclosure content in a response. The
gateway's own default body ceilings (`FERRUM_MAX_REQUEST_BODY_SIZE_BYTES` /
`FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES`, 10 MiB each) admit far more than the
1 MiB scan cap, so the gap is reachable by default. `fail_closed` closes it
(`GHSA-7jh9-fjqf-jcvf`).

"Carries an enforcing body policy" means global `mode: enforce` **and** either
anomaly `scoring` has an applicable rule reading that direction's body or at
least one applicable `action: enforce` rule reads it — `body_text` /
`body_json_path` for requests, `response_body` for responses, plus the
body-scoped `FE-ENCODING-001` / `FE-ENCODING-002` specials when those rules
are themselves enforce (they read both directions). A rule is applicable only
when its path, method, header, and consumer conditions
match the current request. A request-wide `global_exemptions.header_present`
match also suppresses both rule hits and this fail-closed decision. Built-in
rules are monitor-only unless you set `default_rule_action` or `rule_modes`.
Encoding-evasion specials additionally stay monitor under bulk
`default_rule_action: enforce` until an explicit per-rule action promotes them,
so a purely observational WAF (and any `mode: monitor` WAF) keeps prefix-scanning
and never starts blocking. Requests and responses share one decision, so H1,
H2, and H3 behave identically, and the request decision is made on the finalized
backend-visible body — a request transformer that grows a body past the cap is
still governed.

**The cap is measured against plaintext, in both directions.** A globally
enforcing `on_body_too_large: block` is itself a blocking disposition, so a
request or response whose ORIGIN declared a `Content-Encoding` is decoded by the
shared representation gate before the cap is applied — even when every
applicable body rule is monitor-only. Otherwise a compressed body would slip
under a cap its plaintext exceeds. `mode: monitor` never claims: an undecodable
origin coding there costs an observation, not the response.

Prefer sizing over rejecting where you can: setting `max_scan_bytes` at or above
the effective request/response ceiling (including any route-scoped ceiling)
means no admitted body is ever oversize, and `fail_closed` never fires.

### Scan budget and `on_scan_timeout`

`scan_budget_ms` bounds the scan itself. The deadline is **post-hoc only** on
every surface — request metadata, headers, query, path, request and response
bodies, and WebSocket messages alike. The scan always runs to completion and its
hits always decide first, so an enforcing rule that matched still rejects even
when the scan finished over budget, and a body scan is never skipped. On the
body path the clock starts *after* the plugin's pre-scan fairness yield, so
scheduler delay — which a request flood can inflate — is never charged to the
budget.

Because the scan always completes, an over-budget result names a body the WAF
inspected end to end and found nothing in. `on_scan_timeout` therefore decides
exactly one case — a scan that completed **clean but late** — and is a latency
control, not a coverage control.

| `on_scan_timeout` | Outcome for a clean over-budget scan |
| --- | --- |
| `log_and_allow` (default) | Forward, with a sampled warning and `waf.scan_timed_out` metadata |
| `allow` | Forward silently |
| `fail_closed` | Reject when the governed body direction carries an enforcing body policy, and log and allow otherwise |
| `block` | Reject every over-budget scan, on every surface, independently of global mode |

`fail_closed` is the opt-in strict-latency posture, sharing the vocabulary and
the shape of `on_body_too_large: fail_closed`. It asks the same *question* —
could this direction have refused a body? — resolved through
`request_body_policy_enforces` / `response_body_policy_enforces`. Those predicates
are slightly broader than the one `on_body_too_large: fail_closed` consults: as
well as an applicable enforcing body rule (or anomaly scoring), they count an
`on_body_too_large: block` size cap while globally enforcing, because that cap is
itself a blocking body disposition. `mode: monitor` and monitor-only rule sets
without that cap therefore never start blocking. `block` rejects unconditionally,
including when no rule in that direction could have refused anything.

**Size `scan_budget_ms` before reaching for `fail_closed`.** The scan cost is
`O(active_rules × max_scan_bytes)`, and body normalization multiplies it: a
`max_scan_bytes`-sized form-encoded or JSON body containing `%`, `+`, `\`, or `&`
produces up to five decoded variants, each rescanned (the fifth, the layered
decode's second-to-last round, only when all three rounds changed the body and
that round still holds a `+`). With the 1 MiB default cap that is several MiB of
matching per request, and exceeding a 50 ms budget on such traffic is routine
rather than exceptional. Measure the deadline rate in `waf.scan_timed_out`
under `log_and_allow` first, then either raise
`scan_budget_ms`, lower `max_scan_bytes`, or trim the active rule set — the same
"prefer sizing over rejecting" advice that applies to `max_scan_bytes` above.
Turning on `fail_closed` (or `block`) while scans routinely exceed the budget
makes the gateway reject that traffic, with no rule having matched.

Request metadata, header, query, and path scans are deliberately not
disposition-aware under `fail_closed`. They are bounded by the frontend's header
limits rather than by `max_scan_bytes`, are not buffered, decoded, or clamped,
and cannot be made expensive by a large payload, so there is no `max_scan_bytes`
to size and nothing for a fail-closed latency posture to act on. Use `block` to
apply the strict deadline to every surface.

A rejection on the timeout path sets `waf.action=blocked` with
`waf.block_reason=scan_timeout`. The timeout block itself contributes no
`waf.rule_hits`; `waf.block_reason=scan_timeout` (rather than `rule`) names the
deciding control. A monitor-only hit recorded by an earlier phase — a header,
query, or path rule — still appears in `waf.rule_hits` beside it.

### Unbounded response streams

For a pristine backend `text/event-stream`, request `Accept` and internal
streaming markers cannot bypass response-body policy. Because an unbounded
stream cannot be truncated and scanned before headers are committed,
`on_body_too_large` supplies the explicit disposition: `skip` allows it
uninspected; `block` rejects in enforce mode; and both `fail_closed` and
`scan_truncated` reject when an enforcing response-body rule or anomaly-scoring
policy would otherwise claim inspection, while monitor-only policy records and
allows it. The prefix-only opt-out does not reach an unbounded stream — it
concedes the suffix of a bounded body, and here there is no prefix. With metadata
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

## WebSocket message inspection

WebSocket support is not handshake-only. In addition to running the ordinary
HTTP pipeline over the upgrade request (path, query, headers, cookies, method),
the WAF inspects **complete application messages** on the upgraded session in
both directions (private advisory `GHSA-6j3m-vf5h-pgcx`). This applies
identically to HTTP/1.1 upgrades and HTTP/2 / HTTP/3 Extended CONNECT, because
all three frontends share one frame relay.

**Body targets map to complete messages, not wire frames.**

| Direction | Rule set | Gated by |
| --- | --- | --- |
| client → backend | `body_text`, `body_json_path`, body Luhn/CIDR rules, body-scoped encoding specials (`FE-ENCODING-001/002`) | `request_inspection` + `request_body_inspection` |
| backend → client | `response_body`, response Luhn/CIDR rules, the same encoding specials | `response_inspection` + `response_body_inspection` |

Both **Text** and **Binary** messages are inspected, and both use the same
scanner as the corresponding HTTP body (raw bytes, lossy-UTF-8 text, and the
layered decoded variants). The HTTP media-type selectors — `body_methods`,
`body_content_types`, `inspect_multipart`, `inspect_binary_body` — deliberately
do **not** apply here: a WebSocket message carries no `Content-Type`, so
honoring them would let a client bypass an enforcing rule simply by choosing the
Binary opcode.

**Control frames are never scanned as application payload.** Ping, Pong, and
Close pass through untouched, so keepalive and close semantics are unchanged.

**Fragmentation and compression.** No WAF-side reassembly or decompression
exists, and none is needed:

- Continuation frames are reassembled by the parser before the message hook
  runs. Physical fragments are metered separately, and a message that never
  completes is bounded by `FERRUM_WEBSOCKET_MAX_INCOMPLETE_MESSAGE_FRAMES` /
  `FERRUM_WEBSOCKET_MAX_INCOMPLETE_MESSAGE_SECONDS`, which close both peers.
- `permessage-deflate` is never negotiated end to end on a route the WAF
  protects: the client's `Sec-WebSocket-Extensions` offer is stripped before the
  backend handshake and no negotiated extension is echoed back to the client.
  Payloads reaching the WAF are therefore always uncompressed. Config validation
  refuses `websocket_permessage_deflate: passthrough` on any proxy where a `waf`
  instance is effective (directly, through a proxy group, or as a global).
- With `websocket_permessage_deflate: terminate` the gateway negotiates
  compression with each peer itself and inflates every message before the
  relay parses it, so the WAF still scans plaintext, with bounded decompression
  (Close 1009 past the frame or decompressed-message ceiling). The message is
  re-compressed only after the scan, toward a leg that negotiated compression.
  See [routing.md](routing.md#gateway-terminated-compression-terminate).

**Fail-closed behavior** mirrors the HTTP body path, with the connection Close
taking the place of an HTTP rejection response:

| Condition | Outcome |
| --- | --- |
| Enforcing rule hit (global `mode: enforce` + rule `action: enforce`) | Close 1008 |
| Per-message anomaly score ≥ `scoring.block_threshold` while enforcing | Close 1008 |
| Message larger than `max_scan_bytes` | `on_body_too_large`: `fail_closed` (default) closes when that direction carries an enforcing body policy, else prefix-scans; `scan_truncated` prefix-scans; `skip` forwards uninspected; `block` closes whenever globally enforcing |
| Uninspectable message representation | Closes when that direction carries an enforcing body policy |
| Scan exceeded `scan_budget_ms` with no confirmed blocking hit | `on_scan_timeout`: `log_and_allow` (default) and `allow` forward; `fail_closed` closes when that direction carries an enforcing body policy (the session policy mirrors the HTTP `request_body_policy_enforces` / `response_body_policy_enforces` disjunction, `on_body_too_large: block` term included), else forwards; `block` always closes |

Every close uses RFC 6455 code 1008 with a compiled-in reason
(`message rejected by security policy`, `message exceeds inspectable size`,
`message could not be inspected`; a timeout close uses the last of those).
Reasons never echo message bytes, rule ids, or any peer-controlled value.

A WebSocket message carries no `waf.*` transaction metadata, so a message whose
scan missed its deadline is recorded as a sampled `waf`-target warning
**independently of `log_to_stdout`** — that knob selects per-hit rule
diagnostics, not lost-coverage signals. Only the explicit `on_scan_timeout:
allow` opt-out suppresses it. The warning carries the proxy, connection id,
direction, configured action, and whether the message was blocked; it never
carries message bytes, and `warn_sampled` bounds it to one event per source site
per 10 seconds across instances so a message flood cannot amplify it.

**Anomaly scoring is per complete message**, not accumulated across the session.
A long-lived connection has no request-scoped accumulator, and carrying one
would let an unbounded, attacker-driven counter decide admission — and would
make an identical benign message pass or block depending on session history.

**Multiple instances.** Every configured `waf` instance binds and scans
independently, with its own exemption and condition verdicts. The relay's
first-terminal-Close rule then applies, so one message is blocked at most once
and later instances are not invoked for it.

**Observability.** A closed WebSocket session has no per-message
transaction-summary surface, so message findings are emitted as
fixed-cardinality `waf`-target log events instead of `waf.*` transaction
metadata: a diagnostic for every block (always, since the close is the only other
signal), plus one per matched rule and one per non-blocking
oversize/uninspectable/scan-timeout signal when `log_to_stdout` is enabled. No
message bytes are logged. Warnings are sampled once per source site per 10 seconds
across all sessions, with suppressed-event counts; every diagnostic is available
at debug level. Monitor-mode WebSocket findings are non-blocking and
there is no per-message transaction metadata surface, so enable
`log_to_stdout` when staging WebSocket policy in `mode: monitor`; otherwise
those findings intentionally produce no operator-visible signal.

**Operational note.** Configuring WAF body rules on a WebSocket proxy opts that
proxy's sessions into the parsed frame relay; the raw tunnel-mode fast path
cannot inspect messages and is not used for them. This also makes the session
subject to the parsed relay's `FERRUM_MAX_WEBSOCKET_FRAME_SIZE_BYTES` ceiling;
an oversized frame closes with code 1009 even when
`FERRUM_WEBSOCKET_TUNNEL_MODE=true`. Message scanning performs decoded-variant
and rule-set work for every complete message up to `max_scan_bytes`, and the
scan budget is evaluated after that bounded scan completes. For high-rate
WebSocket workloads, size `max_scan_bytes` to the protocol's real message
envelope and pair WAF with `ws_rate_limiting` to bound repeated per-message
work. A WAF with no body rule set, or with body inspection disabled in both
directions, keeps the previous handshake-only behavior and does not force
parsed framing.

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
  "plugin_name": "waf",
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
- **`inspect_tcp` governs a TCP-only surface.** It selects the opening-bytes
  capture that only a TCP frontend performs. A UDP or DTLS session runs the same
  connection-admission hook, but carries no TCP first bytes and is never judged
  by this switch — its datagrams are governed entirely by `inspect_udp`. So the
  documented defaults (`inspect_tcp: true`, `inspect_udp: true`) are usable on a
  UDP route as-is: clean datagrams reach the backend, and a configured signature
  match still drops.
- By default only client→backend traffic is inspected; set `inspect_response`
  to also scan backend→client datagrams. It is a **direction switch inside UDP
  inspection**, not an independent surface: it is read after `inspect_udp` has
  admitted the datagram hook, so `inspect_response: true` inspects nothing while
  `inspect_udp` is false. Under `mode: enforce`, a stream policy whose only
  claimed enforcement is a response-only direction with both `inspect_tcp` and
  `inspect_udp` off is rejected at construction rather than silently doing
  nothing.

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
`waf.rule_hits`, `waf.target`, `waf.severity`, `waf.score` /
`waf.instances.<id>.score` / `waf.instance_scores`, `waf.action`
(`blocked` / `monitored` / `clean`), `waf.first_blocking_rule`,
`waf.block_reason`, `waf.scoring_instance`, `waf.would_block_reason`,
`waf.paranoia`, `waf.detection_rule_hits` / `waf.detection_paranoia` (see
[Detection paranoia level](#detection-paranoia-level)), plus `waf.scan_truncated` / `waf.scan_timed_out` /
`waf.body_too_large` / `waf.body_too_large_target` (`request_body` or
`response_body`) / `waf.body_uninspected` (`content_type`). All of these are
fixed-cardinality; body bytes are never logged. Blocked requests reject before
backend dispatch and still produce a transaction summary carrying these fields,
so blocks are visible in the same per-request log line as allowed traffic.

`waf.block_reason` names why a request was blocked: `rule`, `score`,
`body_too_large`, `content_type`, or `scan_timeout` for HTTP-family traffic, and
`tcp_require_tls`, `first_bytes_unavailable`, or `signature` for stream (TCP/UDP)
traffic. Stream
inspection additionally records `waf.would_block_reason` (the same stream value
set) on `monitor`-mode connections that *would* have blocked under `enforce`,
so enforce-mode impact stays directly countable before you switch modes — in
particular the server-first `first_bytes_unavailable` false-positive risk noted
above, whose would-blocks carry no `waf.rule_hits` to infer from.

`log_to_stdout` additionally emits dedicated structured diagnostics
(`target: "waf"`), independent of any logging plugin. Per-rule details are
available at debug level; warnings sample one event per source site per 10 seconds
and report `suppressed_events` (shared across rules and instances). Each
event carries `action` as that rule's **effective direct outcome** after applying
the global mode (`blocked`, `monitored`, or `disabled`) and `rule_action` as the
configured rule action (`enforce`, `monitor`, or `disabled`). Aggregate anomaly
scoring is evaluated after the per-rule events, so the final transaction
`waf.action` can still be `blocked` when the score crosses its threshold.

The per-instance anomaly score is carried in `waf.instances.<id>.score` (and
`waf.score` when only one scoring instance contributed). Run in `monitor`
first, watch the logs for `waf.action="monitored"` volume and which rules
fire, then switch to `enforce`.

## Configuration reference

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `mode` | enum | `enforce` | `enforce` / `monitor` / `disabled` |
| `default_rule_action` | enum | _(unset)_ | bulk action for built-ins that inherit it; encoding heuristics stay monitor until `rule_modes`; `rule_modes` overrides win |
| `category_modes` | map | `{}` | per-category action for built-in rules; above `default_rule_action`, below `rule_overrides.action` / `rule_modes`; unknown categories rejected |
| `paranoia_level` | int 1–4 | `1` | activate rules with `paranoia_min <= level` |
| `detection_paranoia_level` | int 1–4 | `paranoia_level` | also compile rules up to this level as detection-only (never block or score; reported in `waf.detection_rule_hits`); only `rule_modes: enforce` promotes one |
| `request_inspection` | bool | `true` | scan request metadata |
| `request_body_inspection` | bool | `true` | scan request bodies |
| `response_inspection` | bool | `false` | scan response headers |
| `response_body_inspection` | bool | `false` | scan response bodies |
| `include_default_rules` | bool | `true` | load the built-in pack |
| `disabled_default_rules` | string[] | `[]` | built-in ids to drop |
| `rule_modes` | map | `{}` | per-rule action by id |
| `rule_overrides` | map | `{}` | per-rule fp_filters/conditions/paranoia_min/severity/score/action/exclude (see [Field exclusions](#field-exclusions)); `action` applies to rules already enforced by level and never promotes above `paranoia_level` |
| `custom_rules` | object[] | `[]` | additional rules |
| `scoring` | object | _(off)_ | anomaly scoring (see above) |
| `global_exemptions` | object | _(none)_ | request short-circuits |
| `scan_budget_ms` | int | `50` | budget for the scan itself, measured after the body path's fairness yield (0 = unbounded) |
| `on_scan_timeout` | enum | `log_and_allow` | `allow` / `block` / `fail_closed` / `log_and_allow` |
| `max_scan_bytes` | int | `1048576` | body scan cap |
| `on_body_too_large` | enum | `fail_closed` | `fail_closed` / `scan_truncated` / `skip` / `block` |
| `on_unlisted_content_type` | enum | `allow` | `allow` / `fail_closed` / `block`; request bodies whose `Content-Type` is outside the scan scope (see [Bodies outside the scan scope](#bodies-outside-the-scan-scope-on_unlisted_content_type)) |
| `body_methods` | string[] | `[POST,PUT,PATCH]` | methods whose HTTP request bodies are scanned and governed by `on_unlisted_content_type`; WebSocket messages ignore it |
| `body_content_types` | string[] | `[application/json, text/json, application/x-www-form-urlencoded, application/xml, text/xml, text/plain, text/html]` | inspectable base content types; `+json` / `+xml` suffixed types match via their base family |
| `inspect_multipart` | bool | `false` | scan multipart bodies |
| `inspect_binary_body` | bool | `false` | scan bodies with unknown/binary type |
| `disallowed_methods` | string[] | `[]` | methods flagged by FE-METHOD-001 |
| `reject_status_code` | int 400–599 | `403` | status for blocked requests |
| `reject_content_type` | string | `application/json` | blocked-response content type |
| `reject_body` | string | `{"error":"Forbidden"}` | blocked-response body |
| `log_to_metadata` | bool | `true` | write `waf.*` metadata |
| `log_to_stdout` | bool | `false` | structured hit diagnostics: sampled warnings and per-hit debug detail |
| `stream` | object | _(off)_ | raw TCP/UDP inspection (see [Stream inspection](#stream-tcpudp-inspection)) |

### `stream` block

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `tcp_require_tls` | bool | `false` | reject TCP whose opening bytes aren't a TLS ClientHello (raw-wire proxies only) |
| `inspect_tcp` | bool | `true` | run signatures over TCP opening bytes; TCP frontends only |
| `inspect_udp` | bool | `true` | run signatures over UDP/DTLS datagrams |
| `inspect_response` | bool | `false` | also scan backend→client datagrams; a direction switch inside UDP inspection, so it does nothing unless `inspect_udp` is on |
| `signatures` | object[] | `[]` | byte-pattern rules: `id`, `pattern`, `severity?`, `action?` |
