# ai_tool_governor

Deterministic allow / deny / approval policy for AI **tool and function calls** —
the concrete actions an agent asks a client runtime (or an upstream agent/tool)
to execute: file writes, ticket creation, deploys, DB queries, code execution,
account changes.

`ai_tool_governor` complements [`ai_semantic_firewall`](../plugin_execution_order.md):
the firewall catches *intent* with semantic policy; the governor enforces
*deterministic* policy on concrete **tool names, arguments, JSON Schema,
regexes, risk, caller identity, proxy, and model/provider metadata**, plus an
optional out-of-band approval webhook. It never tries to prove intent — every
decision is a deterministic function of the request/response bytes plus the
approval endpoint's answer.

- **Priority:** `2978` (Admission band) — after `ai_request_guard` (2975), before
  `ai_semantic_cache` (2996) and `ai_federation` (4060, Response band), so
  disallowed tool schemas are screened before caching or federation routing. Set
  `priority_override` (e.g. `2994`, just after `a2a_gateway`) if you want to
  consume MCP/A2A metadata emitted by `mcp_gateway`/`a2a_gateway` first — that
  still runs well before `ai_federation`.
- **Protocols:** HTTP family (HTTP/1.1, HTTP/2, HTTP/3). Raw WebSocket frame
  tools are out of scope for the MVP.
- **Failure policy:** `FailClosed`.
- **Configuration admission:** unknown properties are rejected at every
  fixed-shape layer (`config`, `inspect`, each `tools.<name>` policy,
  `blocked_arg_patterns[i]`, `approval`, `response`, `observability`) with
  path-qualified errors and close-spelling suggestions. The free-form
  `tools` tool-name map and arbitrary per-tool `json_schema` document contents
  stay open. Unknown keys are rejected even when `enabled: false` so a typo
  cannot hide until the plugin is turned on.

## Inspection surfaces

Each is toggled independently under `inspect`; at least one must be enabled.

| Surface | Default | What it governs |
| --- | --- | --- |
| `request_tool_definitions` | `false` | Tool definitions the client exposes to the model (`tools[].function.name`, `functions[].name`). A disallowed definition is rejected/dry-run. |
| `response_tool_calls` | `true` | Buffered response tool calls (`choices[].message.tool_calls[]` and legacy `choices[].message.function_call`). |
| `streaming_response_tool_calls` | `false` | OpenAI SSE `choices[].delta.tool_calls` deltas and legacy `choices[].delta.function_call` (`functions` API) deltas, reassembled across frames. |
| `mcp_tool_calls` | `false` | MCP JSON-RPC `tools/call` request bodies (`params.name` + `params.arguments`), including calls inside JSON-RPC **batch arrays**. Omitted `params.arguments` normalizes to `{}` before evaluation (MCP zero-argument calls); provider response `function.arguments` omissions are not normalized. |
| `a2a_methods` | `false` | A2A JSON-RPC method names (governed against the `tools` map), including batch arrays. |

For **streaming**, tool-call SSE frames are **held** (not forwarded) until the
call is complete and cleared by policy/approval, then the held frames are
released; on a block the stream is **cut with a terminal SSE error event** and
the held frames are dropped — the disallowed call never reaches the client.
Duplicate `tool_calls[].index` values in one frame, or conflicting /
changing `tool_calls[].id` values for the same `(choice, index)` slot, are
**ungovernable** and fail closed in enforce mode on both the live inspector and
buffered-SSE extraction — they are never concatenated into a synthetic
allowed identity. Duplicate `choices[].index` entries and explicitly empty or
non-string call IDs are likewise malformed. JSON `null` for `tool_calls[].id`
is treated as omitted (same as a missing field), matching nearby null-as-absent
conventions. Introducing an ID only after an untagged fragment is an identity
change and fails closed; an omitted / null ID remains valid on continuation
fragments after a stable ID was established.
Ordinary content/role deltas stream through live **until a tool-call batch
opens**; once a batch is pending, ALL subsequent events (other choices'
content, keepalives) are held too and released in original arrival order when
the batch clears — so an allowed multi-choice stream is never reordered, and a
denied one cannot leak content that arrived after the held call. With
multi-choice (`n > 1`) streams, a batch is finalized only once **every** choice
holding tool calls has reported a `finish_reason` (or the stream ends), and
later tool-call deltas form a new, independently governed batch. The plugin detects `"stream": true`
in JSON POST bodies and prefers the reqwest dispatch path for those requests.
Inspection itself is dispatch-arm-independent: reqwest, direct HTTP/2, and
native HTTP/3 streaming responses all drive the same inspector chain, including
requests whose final body transform introduced the streaming marker and
bodyless requests whose backend unexpectedly answers with SSE.
Requests marked streaming still buffer a plain-JSON fallback
response so `tool_calls` in it are governed (a `text/event-stream` response
is released back to the stream path only when streaming inspection is enabled
and a live inspector will govern it). The live inspector attaches to a
**stream-marked** governed request's response **regardless of the response
`Content-Type`**, not only `text/event-stream`: a `request_transformer` can
add `"stream": true` after the proxy's buffering decisions, in which case the
backend's plain `application/json` SSE fallback is delivered on the streaming
path — the attached inspector then governs it by body shape instead of label.
With a streaming-only configuration, the pre-header decision conservatively
buffers every 2xx response until response headers can refine the choice; any
ambiguous non-SSE response stays buffered even when the request was not marked
streaming. Scope the plugin to AI routes and budget for the resulting
latency/memory cost when enabling streaming inspection without buffered-response
inspection.
Framed gRPC / gRPC-Web responses never get an inspector, and a request with
no streaming marker never does either, so ordinary buffered traffic is
unaffected. SSE parsing (live and buffered) accepts all three spec line
terminators (`\r\n`, `\r`, `\n`), so a CR-only stream's events are parsed and
governed like any other; a `\r` at a chunk edge is held until the next chunk
disambiguates a straddled `\r\n`. The inspector also sniffs the stream's
body shape from its leading bytes: a JSON-shaped stream (an SSE fallback, or
a Chat
Completions JSON body a transform relabeled `text/event-stream`) is held in
full and governed at end-of-stream like a buffered JSON body — a denied call
is never forwarded, an allowed body is released unchanged. A stream whose
leading bytes are **neither SSE-shaped nor JSON-shaped** is uninspectable: it
is held in full, cut at end-of-stream in enforce mode, and released unchanged
in dry-run. "SSE-shaped" accepts any syntactically valid SSE field or comment
line — printable text with a `:` separator in the first line — since the SSE
spec ignores unknown field names and legitimate providers open streams with
extension/heartbeat lines like `ping: 1`; opaque treatment is reserved for
genuinely binary starts (gzip magic, control bytes) and a complete first line
with no `:` separator. A stream whose shape never resolves before
end-of-stream is resolved conservatively there: bytes that are **not valid
UTF-8** (never classifiable as SSE or JSON) get the same opaque treatment —
cut in enforce, released in dry-run — while a colon-less printable UTF-8
fragment, which provably contains no `data:` frame, is released unchanged.

**Response buffering on governed requests:** when this plugin governs response
tool calls for a request, a 2xx response with a **missing or non-JSON
`Content-Type`** is **buffered and inspected**, not streamed — a transform
chain can relabel `Content-Type` while the body is still Chat Completions
JSON, so ambiguous labels are treated fail-closed and run through the
JSON-shape fallback. A buffered body that is **SSE-shaped** (its first
non-empty line is a syntactically valid SSE field or comment line — printable
text with a `:` separator, e.g. `data: …`, a `: ping` keepalive comment, or
an extension field like `ping: 1`) is routed through buffered-SSE
governance regardless of its label, so an upstream that omits
`text/event-stream` — or a transform that relabels it — cannot deliver
tool-call deltas uninspected; conversely, an SSE-**labeled** body that is
actually JSON-shaped is governed through the buffered-JSON path. A buffered
SSE-labeled body that carries a `Content-Encoding` is **decoded first**
(gzip/br, the same decode as the final re-check) and the decoded frames are
governed. Response labels released back to the streaming path: framed gRPC /
gRPC-Web content types (owned by the gRPC machinery, out of this plugin's
scope) always, and `text/event-stream` **only when streaming inspection is
enabled and the response carries no `Content-Encoding`** so the live SSE
inspector will attach and can actually parse the frames — an **encoded SSE
response stays buffered even with streaming inspection enabled** (the
inspector reads the raw byte stream, where compressed bytes parse as zero
events; the buffered path decodes and governs instead, failing closed on an
undecodable encoding in enforce mode). With streaming inspection
disabled, SSE stays buffered and is governed by buffered-SSE governance (or
the JSON-shape fallback if the label was lying). Operators should expect
mislabeled, unlabeled, or compressed SSE responses on governed routes to be
delivered buffered rather than streamed.

## Fail-closed handling of uninspectable bodies

In `mode: enforce`, a body the plugin is configured to govern but cannot
inspect is **rejected** with `502 Bad Gateway` rather than
forwarded ungoverned:

- **Request path** (when any request surface is enabled, for JSON `POST`
  bodies): a `Content-Encoding`d body (request decompression runs in later
  body-transform hooks, so it is opaque here), a body larger than **4 MiB**, a
  non-UTF-8 body, or a body that does not parse as JSON despite a JSON
  content-type.
- **Response path** (when `response_tool_calls` is enabled): a 2xx
  **plaintext** (identity-encoded) JSON response body larger than **4 MiB**
  (padding must not smuggle tool calls past the parse limit) — for a body
  with a `Content-Encoding` the cap applies to the **decoded** size instead
  (see the encoded bullet below), so an incompressible payload whose wire
  bytes exceed 4 MiB while its decoded JSON fits is decoded and governed
  normally rather than rejected — and a `tool_calls[]` / `function_call` entry that
  cannot be policy-checked — a missing or non-string `function.name` (policy
  is keyed by name), or a `tool_calls` value that is present but not an array.
  A `null` `tool_calls`/`function_call` is OpenAI's normal content-only shape
  and is fine. An SSE-labeled buffered body whose bytes are **not valid
  UTF-8** (opaque/binary without a `Content-Encoding` header — e.g. a
  transform stripped the header from compressed bytes) cannot be parsed for
  SSE frames at all and fails closed, matching the live inspector's opaque
  handling.
- **Encoded response bodies**: a governed buffered 2xx that carries a
  `Content-Encoding` the plugin cannot decode for inspection — an unsupported
  encoding (`deflate`, `zstd`, …), corrupt `gzip`/`br` bytes, or decoded
  output past the **4 MiB** cap — fails closed. This applies to a
  JSON-labeled backend response, an SSE-labeled encoded body, and the
  post-transform final re-check **regardless of how a transform relabeled the
  `Content-Type`** (only framed gRPC / gRPC-Web, which the plugin never
  buffers or governs, is out of scope). Decodable `gzip`/`br` bodies are
  decompressed and the decoded bytes governed normally.
- **Streaming path**: held tool-call frames plus the partial-event carry are
  capped at **4 MiB**; past that the stream is cut with the terminal SSE error
  event. A stream whose leading bytes are neither SSE-shaped nor JSON-shaped
  (opaque = binary/undecodable only — gzip magic or control bytes, e.g.
  compressed bytes whose `Content-Encoding` header a transform stripped, or a
  complete first line with no `:` separator — never a valid SSE stream that
  merely opens with an unknown field name) is held in full and cut at
  end-of-stream.

In `mode: dry_run` these bodies are forwarded uninspected (and a stream past
the hold cap is released uninspected) — dry-run never disrupts traffic.

## Actions

Per tool (`tools.<name>.action`): `allow`, `deny`, `redact_args`,
`require_approval`, `dry_run`. `default_action` (`allow` / `deny` /
`require_approval`) applies to any tool without an explicit entry.

Every governed request, response, or SSE batch evaluates at most **64 concrete
tool calls**, unconditionally — the cap applies to `allow`, `deny`,
`redact_args`, `require_approval`, and `dry_run`, not only approval fan-out.
Batches above the limit fail closed in enforce mode.

Argument checks (`max_arg_bytes`, `required_args`, `json_schema`,
`blocked_arg_patterns`) apply to the `allow`, `require_approval`, and
`redact_args` actions. A blocked-pattern match denies under
`allow`/`require_approval`, and is **redacted** under `redact_args` (buffered
path). A `redact_args` policy must configure at least one
`blocked_arg_patterns` entry; an empty redaction policy is rejected rather than
silently turning the tool into an allowlist entry. Regexes that match empty
input are rejected at config load; a contextual zero-length match that can
occur only beside non-empty input also fails closed at runtime. Pattern lists
are capped at 32 entries per tool. Each `blocked_arg_patterns[].name` is capped
at 256 UTF-8 bytes (OpenAPI `maxLength: 256` counts Unicode characters; runtime
admission is the stricter byte cap) because names are substituted into
redaction output. `response.redaction_placeholder` is likewise capped at 256
UTF-8 bytes under the same OpenAPI character / runtime byte distinction, and
every append is checked before allocation so redacted output cannot grow past
the 4 MiB inspectable body limit. On paths where arguments cannot be redacted
in place — the **streaming** path, the **request** body (no request-body
transform), and the post-transform **final response** re-check — a
`redact_args` match fails closed rather than forwarding an unredacted secret. A
successful buffered redaction rewrite invalidates origin representation
validators / integrity headers (`ETag`, `Content-Digest`, `Repr-Digest`,
`Digest`, `Content-MD5`, `Last-Modified`, and related checksum / signature
fields) so clients never validate against pre-redaction bytes.

A per-tool **`dry_run`** action is purely observational: it forwards the call
and records `ai_tool_governor.decision=dry_run` for concrete calls and exposed
request definitions. It is evaluated **before** the argument checks above, so
it never rejects — even for oversized args, a failing schema, or a blocked
pattern. Use it to measure what a stricter action *would* do before enforcing.
(This differs from global `mode: dry_run`, which makes every action
observational.)

## Examples

### Allowlist-only (deny everything not explicitly permitted)

```yaml
plugin_name: ai_tool_governor
config:
  mode: enforce
  default_action: deny
  inspect:
    request_tool_definitions: true
    response_tool_calls: true
  tools:
    "github.create_pr":
      action: allow
      max_arg_bytes: 32768
      required_args: ["repo", "title", "body"]
      blocked_arg_patterns:
        - name: secret
          regex: "(?i)(api[_-]?key|password|token)"
```

Any tool other than `github.create_pr` — whether exposed as a definition or
returned as a call — is rejected with `403` by default. Set
`response.deny_status_code` to customize deterministic policy rejections with
an HTTP error status from `400` through `599`.

### Approval-required production writes

```yaml
plugin_name: ai_tool_governor
config:
  mode: enforce
  default_action: deny
  tools:
    "filesystem.write":
      action: require_approval
      risk: high
      json_schema:
        type: object
        required: ["path", "content"]
        properties:
          path: { type: string, pattern: "^/workspace/" }
          content: { type: string }
    "kubectl.apply":
      action: deny
  approval:
    endpoint_url: https://approval.internal.example.com/ferrum/tool-approval
    timeout_ms: 1500
    cache_ttl_seconds: 300
    fail_on_error: reject      # reject | warn | allow
    include_arguments: false
```

`filesystem.write` calls are POSTed to the approval webhook with request
correlation, consumer/proxy/model/provider, tool name, arguments hash, and risk.
Request correlation prefers private canonical state from the built-in
`correlation_id` plugin. On custom-only chains it falls back to transaction
metadata `request_id`, then legacy `correlation_id`; canonical state always wins
over either plugin-writable compatibility key.
`approval.timeout_ms` defaults to 1500 and may not exceed 30000. A single
governed batch waits at most 30s cumulative for approvals, governs at most 64
concrete calls, stops further webhook fan-out after an enforce-mode block, and
cancels an in-flight approval HTTP call when the governing future is dropped
(client cancel). Identical calls reuse the cached decision for
`cache_ttl_seconds`; the cache key covers consumer, proxy, model, **provider**,
tool name, and arguments (every field the webhook receives that can change its
decision). For streamed and buffered-SSE responses the model/provider come from
request/routing metadata or, when absent, from the SSE frames themselves — a
decision made for one model is never reused for another. The cache is
bounded at 4096 entries — at capacity expired entries are purged and new
decisions are simply not cached. When the endpoint is unreachable,
`fail_on_error: reject` blocks the call (`warn`/`allow` fail open).

The webhook returns `{"decision":"allow"|"deny"}` (or `{"allow":true|false}`),
optionally with `{"approval_id":"..."}`.
Approval response bodies are capped at 64 KiB while streaming; an oversized or
unreadable response is handled through `approval.fail_on_error` rather than
buffered without bound.

### Dry-run rollout

```yaml
plugin_name: ai_tool_governor
config:
  mode: dry_run          # evaluate + emit metadata, never reject, never call the webhook
  default_action: deny
  tools:
    "github.create_pr": { action: allow }
```

`dry_run` records `ai_tool_governor.decision` (what *would* have happened) without
blocking any request — use it to observe policy impact before switching to
`enforce`. When one request or response exposes several governable surfaces (a
`tools[]` definition plus an MCP/A2A call, or multiple response tool calls), the
recorded `decision` keeps the **highest-severity** outcome across them: a later
allowed surface never downgrades an earlier `deny`, so rollout logs do not
under-report requests that `enforce` would have rejected.

An individual `tools.<name>.action: dry_run` is distinct from global dry-run
mode: that tool always forwards and records `ai_tool_governor.decision=dry_run`
even while the plugin is in `enforce` mode. The observational label is sticky
over a plain `allow`, but approval outcomes and denials remain higher severity.

## Observability metadata

When `observability.emit_metadata` is on (default), the plugin writes
`ai_tool_governor.*` transaction metadata: `enabled`, `mode`, `decision`
(`allow` / `dry_run` / `deny` / `require_approval` / `approved` /
`approval_denied`),
`tool_names`, `risk` (max), `policy_ids`, `approval_id`, `arguments_hashes`
(SHA-256, when `hash_arguments` is on), and `redacted_tools`.

Raw arguments are **never** placed in metadata and never logged unless
`observability.max_argument_log_bytes > 0` (then a bounded excerpt of a blocked
call's arguments is logged at `debug` for audit). Raw arguments are sent to the
approval webhook only when `approval.include_arguments: true`.

The plugin's internal per-request bookkeeping — governed-body hashes, the
per-call identity multiset used to skip already-governed calls on the
post-transform re-check, and stream/model dispatch markers — is **not** emitted
as transaction metadata. Hash/identity state lives on non-serialized request
fields, and stream/model markers are stripped at the transaction-log boundary,
so disabling metadata/hash observability cannot be bypassed by lifecycle state.

> **Streaming decisions and `mode: dry_run`.** Streaming SSE batches write the
> same decision metadata as buffered responses. The inspector records only the
> configured aggregate fields while a batch is evaluated; the stream-terminal
> hook folds them into `ctx.metadata` before `TransactionSummary` is finalized.
> Thus a dry-run denied/approval-required call remains forwarded but appears in
> transaction logs with `decision`, `tool_names`, and (when
> `hash_arguments: true`) `arguments_hashes`. Streaming **enforce** decisions
> still cut the stream and are also logged at `warn`.

## Composition

- **`ai_semantic_firewall`** — the semantic firewall catches *intent* (prompt
  injection, tool-abuse language, exfiltration). `ai_tool_governor` enforces
  *deterministic* tool/action policy on the concrete call. Run both: the
  firewall (2968) evaluates the prompt/response text; the governor (2978)
  gates the specific tool name and arguments.
- **`mcp_gateway`** — MCP routing, aggregation, and session mediation remain in
  `mcp_gateway`. Enable `inspect.mcp_tool_calls` on `ai_tool_governor` to add
  deterministic approval/argument policy over selected MCP `tools/call` traffic;
  the governor parses the JSON-RPC body directly and does not depend on
  `mcp_gateway` being present. When both plugins share a proxy in
  `aggregate_router` mode, governor policy keys stay the **public** namespaced
  names (for example `github.create_pr`): the gateway's trusted public→upstream
  rewrite is remapped for the final-body recheck only when the final wire name
  exactly matches that staged upstream alias. Final arguments, schemas, required
  fields, regexes, and approvals are still re-evaluated, and any unrelated name
  change fails closed under `default_action: deny`.

## Limitations (MVP)

- Streaming `redact_args` fails closed (cuts the stream) rather than redacting
  split-JSON arguments mid-flight.
- Held streaming tool-call frames are released together at each batch's
  completion boundary (all tool-call-holding choices finished); while a batch
  is pending, other choices' content deltas are held behind it (ordering and
  no-leak-on-deny take precedence over latency for the rare
  multi-choice-with-tools stream).
- Request-path governance is scoped to JSON `POST` bodies (the shape OpenAI,
  MCP, and A2A traffic uses). Framed gRPC / gRPC-Web traffic — including the
  `application/grpc+json` / `application/grpc-web+json` variants, whose bodies
  are length-prefixed wire frames rather than a bare JSON document — is out
  of scope on a mixed proxy in **both directions**: requests are not buffered
  or rejected, and a framed-gRPC **response** that reaches the buffered hooks
  (buffered by `response_body_mode: Buffer` or another plugin) is never
  inspected, size-checked, or rewritten by this plugin.
- A JSON-labelled **response** body that fails to parse is forwarded (only
  oversized responses fail closed) — rejecting every unparseable JSON response
  on a shared proxy would break unrelated routes.
- The plugin governs tool calls; it does not execute tools, manage MCP sessions,
  or replace `mcp_gateway`/A2A routing.
- Streaming inspection is transport-independent across reqwest, direct HTTP/2,
  and native HTTP/3 response arms. `forces_reqwest_dispatch` remains a scoped
  optimization for requests already known to stream, while final request-body
  transforms are reflected in both dispatch and response buffering decisions.
