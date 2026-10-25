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
  `ai_semantic_cache` (4057) and `ai_federation` (4060, Response band), so
  disallowed tool schemas are screened before caching or federation routing. Set
  `priority_override` (e.g. `2994`, just after `a2a_gateway`) if you want to
  consume MCP/A2A metadata emitted by `mcp_gateway`/`a2a_gateway` first — that
  still runs well before `ai_federation`.
- **Protocols:** HTTP family (HTTP/1.1, HTTP/2, HTTP/3). Raw WebSocket frame
  tools are out of scope for the MVP.
- **Request body ceiling:** the plugin declares no plugin-local request-body
  buffer ceiling; governed request buffering is bounded by the gateway's
  retained request ceiling (`FERRUM_MAX_REQUEST_BODY_SIZE_BYTES`, or the finite
  `FERRUM_REQUEST_BUFFER_FALLBACK_MAX_BYTES` when that is `0`), and a governed
  body past the 4 MiB inspection window still fails closed in enforce mode.
- **Failure policy:** `FailClosed`.
- **Configuration admission:** unknown properties are rejected at every
  fixed-shape layer (`config`, `inspect`, each `tools.<name>` policy,
  `blocked_arg_patterns[i]`, `approval`, `response`, `observability`) with
  path-qualified errors and close-spelling suggestions. The free-form
  `tools` tool-name map and arbitrary per-tool `json_schema` document contents
  stay open. Unknown keys are rejected even when `enabled: false` so a typo
  cannot hide until the plugin is turned on. Every accepted key, with its type,
  default, and admitted range, is tabulated under
  [Configuration reference](#configuration-reference).

## Inspection surfaces

Each is toggled independently under `inspect`; at least one must be enabled.

| Surface | Default | What it governs |
| --- | --- | --- |
| `request_tool_definitions` | `false` | Tool definitions the client exposes to the model, in every provider shape: OpenAI `tools[].function.name` and legacy `functions[].name`, Anthropic `tools[].name`, Google `tools[].functionDeclarations[].name`, Bedrock `toolConfig.tools[].toolSpec.name`. A provider built-in that carries a `type` but no name of its own (`{"type": "code_interpreter"}`) is governed under its `type`. A disallowed definition is rejected/dry-run; an entry no shape can name is ungovernable. |
| `response_tool_calls` | `true` | Buffered response tool calls in every provider shape: OpenAI `choices[].message.tool_calls[]` and legacy `choices[].message.function_call`, OpenAI Responses `output[]` items of `type: "function_call"`, Anthropic `content[]` blocks of `type: "tool_use"`, Google `candidates[].content.parts[].functionCall`, Cohere v2 `message.tool_calls[]`, Bedrock Converse `output.message.content[].toolUse`. |
| `streaming_response_tool_calls` | `false` | SSE tool-call deltas, reassembled across frames, in **these five** provider shapes — a narrower set than the buffered row above: OpenAI Chat Completions `choices[].delta.tool_calls` and legacy `choices[].delta.function_call`, OpenAI Responses `response.output_item.added` (a `function_call` item) plus `response.function_call_arguments.delta` (see [Streaming behavior](#streaming-behavior) for the restatement checks), Anthropic `content_block_start` (`content_block.type: "tool_use"`) plus `content_block_delta` (`delta.type: "input_json_delta"`), Cohere v2 `tool-call-start` / `tool-call-delta`, Google `candidates[].content.parts[].functionCall`. Bedrock's binary event stream is **not** accumulated (see [Limitations](#limitations-mvp)). Batch boundaries are OpenAI `finish_reason`, Google `finishReason`, Anthropic `message_delta` (`delta.stop_reason`) / `message_stop`, Cohere `message-end`, and OpenAI Responses `response.completed` / `response.incomplete` / `response.failed`. |
| `mcp_tool_calls` | `false` | MCP JSON-RPC `tools/call` request bodies (`params.name` + `params.arguments`), including calls inside JSON-RPC **batch arrays**. Omitted `params.arguments` normalizes to `{}` before evaluation (MCP zero-argument calls); provider response `function.arguments` omissions are not normalized. |
| `a2a_methods` | `false` | A2A JSON-RPC method names (governed against the `tools` map), including batch arrays. |

### Streaming behavior

- **Hold and release.** Tool-call SSE frames are **held** (not forwarded) until
  the call is complete and cleared by policy/approval, then released. On a block
  the stream is **cut with a terminal SSE error event** and the held frames are
  dropped, so the disallowed call never reaches the client.
- **Ordering.** Ordinary content/role deltas stream live **until a tool-call
  batch opens**. While a batch is pending, ALL later events (other choices'
  content, keepalives) are held too and released in arrival order when the batch
  clears, so an allowed multi-choice stream is never reordered and a denied one
  cannot leak content that arrived after the held call. With multi-choice
  (`n > 1`) streams, a batch is finalized only once **every** choice holding
  tool calls has reported a `finish_reason` (or the stream ends); later
  tool-call deltas form a new, independently governed batch.
- **Deferred cuts.** When an earlier inspector defers a cut, the chain passes its cleared bytes
  through the governor and calls `flush_before_cut` instead of `on_end`. The default hook calls
  `on_end`; the governor overrides it to drop a pending tool-call batch, partial event, or fully
  held body without governing it. This applies in both `enforce` and `dry_run`: the truncated
  call triggers no approval webhook or decision metadata, and none of its held frames are
  released. Only frames the governor already cleared reach the client before the earlier cut.
- **OpenAI Responses restatements.** A Responses stream restates each finished
  call in `response.function_call_arguments.done`, `response.output_item.done`,
  and the `output[]` of the terminal `response.completed` event, and a client may
  act on any of them. Every restatement must equal the name and arguments the
  deltas built **exactly**; a different value, a second
  `response.output_item.added` for the same `output_index`, an argument delta for
  a call no event opened, or an event without a usable `output_index` makes the
  batch ungovernable (fail closed in enforce). A call that appears only in a
  restatement (for example only in `response.completed`) is governed as a
  complete call.
- **Uninspectable events.** An SSE event whose bytes are not valid UTF-8 (even
  in an ignored comment line — a WHATWG client still decodes the event's intact
  `data:` lines), or whose `data:` payload is well-formed JSON nested past the
  inspection parser's limit, cannot be inspected. Enforce mode cuts the stream
  before releasing it or anything held behind it; dry-run forwards it unchanged.
- **Call identity.** Duplicate `tool_calls[].index` values in one frame, or
  conflicting / changing `tool_calls[].id` values for the same
  `(choice, index)` slot, are **ungovernable** and fail closed in enforce mode
  (live inspector and buffered-SSE extraction alike); they are never
  concatenated into a synthetic allowed identity. Duplicate `choices[].index`
  entries and explicitly empty or non-string call IDs are also malformed. JSON
  `null` for `tool_calls[].id` is treated as omitted. Introducing an ID only
  after an untagged fragment is an identity change and fails closed; an
  omitted / null ID remains valid on continuation fragments after a stable ID
  was established.
- **Which responses get an inspector.** The plugin detects `"stream": true` in
  JSON POST bodies and prefers the reqwest dispatch path for those requests,
  but inspection itself is dispatch-arm-independent: reqwest, direct HTTP/2,
  and native HTTP/3 streaming responses all drive the same inspector chain. The
  live inspector attaches to a **stream-marked** governed request's response
  **regardless of the response `Content-Type`** — including requests whose
  final body transform introduced the streaming marker (a `request_transformer`
  can add `"stream": true` after the proxy's buffering decisions) and bodyless
  requests whose backend unexpectedly answers with SSE. Framed gRPC / gRPC-Web
  responses never get an inspector, and neither does a request with no
  streaming marker, so ordinary buffered traffic is unaffected.
- **Buffering cost.** Requests marked streaming still buffer a plain-JSON
  fallback response so `tool_calls` in it are governed (a `text/event-stream`
  response is released to the stream path only when streaming inspection is
  enabled and a live inspector will govern it). With a streaming-only
  configuration, the pre-header decision conservatively buffers every 2xx
  response until response headers can refine the choice; any ambiguous non-SSE
  response stays buffered even when the request was not marked streaming. Scope
  the plugin to AI routes and budget for the latency/memory cost when enabling
  streaming inspection without buffered-response inspection.
- **Line terminators.** SSE parsing (live and buffered) accepts all three spec
  line terminators (`\r\n`, `\r`, `\n`). A `\r` at a chunk edge is held until
  the next chunk disambiguates a straddled `\r\n`. Event framing and the
  leading-bytes shape sniff resume where the previous chunk left off, so a long
  event or prelude delivered in many small chunks costs work linear in its size
  rather than a rescan from its first byte on every chunk.
- **Body-shape sniffing.** The inspector classifies the stream from its leading
  bytes:
  - *SSE-shaped* — any syntactically valid SSE field or comment line (printable
    text with a `:` separator in the first line). The SSE spec ignores unknown
    field names and providers open streams with lines like `ping: 1`, so these
    are parsed normally.
  - *JSON-shaped* — an SSE fallback, or a Chat Completions JSON body a transform
    relabeled `text/event-stream`. Held in full and governed at end-of-stream
    like a buffered JSON body: a denied call is never forwarded, an allowed body
    is released unchanged.
  - *Opaque* — neither SSE- nor JSON-shaped (gzip magic, control bytes, or a
    complete first line with no `:`). Held in full, cut at end-of-stream in
    enforce mode, released unchanged in dry-run.
  - *Unresolved at end-of-stream* — bytes that are not valid UTF-8 get the
    opaque treatment; a colon-less printable UTF-8 fragment, which provably
    contains no `data:` frame, is released unchanged.

### Response buffering on governed requests

When this plugin governs response tool calls for a request, labels are not
trusted, because a transform chain can relabel `Content-Type` while the body is
still Chat Completions JSON:

- A 2xx response with a **missing or non-JSON `Content-Type`** is **buffered
  and inspected**, not streamed, and runs through the JSON-shape fallback.
- A buffered body that is **SSE-shaped** (first non-empty line is a valid SSE
  field or comment line, e.g. `data: …`, a `: ping` keepalive, or `ping: 1`) is
  governed as buffered SSE regardless of its label, so an upstream that omits
  `text/event-stream` cannot deliver tool-call deltas uninspected. Conversely,
  an SSE-**labeled** body that is actually JSON-shaped is governed as buffered
  JSON.
- A buffered SSE-labeled body with a `Content-Encoding` is **decoded first**
  (gzip/br, the same decode as the final re-check) and the decoded frames are
  governed.
- Released back to the streaming path: framed gRPC / gRPC-Web content types
  (owned by the gRPC machinery) always, and `text/event-stream` **only when
  streaming inspection is enabled and the response carries no
  `Content-Encoding`**. An **encoded SSE response stays buffered even with
  streaming inspection enabled**, because the live inspector reads raw bytes
  where compressed data parses as zero events; the buffered path decodes and
  governs instead, failing closed on an undecodable encoding in enforce mode.
- With streaming inspection disabled, SSE stays buffered and is governed as
  buffered SSE (or via the JSON-shape fallback if the label was wrong).

Expect mislabeled, unlabeled, or compressed SSE responses on governed routes to
be delivered buffered rather than streamed.

## Modes

| `mode` | Rejects? | What it does |
| --- | --- | --- |
| `enforce` (default) | yes | Blocks denied calls, cuts blocked streams, and **fails closed** on every body it cannot policy-check. |
| `dry_run` | never by governor policy | Evaluates policy, records the decision `enforce` **would** have reached plus the observation labels below, and forwards. The safe rollout / observe posture. Never calls the approval webhook. An earlier inspector's deferred cut can still end the chain and drop a pending, ungoverned unit. |

`dry_run` still **counts and logs** everything `enforce` would have refused,
including bodies it could not read — it does not disrupt traffic by governor
policy. An earlier inspector's deferred cut still ends the chain and can drop a
pending unit that the governor has not finished governing.

**Global dry-run does not relabel the decision.** `ai_tool_governor.mode` is
what records the posture; `ai_tool_governor.decision` keeps the would-be policy
label. A tool that `enforce` would have blocked is logged as
`mode=dry_run, decision=deny`; a `require_approval` policy is logged as
`mode=dry_run, decision=require_approval` (the webhook is not called, so the
terminal `approved` / `approval_denied` labels never appear in dry-run).
`decision=dry_run` is reserved for two distinct cases: the per-tool
`tools.<name>.action: dry_run` policy (which is observational even while the
plugin is in `enforce` mode), and the dry-run duplicate-key ambiguity
observation described under
[Ambiguous JSON](#fail-closed-handling-of-uninspectable-bodies), which pairs it
with `uninspectable_reason=ambiguous_json`. **Query rollout dashboards on
`mode`, not on `decision`**, or ordinary global dry-run findings are missed.

## Unreadable tool-call shapes (`unknown_shape_action`)

A response can carry a tool call in a provider dialect the extractors above do
not read. Reporting "no tool calls" for such a body would be an **extraction
failure reported as an allow** — the exact fail-open the `FailClosed` policy
exists to prevent.

The plugin therefore scans every governed payload for a live **tool-call
marker**: an object member named `tool_calls`, `toolCalls`, `tool_call`,
`toolCall`, `tool_use`, `toolUse`, `function_call`, `functionCall`,
`function_calls`, or `functionCalls` whose value is non-`null` and non-empty,
or a block tagged `"type": "tool_use"` / `"toolUse"` / `"function_call"` / `"tool-call"`.
A payload that carries such a marker but from which **no call could be
extracted** is ungovernable. When calls **were** extracted, the scan still runs
over every location the extractors did not read: a second call placed in an
unread location (for example a top-level `tool_call` beside a readable
`choices[].message.tool_calls[]`, which a normalizing client runtime may also
honor) is ungovernable too. Locations an extractor did read — including the
argument documents inside them — are skipped, so marker-like names inside a
call's own arguments never count. The same rule applies per SSE frame.

| `unknown_shape_action` | Default | Behavior |
| --- | --- | --- |
| `deny` | yes | Ungovernable: `enforce` rejects the buffered body with `502` / cuts the stream; `dry_run` forwards. |
| `allow` | — | Documented opt-out: forwards the payload as if it carried no tool calls. |

Both settings record the fixed
`ai_tool_governor.uninspectable_reason = unrecognized_tool_call_shape`
observation. The observation writer itself never sets `decision` — the bytes
were not evaluated against policy, so neither `allow` nor `deny` would be a
truthful policy label — and on the forwarding paths (`allow`, or `deny` under
`dry_run`) no decision is set for this case (a stronger decision already
recorded by another surface still stands). The default fail-closed rejection
path is different: when `enforce` rejects or cuts the payload, it also records
`ai_tool_governor.decision = deny` as the rejection outcome alongside the
fixed reason (when metadata emission is enabled). The case is therefore never
*silent* under either setting.

Scoping the posture to a positive marker is deliberate: payloads with **no**
tool surface at all — ordinary REST JSON on a shared proxy, embeddings /
moderations / image responses, content-only completions — stay out of scope
under both settings and are never rejected — at any size inside the 4 MiB
inspection window: the marker scan's node budget covers every value a 4 MiB
document can hold, so a large embeddings batch or numeric array is scanned to
the end rather than refused because it is large. Empty and `null` containers
(`"tool_calls": []`, `"tool_calls": null`) are the documented provider "no
calls" shapes and are not markers.

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
  and is fine. A JSON response that the bounded scanner validates as a complete,
  well-formed document but that the inspection parser cannot materialize —
  nesting past its 128-level recursion limit, or a number outside its range —
  is also uninspectable: other parsers read such a document, so a tool call
  inside it was never evaluated. This applies to buffered JSON, the
  post-transform re-check, buffered and live SSE `data:` payloads, and a fully
  held JSON-shaped stream. Malformed JSON keeps the forward posture listed under
  [Limitations](#limitations-mvp). An SSE-labeled buffered body whose bytes are **not valid
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

- **Ambiguous JSON (duplicate object member names, `GHSA-c78j-5w9p-cpq6`)**:
  `serde_json` collapses duplicate members to the *last* value while many
  backends and clients keep the *first*, so a duplicated tool name or argument
  member means the document this plugin governs is not the document the next
  parser reads. The plugin forwards the original bytes and has no request-body
  transform, so ambiguity is **refused, never canonicalized**. Every governed
  JSON surface is screened: the initial request body, the final
  backend-visible request body, buffered JSON responses (plain and decoded),
  the post-transform final re-check, live and buffered SSE `data:` payloads,
  a fully-held JSON-shaped stream, and the approval webhook's own response.
  A tool call whose `function.arguments` / MCP `params` arrive as a JSON
  *string* gets its content screened separately — the enclosing document scan
  cannot see inside a string — and an ambiguous one joins the ungovernable
  class, exactly like a missing `function.name`. On the streaming path an
  ambiguous frame cuts the stream **before any held bytes are released**.
  Member names are compared after JSON escapes are decoded, so a literal name
  and a `\uXXXX`-escaped spelling of the same code point are one member. The
  screen is non-recursive and bounded by explicit depth, token, member-count,
  member-name, and body-size budgets; exhausting any budget fails closed without
  an unbounded confirmation pass.
  Bytes that are not valid JSON at all keep their existing uninspectable
  handling. Rejection details use a fixed set of reasons and never echo any
  byte of the governed body.

In `mode: dry_run` these bodies are forwarded uninspected (and a stream past
the hold cap is released uninspected). An earlier inspector's deferred cut can
still end the chain in either mode: the governor drops a pending unit at that
cut, including in dry-run. This is a consequence of the earlier cut, not a
governor policy decision. Apart from that case, dry-run never disrupts traffic.
includes ambiguous JSON: dry-run forwards the original bytes unchanged and
records a sanitized fixed-cardinality observation —
`ai_tool_governor.decision=dry_run` plus
`ai_tool_governor.uninspectable_reason=ambiguous_json` — and never claims
enforcement with `decision=deny`. The reason label is sticky and bounded, so
repeated ambiguous frames do not grow metadata cardinality. Generic
uninspectable causes (encoding, size, non-UTF-8) keep their prior forward-only
dry-run posture and are not relabeled as ambiguity.

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
path). Patterns run over the raw arguments text and — when that text contains a
JSON escape — also over its JSON-decoded views: the canonical re-serialization
and every decoded string (member names included). OpenAI and Cohere carry
arguments as model-written JSON *source*, so without this an escaped spelling
(`"api\u005fkey"`, `"http:\/\/"`) would hide a match from the regex while the
executing runtime decodes it. Under `redact_args`, redaction rewrites the raw
text, so a match visible only in a decoded view (it cannot be removed in place)
**denies** the call instead of forwarding the secret. A `redact_args` policy must configure at least one
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

### Tool name globs

A `tools` key containing `*` is a glob: `*` matches any run of characters,
including none, and crosses `.`, `/`, and `_` (a deny glob such as `*delete*`
must not be escapable by the separator a tool name uses). Keys are anchored at
both ends. Precedence for one call name:

1. an **exact** key always wins;
2. otherwise, among matching globs, the one with the **most literal** (non-`*`)
   bytes wins; ties go to fewer wildcards, then to the key's byte order;
3. otherwise `default_action` applies.

So `github.*: allow` plus `github.delete*: deny` allows `github.create_pr` and
denies `github.delete_repo`, and an exact `github.read_secret: deny` beats both.
At most 256 glob keys are admitted, each at most 256 UTF-8 bytes. Glob keys are
never A2A aliases. `ai_tool_governor.policy_ids` records the governing key (the
glob itself for a glob match).

### Caller identity scopes

A tool policy can be scoped to callers with `allowed_consumers` /
`denied_consumers` (Consumer `username`) and `allowed_groups` / `denied_groups`
(Consumer `acl_groups`), evaluated against the gateway-mapped Consumer of the
request:

- a `denied_*` match denies, and wins over any `allowed_*` match;
- with any `allowed_*` list configured, the caller must match an allowed
  consumer or group;
- with any scope configured, a request **without a mapped Consumer** is denied
  (an unmapped external identity cannot be evaluated against these lists).

The scope is decided after a per-tool `deny` or `dry_run` and before argument
checks and approval, so a caller outside the scope never reaches the approval
webhook. A request tool *definition* outside the caller's scope is refused like
a denied tool. Example: `kubectl.apply: {action: require_approval,
allowed_groups: [sre]}` sends SRE calls to approval and denies everyone else.

A per-tool **`dry_run`** action is purely observational: it forwards the call
and records `ai_tool_governor.decision=dry_run` for concrete calls and exposed
request definitions. It is evaluated **before** the argument checks above, so
it never rejects — even for oversized args, a failing schema, or a blocked
pattern. Use it to measure what a stricter action *would* do before enforcing.
(This differs from global `mode: dry_run`, which makes every action
observational.)

## Configuration reference

Every accepted key, with its runtime type, default, and admitted range. This is
the complete fixed-shape surface: a property name that is not listed here is
rejected at admission with a path-qualified error and a close-spelling
suggestion, at every layer (`config`, `config.inspect`, `config.tools.<name>`,
`config.tools.<name>.blocked_arg_patterns[i]`, `config.approval`,
`config.response`, `config.observability`). The two deliberately **open**
surfaces are the `tools` tool-**name** map and the contents of each
`tools.<name>.json_schema` document. Unless the instance is disabled (see
[Disabled instances](#disabled-instances)), a present value of the wrong JSON
type is rejected at admission — `null` included — so a mistyped value never
silently resolves to the default in this table.

### Root

| Key | Type | Default | Admitted values and notes |
| --- | --- | --- | --- |
| `enabled` | boolean | `true` | `false` makes the instance inert (see [Disabled instances](#disabled-instances)). |
| `mode` | string | `enforce` | `enforce` \| `dry_run`. See [Modes](#modes). |
| `default_action` | string | `deny` | `allow` \| `deny` \| `require_approval`. Applies to any tool with no `tools` entry. `allow` additionally requires at least one `tools` entry — an allow-by-default instance with no policies would govern nothing and is rejected. |
| `unknown_shape_action` | string | `deny` | `deny` \| `allow`. Posture for a payload carrying a tool-call marker no extractor could read. See [Unreadable tool-call shapes](#unreadable-tool-call-shapes-unknown_shape_action). |
| `inspect` | object | `{}` | Inspection surfaces. At least one must be enabled after defaults are applied. |
| `tools` | object | `{}` | Free-form map: tool name or `*` glob → policy object (see [Tool name globs](#tool-name-globs)). An empty tool name is rejected; at most 256 glob keys of at most 256 UTF-8 bytes each. |
| `approval` | object | absent | Approval webhook. Required when `mode: enforce` and a `require_approval` action is reachable from a concrete-call surface (`response_tool_calls`, `streaming_response_tool_calls`, `mcp_tool_calls`, or `a2a_methods`). Definition-only inspection blocks `require_approval` locally and needs no webhook. |
| `response` | object | `{}` | Rejection / redaction output shape. |
| `observability` | object | `{}` | Metadata and audit-logging controls. |

### `inspect`

All booleans; see [Inspection surfaces](#inspection-surfaces) for what each one
reads.

| Key | Default |
| --- | --- |
| `request_tool_definitions` | `false` |
| `response_tool_calls` | `true` |
| `streaming_response_tool_calls` | `false` |
| `mcp_tool_calls` | `false` |
| `a2a_methods` | `false` |

Because `response_tool_calls` defaults to `true`, the only way to configure no
surface at all — and be rejected — is to set it explicitly to `false` while
every other surface is `false` or omitted.

### `tools.<name>`

| Key | Type | Default | Admitted values and notes |
| --- | --- | --- | --- |
| `action` | string | **required** | `allow` \| `deny` \| `redact_args` \| `require_approval` \| `dry_run`. `redact_args` additionally requires at least one `blocked_arg_patterns` entry. |
| `risk` | string | `low` | `low` \| `medium` \| `high` \| `critical`. Surfaced as `ai_tool_governor.risk` (max across a batch) and sent in approval requests. Purely a label — it does not itself change the decision. |
| `max_arg_bytes` | integer ≥ 0 | unset (no cap) | Deny when the raw arguments string exceeds this many bytes. |
| `required_args` | array of strings | `[]` | Each entry must be a non-empty string. Deny when any listed key is absent from the parsed arguments object. |
| `blocked_arg_patterns` | array of objects | `[]` | At most **32** entries; each entry is closed to the two keys below. |
| `json_schema` | object | unset | An open JSON Schema document the parsed arguments must satisfy, else deny. Compiled at admission — an invalid schema is rejected. Arbitrary keywords inside the document are intentionally allowed. |
| `allowed_consumers` | array of strings | unset | Consumer usernames allowed to use the tool. 1–256 entries, each 1–512 UTF-8 bytes. See [Caller identity scopes](#caller-identity-scopes). |
| `denied_consumers` | array of strings | unset | Consumer usernames denied the tool; wins over every `allowed_*` match. Same bounds. |
| `allowed_groups` | array of strings | unset | Consumer `acl_groups` allowed to use the tool. Same bounds. |
| `denied_groups` | array of strings | unset | Consumer `acl_groups` denied the tool; wins over every `allowed_*` match. Same bounds. |

### `tools.<name>.blocked_arg_patterns[]`

| Key | Type | Default | Admitted values and notes |
| --- | --- | --- | --- |
| `name` | string | **required** | Non-empty, at most **256 UTF-8 bytes**. Substituted into `response.redaction_placeholder`'s `{name}`. |
| `regex` | string | **required** | Non-empty and must compile. A regex that matches the empty string is rejected at admission — zero-width redaction would amplify a bounded argument without limit. |

### `approval`

| Key | Type | Default | Admitted values and notes |
| --- | --- | --- | --- |
| `endpoint_url` | string | **required** | Must parse as a URL whose scheme is `http` or `https`. The scheme is **case-insensitive** (`HTTPS://…` is admitted; the URL parser normalizes it), and the host is screened against the backend egress policy at admission. An `http://` URL is admitted only to a loopback IP literal written as a dotted-quad `127.d.d.d` or `[::1]` (a co-located sidecar) unless `allow_plaintext: true`: a cleartext channel lets a man-in-the-middle forge `allow` verdicts. |
| `timeout_ms` | integer | `1500` | `1`–`30000`. Per-webhook-call timeout; `0` is rejected rather than meaning "no timeout". |
| `cache_ttl_seconds` | integer ≥ 0 | `300` | `0`–`2592000` (30 days). **`0` disables caching.** The cache is bounded at 4096 entries; at capacity expired entries are purged and new decisions are simply not cached. |
| `fail_on_error` | string | `reject` | `reject` \| `warn` \| `allow`. Behavior when the endpoint cannot be evaluated: `reject` fails closed, `warn` / `allow` fail open. |
| `include_arguments` | boolean | `false` | Include the raw tool arguments in the approval request body. Off by default so secrets are not sent. |
| `headers` | object | `{}` | Extra approval request headers, header name → value; at most 32. A value is a literal or a whole-value `${FERRUM_PLUGIN_SECRET_<NAME>}` reference resolved from the process environment at the **first approval call** (validation does not need the live secret; an unset or invalid secret is an approval endpoint error handled by `fail_on_error`). Names must be valid and unique case-insensitively and may not be `content-type`, `content-length`, `host`, `transfer-encoding`, `connection`, `keep-alive`, `proxy-connection`, `te`, `trailer`, `upgrade`, or `X-Ferrum-Hops`; values are 1–8192 UTF-8 bytes and valid header values. Values are never logged or echoed. |
| `allow_plaintext` | boolean | `false` | Admit an `http://` `endpoint_url` whose host is not a loopback IP literal. Verdicts, any `headers` credential, and (with `include_arguments`) raw arguments then cross the network in clear. |

### `response`

| Key | Type | Default | Admitted values and notes |
| --- | --- | --- | --- |
| `deny_status_code` | integer | `403` | `400`–`599`. Status for a deterministic policy denial in enforce mode. Uninspectable governed bodies keep their own fixed `502`. |
| `redaction_placeholder` | string | `[REDACTED_TOOL_ARG:{name}]` | At most **256 UTF-8 bytes**. `{name}` is replaced with the matched pattern name. |
| `streaming_deny_event` | boolean | `true` | Emit the terminal SSE `error` event when cutting a streamed tool call. Set `false` to cut the stream **silently** — the disallowed call is still never forwarded; the client simply sees the stream end with no in-band explanation. Buffered denials are unaffected. |

### `observability`

| Key | Type | Default | Admitted values and notes |
| --- | --- | --- | --- |
| `emit_metadata` | boolean | `true` | Emit the `ai_tool_governor.*` transaction metadata described under [Observability metadata](#observability-metadata). |
| `hash_arguments` | boolean | `true` | Emit SHA-256 hashes of tool arguments as `ai_tool_governor.arguments_hashes`. Raw arguments are never placed in metadata. |
| `max_argument_log_bytes` | integer ≥ 0 | `0` | When `> 0`, log up to this many bytes of a **blocked** call's raw arguments at `debug` for audit. `0` keeps raw arguments out of logs entirely. |

### Admission diagnostics

A key that is **present but wrong-typed** is reported as a type error naming the
JSON kind that was supplied (`… 'action' must be a string (expected allow, deny,
redact_args, require_approval, or dry_run), got a number`), never as a missing
key — the same shape `risk` and `approval.fail_on_error` already use. A
present-but-empty `approval.endpoint_url` is likewise reported as empty rather
than as absent. Rejected values are never echoed back; only their kind is named.

### Disabled instances

`enabled: false` short-circuits the constructor: the plugin buffers nothing and
inspects nothing, and the *values* of the remaining keys are never parsed. A
disabled draft may therefore carry values this table would otherwise reject —
`mode: 7`, `tools: null`, an out-of-range `deny_status_code` — and still be
admitted.

Property **names** are the exception. Unknown-key rejection runs *before* the
short circuit, at every fixed-shape layer including nested ones, so
`{"enabled": false, "inspect": {"typo": true}}` is rejected even though the
instance is off. That is deliberate: a typo in a disabled draft must not stay
hidden until the reload that flips `enabled: true` and silently drops an
enforcement control.

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
correlation, consumer/proxy/model/provider, tool name, arguments hash, and risk,
plus `principal` — the authority-qualified caller: `{"kind":"consumer",
"namespace","id"}` for a mapped Consumer, or `{"kind":"external","subject",
"mechanism","authority"}` for an external identity, where `authority` is the
opaque hex digest of the verifying authority (it reveals no issuer or URL). The
display `consumer` field alone cannot distinguish the same subject issued by two
accepted authorities; `principal` can.
Request correlation prefers private canonical state from the built-in
`correlation_id` plugin. On custom-only chains it falls back to transaction
metadata `request_id`, then legacy `correlation_id`; canonical state always wins
over either plugin-writable compatibility key.
`approval.timeout_ms` defaults to 1500 and may not exceed 30000. A single
governed batch resolves its approvals with at most **8 webhook calls in
flight** (parallel tool calls cost about one round trip, not one per call),
waits at most 30s in total for approvals, governs at most 64 concrete calls,
starts no further webhook call after an enforce-mode block (calls already in
flight complete and are recorded), and cancels in-flight approval HTTP calls
when the governing future is dropped (client cancel). Identical calls reuse the
cached decision for `cache_ttl_seconds` — within one batch they share a single
resolution, like a cache hit; the cache key covers consumer, **principal**,
proxy, model, **provider**, tool name, and arguments (every field the webhook
receives that can change its decision), so equal subject strings verified by
different authorities never share a decision. For streamed and buffered-SSE responses the model/provider come from
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
`tool_names`, `risk` (the maximum within the winning decision rank; see
below), `policy_ids` (the governing `tools` key — the glob itself for a glob
match), `approval_id`, `arguments_hashes`
(SHA-256, when `hash_arguments` is on), `redacted_tools`, and
`uninspectable_reason` (fixed values only, never raw body bytes):

- `ambiguous_json` — recorded when global `mode: dry_run` observes
  duplicate-key ambiguity without blocking.
- `unrecognized_tool_call_shape` — recorded when a payload carried an
  unreadable tool-call shape, in **both** modes and under **both**
  `unknown_shape_action` settings. The observation itself never sets
  `decision`; a forwarding outcome leaves any decision to other surfaces,
  while the default enforce rejection records `decision = deny` as the
  rejection outcome.

**Bounded observation ledgers.** The comma-delimited cumulative fields —
`tool_names`, `policy_ids`, `approval_id`, `arguments_hashes`, and
`redacted_tools` — are aggregated by winning decision rank across the governed
surfaces of one request and the completed batches of one response stream: a
lower-rank batch is ignored, an equal-rank batch merges into the retained
ledger, and a stronger batch replaces the weaker decision's ledger basis.
`risk` follows the same rule — it is the maximum within the winning decision
rank, so a stronger decision replaces the previous rank's risk even when that
risk was higher. Each ledger is explicitly
bounded: at most **64 distinct values** (matching the 64-call per-batch
governable limit) and at most **8192 UTF-8 bytes** per field, with each
individual value retained to at most **256 UTF-8 bytes** plus a trailing `…`
when it was shortened. The entry and byte ceilings are **independent**, so even
one admissible 64-call batch can exhaust the 8192-byte budget: 64 tool names at
the full 256-byte per-value width plus the 63 delimiter bytes total 16,447 CSV
bytes, so the ledger retains only the first 31 names and counts the remaining 33
as omitted. A single well-formed batch therefore does **not** guarantee complete
metadata; `ai_tool_governor.observations_omitted` is the completeness indicator.
A stream that keeps emitting batches of distinct tool names cannot grow this
state without limit — the documented `0` (unlimited) response-byte policy
leaves no wire-byte ceiling that could serve as the bound. Values are
deduplicated, and order of first observation is preserved.

When a ledger is full, further distinct values dropped by an entry or byte
cap during a merge are counted in `ai_tool_governor.observations_omitted`
(absent when nothing was dropped; rank-displaced observations are not counted)
so a capped field is never silently short. Truncation changes nothing about
enforcement: every tool call is still governed, the highest-severity `decision`
and the winning rank's maximum `risk` are still recorded, and a higher-severity batch replaces
a weaker decision's ledger basis — still under the same entry and byte ceilings,
so the replacement is bounded too and can also omit values counted in
`observations_omitted`.

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
> still cut the stream and emit sampled warnings (one per source site per
> 10 seconds with suppressed-event counts); every detail remains at `debug`.

## Composition

- **`ai_semantic_firewall`** — the semantic firewall catches *intent* (prompt
  injection, tool-abuse language, exfiltration). `ai_tool_governor` enforces
  *deterministic* tool/action policy on the concrete call. Run both: the
  firewall (2968) evaluates the prompt/response text; the governor (2978)
  gates the specific tool name and arguments.
- **`ai_stream_router`** — composition is a **stage** relationship, not a
  priority one. Response-stream inspectors are sorted by
  `ResponseStreamInspectorStage`, and every `ai_stream_router` normalizer
  declares `Normalize`, which sorts before this plugin's default `Inspect`. So
  with a router present the governor inspects the **normalized** OpenAI chunks
  the client will receive, and without one it reads the provider-native frames
  directly. The request-side priorities (`2978` vs `2984`) do not order these
  inspectors.
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
- A JSON-labelled **response** body that is malformed JSON is forwarded (no
  parser reads a tool call out of it) — rejecting every unparseable JSON
  response on a shared proxy would break unrelated routes. Oversized responses,
  and well-formed JSON beyond the inspection parser's nesting/numeric limits,
  fail closed.
- **Provider scope is explicit, not universal.** Buffered tool calls and
  definitions are read in the OpenAI (Chat Completions and Responses),
  Anthropic Messages, Google Gemini, Cohere v2, and Amazon Bedrock Converse
  shapes. **Streaming SSE accumulation is narrower than the buffered set** — it
  covers exactly the five dialects in the `streaming_response_tool_calls` row
  of the inspection table (OpenAI Chat Completions, OpenAI Responses,
  Anthropic, Cohere v2, Google); see the Bedrock bullet below. A dialect
  outside that set is not silently allowed: if the payload carries a tool-call
  marker the plugin cannot resolve into a call, `unknown_shape_action` (default
  `deny`) fails closed and the fixed `unrecognized_tool_call_shape` observation
  is recorded either way. A dialect that names its tool calls with none of the
  documented marker members and none of the marker `type` values would still
  read as call-free; open an issue with the wire shape so it can be added.
- **Bedrock streaming is buffered-only.** Bedrock
  `InvokeModelWithResponseStream` uses the binary
  `application/vnd.amazon.eventstream` framing rather than SSE text, so it is
  never parsed as a stream; a Bedrock Converse response delivered as a buffered
  JSON body is governed normally. Those bytes are neither SSE-shaped nor
  JSON-shaped, so on a stream-marked governed request they take the opaque
  path: held in full and cut at end-of-stream in enforce, released unchanged in
  dry-run.
- **OpenAI Responses governance covers `function_call` items only.** Other
  Responses tool item types (`custom_tool_call`, `computer_call`,
  `local_shell_call`, hosted-tool calls) are outside the buffered and streaming
  extractors alike.
- The unknown-shape posture is scoped to a positive tool-call marker. It does
  not attempt to decide whether an arbitrary body "is an AI response", so a
  provider dialect with no recognizable marker is out of scope in both
  settings.
- The plugin governs tool calls; it does not execute tools, manage MCP sessions,
  or replace `mcp_gateway`/A2A routing.
- Streaming inspection is transport-independent across reqwest, direct HTTP/2,
  and native HTTP/3 response arms. `forces_reqwest_dispatch` remains a scoped
  optimization for requests already known to stream, while final request-body
  transforms are reflected in both dispatch and response buffering decisions.
