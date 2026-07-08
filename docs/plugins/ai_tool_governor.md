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
  `ai_semantic_cache` (2980) and `ai_federation` (4060, Response band), so
  disallowed tool schemas are screened before caching or federation routing. Set
  `priority_override` (e.g. `2994`, just after `a2a_gateway`) if you want to
  consume MCP/A2A metadata emitted by `mcp_gateway`/`a2a_gateway` first — that
  still runs well before `ai_federation`.
- **Protocols:** HTTP family (HTTP/1.1, HTTP/2, HTTP/3). Raw WebSocket frame
  tools are out of scope for the MVP.
- **Failure policy:** `FailClosed`.

## Inspection surfaces

Each is toggled independently under `inspect`; at least one must be enabled.

| Surface | Default | What it governs |
| --- | --- | --- |
| `request_tool_definitions` | `false` | Tool definitions the client exposes to the model (`tools[].function.name`, `functions[].name`). A disallowed definition is rejected/dry-run. |
| `response_tool_calls` | `true` | Buffered response tool calls (`choices[].message.tool_calls[]` and legacy `choices[].message.function_call`). |
| `streaming_response_tool_calls` | `false` | OpenAI SSE `choices[].delta.tool_calls` deltas and legacy `choices[].delta.function_call` (`functions` API) deltas, reassembled across frames. |
| `mcp_tool_calls` | `false` | MCP JSON-RPC `tools/call` request bodies (`params.name` + `params.arguments`), including calls inside JSON-RPC **batch arrays**. |
| `a2a_methods` | `false` | A2A JSON-RPC method names (governed against the `tools` map), including batch arrays. |

For **streaming**, tool-call SSE frames are **held** (not forwarded) until the
call is complete and cleared by policy/approval, then the held frames are
released; on a block the stream is **cut with a terminal SSE error event** and
the held frames are dropped — the disallowed call never reaches the client.
Ordinary content/role deltas stream through live. With multi-choice (`n > 1`)
streams, a batch is finalized only once **every** choice holding tool calls has
reported a `finish_reason` (or the stream ends), and later tool-call deltas
form a new, independently governed batch. The plugin detects `"stream": true`
in JSON POST bodies and pins those requests onto the reqwest dispatch path
where the SSE inspector is wired, so a client-sent streaming request cannot
bypass streaming inspection by targeting a direct HTTP/2 or native HTTP/3
backend; the narrow proxy-core edge cases where a response can still stream on
an uninspected arm are described under [Limitations (MVP)](#limitations-mvp).
Requests marked streaming still buffer a plain-JSON fallback
response so `tool_calls` in it are governed (only a genuine
`text/event-stream` response is released back to the stream path).

**Response buffering on governed requests:** when this plugin governs response
tool calls for a request, a 2xx response with a **missing or non-JSON
`Content-Type`** is **buffered and inspected**, not streamed — a transform
chain can relabel `Content-Type` while the body is still Chat Completions
JSON, so ambiguous labels are treated fail-closed and run through the
JSON-shape fallback. Only two response labels are released back to the
streaming path: a genuine `text/event-stream` (governed by the SSE stream
inspector, or by buffered-SSE governance if another plugin keeps it buffered)
and framed gRPC / gRPC-Web content types (owned by the gRPC machinery, out of
this plugin's scope). Operators should expect mislabeled or unlabeled
responses on governed routes to be delivered buffered rather than streamed.

## Fail-closed handling of uninspectable bodies

In `mode: enforce`, a body the plugin is configured to govern but cannot
inspect is **rejected** (with `response.deny_status_code`) rather than
forwarded ungoverned:

- **Request path** (when any request surface is enabled, for JSON `POST`
  bodies): a `Content-Encoding`d body (request decompression runs in later
  body-transform hooks, so it is opaque here), a body larger than **4 MiB**, a
  non-UTF-8 body, or a body that does not parse as JSON despite a JSON
  content-type.
- **Response path** (when `response_tool_calls` is enabled): a 2xx JSON
  response body larger than **4 MiB** (padding must not smuggle tool calls
  past the parse limit).
- **Streaming path**: held tool-call frames plus the partial-event carry are
  capped at **4 MiB**; past that the stream is cut with the terminal SSE error
  event.

In `mode: dry_run` these bodies are forwarded uninspected (and a stream past
the hold cap is released uninspected) — dry-run never disrupts traffic.

## Actions

Per tool (`tools.<name>.action`): `allow`, `deny`, `redact_args`,
`require_approval`, `dry_run`. `default_action` (`allow` / `deny` /
`require_approval`) applies to any tool without an explicit entry.

Argument checks (`max_arg_bytes`, `required_args`, `json_schema`,
`blocked_arg_patterns`) apply to the `allow`, `require_approval`, and
`redact_args` actions. A blocked-pattern match denies under
`allow`/`require_approval`, and is **redacted** under `redact_args` (buffered
path). On paths where arguments cannot be redacted in place — the **streaming**
path, the **request** body (no request-body transform), and the post-transform
**final response** re-check — a `redact_args` match fails closed rather than
forwarding an unredacted secret.

A per-tool **`dry_run`** action is purely observational: it forwards the call
and records the decision, and is evaluated **before** the argument checks
above, so it never rejects — even for oversized args, a failing schema, or a
blocked pattern. Use it to measure what a stricter action *would* do before
enforcing. (This differs from global `mode: dry_run`, which makes every action
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
returned as a call — is rejected with `502`.

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
    include_prompt_excerpt: false
```

`filesystem.write` calls are POSTed to the approval webhook with request
correlation, consumer/proxy/model/provider, tool name, arguments hash, and risk.
Identical calls reuse the cached decision for `cache_ttl_seconds`; the cache
key covers consumer, proxy, model, **provider**, tool name, and arguments (every
field the webhook receives that can change its decision), and the cache is
bounded at 4096 entries — at capacity expired entries are purged and new
decisions are simply not cached. When the endpoint is unreachable,
`fail_on_error: reject` blocks the call (`warn`/`allow` fail open).

The webhook returns `{"decision":"allow"|"deny"}` (or `{"allow":true|false}`),
optionally with `{"approval_id":"..."}`.

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
`enforce`.

## Observability metadata

When `observability.emit_metadata` is on (default), the plugin writes
`ai_tool_governor.*` transaction metadata: `enabled`, `mode`, `decision`
(`allow` / `deny` / `require_approval` / `approved` / `approval_denied`),
`tool_names`, `risk` (max), `policy_ids`, `approval_id`, `arguments_hashes`
(SHA-256, when `hash_arguments` is on), and `redacted_tools`.

Raw arguments are **never** placed in metadata and never logged unless
`observability.max_argument_log_bytes > 0` (then a bounded excerpt of a blocked
call's arguments is logged at `debug` for audit). Raw arguments are sent to the
approval webhook only when `approval.include_prompt_excerpt: true`.

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
  `mcp_gateway` being present.

## Limitations (MVP)

- Streaming `redact_args` fails closed (cuts the stream) rather than redacting
  split-JSON arguments mid-flight.
- Held streaming tool-call frames are released together at each batch's
  completion boundary (all tool-call-holding choices finished); content deltas
  stream through live in the meantime.
- Request-path governance is scoped to JSON `POST` bodies (the shape OpenAI,
  MCP, and A2A traffic uses). Framed gRPC / gRPC-Web requests — including the
  `application/grpc+json` / `application/grpc-web+json` variants, whose bodies
  are length-prefixed wire frames rather than a bare JSON document — are out
  of scope on a mixed proxy, not buffered or rejected.
- A JSON-labelled **response** body that fails to parse is forwarded (only
  oversized responses fail closed) — rejecting every unparseable JSON response
  on a shared proxy would break unrelated routes.
- The plugin governs tool calls; it does not execute tools, manage MCP sessions,
  or replace `mcp_gateway`/A2A routing.
- Streaming inspection rides the proxy's reqwest dispatch arm (the same
  mechanism `ai_semantic_firewall` uses): governed streaming requests are pinned
  to it via `forces_reqwest_dispatch`, but a response streamed on the direct
  HTTP/2 or native HTTP/3 arm is not inspected. Two proxy-core gaps remain:
  a `request_transformer` that **adds** `stream: true` after the dispatch
  decision on an HTTP/3-classified backend, and a request that stages no JSON
  body whose backend nevertheless answers with tool-call SSE. Neither is
  client-controllable against real AI providers — a client-sent `stream: true`
  JSON POST is detected and pinned, and OpenAI/Anthropic/Gemini-shaped backends
  do not emit tool-call streams for bodyless requests. Buffered responses and
  reqwest-arm SSE are always governed. Shared proxy-core follow-up:
  [#2055](https://github.com/ferrum-edge/ferrum-edge/issues/2055).
