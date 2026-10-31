# a2a_gateway

Part of the [Plugin Reference](../plugins.md).

**Priority:** 2993 · **Phases:** `before_proxy`, `on_final_request_body`, `after_proxy`, `normalize_response_body`, `on_response_body`, `transform_response_body`, `on_final_response_body`, `response_stream_inspector`, `on_response_stream_terminated` · **Protocols:** HTTP, gRPC · **Failure policy:** `FailClosed`

Transparent Agent-to-Agent gateway for standardized A2A traffic over HTTP/HTTPS JSON-RPC, HTTP+JSON/REST, and gRPC/grpcs. The plugin detects A2A operations, applies optional method allow/deny policy, rewrites HTTP Agent Card endpoint URLs to the Ferrum gateway, preserves SSE and gRPC streaming pass-through, and emits `a2a.*` metadata for existing Ferrum authz, logging, tracing, chargeback, and alert plugins.

The implemented A2A protocol version is **0.3.x**, whose canonical gRPC service is **`a2a.v1.A2AService`**. A2A 1.0 (`lf.a2a.v1.A2AService`) is a distinct identity with a renumbered `AgentCard`; it can be detected and policed, but its cards are never decoded as 0.3 — see *gRPC service identity and Agent Card schema* below.

The plugin deliberately does not manage task state, aggregate multiple agents, or implement generic auth, rate limiting, retry, timeout, WAF, tracing, DLP, or semantic safety behavior. Use the existing Ferrum plugins for those concerns.

Unknown keys at the root and in nested fixed-shape objects (`endpoint`, `detection`, `discovery`, `observability`, `policy`, each `policy.methods` entry, and `endpoint.grpc_services` object entries) are rejected at construction. A typo such as `not_a_real_a2a_key` fails closed instead of becoming a silent no-op. Registration is `FailClosed`.

```yaml
plugin_name: a2a_gateway
scope: proxy
config:
  enabled: true
  mode: transparent_proxy
  endpoint:
    path: /a2a
    agent_card_path: /.well-known/agent-card.json
    protocol_versions: ["0.3.0"]
    grpc_services:
      # Canonical A2A 0.3 service (package `a2a.v1`) — card schema `a2a-0.3`.
      - a2a.v1.A2AService
      # A custom service fronting an A2A 0.3 backend must say so explicitly.
      - service: acme.agents.v1.AgentService
        card_schema: a2a-0.3
  detection:
    bindings: [jsonrpc, rest, grpc]
    version_header: A2A-Version
    max_request_body_size: 1048576
    allow_unknown_methods_with_version_header: true
    strip_accept_encoding: true
  discovery:
    rewrite_agent_card_urls: true
    public_base_url: https://agents.example.com
    trust_forwarded_headers: false
    allowed_public_origins: []
  observability:
    emit_metadata: true
    log_payloads: false
    max_payload_size: 1048576
  policy:
    default_action: allow
    methods:
      tasks/pushNotificationConfig/set:
        action: deny
```

**Configuration reference.** Every accepted key, with the domain the constructor
actually admits. Anything not listed is rejected at construction, at the root and
inside each nested object. **`null` is accepted wherever a value is optional and
means exactly the same thing as omitting the key** — the one exception is
`discovery` itself, which is effectively required because rewriting defaults to
enabled (see *Public origin admission* below), plus
`endpoint.grpc_services[].service` and `policy.methods.<name>.action`, which are
required and reject `null`.

| Key | Type | Default | Accepted values and constraints |
| --- | --- | --- | --- |
| `enabled` | boolean | `true` | `false` makes the instance inert; it still contributes to replay provenance. |
| `mode` | string | `transparent_proxy` | Only `transparent_proxy` in V1. |
| `endpoint.path` | string | `/a2a` | Non-empty absolute path beginning with `/`. The JSON-RPC endpoint, the REST prefix, and the policy scope. |
| `endpoint.agent_card_path` | string | `/.well-known/agent-card.json` | Non-empty absolute path beginning with `/`. Matched as a **suffix** of the request path, so `/agents/planner/.well-known/agent-card.json` is in scope. |
| `endpoint.protocol_versions` | string array | `["0.3.0"]` | Non-empty list; every entry must be non-empty and not whitespace-only. Compared as **exact** strings after trimming — no family, range, or wildcard syntax. |
| `endpoint.grpc_services` | array | `["a2a.v1.A2AService", "lf.a2a.v1.A2AService"]` | Non-empty list of either a service-name string or `{service, card_schema}`. Names are dot-separated gRPC identifiers (`[A-Za-z_][A-Za-z0-9_]*`). Duplicate service names are rejected, as is a `card_schema` contradicting a published A2A service name. |
| `endpoint.grpc_services[].card_schema` | string | published layout, else `none` | `a2a-0.3`, `a2a-1.0`, or `none`. |
| `detection.bindings` | string array | `[jsonrpc, rest, grpc]` | Non-empty. Three bindings, six accepted spellings: `jsonrpc` (alias `json-rpc`), `rest` (aliases `http_json`, `http+json`), and `grpc`. Aliases normalize to the canonical name, so listing a binding twice under two spellings is accepted and deduplicates. |
| `detection.version_header` | string | `A2A-Version` | Non-empty, valid HTTP field name. |
| `detection.max_request_body_size` | integer (uint64) | `1048576` | `0` **disables** the plugin-level detection size check entirely; any other value is the byte ceiling above which a JSON-RPC candidate is not parsed. Negative and non-integer values are rejected. |
| `detection.allow_unknown_methods_with_version_header` | boolean | `true` | Treats a version-header-bearing JSON-RPC request as A2A even when the method is unknown; metadata still records `unknown`. |
| `detection.strip_accept_encoding` | boolean | `true` | Removes `Accept-Encoding` (and `grpc-accept-encoding` for gRPC card requests) on requests whose response the plugin may parse or rewrite. It controls compression negotiation only — Agent Card discovery works identically with it disabled. `true` marks request headers mutable for all traffic on the proxy. |
| `discovery.rewrite_agent_card_urls` | boolean | `true` | `false` is explicit passthrough and also disables the protobuf card schema gate. |
| `discovery.public_base_url` | string | none | Absolute `http`/`https` URL, at most 4096 bytes, with an explicit `://` authority, no ASCII whitespace or control characters, no credentials, no query, and no fragment. An intended base path is preserved. The **canonicalized** form is what gets published (see *Public origin admission*). |
| `discovery.trust_forwarded_headers` | boolean | `false` | Derives the origin from `X-Forwarded-Proto` / `X-Forwarded-Host` / `Host`; requires a non-empty `allowed_public_origins` when rewriting is on and no public base is configured. With no `X-Forwarded-Proto`, the scheme is `https` exactly when the client connection is secure (TLS, or HTTP/3) — never inferred from whether the client sent TLS SNI. |
| `discovery.allowed_public_origins` | string array | `[]` | Absolute `http`/`https` origins only — scheme, host, optional port; no paths, credentials, queries, or fragments. Compared after origin normalization. |
| `observability.emit_metadata` | boolean | `true` | Emits the `a2a.*` metadata keys and enables response buffering for metadata extraction. |
| `observability.log_payloads` | boolean | `false` | Copies bounded response payloads into `a2a.payload.response` verbatim. Has no effect unless `emit_metadata` is also `true`. |
| `observability.max_payload_size` | integer (uint64) | `1048576` | Must be **greater than zero** — `0` is rejected, it is not an "unlimited" spelling. Caps payload logging and retained semantic metadata, never the response buffer. |
| `policy.default_action` | string | `allow` | `allow` or `deny`. |
| `policy.methods` | object | `{}` | Keys are canonical A2A method names, the literal `unknown`, or a PascalCase gRPC/REST alias. Two keys that canonicalize to the same method (`tasks/get` and `GetTask`, or `SubscribeToTask` and `TaskSubscription`) are a duplicate and are rejected. |
| `policy.methods.<name>.action` | string | required | `allow` or `deny`. |
| `policy.methods.<name>.allowed_groups` | string array | none | Requires `action: allow`. Grants the method only to a request whose gateway-mapped Consumer holds at least one of these `acl_groups`. Non-empty, at most 512 entries, each non-blank, at most 255 bytes, no control characters other than tab/LF/CR; matched byte-for-byte. |
| `policy.methods.<name>.denied_groups` | string array | none | Requires `action: allow`. A Consumer holding any of these groups is refused the method, even when it also holds an allowed group. Same entry rules; must not share a group with `allowed_groups`. |

**Method policy is decided on the backend-visible body.** For the JSON-RPC
binding the operation lives in the request body, and request-body transformers
run after the arrival-time classification, so the policy is re-decided in the
final request-body phase over the exact representation that will be dispatched.
A method a later transformer substituted is refused there, with the same
response shape the arrival-time refusal uses. REST and gRPC carry the operation
in the request path and are unaffected. An observability-only configuration — no
`deny` anywhere — takes no enforcement decision and does not claim the finalized
representation.

The arrival-time classification also decided how the response is handled —
whether it is buffered, whether it is an Agent Card to rewrite (and whether a
public origin was admitted for it), and whether it streams. A finalized body
whose method changes Agent Card or streaming class (for example a
`request_transformer` rule that turns `tasks/get` into `agent/getCard`) is
therefore refused before dispatch with JSON-RPC `-32001` ("A2A operation changed
after gateway admission", `a2a.error: operation_class_changed`) whenever card
rewriting or metadata depends on that class, instead of being served under
response handling built for a different operation. A same-class method change is
admitted and refreshes `a2a.method` (and `a2a.task_id`, which is removed when
the new envelope carries no task hint). A finalized body of an admitted
JSON-RPC request that can no longer be classified at all — grown past
`detection.max_request_body_size` (HTTP `413`, JSON-RPC `-32013`) or no longer a
JSON document (`-32001`, `a2a.error: operation_class_unprovable`), or a batch
with a member the classifier does not recognize (every request member answered
`-32001`) — is refused
the same way while card rewriting or metadata is enabled; raise
`detection.max_request_body_size` (or set it to `0`) if transforms legitimately
grow bodies past it. A finalized body byte-identical to the one
classified at arrival is not re-parsed, and an instance with no deny rule, no
card rewriting, and no metadata skips the final-body hook entirely.

**Per-consumer method grants.** An `allow` entry in `policy.methods` may carry
`allowed_groups` and/or `denied_groups`, matched against the request's
gateway-mapped Consumer `acl_groups` (resolved by the authentication phase, so
pair it with an auth plugin that maps Consumers). The method is granted iff a
mapped Consumer is present, it holds none of `denied_groups` (which takes
precedence), and `allowed_groups` is absent or it holds at least one of them. A
request with no mapped Consumer is never granted a group-conditioned method.
An ungranted method is refused exactly like a `deny` rule — JSON-RPC `-32001`,
REST `403`, gRPC `PERMISSION_DENIED` — and the grant is re-decided over the final
backend-visible JSON-RPC body. A group-conditioned entry counts as a deny-capable
rule, so it also enables the fail-closed in-scope classification described
below. For example, partner agents may send messages while only internal
consumers may cancel tasks:

```yaml
policy:
  methods:
    message/send:
      action: allow
      allowed_groups: [partner-agents, internal-agents]
    tasks/cancel:
      action: allow
      allowed_groups: [internal-agents]
```

**Batch refusals answer every request member.** A JSON-RPC batch containing a
denied member is refused as a whole and no member is dispatched, so the response
array carries one Response object per non-notification member, in wire order,
preserving each `id`'s exact JSON type and value. The member the policy named
carries the specific refusal and its canonical method; the others carry the same
error code with a batch-level reason, because they were never evaluated
individually. Notification members (no `id`) are correctly unanswered, as
[JSON-RPC 2.0 §6](https://www.jsonrpc.org/specification#batch) requires. A batch
with more than 1024 members is refused with the single-response shape carrying
`"truncated": true` instead of being enumerated; the default
`detection.max_request_body_size` puts that far above any reachable batch.

**Multiple instances.** Two `a2a_gateway` instances may be attached to one proxy.
Detection is per instance and so is the response phase: the instance whose
endpoint, discovery, or gRPC-service scope matched the request owns it, and a
sibling whose scope did not match neither buffers the response, nor captures
payloads under its own `observability` settings, nor rewrites the Agent Card to
its own public base. Request-phase method policy still runs independently in
every instance whose scope matched.

JSON-RPC detection parses `POST endpoint.path` requests with JSON content and recognizes current PascalCase A2A methods such as `SendMessage`, `SendStreamingMessage`, `GetTask`, `ListTasks`, `CancelTask`, `SubscribeToTask`, push-notification config methods, and Agent Card methods. Legacy slash-style method names such as `message/send` are also accepted and normalized to canonical `a2a.method` values for policy and metadata. When a JSON-RPC request exceeds `detection.max_request_body_size`, the plugin fails closed if `policy.default_action: deny` or any per-method deny rule is configured; otherwise it skips detection for observability-only deployments. REST detection matches standard A2A paths under `endpoint.path`, such as `/a2a/message:send`, `/a2a/message:stream`, `/a2a/tasks/{id}`, `/a2a/tasks/{id}:cancel`, `/a2a/tasks/{id}:subscribe`, `/a2a/tasks`, `/a2a/extendedAgentCard`, optional tenant-prefixed forms such as `/a2a/{tenant}/message:send`, the legacy `/a2a/v1/...` form, plus the configured Agent Card discovery suffix. gRPC detection matches configured services — `a2a.v1.A2AService` and `lf.a2a.v1.A2AService` by default — and maps RPC names (`SendMessage`, `SendStreamingMessage`, `GetTask`, `CancelTask`, `TaskSubscription`/`SubscribeToTask`, push-notification config RPCs, `GetExtendedAgentCard`) to canonical A2A method names.

When policy has `default_action: deny`, any per-method deny rule, or any group-conditioned `allow` rule, every request within `endpoint.path` (at a path-segment boundary), the configured discovery suffix, or a configured gRPC service must be classified before forwarding. Unrecognized payloads, methods, paths, and disabled bindings in that scope are refused; an `unknown: allow` rule does not waive failed inspection. Known JSON-RPC methods, including every member of a batch, still receive their own method policy. An observability-only configuration with no deny rules continues forwarding unrecognized requests. Unrelated sibling paths and services remain outside this policy scope.

REST `POST /a2a/tasks` (including `/a2a/v1/tasks`) is unclassified: A2A sends messages and creates tasks through `POST /a2a/message:send`, while `GET /a2a/tasks` lists tasks. The unsupported POST continues only without a deny policy; within a policy-protected scope it fails closed even if `tasks/list`, `message/send`, or `unknown` is allowed.

**gRPC service identity and Agent Card schema.** A gRPC service *name* and an `AgentCard` wire *layout* are two different facts, and A2A has published two of each. A2A **0.3** — the protocol version this plugin implements, and the default `endpoint.protocol_versions` — declares `package a2a.v1` in `specification/grpc/a2a.proto` (`a2aproject/A2A` at tag `v0.3.0`), so its canonical service is **`a2a.v1.A2AService`**, the primary default `endpoint.grpc_services` entry. A2A **1.0** declares `package lf.a2a.v1` with a materially renumbered `AgentCard`, so **`lf.a2a.v1.A2AService`** is a different identity carrying a different card layout. It is also recognized by default to preserve method-policy enforcement for deployments that relied on the former default; its cards remain schema-gated and are never decoded as 0.3. The gateway never infers one from the other.

Each `endpoint.grpc_services` entry therefore has a declared card schema, in one of two spellings:

| Entry | Declared schema | Effect |
| --- | --- | --- |
| `a2a.v1.A2AService` (string) | `a2a-0.3` | Detected, policed, and Agent Card rewriting is implemented. |
| `lf.a2a.v1.A2AService` (string) | `a2a-1.0` | Detected and policed; card rewriting fails closed with `agent_card_grpc_schema_unsupported`. |
| any other name (string) | `none` | Detected and policed; card rewriting fails closed with `agent_card_grpc_schema_undeclared`. |
| `{service: <name>, card_schema: a2a-0.3 \| a2a-1.0 \| none}` | as declared | The explicit form a custom deployment uses to state which published layout its own service serves. |

The two published names have a schema fixed by the specification, so declaring a *contradicting* `card_schema` for one is rejected at config admission rather than honored as an override — the layout is a property of the protocol, not of the deployment. Restating the correct one is accepted and is a no-op. A custom service with no declared schema still gets full detection, method policy, and `a2a.*` metadata; only protobuf card rewriting is withheld. To front a custom or A2A 1.0 service whose cards must pass through untouched, set `discovery.rewrite_agent_card_urls: false` — with rewriting enabled, such a card is refused rather than served with un-rewritten internal URLs.

Agent Card rewriting includes every card in a detected JSON-RPC batch, even when another operation precedes it. Cards whose URLs already match keep their original bytes and signatures; signatures are removed only when a URL changes. Agent Card rewriting applies to buffered HTTP JSON Agent Card responses and to unary gRPC Agent Card responses (`GetAgentCard` / `GetExtendedAgentCard`) for detected Agent Card requests. It rewrites every advertised interface on a transport the gateway fronts: `JSONRPC` (or no transport) and `HTTP+JSON` / `REST` URLs become the public gateway base plus `endpoint.path` (the JSON-RPC endpoint and the REST prefix), and `GRPC` URLs become the public gateway base itself (gRPC addresses `/<service>/<method>` on the origin). The top-level `url` follows `preferredTransport` the same way. Interfaces on any other transport keep the backend's URL. Existing `signatures` are removed because rewritten fields invalidate card signatures. Before this, `GRPC` and `HTTP+JSON` interface URLs were preserved, which published the agent's direct addresses to every discovery client. gRPC rewriting decodes the A2A **0.3.x** protobuf Agent Card wire layout only, mutates only the supported endpoint fields, and re-frames an uncompressed unary response.

Only a **proven-successful** unary reply is treated as a candidate Agent Card: the response must be HTTP `200` *and* carry a terminal `grpc-status` of exactly `0`. On the buffered native-gRPC path plugins see a merged header+trailer view in which the trailing value wins for the reserved terminal keys, so an upstream that streamed `HEADERS(200) + DATA + TRAILERS(grpc-status: 13)` is recognized as the failure it is. An unproven reply — including one with no terminal status at all — is forwarded exactly as the upstream wrote it: it is neither rewritten nor failed closed, so a backend error is never relabelled as a gateway rewrite fault.

Before any byte of a candidate card is interpreted, the **responding service must be declared to carry the `a2a-0.3` layout**. A decoder is chosen by the protocol the endpoint speaks, never by whichever layout the bytes could be coerced into: an `lf.a2a.v1.A2AService` reply is refused with `agent_card_grpc_schema_unsupported` and an undeclared custom service with `agent_card_grpc_schema_undeclared`, neither of which is a complaint about the card's own `protocol_version`.

Once the service's layout is settled, the version gate is **positive and exact**, and has two independent requirements. First, the card must carry an explicit `protocol_version` (field 16) on the wire whose trimmed value equals an entry of `endpoint.protocol_versions`. That list is a set of exact version strings — there is no family, range, or wildcard syntax — so configuring `["0.3.0"]` admits `0.3.0` and refuses `0.3.99`; admitting another point release means listing it. Second, the matched version must belong to the A2A **0.3** family, which is the only wire layout this rewriter implements: a configured `1.0.0` that a backend echoes back is an exact match and is still refused. **A card with an absent or empty `protocol_version` fails closed** — it is not assumed to be 0.3.x even when `endpoint.protocol_versions` says so. A2A renumbered `AgentCard` for 1.0 (field 3 became `supported_interfaces`, `signatures` moved from 17 to 13, field 14 became `icon_url`, and `protocol_version` was removed), and proto3 cannot distinguish an unset field from an empty string, so an empty version is the exact case where the gateway cannot tell the two layouts apart. Rewriting it with 0.3 field numbers would flatten each interface into a bare URL and re-serve the card under its now-invalid original signature, so the plugin refuses instead.

An admitted card is then **schema-validated before any field is rewritten**, over the complete A2A 0.3 top-level `AgentCard` field table (`a2aproject/A2A` at tag `v0.3.0`). Three properties are enforced for every one of the seventeen known top-level fields:

- **Wire type.** Length-delimited for every string, submessage, map entry, and repeated string — `name` (1), `description` (2), `url` (3), `provider` (4), `version` (5), `documentation_url` (6), `capabilities` (7), `security_schemes` (8), `security` (9), `default_input_modes` (10), `default_output_modes` (11), `skills` (12), `preferred_transport` (14), `additional_interfaces` (15), `protocol_version` (16), and `signatures` (17) — and a varint for the one boolean, `supports_authenticated_extended_card` (13), whose value must additionally be a canonical `0` or `1`. A known field with an unexpected wire type would otherwise fall through the rewriter's catch-all and be preserved verbatim beside rewritten siblings after the signature block was dropped.
- **Multiplicity.** Every singular field may appear at most once; a duplicate fails closed, because proto3 last-wins semantics would let a backend hide the URL that actually gets served behind a decoy earlier in the message. The genuinely repeated fields (8, 9, 10, 11, 12, 15, 17) may of course repeat.
- **UTF-8 for every known string that is re-emitted** — `name`, `description`, `version`, `documentation_url`, `default_input_modes`, `default_output_modes`, `preferred_transport`, and `protocol_version`. These are copied into the rebuilt card, so a value the gateway cannot represent as text is not republished as though it had been inspected.

`AgentCard.url` (3) is held to a stronger proof: it must parse as an absolute `http`/`https` URL with a real host and no embedded credentials, bounded to 4096 bytes and free of ASCII whitespace and control characters. A prefix test would not do — `https://`, `https://:8080/a2a`, and `http://` followed by a control character all begin with those bytes without being a URL, and a serialized `AgentInterface` (which is what field 3 holds in the A2A 1.0 layout) is frequently valid UTF-8, so this check is what actually distinguishes a URL string from a submessage. A value that fails it is treated as a layout mismatch. The proof requires an explicit canonical authority spelling before any path, query, or fragment — forms such as `http:///a2a`, where WHATWG recovery would infer a host only after consuming an extra slash, are rejected because hostile wire input can be consumed by parsers with different recovery rules.

**Where the validation boundary is.** The opaque submessages this rewriter deliberately preserves — `provider`, `capabilities`, each `security_schemes` map entry, each `security`, each `skills`, and each `signatures` — are checked for wire type and multiplicity **only**. Their contents are never decoded, and the gateway makes no claim that they are well formed. The single nested exception is `additional_interfaces`, which the rewriter itself parses and can mutate: each `AgentInterface` is validated for wire type and multiplicity on `url` (1) and `transport` (2), and its `url` is **required** and held to the same absolute-URL proof. An interface with a missing URL is not a usable endpoint — it could never be the JSON-RPC endpoint the gateway fronts, so it would be preserved untouched inside a card published as rewritten with its signatures removed, while also being the only thing that made the card look like it advertised an endpoint at all — so it fails closed with `agent_card_protobuf_interface_url_missing`. Unknown fields with any valid wire type are preserved untouched, so a newer 0.3.x point release that adds a field still round-trips. The protobuf decoder is strict about hostile framing too: over-long, over-range, and non-canonical (redundantly padded) varints, field numbers of `0` or above the protobuf maximum `2^29 - 1`, out-of-range length prefixes, and the group wire types are all rejected rather than truncated or resynchronized against.

Unproven versions, layout mismatches, schema faults, malformed frames, and non-identity `grpc-encoding` all fail closed as a **trailers-only gRPC `INTERNAL` under HTTP `200`** — the same shape as the gateway's other gRPC terminals, so a policy refusal is not published as a synthetic backend 5xx — with an empty body and a fixed `a2a.error` diagnostic when metadata emission is enabled; response bytes are never reflected into `grpc-message` or metadata. The diagnostics are a closed set of fixed strings, and this is the complete list of the ones reachable by a client on the gRPC Agent Card path:

| Stage | Diagnostic | Meaning |
| --- | --- | --- |
| Service schema | `agent_card_grpc_schema_unsupported` | The responding gRPC service is declared to carry a known Agent Card layout this gateway does not implement (`a2a-1.0`). |
| Service schema | `agent_card_grpc_schema_undeclared` | The responding gRPC service declares no Agent Card layout (`none`), so there is nothing to decode against. |
| Framing | `agent_card_grpc_encoding_unsupported` | `grpc-encoding` or the frame's compressed-flag byte is anything but identity. |
| Framing | `agent_card_grpc_frame_malformed` | The reply is not exactly one length-prefixed unary message. |
| Framing | `agent_card_grpc_frame_too_large` | The rewritten card cannot be addressed by the 32-bit gRPC length prefix. |
| Version/layout | `unsupported_agent_card_protobuf_version` | `protocol_version` is absent, empty, not configured, or not in the 0.3 family. |
| Version/layout | `agent_card_protobuf_shape_unrecognized` | The message does not decode as any recognizable Agent Card shape. |
| Version/layout | `agent_card_protobuf_url_layout_mismatch` | A rewritable URL field does not parse as a bounded absolute `http`/`https` URL with a real host and no embedded credentials, so the layout is not 0.3. |
| Schema | `agent_card_protobuf_field_wire_mismatch` | A known 0.3 field carries a wire type the schema does not declare. |
| Schema | `agent_card_protobuf_field_duplicated` | A singular 0.3 field appears more than once. |
| Schema | `agent_card_protobuf_field_invalid` | A field number is `0` or above the protobuf maximum `2^29 - 1`. |
| Schema | `agent_card_protobuf_string_invalid` | A known 0.3 string field that would be re-emitted is not valid UTF-8. |
| Schema | `agent_card_protobuf_bool_invalid` | `supports_authenticated_extended_card` carries a varint that is not a canonical `0` or `1`. |
| Schema | `agent_card_protobuf_interface_url_missing` | An `AgentInterface` in `additional_interfaces` carries no `url`, so it is not a usable endpoint. |
| Schema | `agent_card_protobuf_url_invalid` | A rewritable URL field is not valid UTF-8. |
| Decoding | `agent_card_protobuf_truncated` | The message ends inside a tag, varint, or length-delimited value. |
| Decoding | `agent_card_protobuf_length_invalid` | A length prefix is out of range for the remaining bytes. |
| Decoding | `agent_card_protobuf_varint_overflow` | A varint is over-long or exceeds 64 bits. |
| Decoding | `agent_card_protobuf_varint_noncanonical` | A varint is redundantly padded. |
| Decoding | `agent_card_protobuf_wire_type_unsupported` | A group (or otherwise unsupported) wire type appears. |
| Emission | `agent_card_protobuf_rewrite_unstable` | The measuring and writing passes disagreed, so the declared length would not describe the emitted bytes. |
| Emission | `agent_card_public_origin_unavailable` | No admitted public origin is available for the card; no backend card is returned. Also reachable on the HTTP bindings, where it is an HTTP `502` with a JSON diagnostic body. |
| Emission | `agent_card_grpc_rewrite_not_applied` | An admitted card's rewrite never reported an outcome, so it must not be served un-rewritten. Also reachable on the HTTP bindings, with the same `502` shape. |

A card the plugin admitted whose rewrite never reaches the client fails closed the same way, so "the rewrite silently did not run" can never be mistaken for "no rewrite was needed". A rewrite that would exceed the per-response retained-response ceiling is refused during construction and surfaces as the shared health-neutral gateway capacity terminal instead. Operators fronting a non-0.3 A2A backend should therefore set `discovery.rewrite_agent_card_urls: false` — with it enabled, such cards are refused rather than silently served with un-rewritten internal URLs. **Public origin admission:** rewriting defaults to enabled, so an empty plugin configuration is rejected. Set `discovery.public_base_url` explicitly, or set both `discovery.trust_forwarded_headers: true` and a nonempty `discovery.allowed_public_origins` list of absolute HTTP(S) origins (scheme, host, optional port; no paths, credentials, queries, or fragments). For example, `allowed_public_origins: [https://agents.example.com]`. Request-derived origins must match this list after URL origin normalization; schemes and non-default ports remain significant. Comma-separated forwarded chains, malformed values, missing origins, and origins outside the list are refused before contacting the agent, with HTTP 502 or gRPC INTERNAL and `agent_card_public_origin_unavailable`. Configure the trusted front door to replace forwarded headers; the allowlist constrains the advertised destination even if a caller supplies them. A configured public base takes precedence. To intentionally publish backend cards unchanged, set `discovery.rewrite_agent_card_urls: false`; this explicit passthrough also disables the protobuf rewrite/schema gate. Existing configurations without a public base must make one of these choices.

**The published base URL is the canonicalized one.** `discovery.public_base_url` is validated through a normalizing URL parser, and it is the parser's canonical serialization — not the operator's raw string — that every rewritten card URL is built from, with any trailing slash removed and an intended base path preserved. IDNA, case, default-port, and percent-encoding normalization therefore happen once, at admission. Spellings a normalizing parser silently repairs are refused outright rather than stored, because the value it accepted would not be the value that was written: leading or trailing whitespace, embedded tabs, newlines, or other ASCII control characters, and authority-less forms such as `https:agents.example.com` or `https:/agents.example.com`. `discovery.allowed_public_origins` entries are held to the same requirements. The same proof is applied to backend-supplied card URLs before they are rewritten.

**Agent Card production is bounded.** Both card representations are produced the same way: an admission pass proves the response is a rewritable card without emitting a byte, and the replacement is then written through the per-response retained-response sink inside the reserved producer window, so an amplifying rewrite is refused *while* it is being written rather than materialized in full and rejected afterwards. A refusal on capacity surfaces as the shared health-neutral gateway capacity terminal, never as a gateway fault; a card the plugin admitted whose rewrite never reached the client fails closed with `agent_card_grpc_rewrite_not_applied` on either binding (HTTP `502` with a JSON diagnostic body, or the trailers-only gRPC `INTERNAL` described above). The public endpoint and card URLs are built once per response rather than once per advertised interface.

**Composition with `grpc_web`.** The gRPC-Web translator re-frames the response body — appending the terminal trailer frame, and base64-encoding it in text mode — in the ordinary response transform stage, at a lower priority than this plugin. So when both plugins are configured, the unary Agent Card is rewritten one phase earlier, in the response normalize phase, while the body is still exactly one native gRPC frame; the rewritten card is then what the translator frames, and downstream response guardrails see the client-visible URLs. Native gRPC without the translator is unchanged and keeps the ordinary staged transform. Either way the outcome is reported through the same fail-closed lifecycle, and the translator's own request handling is untouched.

**Composition with `request_deduplication`.** Agent Card rewriting is a client-facing presentation transform, and a deduplicated replay is served as an already-finalized representation without re-running such transforms. So `a2a_gateway` stamps every retained response with a content digest of its whole accepted configuration — `discovery.public_base_url`, `endpoint.path`, `endpoint.agent_card_path`, `endpoint.protocol_versions`, `discovery.rewrite_agent_card_urls`, and the `enabled` switch — and a stored representation replays only while that digest still matches. Changing the public base, the endpoint path, the admitted protocol versions, or enabling/disabling the plugin therefore retires every representation captured under the old settings rather than replaying a card that advertises a superseded endpoint.

That proof is only available when the rewritten origin comes from configuration. With `discovery.public_base_url` **unset** and `discovery.trust_forwarded_headers: true`, the origin is instead derived from the request's `X-Forwarded-Proto` / `X-Forwarded-Host` / `Host` and — absent a forwarded scheme — from whether the connection itself is secure (TLS on HTTP/1.1 and HTTP/2, always on HTTP/3). The deduplication fingerprint binds neither the complete forwarded header set nor the transport's security, so two requests sharing a replay key can legitimately deserve cards advertising different origins. Configuration admission therefore rejects that specific pairing with HTTP 400 (fatal in file mode, a rejected update in DP), naming both instances; setting `discovery.public_base_url` resolves it. A configured-public-base deployment composes with `request_deduplication` normally. At runtime the same case degrades the proxy's presentation provenance to "unprovable", so admission paths that only warn on pre-existing data still retain and replay nothing.

Metadata keys include `a2a.enabled`, `a2a.mode`, `a2a.binding`, `a2a.method`, `a2a.protocol_version`, `a2a.streaming`, `a2a.policy_decision`, `a2a.task_id`, `a2a.context_id`, `a2a.task_state`, `a2a.error`, `a2a.response_body_size`, and `a2a.ttfb_ms` for streaming responses when headers arrive. For detected 2xx SSE streams, the observe-only inspector writes `a2a.stream_events` and, when observed, `a2a.task_state`, `a2a.task_id`, and `a2a.context_id` into the request's transaction metadata at stream termination (before the transaction summary is built), so they appear in `TransactionSummary.metadata` alongside the buffered-path keys and are subject to the same key-based metadata redaction (`FERRUM_LOG_REDACT_METADATA_KEYS`). They are no longer emitted as raw structured trace fields, which bypassed metadata redaction. `observability.log_payloads` is disabled by default because it copies bounded response payloads into `a2a.payload.response` verbatim; payload contents are not field-redacted by key-based metadata redaction, and request payloads are not logged. Because `a2a.payload.response` is itself a metadata key, payload capture is part of metadata emission: `observability.log_payloads` has no effect unless `observability.emit_metadata` is also `true`.

Because `detection.strip_accept_encoding` defaults to `true`, attaching this plugin to a proxy marks request headers as mutable and can force a per-request header clone even for non-A2A traffic on mixed high-QPS listeners. Operators that do not need Agent Card rewriting or response metadata parsing can set `detection.strip_accept_encoding: false` and `discovery.rewrite_agent_card_urls: false` to avoid that path.

The option controls compression negotiation and nothing else. Setting `detection.strip_accept_encoding: false` while leaving Agent Card rewriting enabled is a supported combination: the public origin is resolved from the request hook's own header map and the admitted result is retained for the response phase, so a forwarded-origin card request is served identically whether or not the plugin declares request-header mutation.

**Encoded and partial HTTP Agent Cards.** Stripping `Accept-Encoding` only discourages compression; a backend may still send a `gzip`/`br` card, and a range-capable static host may answer `206` slices. With rewriting enabled, a buffered HTTP Agent Card fragment is claimed through the shared representation gate regardless of its top-level media type, including `multipart/byteranges` with JSON parts. A `206`/`226` fragment is refused with the gate's fail-closed `502`; multipart bodies are never reconstructed or rewritten. Content-coded complete responses retain the JSON-or-absent media check: a supported coding is decoded (bounded by `FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES` and charged to the retained-response budget) and the decoded card is rewritten and served as identity bytes, while an unsupported or malformed coding, or a client that refuses identity, is refused with `502` (or the health-neutral capacity terminal when the budget is exhausted). An encoded JSON card is never forwarded with the backend's internal URLs. Complete identity bodies are unaffected.

**Bounded semantic metadata.** Request hints, buffered JSON replies, and completed SSE observations use the same bounds. `a2a.task_id`, `a2a.context_id`, textual `a2a.error`, and `a2a.protocol_version` are capped at `min(observability.max_payload_size, 1024)` UTF-8 bytes per field, including a trailing `~` marker when truncated. A companion `<key>.truncated: true` distinguishes the diagnostic prefix from a complete identifier; truncated identifiers must not be used as exact correlation keys. Ordinary identifiers are unchanged. Task states normalize to `submitted`, `working`, `input-required`, `completed`, `canceled`, `failed`, `rejected`, `auth-required`, or `unknown`; arbitrary states become `unknown` with `a2a.task_state.unrecognized: true`. A normalized state that cannot fit the configured bound is omitted instead of publishing a partial state. Oversized state inputs and omitted states carry `a2a.task_state.truncated: true`. These limits apply even when payload logging is disabled and do not change forwarded response bytes. The SSE observer applies them when a value enters its state, as each event completes, so a long-lived stream retains at most the bounded id/context values and a normalized state between events — never a backend-sized string.

**Response buffering.** Either `observability.emit_metadata` or `discovery.rewrite_agent_card_urls` (both default `true`) makes the plugin require response body buffering. With the defaults, each detected, non-streaming A2A HTTP response is fully buffered so the plugin can extract response metadata (`a2a.task_id`, `a2a.context_id`, `a2a.task_state`, `a2a.error`) and rewrite Agent Card URLs; with only `rewrite_agent_card_urls` enabled, just Agent Card responses are buffered. Detected unary gRPC Agent Card responses are also buffered when `discovery.rewrite_agent_card_urls` is enabled so the protobuf card can be rewritten; other gRPC responses remain streaming pass-through. SSE (`text/event-stream`) responses are never buffered and pass straight through. This holds on retry-enabled proxies too: when a request the plugin classified as non-streaming unexpectedly answers with `text/event-stream`, the plugin releases the response from retry buffering after headers arrive (`may_release_response_body_under_retries` / `should_release_response_body_under_retries`), so the stream is delivered incrementally instead of being collected to the response-size cap; a retryable status is still discarded before any bytes reach the client, and all non-SSE responses (JSON and otherwise) stay buffered for metadata extraction, Agent Card rewriting, and retry replay. When metadata emission is enabled, an observe-only SSE inspector forwards each chunk immediately and independently reassembles bounded SSE events for completion metadata; it never holds, mutates, reorders, or terminates response bytes. This buffering is bounded only by the global `FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES` limit — `observability.max_payload_size` caps payload logging and retained semantic metadata, not the response buffer. To keep all A2A responses fully streaming, set both `observability.emit_metadata: false` and `discovery.rewrite_agent_card_urls: false`; the plugin then still detects requests and applies method allow/deny policy, but emits no `a2a.*` metadata.

**Streaming metadata and residuals.** For detected 2xx SSE responses, the observer counts `data:` events and extracts the latest task state plus task/context ids from JSON event payloads. `a2a.streaming` and `a2a.ttfb_ms` are recorded as for any other response. At stream termination, `a2a_gateway` uses core's mutable terminal write-back to add the observed values to `TransactionSummary.metadata`, where the normal metadata redaction policy applies; it does not emit them as raw structured trace fields. Response stream inspectors run on the shared reqwest, direct HTTP/2, and native HTTP/3 dispatch paths. Native gRPC streaming deliberately remains pass-through without event counting or terminal task-state extraction because protobuf-framed streams require a separate transport-aware observer.

---
