# serverless_function

Part of the [Plugin Reference](../plugins.md).

**Priority:** 3025 · **Phases:** finalized request egress · **Protocols:** HTTP, gRPC · **Failure policy:** `KeepLastKnownGood`

Invokes AWS Lambda, Azure Functions, or Google Cloud Functions as middleware in the proxy pipeline. Two modes are supported:

- **`pre_proxy`** (default) — calls the function with request context, injects response headers/metadata into the proxied request, then continues to the backend.
- **`terminate`** — calls the function and returns its response directly to the client, bypassing backend proxying.

## Provider Configuration

**AWS Lambda** — uses the Lambda Invoke API with SigV4 request signing:

| Parameter | Type | Default | Description |
|---|---|---|---|
| `provider` | String | (required) | `"aws_lambda"` |
| `aws_region` | String | — | AWS region. Falls back to `AWS_DEFAULT_REGION` / `AWS_REGION` env var. The default endpoint is partition-aware: a `cn-*` region derives `https://lambda.<region>.amazonaws.com.cn`, every other region derives `https://lambda.<region>.amazonaws.com`. With process-environment credentials it must be a commercial, GovCloud, or China region (see [Ambient AWS credential scope](#ambient-aws-credential-scope)) |
| `aws_credentials` | String | `"static"` | `"static"` signs with the literal key pair below (config or environment, resolved once). `"default_chain"` signs with the workload identity from the AWS SDK default chain and refreshes it before expiry — see [Workload identity](#workload-identity-aws_credentials-default_chain). Builds with the `secrets-aws` (or `cloud-secrets`) feature only |
| `aws_access_key_id` | String | — | IAM access key. Falls back to `AWS_ACCESS_KEY_ID` env var; a process-environment credential is [scoped to official AWS Lambda endpoints](#ambient-aws-credential-scope). Interpolated into the SigV4 `Authorization` header, so the effective value must be an HTTP field value (no NUL, CR, LF, or other control byte except horizontal tab); refused at admission otherwise. Not allowed with `aws_credentials: default_chain` |
| `aws_secret_access_key` | String | — | IAM secret key. Falls back to `AWS_SECRET_ACCESS_KEY` env var; a process-environment credential is [scoped to official AWS Lambda endpoints](#ambient-aws-credential-scope). Not allowed with `aws_credentials: default_chain` |
| `aws_function_name` | String | — | Lambda function name, partial ARN, or full ARN, validated against the Lambda Invoke API `FunctionName` grammar (≤ 170 characters). Falls back to `AWS_LAMBDA_FUNCTION_NAME` env var; the environment value is held to the same grammar |
| `aws_session_token` | String | — | STS session token. Falls back to `AWS_SESSION_TOKEN` env var only when `aws_access_key_id` and `aws_secret_access_key` also come from the environment (a token is bound to its access key, so it never completes a config key pair); a process-environment token is [scoped to official AWS Lambda endpoints](#ambient-aws-credential-scope). Sent verbatim as `x-amz-security-token`, so it is held to the same HTTP field-value rule as `aws_access_key_id`. Not allowed with `aws_credentials: default_chain` |
| `aws_qualifier` | String | — | Optional version/alias qualifier (e.g., `$LATEST`, `prod`), validated against the Lambda Invoke API `Qualifier` grammar: `A-Z a-z 0-9 $ _ -`, ≤ 128 characters |
| `allow_plaintext` | Boolean | `false` | Admit an `http://` `function_url` / `aws_endpoint_url` whose host is not a loopback IP literal. The invocation payload and provider credential then travel in clear. The `AWS_LAMBDA_ENDPOINT_URL` fallback is not screened. |
| `aws_endpoint_url` | String | — | Optional HTTP(S) origin-only Lambda endpoint override. No userinfo, path, query, or fragment; falls back to `AWS_LAMBDA_ENDPOINT_URL`. With process-environment credentials a configured `aws_endpoint_url` must be an official AWS Lambda endpoint unless `allow_custom_endpoint_with_ambient_credentials` is `true`; an `AWS_LAMBDA_ENDPOINT_URL` fallback is trusted like the environment credentials |
| `allow_custom_endpoint_with_ambient_credentials` | Boolean | `false` | Deliberately let process-environment (or `default_chain`) AWS credentials sign invocations for a config-chosen endpoint outside the official scope (LocalStack, an air-gapped ISO partition, the AWS European Sovereign Cloud). See [Ambient AWS credential scope](#ambient-aws-credential-scope) |
| `payload_format` | String | `"ferrum"` | `"ferrum"` uses the [Ferrum payload](#function-request-payload) and response contracts. `"aws_api_gateway_v2"` (requires `mode: terminate`) speaks the API Gateway HTTP API proxy-integration contract — see [API Gateway payload format](#api-gateway-payload-format-aws_api_gateway_v2) |

**Lambda Invoke API failures are invocation failures.** The synchronous Invoke API answers HTTP 200 for every invocation that ran — the function's result, or its error with `X-Amz-Function-Error`, is the body. Any other status (429 throttling, 403 access denied, 404 missing function, 413 oversized payload, 5xx service errors) is authored by the Lambda service, not by the function, so in every mode (pre_proxy, HTTP terminate, and native gRPC terminate) it follows `on_error` / `error_status_code` with the fixed class `lambda_service_error`: `on_error: continue` falls through to the backend and `reject` returns the configured status with the fixed error body. The AWS error body (which names function ARNs, account ids, and principals) is never read or returned; the operator log records the HTTP status and the bounded `x-amzn-ErrorType` exception name. Azure and GCP HTTP triggers author their own status, so their terminate passthrough is unchanged.

**Azure Functions** — calls the HTTP trigger URL:

| Parameter | Type | Default | Description |
|---|---|---|---|
| `provider` | String | (required) | `"azure_functions"` |
| `function_url` | String | (required) | HTTP(S) trigger URL without URL userinfo or a fragment. Path/query credentials are accepted for provider compatibility but redacted structurally from diagnostics and non-admin/audit projections. An `http://` URL is refused unless its host is a loopback IP literal written as `127.d.d.d` or `[::1]`, or `allow_plaintext: true` is set |
| `azure_function_key` | String | — | Function key for auth. Falls back to the `FERRUM_PLUGIN_SECRET_AZURE_FUNCTIONS_KEY` env var (never the ambient `AZURE_FUNCTIONS_KEY`, because the key is sent to the config-chosen `function_url`). The effective value is parsed into the `x-functions-key` field value at config load, so a credential that cannot form an HTTP field value (NUL, CR, LF, or any other control byte except horizontal tab) is rejected at admission instead of failing every invocation |

**GCP Cloud Functions** — calls the HTTPS trigger URL:

| Parameter | Type | Default | Description |
|---|---|---|---|
| `provider` | String | (required) | `"gcp_cloud_functions"` |
| `function_url` | String | (required) | HTTP(S) trigger URL without URL userinfo or a fragment. Path/query credentials are accepted for provider compatibility but redacted structurally from diagnostics and non-admin/audit projections. An `http://` URL is refused unless its host is a loopback IP literal written as `127.d.d.d` or `[::1]`, or `allow_plaintext: true` is set |
| `gcp_bearer_token` | String | — | Bearer token for auth. Falls back to the `FERRUM_PLUGIN_SECRET_GCP_CLOUD_FUNCTIONS_BEARER_TOKEN` env var (never the ambient `GCP_CLOUD_FUNCTIONS_BEARER_TOKEN`). The assembled `Authorization: Bearer <token>` field value is parsed at config load under the same rule as `azure_function_key` |

## Common Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `mode` | String | `"pre_proxy"` | `"pre_proxy"` or `"terminate"`. Unknown values rejected at plugin load. In `terminate` mode, native `application/grpc` requests use the [gRPC terminate response contract](#function-response-format-terminate-mode--native-grpc) (raw protobuf message bytes plus protocol-owned status/trailers). gRPC-Web terminate is rejected with 500; HTTP terminate behavior is unchanged |
| `forward_body` | bool | `false` | Include the lossless buffered request body for every method. UTF-8 bytes are an exact string with `body_encoding: "utf8"`; other bytes are base64 with `body_encoding: "base64"`. The active media type is carried separately as `body_content_type` |
| `forward_headers` | String[] | `[]` | Header names to forward to the function (lowercased at config load). Each entry must be a non-empty RFC 9110 field-name token — an empty string or a name containing a space or another separator is rejected at plugin load. Read from the effective `before_proxy` header view, so a field line an earlier plugin removed — `authorization` under `strip_authorization_on_success`, or a gateway-owned `claim_headers` destination with no verified claim — is absent from the payload rather than re-read from the client's original request. `x-real-ip` is additionally dropped whenever the immediate socket peer is not in `FERRUM_TRUSTED_PROXIES`, matching the primary backend request — the payload's `client_ip` field already carries the gateway-resolved address |
| `forward_query_params` | bool | `false` | Include decoded query parameters after omitting credentials that an earlier auth plugin marked for backend stripping. Decodes the same canonical backend-visible query primary dispatch forwards (including any prior `request_transformer` ordered query mutation), through the shared canonicalizer OPA and `mesh_route_dispatch` use, so the payload is identical on HTTP/1.1, HTTP/2, and HTTP/3. Duplicate decoded names (including percent-encoded aliases and bare/valued pairs), literal `+` ambiguity, an unencoded `;`, malformed percent-encoding, non-UTF-8 decodings, and parameters lacking the original encoded representation fail closed before invocation — including before a pre-proxy function can approve the request |
| `timeout_ms` | u64 | `5000` | Function invocation timeout in milliseconds, `1`-`900000` (15 minutes, the Lambda synchronous invocation maximum). A larger value is refused at admission rather than held as a per-request bound |
| `max_response_body_bytes` | u64 | `10485760` | Max function response body size (10 MiB), `1`-`67108864` (64 MiB). The response is buffered whole, so this is the per-invocation retained-memory ceiling |
| `on_error` | String | `"reject"` | `"reject"` returns error to client; `"continue"` skips and proxies normally. Unknown values rejected at plugin load |
| `error_status_code` | u16 | `502` | Final HTTP error status when rejecting on error. Must be in range 400-599 |

**Strict config validation:** the config must be an object, unknown fields are rejected, and explicit `null` is rejected for every property (omit an optional field instead; required fields must be non-null). Unknown `provider`, `mode`, `on_error`, `aws_credentials`, or `payload_format` values, non-string values for string fields, `timeout_ms` outside `1`-`900000`, `max_response_body_bytes` outside `1`-`67108864`, and `error_status_code` outside 400-599 are rejected. A repeated `forward_headers` name is forwarded once.

**Validation is provider-independent for every field the operator supplied.** A recognized field belonging to another provider is still checked — its JSON type, the Lambda identifier grammars, the credential field-value grammar, and the URL contract below — because the published schema types those fields unconditionally and because a later `provider` change must not turn an already-admitted row into a constructor error. A well-typed, well-formed inactive field remains accepted and ignored. Only the *availability* of a credential is provider- and node-specific.

`function_url` and `aws_endpoint_url` share one lexical URL contract, identical in runtime admission and in the published schema: an `http`/`https` scheme, a non-empty host (registered name, IPv4 literal, or bracketed IPv6 literal), an optional port in 0-65535, no URL userinfo (`user:password@host`), no fragment, and no raw ASCII whitespace or control character anywhere in the value. A space belongs percent-encoded (`%20`); a raw one is rejected rather than silently normalized into a stored string that differs from the value sent. The AWS endpoint override must additionally be an origin only, with no path or query. A non-default port in either URL is part of the SigV4 canonical `Host`, so a signature-verifying custom endpoint accepts the invocation. Automatic redirects are disabled. In `pre_proxy` mode only a 2xx function response is approval; every other response uses `on_error` and `error_status_code`. In `terminate` mode only final 2xx-5xx statuses (`200..=599`) are returned intentionally; informational or out-of-range three-digit statuses use the configured error path.

The function is invoked in the **finalized-request-egress** phase, after
request-body transforms and after every final request-policy hook has accepted
the representation — including protocol and integrity validation,
WAF/OpenAPI/body/size policy, AI request guardrails, and mandatory audit
admission. None of those policies can reject only after the function was
contacted. Backend admission,
circuit-breaker, and transport checks still occur later where applicable.
When `forward_body` is enabled, the plugin buffers for every HTTP method and
fails closed without calling the function if no body was ever collected for a
request that may carry one, or if the request carries a non-identity
`Content-Encoding`. The forwarded bytes are the backend-visible body, so
operator-configured `request_transformer` removals and redactions are applied
before the function sees them. The encoding check consults the **original**
request headers (captured at request intake) as well as the active header map:
a header-only `request_transformer` that removes or renames `Content-Encoding`
before this plugin cannot strip the label off still-compressed bytes and
smuggle them past the boundary. The payload has one authoritative lossless
body representation: Ferrum never parses JSON into a structured value, so
duplicate object members, lexical number forms, whitespace, and every other
byte remain identical to the backend-visible request. Valid UTF-8 is carried as
an exact JSON string with `body_encoding: "utf8"`; arbitrary bytes use base64
with `body_encoding: "base64"`. `body_content_type` separately records the
active hook `Content-Type` when present without changing the representation.
Query forwarding starts from the same canonical effective query used for
backend dispatch (transformer outbound query when present, otherwise the
retained raw query, then auth credential strips), so credentials that an
earlier auth plugin marked for hiding are removed before parsing and cannot be
resurrected in external policy egress, and operator query transforms are
reflected rather than ignored. Query/body representation ambiguity is governed
input and remains fail-closed even with `on_error: "continue"`; that option
applies to invocation/response failures, not to inputs the configured policy
cannot inspect faithfully. A serverless body-egress instance may share a
protocol chain with a request-body transformer, because the function observes
the post-transform representation. The fail-closed composition rule is
retained, at plugin-cache construction, for anything that still egresses
*earlier*: a registered custom plugin declaring
`egresses_request_body_before_finalization()` may not share a protocol chain
with a request-body transformer, nor with any plugin declaring
`enforces_finalized_request_policy()`, and may not simultaneously declare
`dispatches_finalized_request_egress()`. This is capability-based rather than a
built-in-name exception.

Candidate composition admission derives only the serverless protocol, effective priority, `mode`, and `forward_body` capabilities and does not construct the environment-bound HTTP/AWS client. CP/database admission of the plugin config itself is likewise **shape-only**: it validates every supplied field but does not require the AWS/Azure/GCP credentials that intentionally exist only on DPs, exactly as the descriptor, MMDB, and DTLS dependencies of other plugins are deferred. Runtime cache construction on the serving node still resolves and validates them fail closed — a data plane missing `aws_access_key_id` (in config or environment) refuses the plugin generation, and a file-mode gateway refuses to start. The consequence is deliberate: `ferrum-edge validate` checks the shape of the row, not whether this particular node happens to hold the credentials the row will need at serve time.

## Function Request Payload

The plugin sends a JSON payload to the function:

```json
{
  "method": "POST",
  "path": "/api/v1/users",
  "client_ip": "10.0.0.1",
  "consumer_username": "alice",
  "authenticated_identity": "user@example.com",
  "headers": { "x-request-id": "abc-123" },
  "query_params": { "page": "1" },
  "body": "{\"name\":\"Alice\"}",
  "body_encoding": "utf8",
  "body_content_type": "application/json"
}
```

For a non-UTF-8 body, `body` contains standard base64 and `body_encoding` is `"base64"`. The encoding field is always present when body forwarding is enabled. The payload is serialized directly from the finalized request (the body is never copied into an intermediate JSON value, and base64 is produced while writing).

## API Gateway payload format (`aws_api_gateway_v2`)

With `payload_format: aws_api_gateway_v2` (`provider: aws_lambda`, `mode: terminate`), an existing Lambda handler written for an API Gateway HTTP API proxy integration (payload format 2.0 — `aws-lambda-go` `events.APIGatewayV2HTTPRequest`, SAM/CDK/Serverless Framework HTTP API handlers) can be fronted without a rewrite. The function receives:

```json
{
  "version": "2.0",
  "routeKey": "$default",
  "rawPath": "/api/v1/users",
  "rawQueryString": "page=1",
  "cookies": ["session=abc"],
  "headers": { "x-request-id": "abc-123", "user-agent": "curl/8.5" },
  "queryStringParameters": { "page": "1" },
  "requestContext": {
    "http": { "method": "POST", "path": "/api/v1/users", "sourceIp": "10.0.0.1", "userAgent": "curl/8.5" },
    "routeKey": "$default",
    "stage": "$default",
    "time": "24/Oct/2026:12:00:00 +0000",
    "timeEpoch": 1792843200000,
    "authorizer": { "lambda": { "consumer_username": "alice", "authenticated_identity": "user@example.com" } }
  },
  "body": "{\"name\":\"Alice\"}",
  "isBase64Encoded": false
}
```

The event is built from the same finalized request view and the same fail-closed selection as the Ferrum payload: `headers` and `cookies` carry only the configured `forward_headers` (a forwarded `cookie` header becomes the `cookies` array), `rawQueryString` / `queryStringParameters` only an unambiguous forwarded query (re-encoded from the canonical decoded parameters; an ambiguous query is refused before invocation exactly as for the Ferrum payload), and `body` / `isBase64Encoded` only with `forward_body` (exact UTF-8 or standard base64). The gateway-authenticated consumer and identity ride in `requestContext.authorizer.lambda`, where API Gateway puts Lambda-authorizer context.

The function result is mapped like an API Gateway proxy integration. A JSON object with `statusCode` is a structured response: `statusCode` (an integer in 200-599), optional `headers` (string values), `multiValueHeaders` (arrays of strings), `cookies` (one `Set-Cookie` each), `body` (a string), and `isBase64Encoded` (decode `body` from standard base64); other members are ignored. `headers` and `multiValueHeaders` are merged the way API Gateway merges them: an identical name/value pair in both (names compared case-insensitively) is one field line, so the same `Location` or `Content-Type` in both containers is not turned into a repeated field; genuinely conflicting singleton values are still dropped by the sanitizer below. A structured response may author at most 128 header field lines and 32 KiB of header names and values in total. A JSON string result is returned as the decoded string (`"Hello"` becomes the body `Hello`), and any other JSON value as its JSON text, both with status 200 and `content-type: application/json`. The Lambda Invoke response's own headers are not returned. Mapped headers pass through the same sanitization as provider response headers (hop-by-hop, `Connection`-listed, credential, provider-control, and signed-URL leak screening), and the response then follows the normal terminate framing and body lifecycle below. A result with duplicate JSON members, malformed JSON, a non-integer or out-of-range `statusCode`, a non-string header value, an invalid header name/value, or invalid base64 fails with the fixed `invalid_api_gateway_response` class under `on_error`; the result is never echoed. A native gRPC terminate request is refused before invocation with `unsupported_grpc_payload_format`. The REST API (payload format 1.0) event is not implemented.

## Function Response Format (pre_proxy mode)

The function should return JSON with optional `headers` and `metadata` fields:

```json
{
  "headers": {
    "x-custom-header": "computed-value",
    "x-user-tier": "premium"
  },
  "metadata": {
    "decision": "allowed",
    "reason": "user is premium"
  }
}
```

The response body must be a JSON **object**. Invalid JSON, an empty body, or any non-object JSON value (`null`, a string, number, array, …) is treated as an invocation failure with the fixed `invalid_pre_proxy_response` error class and routed through `on_error` / `error_status_code` — it is never silently ignored. An empty object (`{}`) is valid and simply injects nothing.

Headers are validated before injection; invalid and hop-by-hop/protocol-managed request headers are ignored. Metadata is stored under `serverless_function.<plugin-config-id>.metadata.<key>`, while invocation status and sanitized error class use the same instance namespace. Namespace segments percent-encode punctuation other than `-`/`_`. This keeps multiple instances independent and deterministic in transaction metadata.

## Function Response Format (terminate mode — native gRPC)

When `mode` is `terminate` and the client request was classified as native gRPC by the frontend at intake, the function must return HTTP 2xx with a JSON object. Classification uses the request-scoped HTTP flavor the frontend stamps once, not the live effective `content-type`: an earlier hook such as `request_transformer` can rewrite that header to `application/grpc`, and honouring it would frame a unary gRPC response for a request the reject finalizer and the H1/H2/H3 writers still treat as ordinary HTTP. A request stamped as native gRPC stays on this contract even if a prior hook removed or changed the header. Ferrum frames a single uncompressed unary DATA message and owns reserved terminal metadata:

```json
{
  "grpc_status": 0,
  "grpc_message": "optional human-readable status",
  "message_base64": "optional standard-base64 raw protobuf message bytes",
  "status_details_base64": "optional standard-base64 for grpc-status-details-bin",
  "trailers": {
    "x-custom-trailer": "value"
  }
}
```

| Field | Required | Rules |
|---|---|---|
| `grpc_status` | yes | Unsigned integer (`u32`). Emitted as the protocol-owned `grpc-status` trailer (or trailers-only header when there is no message) |
| `grpc_message` | no | String of human-readable text. CR/LF are normalized to spaces and the value is trimmed, then percent-encoded into the canonical `grpc-message` wire form required by the gRPC HTTP mapping: bytes the grammar allows unescaped (`%x20-%x24`, `%x26-%x7E`) stay literal, while `%` and every byte outside that range — controls, `DEL`, and each UTF-8 byte of a non-ASCII character — become `%XX` with uppercase hex. The 8 KiB trailer **wire**-value ceiling is measured on the encoded value, since encoding expands a byte threefold. Omitting the field emits no `grpc-message` at all; an over-ceiling value fails closed rather than being truncated or dropped |
| `message_base64` | no | Standard base64 of the **raw** protobuf message (not length-prefixed). Gateway prepends the 5-byte uncompressed gRPC frame header. Decoded size plus frame overhead must fit `max_response_body_bytes` |
| `status_details_base64` | no | Standard base64 for `grpc-status-details-bin` (revalidated and re-encoded). The 8 KiB ceiling is on the re-encoded **wire** value, so the decoded payload may be at most 6144 bytes — base64 expands four characters per three bytes |
| `trailers` | no | Object of string trailer values. At most 32 entries; each **wire** value ≤ 8 KiB, subject to the aggregate block budget below. Names use the gRPC Custom-Metadata alphabet (`0-9`, lowercase `a-z`, `_`, `-`, `.` after case normalization); text values must be printable ASCII, and `-bin` values must be standard base64 with or without padding. Reserved / protocol-owned names (`grpc-status`, `grpc-message`, `grpc-status-details-bin`, `content-type`, hop-by-hop, `grpc-encoding`, `grpc-accept-encoding`, …) are rejected — use the dedicated fields above. Trailer names are case-insensitive on the wire but JSON members are not, so two members that differ only in case (`X-Foo` and `x-foo`) are rejected instead of one silently overwriting the other |

The 8 KiB ceiling bounds one field. The **complete** terminal metadata block — `grpc-status`, the optional percent-encoded `grpc-message`, the optional re-encoded `grpc-status-details-bin`, every custom trailer, and the gateway's own `content-type` — is bounded separately at **16 KiB**, charged the way an HTTP/2 peer charges a header list against `SETTINGS_MAX_HEADER_LIST_SIZE` (RFC 9113 §6.5.2) and an HTTP/3 peer charges a field section against `SETTINGS_MAX_FIELD_SECTION_SIZE` (RFC 9114 §4.2.2): name bytes + value bytes + 32 bytes per field. Without it, 32 individually valid 8 KiB trailers would authorize roughly 256 KiB of terminal metadata that no client is obliged to accept. 16 KiB is the smallest header-list size a Ferrum listener ever advertises (`FERRUM_MAX_HEADER_SIZE_BYTES` defaults to 32 KiB and is floored at 16 KiB for HTTP/2), so an accepted block stays deliverable rather than being accepted here and reset by the peer. An over-budget block fails closed with the fixed `invalid_grpc_terminate_response` class; the diagnostic names no trailer and echoes no value.

The raw function output is screened for duplicate JSON object member names before it is parsed. `serde_json` keeps the **last** of duplicate members while many other parsers keep the **first**, so a document that declares `grpc_status` twice — or spells one occurrence with a `\u` escape, or duplicates a member inside `trailers` — describes two different terminal outcomes depending on who reads it. Since the gateway binds what it parsed as provenance and emits it as trailers, such a document is refused with the fixed `invalid_grpc_terminate_response` class rather than resolved. The screen uses the same bounded scanner every governed JSON surface uses (`body_validator`, `openapi_validator`, `ai_tool_governor`); its diagnostics are fixed-cardinality and never echo any byte of the function response. Ordinary malformed JSON keeps its existing malformed-body error.

Unknown top-level fields are rejected. Streaming and compression contract shapes (`streaming`, `messages`, `grpc_encoding`, `message_compressed`, `compression`) fail closed with `unsupported_grpc_terminate_encoding`. Malformed or oversized output fails closed and never falls through with `on_error: "continue"` — including the **raw** response that crosses `max_response_body_bytes` before the contract is parsed at all, which is classified as function output rather than as an ordinary invocation failure and therefore rejects with the `response_body_too_large` class instead of proxying the request to the backend. Ordinary invocation failures (connect, timeout, transport reset, a provider-reported function error) keep the documented `continue` behavior. Errors normalize to trailers-only gRPC failures (HTTP 200 + `grpc-status`) without reflecting the untrusted function body. gRPC-Web terminate remains unsupported and is refused before invocation. The refusal reads the request-scoped gRPC-Web markers, not the live `content-type`: when the `grpc_web` plugin is enabled it has already rewritten the request to `application/grpc` by the time this plugin runs, so a translated browser request is refused rather than framed as native gRPC.

A successful unary response is HTTP 200 with `content-type: application/grpc`, optional DATA, and terminal trailers. Trailers-only responses (no `message_base64`) keep `grpc-status` in the initial HEADERS block.

This is the only plugin rejection allowed to put a body on a native gRPC stream, and the authorization is request-scoped provenance rather than response shape: the gateway records the exact frame, the HTTP status, and the terminal trailers this contract produced, and preserves them only for a rejection that still matches all of them. Any other rejection — including one whose body happens to be a well-formed unary frame and whose headers claim `application/grpc` plus `grpc-status` — normalizes to trailers-only, as does this one if a later `after_proxy` decorator or response-body transform rewrites the body. Client-visible trailers come only from the validated contract above, so gateway-managed and decorator-added response headers (CORS, header policy, internal bridge fields) stay in the initial HEADERS block and can never surface as custom trailers.

Because it is a real client-visible representation rather than a trailers-only error, the framed terminate response also enters the shared response-body policy lifecycle (`on_response_body`, representation admission, response transforms, `on_final_response_body`) under the same two-tier buffering gate every other synthetic short-circuit uses, so configured gRPC response validators, guardrails, and size limits are not bypassed. Ordinary gRPC rejections and gRPC-Web stay trailers-only and skip that lifecycle — they carry no body to inspect.

Invalidating the authorized representation fails closed. If a body policy replaces the response, or a transform rewrites the authorized frame without selecting a new rejection, the frame is dropped **and** the contract's `grpc-status` is discarded with it: a rejection that chose its own status normalizes to that status' gRPC error, and a residual `grpc-status: 0` becomes `INTERNAL` with a gateway-authored `grpc-message`. A successful unary response can never degrade into an empty Trailers-Only success, and a later unrelated rejection can never inherit the original successful trailers.

The status-only shape (no `message_base64`) carries the same provenance even though it authors no DATA, so it is governed the same way. While the reply is unchanged — the authored HTTP status and a still-empty body — it is legitimately trailers-only, and its **complete** terminal metadata is restored from the validated contract rather than read out of the reject header map, which by then has been through `after_proxy` decorators, initial-response-header policy, and the shared body lifecycle: `grpc-status`, `grpc-message` when the contract supplied one, `grpc-status-details-bin`, and every validated custom trailer. Non-terminal response decorators may still contribute initial response headers, but they cannot alter, drop, or inject contract terminal metadata. An omitted `grpc_message` is emitted as omission — a status-only success (`grpc_status: 0` with no message) does not gain a synthesized error string, and neither does a nonzero contract that deliberately said nothing.

If the status changes, or a body the contract never authored appears, the reply fails closed exactly like an invalidated framed response: the unauthorized bytes are dropped and a residual `grpc-status: 0` becomes a nonzero gRPC error. Invalidation also discards *every* terminal key the contract authored, so a replacement error never ships beside the original contract's `grpc-status-details-bin` (which encodes the successful response the client is not receiving) or its custom trailers. The status-only provenance can never authorize DATA, because the contract authored none. H1/H2, native HTTP/3, and the HTTP/3 cross-protocol bridge resolve all of this through one shared representation, so the three paths cannot drift; only the intentionally distinct HTTP-to-gRPC status table used by the HTTP/3 writer differs. The native HTTP/3 finalized-request-egress rejection is written through the same context-aware writer every other H3 plugin rejection uses, so the authored frame and terminal metadata carry their request-scoped provenance across that boundary and an original gRPC-Web client's refusal keeps browser framing rather than being re-encoded as native gRPC.

In `terminate` mode for ordinary HTTP, applicable end-to-end function response headers (including repeated `Set-Cookie`, benign singleton `Location`, `Content-Location`, and `Refresh`, list-valued `Link`, `Retry-After`, `ETag`, and `Content-Disposition`) are returned with the function status/body. Hop-by-hop, `Connection`-listed, transport-managed, provider-control, and credential-bearing fields are stripped.

**Signed-URL leak protection.** The URL-valued headers `Location`, `Content-Location`, `Refresh` (`url=` and bare URI forms after semicolon, comma, or ASCII-whitespace delay separators), and every target in `Link` are also removed when a relative, absolute, encoded, or nested target exposes the configured function's signed path/query components. Multiple field lines for a singleton URL-valued header fail closed instead of being comma-folded; repeated `Link` lines are revalidated as the exact combined list returned downstream. A complete signed path is matched at slash-delimited segment boundaries even when the response adds prefix or descendant segments, but not inside lookalikes such as `/signed/triggered`. Both non-empty components of every configured query pair are protected credential scalars: a key remains protected whether it is key-only (`?SIGNED_TOKEN=`) or paired with a value (`?SIGNED_TOKEN=1`), and a non-empty value is protected independently. Each scalar remains protected if copied into either side of another query pair, into a decoded path at URI-component boundaries (including path-parameter/query delimiters), or into a decoded fragment at URI-component boundaries. Decoded scalar fragments are checked directly even when they are not themselves URI-shaped. Query comparison follows generic URI semantics: percent escapes are decoded, but a literal `+` remains `+` rather than becoming a form-data space. URI userinfo, malformed target syntax, malformed percent triplets, percent-decoded non-UTF-8 bytes, and inspection-budget overflow fail closed even when the configured function uses a root path with no signed query. Explicit numeric authority ports are inspected before URL normalization can erase a scheme's default port. Inspection is bounded to 16 KiB per URL-valued field, 32 `Link` targets, 32 embedded path URI references, eight percent-decoding transforms, and two nested URI-reference hops. Residual encoding or another structural URI reference at the nesting boundary also removes that field rather than forwarding an unproven target; ordinary non-URL `Refresh` directives, quoted `Link` parameters, unrelated same-origin/cross-origin targets, and scalar labels that contain no signed component remain observable. This bounded fail-closed boundary prevents deeper redirector chains from hiding a signed destination without introducing unbounded decoding or substring matching.

**Framing and body lifecycle.** Ferrum recomputes framing; HEAD, 204, 205, and 304 responses have no body. Every other non-empty final 2xx-5xx terminate response is application-owned content and enters the shared synthetic response-body lifecycle when an active plugin requests buffering. Successful-response guardrails retain their configured status scope, while response transforms also apply to function redirects and errors; changed bytes receive the same stale range, validator, digest/checksum, and content-bound-signature invalidation as a transformed backend response. Ordinary gateway-generated non-2xx rejections remain outside this body-transform contract. `206 Partial Content` and `226 IM Used` are not transformed because their bytes depend on range or delta metadata; their statuses, representation metadata, and bodies remain coherent. Transform-dependent header hooks also decline them instead of relabelling untouched bytes. Inspection still runs, and an enforcing redaction-dependent plugin rejects governed range/delta content when it cannot safely rewrite those bytes.

The complete slash-trimmed signed function path is also protected when copied exactly into either side of a decoded redirect query pair. For example, a function destination ending in `/api/signed-token` causes `?leak=api/signed-token` and `?api/signed-token=other` to be stripped even when the destination has no signed query. Longer scalar lookalikes such as `api/signed-token-extra` remain observable.

Protected query scalars also govern exact ASCII-case-insensitive URI scheme copies such as `secret://attacker.example`; longer scheme lookalikes remain observable.

Leading and trailing slashes are part of each protected query scalar and are never trimmed. A slash-only scalar remains governed and therefore causes ambiguous URL-path surfaces to fail closed rather than becoming an empty, unprotected value. DNS-compatible scalars are also protected when copied as complete hostname-label sequences in a response URL authority, including the lowercase/IDNA-normalized form a URL parser sends to DNS; exact numeric port copies are protected as well, including explicit default ports that URL normalization omits. Longer label and substring lookalikes remain observable.

If request deduplication acquired an idempotency key earlier in the chain, each deduplication instance independently stores the final terminal status/body plus a cache-safe subset of the settled headers, so one instance cannot consume another instance's completion ownership. Candidate admission and cache construction reject terminate-mode priority overrides that place the function at or before any applicable `request_deduplication` instance; identical retries therefore cannot reach the external side effect before ownership is acquired. A function payload-validation, unsupported-gRPC-Web terminate refusal, DNS denial, or denied literal-IP endpoint proven to occur before invocation releases every acquired local/Redis owner after the rejection is committed, allowing a corrected retry immediately; a real remote 502 is an application response, and other failures after invocation becomes possible retain the existing uncertain-side-effect protection. Replay is deliberately not a byte-for-byte copy of the first response headers: security sanitization removes session/credential fields such as `Set-Cookie`, `Authorization`, and `WWW-Authenticate`, per-request `Retry-After`, trace/correlation headers, and rate-limit counters before storage and again on replay. The stored body is already the finalized client representation, so a replay does not run ordinary presentation transforms a second time; response inspectors and final-body validators still evaluate it. If current inspection records a redaction decision, that policy's transform alone must rewrite the replay under the current policy or the replay fails closed with 502. Empty and HEAD terminal responses are still covered through the final committed-response hook even though there are no body bytes to inspect or transform. If the function may already have executed but `on_error: "continue"` falls through to a streamed backend response, each owning in-flight marker is retained until its TTL even after a clean stream completion because no replayable function response exists.

## Environment Variable Fallback

Cloud credential fields fall back to well-known environment variables when not set in plugin config. Config values always take precedence. These env vars may themselves be resolved by the gateway's secret resolution system (Vault, AWS Secrets Manager, etc.). The Azure function key and GCP bearer token are sent to the config-chosen `function_url`, so their fallbacks are confined to the [plugin-secret namespace](../configuration.md): `FERRUM_PLUGIN_SECRET_AZURE_FUNCTIONS_KEY` and `FERRUM_PLUGIN_SECRET_GCP_CLOUD_FUNCTIONS_BEARER_TOKEN`. The ambient `AZURE_FUNCTIONS_KEY` / `GCP_CLOUD_FUNCTIONS_BEARER_TOKEN` variables are never read.

## Workload identity (`aws_credentials: default_chain`)

`aws_credentials: default_chain` signs Lambda invocations with the gateway process's own AWS identity from the AWS SDK default credential chain, in order: the `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN` variables, shared config/credentials profile files, web identity (EKS IRSA: `AWS_WEB_IDENTITY_TOKEN_FILE` + `AWS_ROLE_ARN`), ECS container credentials (task roles), and EC2 instance metadata (IMDSv2 instance profiles). This is how IAM-role-only deployments run without long-lived keys.

- **Refreshed before expiry, without blocking requests.** The current credential is read lock-free on every invocation. Five minutes before it expires one background refresh starts while requests keep signing with the still-valid credential. Only when no usable credential is cached (first use, or after a failed renewal let it expire) does a request wait — at most 10 seconds — for one fetch that every concurrent request shares. A failed fetch backs off for 5 seconds. A credential within 10 seconds of expiry is never signed with.
- **Fails closed.** With no usable credential the invocation fails before anything is sent, with the fixed class `aws_credentials_unavailable`, under `on_error` / `error_status_code`. A provider answer whose key id or session token is not an HTTP field value is refused the same way.
- **Scoped like process-environment credentials.** The chain is the process's own identity, so every rule in [Ambient AWS credential scope](#ambient-aws-credential-scope) applies — region grammar, official endpoints only, the per-request re-check, the `AWS_LAMBDA_ENDPOINT_URL` trust rule, and the explicit `allow_custom_endpoint_with_ambient_credentials` opt-in — including in CP/admin shape-only admission.
- **No literal credentials alongside.** `aws_access_key_id`, `aws_secret_access_key`, and `aws_session_token` are refused with `default_chain`.
- **Feature-gated.** The chain is compiled in with the `secrets-aws` (or `cloud-secrets`) Cargo feature, which already carries `aws-config` for the AWS Secrets Manager backend. CP/admin shape-only admission accepts the row on any build (whether the serving node carries the chain is node-local, like its credentials); a serving node built without the feature refuses to construct it.

## Ambient AWS credential scope

The AWS credential fallbacks (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`) are a different trust class from the `FERRUM_PLUGIN_SECRET_<NAME>` namespace. A plugin-secret value is one the environment owner deliberately placed where plugin configs may use it, so it may follow a config to its chosen endpoint. The standard AWS variables are the gateway process's own cloud identity — often exported for unrelated reasons (a launcher that copies a task role or instance profile into the environment, a CI runner) — and the principal writing plugin config (an admin API `operator`, a CP tenant, a mesh policy author) does not own them. The same rule therefore applies to `serverless_function` (`aws_lambda`) and to `ai_federation` (`aws_bedrock`).

By default these plugins read **only** those three variables (plus the region variables and, for Lambda, `AWS_LAMBDA_FUNCTION_NAME` / `AWS_LAMBDA_ENDPOINT_URL`) from the process environment. The only consumer of the AWS SDK default credential chain — instance metadata (IMDS), ECS container credentials (`AWS_CONTAINER_CREDENTIALS_*`), web identity tokens, and shared config or credentials profile files — is `serverless_function` with the explicit [`aws_credentials: default_chain`](#workload-identity-aws_credentials-default_chain) opt-in, and those credentials are held to the same scope, so the scope below covers every ambient credential source either plugin uses. A value the gateway's external secret resolution writes into those variables (the `_VAULT`, `_AWS`, `_FILE`, … suffixes) is treated as ambient too.

- **Config credentials are not scoped.** When `aws_access_key_id` and `aws_secret_access_key` (and `aws_session_token`, when one is used) are written into the plugin config, they are the config author's own credentials and may sign requests for any endpoint the config validly names — a LocalStack origin, a mock server, a corporate proxy. `AWS_SESSION_TOKEN` is never paired with a config key pair: an STS session token is bound to its access key, so the environment token is only used when the key id and secret also came from the environment.
- **Process-environment credentials are scoped to the service.** When the key id or the secret resolves from the environment, the region must be a commercial (`us|eu|ap|sa|ca|me|af|il|mx-<area>-<n>`), GovCloud (`us-gov-<area>-<n>`), or China (`cn-<area>-<n>`) region — the AWS SDK partition grammars, with lowercase letters only — and the endpoint the config chooses must be an official endpoint of that service for that region, over HTTPS on the default port:
  - `<service>[-fips].<region>.amazonaws.com`,
  - dual-stack `<service>[-fips].<region>.api.aws`,
  - an interface VPC endpoint `vpce-<id>[-<az>].<service>[-fips].<region>.vpce.amazonaws.com`,

  where `<region>` is a commercial or GovCloud region; a China (`cn-*`) region uses `amazonaws.com.cn` in place of `amazonaws.com` and the dual-stack `api.amazonwebservices.com.cn` in place of `api.aws`. No other pairing of region and suffix matches.

  `<service>` is `lambda` for `serverless_function` and `bedrock-runtime` for `ai_federation`. Generic `*.amazonaws.com` is deliberately **not** accepted: customer-owned EC2 DNS names, load balancers, API Gateway stages, and S3 buckets and websites live under that suffix too. That is also why the region is matched against the partition grammar rather than its shape: a legacy dash-style S3 host such as `lambda.s3-us-west-2.amazonaws.com` is the bucket named `lambda`, and `s3-us-west-2`, `s3-external-1`, or `s3-website-us-east-1` is not a region. The config-chosen endpoint is the host derived from `aws_region` (so a malformed region cannot redirect the derived host), `aws_endpoint_url`, or the Bedrock `base_url`.
- **`AWS_LAMBDA_ENDPOINT_URL` is trusted like the environment credentials.** It is set by the same environment owner, so when a `serverless_function` row sets no `aws_endpoint_url`, an `AWS_LAMBDA_ENDPOINT_URL` endpoint (the usual LocalStack setup) needs no opt-in. The region is still screened, and a config-set `aws_endpoint_url` stays scoped even when `AWS_LAMBDA_ENDPOINT_URL` is set.
- **Partitions without public endpoints need the opt-in.** The air-gapped ISO partitions (`us-iso-*`, `us-isob-*`, `eu-isoe-*`, `us-isof-*`) and the AWS European Sovereign Cloud (`eusc-*`, `*.amazonaws.eu`) use their own region grammars and DNS suffixes and are not modelled, so process credentials reach them only through `allow_custom_endpoint_with_ambient_credentials` (the region screen applies even with an `AWS_LAMBDA_ENDPOINT_URL`).
- **Enforced twice.** Configuration admission refuses an out-of-scope region or endpoint with a validation error that names the environment-resolved fields and the opt-in, never the endpoint, the region, or a credential. CP/admin shape-only admission of `serverless_function` cannot see a serving node's environment, so whenever the row omits the key pair it screens a configured `aws_region` (even with no endpoint configured) and a configured `aws_endpoint_url`; the serving node re-checks the fully resolved values when it builds its plugin cache. Every request then re-checks the endpoint before signing: `serverless_function` fails closed with `500` (`ambient_credential_endpoint_refused`) regardless of `on_error`, and `ai_federation` treats it as a pre-wire dispatch-policy rejection of that provider. Both emit a sampled warning that names the redacted destination or the provider, never a credential.
- **Explicit opt-in.** `allow_custom_endpoint_with_ambient_credentials: true` (a top-level `serverless_function` field, a per-provider `ai_federation` field; default `false`) lifts the scope for that instance or provider, for a deliberately chosen private endpoint such as LocalStack or an air-gapped partition. Anyone who can write that plugin config can then direct the process credentials to the endpoint it names, so prefer config credentials (or an official VPC endpoint, which needs no opt-in) where possible.

Azure Functions and GCP Cloud Functions credentials have no process-environment fallback outside the plugin-secret namespace, and `ai_federation` reads no ambient credential for any provider other than `aws_bedrock` (Google Vertex service-account OAuth is additionally pinned to `https://oauth2.googleapis.com/token`).

## Example: AWS Lambda pre-proxy enrichment

```yaml
plugin_name: serverless_function
config:
  provider: aws_lambda
  aws_region: us-east-1
  aws_function_name: enrich-request
  mode: pre_proxy
  forward_headers: ["authorization", "x-request-id"]
  forward_body: true
  timeout_ms: 3000
  on_error: continue
```

## Example: Azure Functions terminate mode

```yaml
plugin_name: serverless_function
config:
  provider: azure_functions
  function_url: https://my-app.azurewebsites.net/api/compute
  mode: terminate
  forward_body: true
  timeout_ms: 10000
```

---
