# AI Prompt Compressor Plugin

`ai_prompt_compressor` shortens the prompt text sent to an LLM backend to reduce
token usage — and therefore cost and latency — while preserving meaning. It
rewrites prompt-bearing fields only in admitted OpenAI Chat Completions and
legacy Text Completions request representations — plus, as explicit
fixed-family opt-ins, OpenAI Responses and Anthropic Messages bodies —
replacing long content strings with shorter, statistically filtered versions
before the request is forwarded upstream.

- **Priority:** `4055` (Response band, immediately after `compression`).
- **Protocols:** HTTP only. Native gRPC wire frames are not compressed.
- **Lifecycle:** request buffering is enabled only for candidate JSON `POST`
  bodies; `before_proxy` rewrites direct-dispatch metadata and stages bounded
  state; `transform_request_body_with_context` produces the final wire bytes
  (`transform_request_body` remains for context-free callers);
  `on_final_request_body_with_context` rejects requests whose marker
  sanitation failed or whose final representation still carries a configured
  marker.
- **Failure policy:** `KeepLastKnownGood` — a bad config is rejected at
  load/reload without failing an already-serving cache.

## How it works

The plugin is **model-free**: it embeds no language model, makes no network
calls, and adds no new crate dependencies. Instead of running a transformer to
score token importance, it uses a compact statistical **extractive** filter:

1. **Tokenize** the content into words, preserving structure. Whitespace-run
   boundaries and paragraph breaks are tracked so the output stays readable.
2. **Protect structural spans** that must never be altered — fenced/inline code
   delimited by matching backtick runs of any length, URLs (`http://`,
   `https://`), Unicode numbers, `snake_case`, `lowerCamelCase`, multi-capital
   `PascalCase`, `kebab-case`, and uppercase acronyms are always kept verbatim.
3. **Score each candidate word** by a handful of cheap features:
   - stop-word membership (common filler words score lowest),
   - length (longer words tend to carry more meaning),
   - in-document rarity (a word used once outranks a frequently repeated one),
   - a proper-noun / entity signal (an original-case leading capital).
4. **Always keep critical words** so meaning is not inverted or widened:
   negations (`not`, `never`, `cannot`, `won't`, …) and the restrictive
   connectives `unless`, `except`, and `only` — each together with the word
   right after it — plus conditions and obligations (`if`, `must`, `before`,
   `after`, `until`, `exactly`), quantifiers (`all`, `every`, `each`, `any`),
   and spelled-out numbers (`zero` … `twelve`, `hundred`, `thousand`,
   `million`, `billion`). Matching is case-insensitive, so an uppercase `NOT`
   or `DON’T` is a critical word rather than a protected acronym and still
   protects its complement.
5. **Drop the lowest-scoring words** until roughly `target_ratio` of the words
   remain, then reconstruct the text with single-space and newline separators.

The transformation is intentionally lossy (extractive compression removes filler
words), which is why it only runs on roles you opt into and only on content long
enough to be worth compressing.

### What gets compressed

- OpenAI Chat Completions `messages[].content` for every message whose `role` is
  in `compress_roles`.
  Both the string form and the multimodal array form
  (`[{ "type": "text", "text": "…" }, …]`) are handled; non-text parts (e.g.
  `image_url`) are left untouched.
- OpenAI legacy Text Completions `prompt` (string or array of strings) — but
  only when `"user"` is an eligible role, since a completions prompt is user
  text.
- With `request_family: responses`, an OpenAI Responses body: a string
  `input` (user text, so only when `"user"` is eligible), the `input_text` /
  `output_text` parts (or string `content`) of `input` message items whose
  `role` is eligible, and `instructions` when `system` or `developer` is
  eligible. Other item kinds (`function_call`, `function_call_output`,
  `reasoning`, item references, …) and non-text parts are left untouched.
- With `request_family: anthropic_messages`, an Anthropic Messages body:
  `messages[].content` (string or `text` blocks) for eligible roles and the
  top-level `system` prompt (string or `text` blocks) when `system` is
  eligible. `tool_use`, `tool_result`, image, document, and thinking blocks
  are left untouched.

With `request_family: auto` (the default), the parsed shape must agree with a
standard operation path ending in `/chat/completions` or `/completions`.
Image-generation paths, arbitrary JSON carrying a `prompt`, provider-native
markers, mixed `messages`+`prompt` bodies, malformed JSON, and other shapes
rejected by coarse family classification pass through unchanged. That
unchanged promise does not extend to every malformed inner field: coarse
classification accepts a `messages` array before `role`/`content` validation,
so valid JSON with an admitted coarse shape but malformed inner `role` or
`content` fields (for example a non-string `role`) skips statistical
compression yet, when `preserve_tag` is configured, still goes through the
marker-only fallback that strips configured markers from JSON string values.
Without a configured `preserve_tag`, that fallback is a no-op and the body
passes through unchanged. A fixed request family is the explicit
opt-in for a compatible custom endpoint path; shape validation still applies.
For example, `request_family: chat_completions` admits a compatible `/custom`
endpoint whose body would pass through unchanged under `auto`. `auto` never
admits Responses or Anthropic Messages bodies; their fixed families reject a
body carrying another provider's markers, a legacy `prompt`, or (for
`responses`) a `messages` array.

Only the decoded values of targeted fields are intentionally compressed. When a
normal admitted field rewrite succeeds (including below-floor marker cleanup),
Ferrum serializes the **complete** parsed JSON value to new bytes. Non-target
decoded values remain semantically equal, but lexical JSON details are not
preserved: whitespace is compacted, equivalent escape spellings can normalize,
duplicate object names collapse according to `serde_json`'s last-value behavior,
and original numeric spelling/object-member byte order are outside the contract.
Marker-only bounded fallbacks instead remove configured markers directly from
admitted JSON string **values**. Object member names are never sanitized and
remain byte-for-byte unchanged, including their original escape spelling.
Every other source byte is preserved as well. Requests with neither a successful
rewrite nor value cleanup retain their original bytes.

## Configuration

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `compress_roles` | string[] | `["user"]` | Message roles whose `content` is compressed (trimmed and case-insensitive). Must be non-empty, with at most 32 entries of at most 64 characters and no blank entries. When it contains `user`, the legacy top-level `prompt` (and a string Responses `input`) is compressed too; `system` covers the Anthropic `system` prompt, and `system` or `developer` covers Responses `instructions`. |
| `target_ratio` | number | `0.5` | Fraction of word-tokens to keep. `0.5` targets ~50% reduction; `0.3` is more aggressive. Must be strictly between `0` and `1`. |
| `min_content_tokens` | integer | `200` | Estimated-token floor per content string. Range `0..=131072`; content below this is passed through unchanged so short prompts are not mangled. |
| `max_scan_bytes` | integer | `1048576` | Skip statistical compression when the request body exceeds this many bytes. Range `1..=1048576`; the upper bound is immutable. Configured preserve-marker sanitation remains active up to the hard maximum. |
| `preserve_tag` | string | _(unset)_ | Optional marker name. Text wrapped in `<TAG>…</TAG>` is copied through verbatim and all markers are stripped. Nested spans are flattened; unmatched open text is preserved to the end; unmatched closes are stripped. Must contain 1–64 ASCII letters, digits, `-`, and `_`. |
| `request_family` | string | `auto` | `auto` requires the body shape to agree with a standard `/chat/completions` or `/completions` path. Use `chat_completions` or `text_completions` only as an explicit assertion for a compatible custom endpoint. `responses` and `anthropic_messages` admit OpenAI Responses and Anthropic Messages bodies on any path; `auto` never does. Fixed `text_completions` configurations must include `user` in `compress_roles` because the top-level prompt is user text. |
| `target_max_tokens` | integer | _(unset)_ | Optional aggregate estimated-token budget, `1..=131072`, for all eligible prompt text in one request. Requests within it are not statistically compressed; larger requests keep a per-request word ratio of `target_max_tokens / eligible_tokens`, never more aggressive than `target_ratio`. |
| `mode` | string | `enforce` | `enforce` forwards compressed prompts. `observe` runs the identical bounded pipeline, records would-be savings, and forwards the original prompt text. |
| `sample_rate` | number | `1` | Fraction of requests, greater than `0` and at most `1`, eligible for statistical compression (or observation). |

Token counts are **estimated** with a ~4-characters-per-token heuristic; the
plugin embeds no model tokenizer, so `min_content_tokens` and the reported
savings are approximations. Integer fields accept any mathematically integral
JSON number (`200` and `200.0` alike); fractional, negative, and out-of-range
values are rejected.

### Budget mode, observe mode, and sampling

`target_max_tokens` is a context-window control: short requests are left
intact and only requests whose eligible text (estimated over the concatenated
eligible fields) exceeds the budget are compressed, removing only as much as
needed. `target_ratio` remains the most aggressive keep ratio allowed, and the
per-field `min_content_tokens` floor still applies. The budget is **best
effort**: the keep decision targets words rather than estimated tokens, and
protected spans, critical words, and the `target_ratio` floor are always kept,
so a request can remain above the budget. Such a request is forwarded at the
best achievable size rather than refused; pair the plugin with
`ai_request_guard` if an absolute ceiling must be enforced.

`mode: observe` is the safe rollout posture for this intentionally lossy
transform. It computes exactly what `enforce` would, records the would-be
counters under separate `ai_prompt_compressor.observed_*` keys (see
Observability), and forwards the original prompt text. Configured
`preserve_tag` markers are still removed and still fail closed in observe mode.

`sample_rate` applies statistical work to a fraction of requests. The decision
is deterministic per request and per instance (derived from the request's
receive time), so the metadata stage, the wire transform, and retries agree.
An unsampled request is forwarded uncompressed and records
`ai_prompt_compressor.instances.<id>.skipped = not_sampled`; marker sanitation
applies to every request. The context-free compatibility transform has no
request identity and treats every request as sampled.

The scan ceiling is only the outer bound. Before token allocation or scoring,
the plugin rejects compression work for a body containing more than 524,288
eligible prompt bytes, 32,768 combined whitespace/tokenizer/marker work units,
256 rewritable text fields, or 1,024 configured preserve markers. Scoring uses
linear-time partial selection rather than sorting all candidates. Complete JSON
output may grow beyond `max_scan_bytes` when untouched short-exponent numbers
normalize, but it can never exceed the immutable 1,048,576-byte output bound.
A process-wide eight-job admission budget prevents concurrent statistical
compressors from multiplying intermediate allocations. Admitted jobs run on
Tokio's blocking worker pool instead of request executors; saturated or
over-budget statistical work passes through unchanged when no preserve tag is
configured, and records a skip reason (see Observability). Without a preserve
tag, a body too short for any field to reach `min_content_tokens` (or to exceed
`target_max_tokens`) is skipped before it is copied or parsed.

When `preserve_tag` is configured, marker removal is a separate bounded
correctness path: up to 32 sanitation jobs parse and classify concurrently.
Saturation fails closed before cloning the buffered body instead of retaining a
waiter queue. If statistical compression is saturated, any work counter is
exceeded, or JSON reserialization would exceed the hard output bound, the
plugin removes markers directly from admitted JSON string values while never
changing object member names. This value-only pass preserves all other source
bytes (including whitespace, duplicate names, member order, escapes, and number
spelling). Escaped marker spellings such as `\u003ckeep\u003e` are recognized in
values too. Removal repeats until a pass changes nothing, because deleting one
marker can join its neighbours into a new one (`<ke<keep>ep>` becomes
`<keep>`); at most eight linear passes run, and anything still left is refused
by the final residual-marker check below. The gateway applies a 1,048,576-byte
plugin-local buffer limit to these candidate requests even when its global body
limit is unlimited; a larger candidate is rejected with `413`, while sanitation
worker unavailability is rejected with `503`. The context-free compatibility
transform has no rejection channel and returns an empty, marker-free invalid
request representation on that exceptional failure. Reusable transformed-body
staging is separately capped at 65,536 bytes; larger direct-dispatch prompts
retain only the metadata representation.

An empty config object (`{}`) is valid and applies the defaults: on standard
OpenAI Chat/Text Completions paths, compress `user` content longer than ~200
tokens down to ~50%. Unknown fields, explicit `null`, wrong types, and values
outside the documented ranges reject the config instead of selecting defaults.

### Examples

Default behavior — compress long user prompts to ~50%:

```json
{
  "plugin_name": "ai_prompt_compressor",
  "config": {}
}
```

Aggressive compression of both user and system messages, protecting a span:

```json
{
  "plugin_name": "ai_prompt_compressor",
  "config": {
    "compress_roles": ["user", "system"],
    "target_ratio": 0.35,
    "min_content_tokens": 150,
    "preserve_tag": "keep"
  }
}
```

Observe what a budget-driven rollout would save on an Anthropic Messages route
before enforcing it, sampling a quarter of traffic:

```json
{
  "plugin_name": "ai_prompt_compressor",
  "config": {
    "request_family": "anthropic_messages",
    "compress_roles": ["user"],
    "target_max_tokens": 8000,
    "mode": "observe",
    "sample_rate": 0.25
  }
}
```

With `preserve_tag: "keep"`, a prompt such as:

```
Summarize the following retrieved context for the user, and be concise.
<keep>Order #ABC-9931-XYZ ships on 2026-07-10.</keep>
... (long retrieved context) ...
```

keeps `Order #ABC-9931-XYZ ships on 2026-07-10.` verbatim (markers removed) while
compressing the surrounding instructions and context.

## Ordering and interactions

The priority (`4055`) places the compressor **after** the AI security and policy
plugins and after `compression` request decompression:

- `ai_prompt_shield` (2925), `ai_semantic_firewall` (2968), and
  `ai_request_guard` (2975) see the original content — compression never blinds
  PII detection, prompt-injection detection, or request validation.
- `ai_semantic_cache` (4057) looks up **after** this plugin, over the
  compressed backend-visible prompt and after this plugin's final hook has
  enforced any staged marker-sanitization rejection. A cached completion is
  therefore keyed to the bytes the provider would actually receive, and a hit
  can never bypass a rejection this plugin already decided on. Enabling
  compression on a route changes its cache keys, so existing entries stop
  matching.
- `compression` (4050) can decode opt-in gzip/brotli request bodies before the
  compressor rewrites the standard backend-dispatch body.

How the compressed body reaches the backend:

- On the standard backend-dispatch path, the context-aware request-body
  transform produces the bytes actually sent upstream. With opt-in gzip/brotli
  request decompression, the decompressed plaintext is what gets compressed and
  measured.
- For already-plaintext JSON uploads, `before_proxy` also rewrites
  `ctx.metadata["request_body"]` so direct dispatchers that read that metadata
  forward the compressed prompt.
- Results of at most 65,536 bytes are staged privately and reused when the
  input is unchanged; larger results are recomputed at wire dispatch under the
  same work budget. If an earlier wire transform changed the bytes, the stage is
  discarded and the plugin recomputes against the actual body.
- `auto` family admission always uses the original incoming path, even when
  routing rewrites the backend path, so staging and recomputation cannot change
  eligibility.
- `ai_federation` consumes the final request body after decompression and this
  transform, so provider dispatch uses the same compressed representation.

The final context-aware body hook is the fail-closed backstop for the exact
backend-visible representation. For example, if request decompression produces
more than the immutable 1,048,576-byte marker-sanitation ceiling, the request
is rejected before backend dispatch rather than forwarding configured markers.
Marker-sanitation worker exhaustion returns a gateway-local `503`; it is never
retried or charged to backend circuit-breaker and passive-health accounting.

With a configured `preserve_tag`, the final hook also re-verifies the final
body of every candidate JSON `POST` (in `auto`, one on a standard operation
path). An admitted body whose string values still contain a configured marker
is refused with `400` — for example a marker written by a body transform that
runs after this plugin (a `request_transformer` rule with a later
`priority_override`), or one that bounded removal could not resolve. Bodies
with neither a literal `<` nor a `\u003c` escape skip the check after one
linear byte scan; the check otherwise runs on the bounded sanitation lane, so
saturation is a `503` and a final body above the hard ceiling is a `413`.

A content-coded body is never compressed (only configured `compression`
request decompression exposes plaintext to the rewrite). With a configured
`preserve_tag`, such candidates are buffered and claimed by the shared request
representation gate, which decodes `gzip`/`br` codings into an inspection view
the final hook verifies; an unsupported or malformed coding is refused with
`400` by the gate. The encoded bytes are forwarded unchanged when no marker is
found.

If `ai_prompt_shield` is redacting, the compressor operates on the already
redacted text, so redaction is preserved and then compressed.

## Observability

When compression rewrites a field, the plugin records log-safe counters on the
request context (in `mode: observe`, the same four counters are recorded as
`ai_prompt_compressor.observed_original_tokens`, `.observed_compressed_tokens`,
`.observed_tokens_saved`, and `.observed_fields_compressed`, plus the matching
`instances.<id>.observed_*` keys, and the unprefixed keys stay absent). Standard dispatch clears provisional metadata-copy counters and
records the authoritative wire transformation; direct metadata dispatch retains
the counters for the exact body it consumes:

- `ai_prompt_compressor.original_tokens`
- `ai_prompt_compressor.compressed_tokens`
- `ai_prompt_compressor.tokens_saved`
- `ai_prompt_compressor.fields_compressed`

The unsuffixed keys aggregate all configured compressor instances. Each instance
also emits the same four counters under
`ai_prompt_compressor.instances.<process_instance_id>.*`, so one instance never
overwrites another or double-counts a retry. Context-free compatibility
transforms cannot write request metadata and therefore emit no counters.

When statistical compression of an admitted candidate is skipped for a reason
other than ordinary ineligibility, the instance records
`ai_prompt_compressor.instances.<process_instance_id>.skipped` with one of:

- `saturated` — the process-wide eight-job statistical budget was full;
- `work_limit` — the body exceeded `max_scan_bytes`, a work counter, or the
  output bound;
- `not_sampled` — the request fell outside `sample_rate`.

A short, ineligible, or within-budget request records no skip reason.

## Safety and limitations

- **Only JSON POST bodies are touched.** Non-JSON content types, non-`POST`
  methods, and unparseable JSON are forwarded unchanged. Bodies over
  `max_scan_bytes` skip statistical compression; with `preserve_tag` configured,
  admitted bodies still remove markers up to the immutable hard ceiling.
- **Only admitted request families are touched.** `auto` requires a standard
  Chat/Text Completions path and matching shape. Fixed-family mode is an
  operator assertion for custom compatible endpoints; unsupported, ambiguous,
  or malformed shapes rejected by coarse classification still pass through
  unchanged. Valid JSON admitted at the coarse level but with malformed inner
  `role`/`content` fields skips statistical compression; with `preserve_tag`
  configured it can still receive marker-only string-value cleanup (see
  above), and without one it passes through unchanged.
- **Encoded bytes are never rewritten.** A non-`identity` `Content-Encoding`
  stays untouched unless an earlier configured decompression transform produces
  plaintext on the standard wire path. With `preserve_tag` configured, the
  decoded view is still verified for markers (see above).
- **Extractive output is terse.** Compression removes filler words, so the
  rewritten prompt reads as clipped, keyword-dense text. LLMs handle this well,
  but review `target_ratio` for quality-sensitive workloads and prefer a higher
  ratio (or a `preserve_tag`) where exact wording matters.
- **Token counts are estimates**, not a provider tokenizer's exact count.
- **Only the documented prompt fields are compressed.** Under `auto`, only
  `messages[].content` and the legacy `prompt`; Responses and Anthropic
  Messages fields only under their fixed families. Other prompt-carrying
  shapes (embeddings `input`, Gemini `contents`, Bedrock and Cohere bodies)
  are deliberately left intact.
- **Negations and restrictive connectives keep their complement.** Negation
  words (including uppercase and curly-quote contractions such as `DON’T`),
  `unless`, `except`, and `only`, and the word immediately after each, are
  always kept, so a surviving "not" cannot re-bind to a later clause.
  Conditions, obligations, quantifiers, and spelled-out numbers are kept too.
  Longer qualified phrases can still lose trailing words — prefer
  `preserve_tag` around meaning-critical instructions.
- **English/space-delimited text is assumed.** Scoring tokenizes on ASCII
  whitespace, so unsegmented scripts (CJK, Thai) inside a message form one
  oversized token that may be kept or dropped wholesale. Do not enable
  compression for roles that routinely carry such content.
- **Pasted structured data is scored as prose.** JSON/YAML/CSV embedded in a
  message (outside code fences) can still lose ordinary digitless lowercase
  keys and values. Wrap such payloads in a fenced code block or a
  `preserve_tag` span.
- **`preserve_tag` markers never reach the provider for an admitted request
  family when they occur in string values.** Markers are stripped from balanced,
  repeated, adjacent, nested, malformed, and JSON-escaped value sequences, even
  when content is below
  `min_content_tokens`, compression yields no reduction, work/output limits are
  exceeded, or statistical admission is saturated. Object member names are a
  schema boundary: their bytes are always left exactly as received, even when a
  name contains literal or escaped preserve markers. Invalid JSON and
  unsupported/ambiguous shapes are not admitted and retain their original bytes.
  An admitted decoded body above the immutable sanitation ceiling fails closed
  instead of reaching the provider, and an admitted final representation that
  still carries a marker in a string value — including a content-coded body's
  decoded view and a marker a later transform reintroduced — is refused with
  `400`.

## Testing

Unit tests live in `tests/unit/plugins/ai_prompt_compressor_tests.rs` and cover
runtime/OpenAPI config parity, request-family admission (including the
Responses and Anthropic Messages families), work budgets, protected spans
(multi-backtick code/URLs/Unicode numbers/common identifiers), negation and
critical-word preservation (including uppercase forms), nested, malformed, and
self-synthesizing `preserve_tag` sequences, final residual-marker refusal
(later transforms and content-coded bodies), budget/observe/sampling modes,
skip-reason metadata, whole-body JSON
reserialization, marker-safe bounded fallbacks and saturation, exponent-number
output growth, gzip/brotli composition, final-wire statistics, multimodal parts,
JSON safety/passthrough, and the direct-dispatch metadata rewrite.

Run them with:

```bash
cargo test --test unit_plugins_a_tests ai_prompt_compressor
```
