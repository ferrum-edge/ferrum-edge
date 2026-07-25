# AI Prompt Compressor Plugin

`ai_prompt_compressor` shortens the prompt text sent to an LLM backend to reduce
token usage — and therefore cost and latency — while preserving meaning. It
rewrites prompt-bearing fields only in admitted OpenAI Chat Completions and
legacy Text Completions request representations, replacing long content strings
with shorter, statistically filtered versions before the request is forwarded
upstream.

- **Priority:** `4055` (Response band, immediately after `compression`).
- **Protocols:** HTTP only. Native gRPC wire frames are not compressed.
- **Lifecycle:** the per-request buffering gate admits candidate JSON `POST`
  bodies; `before_proxy` rewrites direct-dispatch metadata and privately stages
  bounded state; `transform_request_body_with_context` produces the final wire
  bytes (with `transform_request_body` retained for context-free compatibility);
  `on_final_request_body_with_context` enforces marker-sanitation failures.
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
4. **Always keep negations** (`not`, `never`, `cannot`, `won't`, …) so meaning is
   not inverted.
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

With `request_family: auto` (the default), the parsed shape must agree with a
standard operation path ending in `/chat/completions` or `/completions`.
Image-generation paths, arbitrary JSON carrying a `prompt`, provider-native
markers, mixed `messages`+`prompt` bodies, malformed content parts, and other
ambiguous shapes pass through unchanged. A fixed request family is the explicit
opt-in for a compatible custom endpoint path; shape validation still applies.

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
| `compress_roles` | string[] | `["user"]` | Message roles whose `content` is compressed (case-insensitive). Must be non-empty. When it contains `user`, the legacy top-level `prompt` is compressed too. |
| `target_ratio` | number | `0.5` | Fraction of word-tokens to keep. `0.5` targets ~50% reduction; `0.3` is more aggressive. Must be strictly between `0` and `1`. |
| `min_content_tokens` | integer | `200` | Estimated-token floor per content string. Range `0..=131072`; content below this is passed through unchanged so short prompts are not mangled. |
| `max_scan_bytes` | integer | `1048576` | Skip statistical compression when the request body exceeds this many bytes. Range `1..=1048576`; the upper bound is immutable. Configured preserve-marker sanitation remains active up to the hard maximum. |
| `preserve_tag` | string | _(unset)_ | Optional marker name. Text wrapped in `<TAG>…</TAG>` is copied through verbatim and all markers are stripped. Nested spans are flattened; unmatched open text is preserved to the end; unmatched closes are stripped. May contain at most 64 ASCII letters, digits, `-`, and `_`. |
| `request_family` | string | `auto` | `auto` requires the body shape to agree with a standard `/chat/completions` or `/completions` path. Use `chat_completions` or `text_completions` only as an explicit assertion for a compatible custom endpoint. Fixed `text_completions` configurations must include `user` in `compress_roles` because the top-level prompt is user text. |

Token counts are **estimated** with a ~4-characters-per-token heuristic; the
plugin embeds no model tokenizer, so `min_content_tokens` and the reported
savings are approximations.

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
configured.

When `preserve_tag` is configured, marker removal is a separate bounded
correctness path: up to 32 sanitation jobs parse and classify concurrently.
Saturation fails closed before cloning the buffered body instead of retaining a
waiter queue. If statistical compression is saturated, any work counter is
exceeded, or JSON reserialization would exceed the hard output bound, the
plugin removes markers directly from admitted JSON string values while never
changing object member names. This value-only pass preserves all other source
bytes (including whitespace, duplicate names, member order, escapes, and number
spelling). Escaped marker spellings such as `\u003ckeep\u003e` are recognized in
values too. The gateway applies a 1,048,576-byte
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
- `ai_semantic_cache` (2996) computes its cache key from the original prompt, so
  cache hit rates are unaffected.
- `compression` (4050) can decode opt-in gzip/brotli request bodies before the
  compressor rewrites the standard backend-dispatch body.

On the standard backend-dispatch path, the context-aware request-body transform
produces the compressed bytes actually sent upstream. For already-plaintext JSON
uploads, `before_proxy` also rewrites `ctx.metadata["request_body"]` so direct
dispatchers that consume that metadata can forward the compressed prompt. The
plugin stages results of at most 65,536 bytes privately and reuses them when the
authoritative input is unchanged; larger results are not duplicated beside
request metadata and are recomputed on normal wire dispatch under the same work
budget. Digest validation for staged results uses the immutable 1,048,576-byte
body ceiling, so marker-only sanitation above `max_scan_bytes` can still reuse
its staged output. If an earlier wire transform changed the bytes, the plugin
discards any stage and recomputes against the actual representation. Auto-family
admission continues to use the original incoming operation path even when
routing rewrites the backend path, so staged reuse, recomputation, and the
65,536-byte threshold cannot change eligibility. The path snapshot is one
private typed value per request, shared by all compressor instances rather than
stored in public metadata. Opt-in gzip/brotli decompression therefore compresses
and measures the resulting plaintext on the standard path. `ai_federation`
consumes the authoritative final request body after decompression and the
context-aware transform, so provider dispatch uses that same compressed
representation for plaintext and opt-in compressed uploads.

The final context-aware body hook is the fail-closed backstop for decoded
representations. For example, if request decompression produces more than the
immutable 1,048,576-byte marker-sanitation ceiling, the request is rejected
before backend dispatch rather than forwarding configured markers.
Marker-sanitation worker exhaustion returns a gateway-local `503`; it is never
retried or charged to backend circuit-breaker and passive-health accounting.

If `ai_prompt_shield` is redacting, the compressor operates on the already
redacted text, so redaction is preserved and then compressed.

## Observability

When compression rewrites a field, the plugin records log-safe counters on the
request context. Standard dispatch clears provisional metadata-copy counters and
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

## Safety and limitations

- **Only JSON POST bodies are touched.** Non-JSON content types, non-`POST`
  methods, and unparseable JSON are forwarded unchanged. Bodies over
  `max_scan_bytes` skip statistical compression; with `preserve_tag` configured,
  admitted bodies still remove markers up to the immutable hard ceiling.
- **Only admitted request families are touched.** `auto` requires a standard
  Chat/Text Completions path and matching shape. Fixed-family mode is an
  operator assertion for custom compatible endpoints; unsupported, ambiguous,
  or malformed shapes still pass through unchanged.
- **Encoded bytes are never parsed as JSON.** A non-`identity`
  `Content-Encoding` stays untouched unless an earlier configured decompression
  transform produces plaintext on the standard wire path.
- **Extractive output is terse.** Compression removes filler words, so the
  rewritten prompt reads as clipped, keyword-dense text. LLMs handle this well,
  but review `target_ratio` for quality-sensitive workloads and prefer a higher
  ratio (or a `preserve_tag`) where exact wording matters.
- **Token counts are estimates**, not a provider tokenizer's exact count.
- **Only `messages[].content` and the legacy `prompt` are compressed.** Other
  prompt-carrying shapes (embeddings `input`, Anthropic top-level `system`) are
  deliberately left intact.
- **Negations keep their complement.** Negation words (including curly-quote
  contractions such as `don’t`) and the word immediately after them are always
  kept, so a surviving "not" cannot re-bind to a later clause. Longer negated
  phrases can still lose trailing qualifiers — prefer `preserve_tag` around
  meaning-critical instructions.
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
  instead of reaching the provider.

## Testing

Unit tests live in `tests/unit/plugins/ai_prompt_compressor_tests.rs` and cover
runtime/OpenAPI config parity, request-family admission, work budgets, protected
spans (multi-backtick code/URLs/Unicode numbers/common identifiers), negation
preservation, nested/malformed `preserve_tag` sequences, whole-body JSON
reserialization, marker-safe bounded fallbacks and saturation, exponent-number
output growth, gzip/brotli composition, final-wire statistics, multimodal parts,
JSON safety/passthrough, and the direct-dispatch metadata rewrite.

Run them with:

```bash
cargo test --test unit_tests ai_prompt_compressor
```
