# AI Prompt Compressor Plugin

`ai_prompt_compressor` shortens the prompt text sent to an LLM backend to reduce
token usage — and therefore cost and latency — while preserving meaning. It
rewrites the prompt-bearing fields of an OpenAI-shaped chat/completions request
body, replacing long content strings with shorter, statistically filtered
versions before the request is forwarded upstream.

- **Priority:** `2983` (Admission band, right after `ai_semantic_cache` and just
  before `ai_federation`).
- **Protocols:** HTTP only. Native gRPC wire frames are not compressed.
- **Hooks:** `before_proxy`, `transform_request_body`.
- **Failure policy:** `KeepLastKnownGood` — a bad config is rejected at
  load/reload without failing an already-serving cache.

## How it works

The plugin is **model-free**: it embeds no language model, makes no network
calls, and adds no new crate dependencies. Instead of running a transformer to
score token importance, it uses a compact statistical **extractive** filter:

1. **Tokenize** the content into words, preserving structure. Whitespace-run
   boundaries and paragraph breaks are tracked so the output stays readable.
2. **Protect structural spans** that must never be altered — fenced code blocks
   (```` ``` ````), inline code (`` ` ``), URLs (`http://`, `https://`), numbers,
   `snake_case`/identifier tokens, and uppercase acronyms are always kept
   verbatim.
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

- `messages[].content` for every message whose `role` is in `compress_roles`.
  Both the string form and the multimodal array form
  (`[{ "type": "text", "text": "…" }, …]`) are handled; non-text parts (e.g.
  `image_url`) are left untouched.
- The legacy top-level `prompt` field (string or array of strings) — but only
  when `"user"` is an eligible role, since a completions `prompt` is user text.

Everything else in the body — `model`, `temperature`, tool definitions,
metadata, and messages for non-eligible roles — is passed through byte-for-byte.
Embeddings requests (`input`) and Anthropic top-level `system` strings are **not**
compressed.

## Configuration

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `compress_roles` | string[] | `["user"]` | Message roles whose `content` is compressed (case-insensitive). Must be non-empty. When it contains `user`, the legacy top-level `prompt` is compressed too. |
| `target_ratio` | number | `0.5` | Fraction of word-tokens to keep. `0.5` targets ~50% reduction; `0.3` is more aggressive. Must be strictly between `0` and `1`. |
| `min_content_tokens` | integer | `200` | Estimated-token floor per content string. Content below this is passed through unchanged so short prompts are not mangled. |
| `max_scan_bytes` | integer | `1048576` | Skip compression entirely when the request body exceeds this many bytes. |
| `preserve_tag` | string | _(unset)_ | Optional marker name. Text wrapped in `<TAG>…</TAG>` is copied through verbatim and the markers are stripped, letting you protect must-keep spans. May contain ASCII letters, digits, `-`, and `_`. |

Token counts are **estimated** with a ~4-characters-per-token heuristic; the
plugin embeds no model tokenizer, so `min_content_tokens` and the reported
savings are approximations.

An empty config object (`{}`) is valid and applies the defaults: compress `user`
content longer than ~200 tokens down to ~50%.

### Examples

Default behavior — compress long user prompts to ~50%:

```json
{
  "name": "ai_prompt_compressor",
  "config": {}
}
```

Aggressive compression of both user and system messages, protecting a span:

```json
{
  "name": "ai_prompt_compressor",
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

The priority (`2983`) places the compressor **after** the AI security and policy
plugins so they inspect the original, uncompressed prompt:

- `ai_prompt_shield` (2925), `ai_semantic_firewall` (2968), and
  `ai_request_guard` (2975) see the original content — compression never blinds
  PII detection, prompt-injection detection, or request validation.
- `ai_semantic_cache` (2980) computes its cache key from the original prompt, so
  cache hit rates are unaffected.
- `ai_federation` (2985) runs **after** the compressor. The compressor rewrites
  `ctx.metadata["request_body"]` in `before_proxy`, so when federation dispatches
  directly to a provider it forwards the compressed prompt.

On the standard backend-dispatch path, `transform_request_body` produces the
compressed bytes actually sent upstream (this hook, not the metadata copy, is
authoritative for the wire and is the only hook the HTTP/3 cross-protocol path
invokes). Compression is deterministic, so both paths agree.

If `ai_prompt_shield` is redacting, the compressor operates on the already
redacted text, so redaction is preserved and then compressed.

## Observability

When compression reduces the token estimate, the plugin records log-safe counters
on the request context, which flow into transaction summaries:

- `ai_prompt_compressor.original_tokens`
- `ai_prompt_compressor.compressed_tokens`
- `ai_prompt_compressor.tokens_saved`
- `ai_prompt_compressor.fields_compressed`

## Safety and limitations

- **Only JSON POST bodies are touched.** Non-JSON content types, non-`POST`
  methods, unparseable JSON, and bodies over `max_scan_bytes` are forwarded
  unchanged.
- **Transport-compressed bodies are skipped.** A request with a non-`identity`
  `Content-Encoding` is opaque to the compressor and passes through untouched.
- **Extractive output is terse.** Compression removes filler words, so the
  rewritten prompt reads as clipped, keyword-dense text. LLMs handle this well,
  but review `target_ratio` for quality-sensitive workloads and prefer a higher
  ratio (or a `preserve_tag`) where exact wording matters.
- **Token counts are estimates**, not a provider tokenizer's exact count.
- **Only `messages[].content` and the legacy `prompt` are compressed.** Other
  prompt-carrying shapes (embeddings `input`, Anthropic top-level `system`) are
  deliberately left intact.

## Testing

Unit tests live in `tests/unit/plugins/ai_prompt_compressor_tests.rs` and cover
config validation, role targeting, thresholds, protected spans (code/URLs/
numbers/identifiers), negation preservation, `preserve_tag`, multimodal parts,
JSON safety/passthrough, and the `before_proxy` metadata rewrite.

Run them with:

```bash
cargo test --test unit_tests ai_prompt_compressor
```
