---
paths:
  - "src/**"
  - "tests/**"
---

# Validation Diagnostics

- Two layers: serde families are sanitized structurally at the document boundary;
  `startup::render_startup_error` sanitizes EVERY rendered cause independently
  with `sanitize_startup_cause`, then joins with `: `. For each ORIGINAL cause,
  redact configured database URLs and registered external secrets FIRST, then
  withhold quoted spans with `sanitize_custom_message`. A quote inside a URL or
  secret must not truncate the value before the credential scrubbers match it.
  If credential scrubbing changes quote/escape syntax, withhold that cause in
  full as `<redacted diagnostic>`: a secret can itself be a delimiter.
  Both `run` and `validate` use it. Never sanitize only the joined chain: an
  unterminated quote in one cause must not swallow the next cause's field/index
  or reason.
- Validation diagnostics: schema names in backticks; document values omitted or
  strings in double quotes with Debug escaping (`{value:?}`). This convention
  makes semantic validators safe by construction at rendering. BARE document
  value interpolation is a defect and is forbidden. Single-quoted interpolation
  without escaping is also unsafe when a value contains an apostrophe. Numeric
  values need explicit double quotes or omission (Debug does not quote numbers).
  For a JSON Value/type rejection, Debug-escape its Display string (for example
  `value = value.to_string()` with `{value:?}`), so numbers and whole containers
  are withheld as well as strings.
  The custom pass withholds double/single-quoted spans and keeps backticks;
  unterminated spans are withheld through the end of their own cause.
- Classify serde families only on the bare inner error, with an exact prefix at
  position zero. Keep `serde_path_to_error` path metadata separate until composition.
  Paths and unknown-field messages can echo document KEYS; never treat them as
  trusted error text or put credentials in keys.
- Native YAML and parser-level errors are custom text unless a value-tree
  deserialization supplies a separate bare inner error. Never scan a rendered
  path or context chain for a family. Do not retain raw errors below safe wrappers.
  Exception: the exact leading `duplicate entry with key "` family from the
  bare YAML Value parser preserves its document key as `duplicate field` metadata.
- Warnings/errors bypassing the final renderer must emit through
  `startup::sanitize_startup_cause` (with known URLs where available) or omit
  values. Quoting alone does NOT sanitize a tracing event. This includes backup,
  SQL/Mongo quarantine/rejection, validation-pipeline and unknown-plugin logs.
  Migration/backup version diagnostics omit values even before rendering.
  Regex-library errors can reproduce patterns bare: replace them with the
  field/index and a fixed rejection reason.
- Plugin cache construction/composition, optional omission, startup and reload
  emissions quote supplied identities/priorities and sanitize before tracing.
  The registered `plugin_cache_tests` captured-log matrix exercises final
  constructor, startup, full-rebuild and delta emissions for global, proxy and
  proxy-group scopes, including hostile identities/unknown keys, fixed spelling
  suggestions, numeric bounds and optional omission. It checks event counts,
  levels, retained schema/reasons and rejected-reload snapshot identity with
  scoped subscribers and no environment mutation. Returned constructor causes
  still depend on the producer convention above; sanitize copies at emission,
  retaining the original causes for the eventual rendering boundary.
- Converted diagnostic families are pinned by their registered
  constructor/rendered-output and captured-log regressions, not listed here.
  When touching a converted site or adding a sibling validator, keep the same
  split: fixed schema paths, rule/record/provider ordinals, typed failure
  classes, and fixed rejection reasons stay visible; supplied names, keys,
  identities, URLs, paths, patterns, numeric values, and parser payloads are
  withheld. Shared helper context that may contain document keys is
  Debug-escaped as a whole, with a separate fixed schema field when one is
  available. JSON Display strings are Debug-escaped even when a sibling guard
  already does so. Successful-admission DEBUG/INFO events sanitize supplied
  scalars at emission too, including defaults and normalized selections. Typed
  mesh adapters use `plugins::mesh::diagnostics`: extend its scoped path table
  when adding typed fields, and never infer trust from a global field-name
  allowlist. SQL literals, fixed migration/listener/fault labels, and
  schema-only constants are not document-value interpolation.
- Scope of #5591: `src/config`, `src/modes`, `src/cli.rs`, `src/startup.rs`,
  `src/gateway_entry.rs`, `src/config_sources`, `src/grpc`, `src/capture`, and
  `src/plugins/waf`.
  Withholding is conditional on safe producer interpolation:
  apostrophe-leading single-quoted values, bare values,
  and retained third-party parser text can still expose supplied data. Do not
  describe the renderer alone as fail-closed for arbitrary diagnostic text.
- The mechanical producer/emitter contract is
  `tests/unit/cli/diagnostic_source_guard_tests.rs` (registered in `cli/mod.rs`).
  Its explicit `ROOTS` list covers the above roots except `src/capture`, whose
  generated shell commands also use quoted interpolation. Capture parsing has
  rendered-output and captured-log regressions. The guard scans every Rust file
  in its roots, plus the converted shared unknown-key, rate-limit, socket-host,
  byte-budget, replay-partition and response-body helpers and notifications,
  including multiline/nested macros
  and raw strings, for single-quoted interpolation in diagnostic macros and for
  named error/message captures in `warn!`/`error!` without a sanitizer call in
  that statement. Its exact, commented exception list contains SQL query syntax,
  not document-value diagnostics. Keep schema names in backticks. The guard
  prevents those syntax regressions in scope; it cannot infer whether arbitrary
  bare arguments are document values or prove third-party errors safe. Retain
  rendered-output/captured-log regressions for semantic and emission coverage.
