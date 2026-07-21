//! Secret resolution with pluggable backends.
//!
//! Any `FERRUM_*` environment variable can be loaded from an external source
//! by setting a suffixed variant instead of the variable itself.
//!
//! Startup secret resolution finishes before non-blocking logging and the
//! multi-threaded gateway runtime, and its temporary runtime is dropped before
//! env mutation happens.

#[cfg(feature = "secrets-aws")]
mod aws;
#[cfg(feature = "secrets-azure")]
mod azure;
pub mod env;
pub mod file;
#[cfg(feature = "secrets-gcp")]
mod gcp;
mod registry;
#[cfg(feature = "secrets-vault")]
mod vault;

#[cfg(any(feature = "secrets-aws", feature = "secrets-vault"))]
pub(crate) fn split_reference_field(reference: &str) -> (&str, Option<&str>) {
    match reference.split_once('#') {
        Some((base, field)) => (base, Some(field)),
        None => (reference, None),
    }
}

#[allow(unused_imports)]
pub use registry::{
    EXTERNAL_SECRET_SUFFIXES, ResolvedEnvSecrets, ResolvedSecret, external_source_configured,
    resolve_all_env_secrets, resolve_external_reference, resolve_secret,
};

/// Base `FERRUM_*` variables whose current value was materialized from an
/// external secret source in this process.
///
/// Only the key names are stored *here*. The values are read back from the
/// process environment (startup writes them there with `set_var` before config
/// is parsed) the first time redaction runs, which is what makes redaction
/// key-tied rather than a guess about what looks secret.
///
/// That read-back is not copy-free, and pretending otherwise would be
/// misleading: [`REDACTION_PLAN`] retains, for the process lifetime, the exact
/// value of every externally resolved key plus the bounded set of derived forms
/// from [`derive_candidates`] (trimmed, per-segment, case-normalized, and
/// JSON-escaped). Matching a value that a validator re-rendered requires having
/// that rendering to compare against, so the copies are the cost of the
/// coverage. The tradeoff is deliberate and bounded: the plan is built once,
/// deduplicated, and never rebuilt or extended, and the *environment* remains
/// the only place the value is written or mutated.
static EXTERNAL_SECRET_KEYS: std::sync::OnceLock<std::collections::BTreeSet<String>> =
    std::sync::OnceLock::new();

/// Fast path for the log-record boundary.
///
/// `false` until at least one base variable is actually materialized from an
/// external source, which is the overwhelmingly common case (no external
/// secrets configured, and every unit/integration test). Every log record — including
/// per-transaction access-log records on the proxy hot path — passes through
/// [`redact_log_record`], so the "nothing to redact" case must cost a single
/// relaxed atomic load and nothing else.
static REDACTION_ACTIVE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Substituted for an externally resolved value in an operator-facing message.
pub const EXTERNAL_SECRET_PLACEHOLDER: &str = "<redacted: value from external secret source>";

/// Record which base variables were materialized from an external secret
/// source.
///
/// Called exactly once at startup, immediately after the resolved values are
/// written to the environment and before any configuration is parsed. Later
/// calls are ignored, so this cannot be re-pointed after config load.
///
/// This is what makes downstream redaction *key-tied* rather than a guess about
/// what looks secret: an externally resolved variable is known by name, so a
/// diagnostic about it can name the variable and withhold only its value.
pub fn record_external_secret_keys<I>(keys: I)
where
    I: IntoIterator<Item = String>,
{
    let keys: std::collections::BTreeSet<String> = keys.into_iter().collect();
    let any = !keys.is_empty();
    if EXTERNAL_SECRET_KEYS.set(keys).is_ok() && any {
        // Arm the log-record boundary only once there is something to redact.
        // Ordering is `Release`/`Acquire` against the plan build so a reader
        // that observes `true` also observes the recorded key set.
        REDACTION_ACTIVE.store(true, std::sync::atomic::Ordering::Release);
    }
}

/// True when `key`'s current value came from an external secret source.
///
/// Returns `false` before [`record_external_secret_keys`] runs and in any
/// process that never resolved external secrets (including unit tests), so
/// ordinary configuration diagnostics are unaffected.
pub fn is_external_secret_key(key: &str) -> bool {
    EXTERNAL_SECRET_KEYS
        .get()
        .is_some_and(|keys| keys.contains(key))
}

/// Render one operator-facing field that was derived from `env_key`, withholding
/// it entirely when that variable was externally resolved.
///
/// **Key-tied first, not textual**, because these call sites *re-render* a value
/// rather than echoing it. `OperatingMode`'s `Debug` rendering is the motivating
/// case: a `FERRUM_MODE_FILE` holding `database` surfaces as `Database`, a form
/// [`derive_candidates`] deliberately does not produce (it derives ASCII upper-
/// and lowercase, not the `Debug`/`Display` casing of every enum in the crate).
/// Widening candidate derivation to chase enum renderings would be exactly the
/// open-ended normalization the redaction design rejects, and would cost the
/// bounded-candidate guarantee. Withholding by key instead is exact: the
/// variable is known by name to have been externally resolved, so *no* rendering
/// of its value can escape.
///
/// [`redact_external_secret_values`] still runs as the second pass, covering a
/// field that interpolates some *other* externally resolved variable's value
/// verbatim.
///
/// Disclosure surfaces that re-render a typed config value use this: the
/// `validate` report's `Mode:` line (`cli::report_field`, a `println!` the
/// tracing boundary never sees), `run`'s `Operating mode:` record in
/// `main.rs` (which *does* reach [`redact_log_record`], but where the structural
/// redactor cannot match the re-rendered form for the reason above), and
/// startup listen/port lines that print a parsed integer or `SocketAddr`
/// (`080` / ` 80` → `80`). That canonical scalar is often below
/// [`RedactionPlan::MIN_DERIVED_CANDIDATE_LEN`], so the textual pass cannot
/// cover it without globally arming every two-digit string. The same applies to
/// a disabled-listener `=0`, an overload threshold logged as `1` from `1.0`,
/// and a logging-clamp `supplied`/`applied` field — those sites must name the
/// variable rather than relying on the length filter. A new value-bearing
/// startup line that re-renders a typed value must go through here (or
/// [`report_env_fields`] when more than one variable contributed) and name the
/// variable(s) it came from.
pub fn report_env_field(env_key: &str, rendered: &str) -> String {
    report_env_fields(&[env_key], rendered)
}

/// Like [`report_env_field`], but withholds when **any** of `env_keys` was
/// externally resolved.
///
/// Use this for a composed rendering that depends on more than one variable —
/// notably a listener `SocketAddr` built from a bind-address key and a port
/// key. Key-tying only the port leaves a normalized bind address
/// (`FERRUM_PROXY_BIND_ADDRESS_FILE=0:0:0:0:0:0:0:1` → `[::1]:…`) visible,
/// because that form matches neither the materialized value nor a derived
/// candidate the length filter would keep.
pub fn report_env_fields(env_keys: &[&str], rendered: &str) -> String {
    if env_keys.iter().any(|key| is_external_secret_key(key)) {
        return EXTERNAL_SECRET_PLACEHOLDER.to_string();
    }
    redact_external_secret_values(rendered)
}

/// Format `KEY=value` for a startup/validate diagnostic, withholding the value
/// when `env_key` was externally resolved.
///
/// Disabled-listener lines historically hard-coded `FERRUM_PROXY_HTTP_PORT=0`.
/// When the port was externally sourced as `000` (or any other spelling that
/// parses to zero), that `0` is a short canonical rendering the textual
/// redactor deliberately does not admit — so the assignment must be key-tied.
pub fn report_env_assignment(env_key: &str, rendered: &str) -> String {
    format!("{env_key}={}", report_env_field(env_key, rendered))
}

/// Render a listener address that depends on both a bind-address variable and a
/// port variable. Withholds when either key was externally resolved.
pub fn report_listener_addr(bind_key: &str, port_key: &str, rendered: &str) -> String {
    report_env_fields(&[bind_key, port_key], rendered)
}

/// Render the `'…'`-quoted echo of a value a hand-written validator produced by
/// **transforming** `env_key`'s value, withholding it when that variable was
/// externally resolved.
///
/// This is the boundary [`RedactionPlan::MIN_DERIVED_CANDIDATE_LEN`] names as
/// the one it cannot cover. Ferrum's validators do not echo what was
/// materialized; they echo a normalization of it — `trim()`, an ASCII case
/// fold, a comma-segment split, or some composition of the three. Those forms
/// *are* derived by [`derive_candidates`], but only above a 3-byte minimum,
/// because arming a one- or two-byte string process-wide would shred every
/// unrelated diagnostic containing it. So a short value slips the textual pass
/// in precisely the case the pass exists for: `FERRUM_MIGRATE_ACTION_FILE=X`
/// errors as `'x'`, and `FERRUM_TLS_EARLY_DATA_METHODS_FILE=p` warns as `'P'` —
/// neither of which equals the materialized value, and neither of which the
/// filter may admit at that length.
///
/// Withholding by key is exact where widening the filter is not: the variable
/// is known *by name* to have been externally resolved, so no rendering of its
/// value — present or future, however normalized — can escape, and nothing is
/// armed globally. The quoting lives here rather than at the call sites so the
/// withheld form is never `'<redacted: …>'`, which reads as though the operator
/// had literally configured the placeholder.
///
/// When `env_key` was **not** externally resolved this is byte-for-byte the
/// `'{value}'` the site printed before, so ordinary configuration typos keep
/// showing the value that makes them diagnosable. The final-error backstop
/// ([`redact_external_secret_values`]) and the log-record boundary
/// ([`redact_log_record`]) still run downstream and still cover a message that
/// interpolates some *other* variable's value verbatim.
///
/// A new hand-written validator that re-renders a `FERRUM_*` value must call
/// this rather than widen candidate derivation.
pub fn quoted_env_value(env_key: &str, rendered: &str) -> String {
    if is_external_secret_key(env_key) {
        return EXTERNAL_SECRET_PLACEHOLDER.to_string();
    }
    // Same second pass as `report_env_field`: `env_key` itself was not
    // externally resolved, but the text may still interpolate some *other*
    // resolved variable's value verbatim. A no-op when nothing is armed, which
    // is every process that resolved no external secrets.
    format!("'{}'", redact_external_secret_values(rendered))
}

/// True when `value` **is**, exactly, an externally resolved secret value.
///
/// This answers a question [`redact_external_secret_values`] cannot: where a
/// string came from, rather than what it looks like once resolved material has
/// been removed from it. Redaction matches a candidate **inside** a message, so
/// it covers a diagnostic that quotes a whole resolved value — but a caller that
/// is about to print a *fragment* of such a value has the containment the other
/// way round, and no candidate matches. The fragment then escapes even though
/// the value it came from is armed.
///
/// `tls::source::CertSourceUri::redacted_option_value` is the motivating case: a
/// source URI materialized from `FERRUM_FRONTEND_TLS_CERT_SOURCE_FILE` carries
/// its `?poll=` option inside the resolved value, so logging that option alone
/// discloses a slice of a secret the redactor will never match. Deriving every
/// query value into a candidate instead was rejected: it would arm short,
/// arbitrary strings process-wide, which is precisely the blind substring
/// corruption [`RedactionPlan::MIN_DERIVED_CANDIDATE_LEN`] exists to prevent.
///
/// Matching is **whole-value equality against the value as materialized**. It is
/// deliberately neither containment nor a match against a [`derive_candidates`]
/// form, because neither of those is provenance:
///
/// * Containment is not origin. A candidate that merely occurs somewhere inside
///   a locally authored string proves nothing about where that string came from,
///   and a *derived* fragment proves less still — it is a rewrite of some other
///   variable's value. Answering `true` there withholds an ordinary local
///   diagnostic on a coincidence, and a caller that reads it as "this is secret
///   material" is reading a claim the implementation cannot support.
/// * Containment also fails in the direction that matters here, so it is not
///   even a safe over-approximation. The caller must hand over the value it
///   actually holds, **complete**: a URI's query is part of the resolved string,
///   so a query-stripped identifier is a strict prefix of the secret, contains
///   no whole candidate, and answers `false` on genuinely secret material.
///
/// Equality carries **no minimum length** — unlike
/// [`RedactionPlan::MIN_DERIVED_CANDIDATE_LEN`], which exists to stop a short
/// derived form being armed as a process-wide substring. Nothing is armed here:
/// a one-byte resolved value is answered exactly and no unrelated text is ever
/// rewritten because of it. The materialized value and its `trim()`ed form are
/// both accepted because a configuration reader may trim before storing; both
/// are whole representations of the same secret rather than fragments of it.
///
/// `false` in any process that resolved no external secrets, so ordinary
/// configuration diagnostics keep printing their values.
///
/// **Residual, deliberate:** this is *value* provenance, so a caller must pass
/// the string exactly as configured. A value Ferrum has already rewritten — a
/// serde round trip through `tls::source::CertSource::to_config_value`, which
/// reorders options and drops percent-encoding — is no longer the materialized
/// string and is answered `false`. Widening to cover rewrites would reintroduce
/// exactly the derived-form guessing this exists to avoid; a site that cannot
/// hold the original string must withhold key-tied instead
/// ([`report_env_field`]).
pub fn is_external_secret_value(value: &str) -> bool {
    redaction_plan().is_some_and(|plan| plan.is_exact_value(value))
}

/// Remove externally resolved secret values from an operator-facing message.
///
/// This is the backstop behind the structured boundary in
/// `config::env_config_macro::invalid_env_value`, which is where typed
/// `EnvConfig` parse failures already withhold the raw value by key. Config
/// validation is far wider than that one site — hand-written messages, URL and
/// namespace validators, and the file-mode spec loader all interpolate resolved
/// values — and a resolved secret is indistinguishable from ordinary
/// configuration once it is in the environment. Rather than auditing every
/// present and future message, the final rendering of a startup/validation
/// failure is filtered here against the authoritative set of externally
/// resolved keys.
///
/// Replacement is by key, never guessed at by shape: the value is read back
/// from the environment under a name known to have come from an external
/// source. The value exactly as materialized has deliberately no minimum
/// length — a short resolved secret is still a secret, and mangling an
/// unrelated substring of a diagnostic is strictly preferable to printing the
/// secret. Longest candidates are replaced first so one secret that contains
/// another cannot leave a fragment behind.
///
/// Exact-value matching alone is not sufficient, because validators and the
/// logging sink both re-render a value before it reaches an operator: list
/// parsers trim entries, `FERRUM_TLS_EARLY_DATA_METHODS` uppercases them, and
/// the tracing layer JSON-escapes the whole record. [`derive_candidates`]
/// therefore expands each value into a small, explicitly bounded set of those
/// forms. See it for the bound and the deliberate residual.
///
/// Matching runs against the *original* diagnostic only. Substituted
/// placeholders are never re-examined, so a resolved value that happens to be a
/// substring of [`EXTERNAL_SECRET_PLACEHOLDER`] (`value`, `external`, `a`)
/// cannot make one replacement's output the next replacement's input. A
/// repeated-substitution loop over the running message compounds instead:
/// n such values multiply the diagnostic by roughly the placeholder's density
/// of each, which turns a handful of externally resolved short secrets into a
/// validation-time memory/CPU exhaustion. See [`RedactionPlan::redact`] for the
/// bound.
pub fn redact_external_secret_values(message: &str) -> String {
    match redaction_plan() {
        Some(plan) => plan.redact(message).into_owned(),
        None => message.to_string(),
    }
}

/// Redact a fully serialized log record in place, at the emission boundary.
///
/// The by-key boundary in `config::env_config_macro::invalid_env_value` and the
/// final-error backstop above only cover values that reach an operator through
/// a returned `Result`. Diagnostics emitted as `warn!`/`info!` *during*
/// `EnvConfig::from_env()` or spec validation are written straight to the sink
/// and never pass through either — a `FERRUM_TLS_EARLY_DATA_METHODS_FILE`
/// holding a non-GET token is uppercased and warned about on a **successful**
/// default `validate` run, so there is no returned error to filter at all.
///
/// This is the one place every tracing record is materialized as bytes
/// (`logging::non_blocking::RecordWriter::submit`), so filtering here covers
/// present and future log sites without auditing each one.
///
/// # Why this boundary is structural, not textual
///
/// A record here is a complete JSON document: the fmt layer is configured
/// `.json()` in `main::init_logging`, `stdout_logging` access records go
/// through `NonBlockingSink::try_write_json`, and the sink's own failure notice
/// is a JSON literal. Running the flat [`RedactionPlan::redact`] pass over
/// those *serialized* bytes is not safe, because a resolved value has
/// deliberately no minimum length and no required shape. A secret of `"`
/// matches every structural quote in the record and a secret of `,`, `{`, or
/// `:` matches every delimiter, so a textual pass rewrites JSON syntax into
/// placeholder text and emits a line no log pipeline can parse; a secret equal
/// to `level`, `target`, or `message` rewrites the schema's own field names.
///
/// So the record is parsed, redacted per *value*, and reserialized:
///
/// * object **keys** are rewritten unless they occupy a position in the
///   *tracing envelope*, which is decided by the record's [`LogRecordSource`]
///   and its position in the document, never by spelling alone. Access records
///   are not all-static: `TransactionSummary.metadata` and
///   `StreamTransactionSummary.metadata` serialize a `HashMap` as a nested JSON
///   object whose keys are whatever plugins inserted at runtime, and
///   `plugins::utils::log_schema` promotes operator configuration into key
///   position outright — `rename:` renames a field to an operator-supplied
///   string, `static_fields:` takes its keys straight from the config map, and
///   `MetadataPolicy::Flatten` lifts metadata keys to the top level behind an
///   operator-supplied prefix. Any of those can carry an externally resolved
///   value, so a key that matches a candidate has both the key *and* the value
///   beneath it replaced (see [`RedactionPlan::redact_json_value`]).
///
///   The envelope names are exempt because their presence is structural, not
///   derived: `level` appears in every fmt-layer record regardless of what any
///   secret holds, so leaving it discloses nothing, while rewriting it would
///   silently change the record's schema for every downstream consumer. `level`
///   stays `level` even when `level` is itself a resolved secret; its
///   occurrences in *values* are still redacted.
///
///   The exemption is *scoped*, because the same spellings are reachable as
///   operator/plugin-supplied keys. It applies only to a record the sink
///   received from the tracing fmt layer ([`LogRecordSource::TracingEnvelope`]),
///   and within such a record only at the two positions the formatter actually
///   emits it: the root object ([`TRACING_ENVELOPE_ROOT_KEYS`]) and `message`
///   inside the root `fields` object ([`TRACING_ENVELOPE_FIELDS_KEYS`]). An
///   access record ([`LogRecordSource::Dynamic`], everything reaching
///   `try_write_json`) has no envelope at all, so *no* key in it is exempt at
///   any depth — including the root, which is exactly where
///   `MetadataPolicy::Flatten` and `rename:` deposit operator-supplied names.
///   A depth test alone would not do: a flattened dynamic `filename` occupies
///   the root of an access record, the same depth as the genuine envelope
///   field.
/// * string **values** are matched after unescaping, so JSON escaping cannot
///   smuggle a value past the scan and the reserializer re-escapes correctly.
///   (The escaped form stays a candidate in its own right — for
///   [`redact_external_secret_values`], which does filter raw text, and for the
///   pre-parse screen, which sees the record already escaped.)
/// * numeric, boolean, and null **values** are matched against their rendered
///   form — an externally resolved port or flag is a scalar in the record, not
///   a string — and a match replaces the whole scalar with the placeholder
///   string. All three unquoted scalar forms are treated alike; leaving any of
///   them out would emit that value's own representation.
/// * field **order** is preserved (see [`LogJson`]), so a redacted record
///   differs from an unredacted one only in the values that were redacted.
///
/// Fail-closed: a record that is not well-formed JSON, or that cannot be
/// reserialized, cannot be sanitized without risking either a leak or a
/// corrupt line, so it is replaced with [`withheld_log_record`] — a fixed,
/// valid JSON line whose own field values have themselves been through this
/// same structural redaction, so a short exact secret that happens to equal
/// `WARN` or `ferrum_edge::secrets` is not disclosed by the very record that
/// exists to withhold one. The candidate is never emitted on any failure path.
/// This costs the operator one anomalous diagnostic rather than a secret.
///
/// Callers on the hot path pay one relaxed atomic load when no external secret
/// was ever resolved, and one allocation-free scan
/// ([`RedactionPlan::contains_candidate`]) when one was but this record does
/// not contain it — parsing and copying happen only for records that actually
/// carry a resolved value.
pub(crate) fn redact_log_record(record: &mut Vec<u8>, source: LogRecordSource) {
    if !REDACTION_ACTIVE.load(std::sync::atomic::Ordering::Acquire) {
        return;
    }
    let Some(plan) = redaction_plan() else {
        return;
    };

    let trailing_newline = record.last() == Some(&b'\n');
    let root = source.root_position();
    // Scoped so the immutable borrow of `record` ends before the assignment.
    let outcome = match std::str::from_utf8(record) {
        // Non-UTF-8 bytes cannot be scanned at all, so this record cannot be
        // shown to be free of a resolved value. Unreachable for the three
        // producers above; withhold rather than guess.
        Err(_) => Some(withheld_record(plan, trailing_newline)),
        Ok(text) if plan.contains_candidate(text) => {
            let redacted = plan.redact_json_record(text, root);
            Some(match redacted {
                Some(mut redacted) => {
                    if trailing_newline {
                        redacted.push('\n');
                    }
                    redacted.into_bytes()
                }
                None => withheld_record(plan, trailing_newline),
            })
        }
        // Nothing to redact: leave the record's bytes exactly as serialized.
        Ok(_) => None,
    };
    if let Some(outcome) = outcome {
        *record = outcome;
    }
}

/// Template for the record emitted in place of one that cannot be structurally
/// sanitized.
///
/// Deliberately a valid JSON object carrying the same stable `level`/`target`/
/// `message` keys the fmt layer emits, so a log pipeline sees a well-formed
/// line it can account for instead of a silent gap or a parse error. It is a
/// fixed literal with no interpolation, so it cannot carry a value *derived*
/// from the record it replaces.
///
/// It can still *collide* with one, though: a resolved value has deliberately
/// no minimum length, so an exact secret of `WARN`, `secret`, `values`, or
/// `ferrum_edge::secrets` is present verbatim in this literal's own field
/// values. Emitting the template unchanged would therefore disclose a short
/// exact secret on the one path that exists to prevent disclosure. So the
/// template is passed through the *same* structural redaction as every other
/// record when the plan is built, and [`withheld_log_record`] is what is
/// actually emitted. See [`RedactionPlan::build`].
pub const WITHHELD_LOG_RECORD: &str = concat!(
    r#"{"level":"WARN","target":"ferrum_edge::secrets","#,
    r#""message":"log record withheld: it is not well-formed JSON and could not be checked for externally resolved secret values"}"#
);

/// Fallback when even [`WITHHELD_LOG_RECORD`] cannot be reserialized.
///
/// A valid, minimal, candidate-free JSON object. Its two bytes are JSON syntax
/// rather than content derived from any value, exactly like the delimiters and
/// schema keys the structural redactor already leaves alone.
const MINIMAL_WITHHELD_LOG_RECORD: &str = "{}";

/// The withheld-record line for this process, with any externally resolved
/// value already removed from its field values.
///
/// Returns the bare template before redaction is armed, where there is nothing
/// to collide with.
//
// Library/external-test accessor: the only consumer is
// `tests/unit/secrets/redaction_tests.rs`, which asserts the process-specific,
// already-redacted template. Production has no use for it — `redact_log_record`
// already holds the `&RedactionPlan` snapshot it is acting on and reaches
// `plan.withheld_record` through `withheld_record(plan, ..)`, so calling this
// there would add a second global-plan lookup and let the emitted line come
// from a different snapshot than the record being withheld. The binary target
// therefore compiles it unused; scoped to this accessor only.
#[allow(dead_code)]
pub fn withheld_log_record() -> &'static str {
    match redaction_plan() {
        Some(plan) => plan.withheld_record.as_str(),
        None => WITHHELD_LOG_RECORD,
    }
}

fn withheld_record(plan: &RedactionPlan, trailing_newline: bool) -> Vec<u8> {
    let mut bytes = plan.withheld_record.as_bytes().to_vec();
    if trailing_newline {
        bytes.push(b'\n');
    }
    bytes
}

/// Which producer handed a record to the sink.
///
/// The tracing envelope is a property of the *producer*, not of a key's
/// spelling: `filename` is a structural field the fmt layer emits on every
/// event, and it is also a perfectly ordinary key for `log_schema`'s `rename:`,
/// `static_fields:`, or a flattened plugin `metadata` entry to occupy in an
/// access record. Nothing in the serialized bytes distinguishes the two, so the
/// distinction is carried explicitly from the emission site instead of guessed
/// at from shape. See [`redact_log_record`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LogRecordSource {
    /// `tracing_subscriber`'s JSON fmt layer (`logging::non_blocking`'s
    /// `MakeWriter` impl), and the sink's own failure-notice literal, which is
    /// a fixed string carrying that same envelope. Keys in envelope position
    /// are exempt from key redaction.
    TracingEnvelope,
    /// Every other producer: `stdout_logging` access records via
    /// `try_write_json`, and arbitrary operator-shaped bytes via
    /// `try_write_bytes`. These have no tracing envelope, so no key in them is
    /// structural at any depth — including the root.
    Dynamic,
}

impl LogRecordSource {
    fn root_position(self) -> EnvelopePosition {
        match self {
            Self::TracingEnvelope => EnvelopePosition::TracingRoot,
            Self::Dynamic => EnvelopePosition::Dynamic,
        }
    }
}

/// Where the object currently being walked sits relative to the tracing
/// envelope, which is what decides whether a key may be exempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EnvelopePosition {
    /// The root object of a record emitted by the tracing fmt layer.
    TracingRoot,
    /// The `fields` object directly beneath such a root.
    TracingFields,
    /// Anywhere else. No key here is structural: nested span field names,
    /// anything inside an array, every object in an access record, and every
    /// object below the two envelope positions above.
    Dynamic,
}

impl EnvelopePosition {
    /// Position of the object reached by descending through `key`.
    ///
    /// The envelope is exactly two levels deep and does not nest further, so
    /// every descent other than root -> `fields` lands in dynamic territory.
    fn child(self, key: &str) -> Self {
        match self {
            Self::TracingRoot if key == "fields" => Self::TracingFields,
            _ => Self::Dynamic,
        }
    }

    /// Whether `key` is a structural envelope name *at this position*.
    fn exempts(self, key: &str) -> bool {
        match self {
            Self::TracingRoot => TRACING_ENVELOPE_ROOT_KEYS.contains(&key),
            Self::TracingFields => TRACING_ENVELOPE_FIELDS_KEYS.contains(&key),
            Self::Dynamic => false,
        }
    }
}

/// Root-object keys the `tracing_subscriber` JSON formatter emits.
///
/// Their presence at that position is structural rather than derived from
/// configuration: they appear in every fmt-layer record no matter what any
/// resolved value holds, so leaving them intact discloses nothing about a
/// secret, while rewriting one would make the record unparseable for downstream
/// consumers — the contract that fixed schema keys stay stable and ordered.
///
/// `message` is listed because the formatter hoists it to the root when
/// configured with `flatten_event(true)`; Ferrum's layer is not, so in practice
/// it arrives under `fields` (see [`TRACING_ENVELOPE_FIELDS_KEYS`]) and the
/// root entry is what [`WITHHELD_LOG_RECORD`] carries.
///
/// Deliberately *not* covered: any of these spellings in an access record, at
/// the root or anywhere else. `log_schema`'s `rename:`, `static_fields:`, and
/// `MetadataPolicy::Flatten` can all move an operator-supplied string into a
/// top-level key, so a `filename` there is not structural and stays subject to
/// the candidate screen. [`LogRecordSource`] is what tells the two apart.
const TRACING_ENVELOPE_ROOT_KEYS: [&str; 11] = [
    "timestamp",
    "level",
    "fields",
    "message",
    "target",
    "span",
    "spans",
    "threadId",
    "threadName",
    "filename",
    "line_number",
];

/// Keys that are structural inside a tracing record's root `fields` object.
///
/// Only the event message. The remaining entries there are `tracing` event
/// field names, which are not part of the envelope, so they stay screened.
const TRACING_ENVELOPE_FIELDS_KEYS: [&str; 1] = ["message"];

/// An order-preserving JSON document, used only by [`redact_log_record`].
///
/// `serde_json::Value` stores objects in a `BTreeMap` — the `preserve_order`
/// feature is deliberately not enabled crate-wide, since it would change every
/// admin API response body — so round-tripping a record through it would
/// alphabetize the fields of every access-log line that happened to contain a
/// resolved value. Redaction must change values and nothing else, so objects
/// are held here as an ordered key/value list.
///
/// Depth is bounded by `serde_json`'s own recursion limit on the parse, which
/// also bounds the redaction walk and the reserialization.
enum LogJson {
    Null,
    Bool(bool),
    Number(serde_json::Number),
    String(String),
    Array(Vec<LogJson>),
    Object(Vec<(String, LogJson)>),
}

impl<'de> serde::Deserialize<'de> for LogJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct LogJsonVisitor;

        impl<'de> serde::de::Visitor<'de> for LogJsonVisitor {
            type Value = LogJson;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a JSON value")
            }

            fn visit_unit<E: serde::de::Error>(self) -> Result<LogJson, E> {
                Ok(LogJson::Null)
            }

            fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<LogJson, E> {
                Ok(LogJson::Bool(value))
            }

            fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<LogJson, E> {
                Ok(LogJson::Number(value.into()))
            }

            fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<LogJson, E> {
                Ok(LogJson::Number(value.into()))
            }

            fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<LogJson, E> {
                serde_json::Number::from_f64(value)
                    .map(LogJson::Number)
                    .ok_or_else(|| E::custom("non-finite number"))
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<LogJson, E> {
                Ok(LogJson::String(value.to_string()))
            }

            fn visit_string<E: serde::de::Error>(self, value: String) -> Result<LogJson, E> {
                Ok(LogJson::String(value))
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<LogJson, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut items = Vec::new();
                while let Some(item) = seq.next_element()? {
                    items.push(item);
                }
                Ok(LogJson::Array(items))
            }

            fn visit_map<A>(self, mut map: A) -> Result<LogJson, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut entries = Vec::new();
                while let Some(entry) = map.next_entry::<String, LogJson>()? {
                    entries.push(entry);
                }
                Ok(LogJson::Object(entries))
            }
        }

        deserializer.deserialize_any(LogJsonVisitor)
    }
}

impl serde::Serialize for LogJson {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::{SerializeMap, SerializeSeq};

        match self {
            Self::Null => serializer.serialize_unit(),
            Self::Bool(value) => serializer.serialize_bool(*value),
            Self::Number(value) => value.serialize(serializer),
            Self::String(value) => serializer.serialize_str(value),
            Self::Array(items) => {
                let mut seq = serializer.serialize_seq(Some(items.len()))?;
                for item in items {
                    seq.serialize_element(item)?;
                }
                seq.end()
            }
            Self::Object(entries) => {
                let mut map = serializer.serialize_map(Some(entries.len()))?;
                for (key, value) in entries {
                    map.serialize_entry(key, value)?;
                }
                map.end()
            }
        }
    }
}

/// Values are written to the environment and [`record_external_secret_keys`] is
/// called before any configuration is parsed, and neither is mutated
/// afterwards, so the candidate set is fixed for the process lifetime and is
/// built once on first use rather than per diagnostic. That matters because
/// [`redact_log_record`] runs per log record.
static REDACTION_PLAN: std::sync::OnceLock<RedactionPlan> = std::sync::OnceLock::new();

fn redaction_plan() -> Option<&'static RedactionPlan> {
    let keys = EXTERNAL_SECRET_KEYS.get()?;
    let plan = REDACTION_PLAN.get_or_init(|| {
        RedactionPlan::build(keys.iter().filter_map(|key| std::env::var(key).ok()))
    });
    (!plan.candidates.is_empty()).then_some(plan)
}

/// Derived forms of one resolved value, ordered by nothing in particular —
/// [`RedactionPlan::build`] dedups and orders them.
///
/// The expansion is deliberately small and enumerable rather than a general
/// normalization, so what is and is not covered can be audited:
///
/// 1. the value as materialized, and its `trim()`ed form (list and scalar
///    validators trim before echoing);
/// 2. each comma-separated segment, trimmed — `Vec<String>` parsing splits on
///    `,` and trims, and `EnvConfig::validate` echoes the *entry*, not the
///    whole variable (`Invalid FERRUM_CP_NAMESPACES entry '...'`);
/// 3. the ASCII upper/lowercase of each of the above, for case-normalizing
///    validators such as `FERRUM_TLS_EARLY_DATA_METHODS`;
/// 4. the reference rewrites this codebase performs on a value that names a
///    source — see [`derive_reference_forms`];
/// 5. the canonical rendering of a value that is parsed into a scalar — see
///    [`derive_scalar_forms`];
/// 6. the ASCII upper/lowercase of each of the above (again, for 4 and 5), and
/// 7. the JSON-escaped body of each of the above, because the tracing fmt
///    layer escapes the record before [`redact_log_record`] sees it.
///
/// Bounded at
/// `(2 + MAX_LIST_SEGMENTS + MAX_REFERENCE_FORMS + MAX_SCALAR_FORMS) * 3 * 2`
/// forms per value — a fixed ceiling, not a function of message size — so no
/// configuration can turn candidate discovery into an amplification vector.
/// Each derivation below is a single deterministic rewrite of the value itself,
/// never a rewrite of another derived form, so the expansion stays additive
/// rather than combinatorial.
///
/// **Residual, deliberate:** a value with more than `MAX_LIST_SEGMENTS`
/// comma-separated segments contributes no per-segment candidates. Such a value
/// is a configuration list rather than credential material, and its whole and
/// trimmed forms are still redacted; the alternative is an unbounded candidate
/// set driven by attacker-influenced input.
fn derive_candidates(value: &str) -> Vec<String> {
    /// A value with more segments than this is a list, not a credential.
    const MAX_LIST_SEGMENTS: usize = 32;

    let mut forms: Vec<String> = vec![value.to_string(), value.trim().to_string()];

    let segments: Vec<&str> = value.split(',').collect();
    if segments.len() > 1 && segments.len() <= MAX_LIST_SEGMENTS {
        forms.extend(
            segments
                .into_iter()
                .map(|segment| segment.trim().to_string()),
        );
    }

    forms.extend(derive_reference_forms(value));
    forms.extend(derive_scalar_forms(value));

    let case_forms: Vec<String> = forms
        .iter()
        .flat_map(|form| [form.to_ascii_uppercase(), form.to_ascii_lowercase()])
        .collect();
    forms.extend(case_forms);

    let escaped_forms: Vec<String> = forms
        .iter()
        .filter_map(|form| json_escaped_body(form))
        .collect();
    forms.extend(escaped_forms);

    forms
}

/// Upper bound on the forms [`derive_reference_forms`] can return.
const MAX_REFERENCE_FORMS: usize = 5;

/// Rewrites this codebase performs on a resolved value that *names a source*,
/// before printing it back to an operator.
///
/// An externally resolved variable is not always consumed as opaque material.
/// `FERRUM_FRONTEND_TLS_CERT_PATH_FILE` can materialize a `vault://…` or
/// `file://…` URI, and `FERRUM_DB_URL_FILE` materializes a database URL; both
/// are then re-rendered by Ferrum itself before any diagnostic prints them, so
/// the value *as materialized* is not the string the operator sees:
///
/// * `tls::source::CertSourceUri::parse` splits `<scheme>://<identifier>?<query>`
///   and keeps only the identifier, and
///   `secrets::registry::SecretBackend::source` renders the completed fetch as
///   `<provider>:<identifier>` — one colon, no `//`, which is the shape a
///   single-key `resolve_secret`/`resolve_external_reference` caller reports.
///   (TLS material no longer carries that string: `load_secret_material` now
///   stamps `MaterializedMaterial`'s `display_source_id` with the provider-only
///   `CertSourceUri::redacted_source_id()`, so a PEM-parse failure prints
///   `vault://<redacted source reference>`. This derivation stays because it
///   covers the callers that still echo the rewritten reference, and because a
///   defense that only holds while one call site keeps its current shape is not
///   a defense.)
/// * a `file://` source is reported by its bare filesystem path, the scheme
///   stripped entirely (`CertSource::Path` / `load_file_material`).
/// * a database URL is echoed credential-redacted by
///   `config::db_backend::redact_url` (MongoDB TLS-conflict diagnostics, driver
///   error scrubbing), which rewrites userinfo and query values but leaves the
///   host, path, and remaining query of the resolved value intact.
///
/// Each of these is a deterministic function of the value that this code
/// already owns, so each is reproduced here rather than re-audited at every
/// print site. Non-URI values fall through and contribute nothing: the scheme
/// branch requires a literal `://` with an RFC-3986-shaped scheme, and
/// `redact_url`'s `<invalid-url>` sentinel is deliberately dropped — admitting
/// it would redact that fixed marker out of every unrelated diagnostic.
fn derive_reference_forms(value: &str) -> Vec<String> {
    let mut forms: Vec<String> = Vec::new();
    let trimmed = value.trim();

    if let Some((scheme, rest)) = trimmed.split_once("://")
        && !scheme.is_empty()
        && scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
    {
        let identifier = rest.split('?').next().unwrap_or(rest);
        forms.push(format!("{scheme}:{identifier}"));
        forms.push(identifier.to_string());
        if identifier != rest {
            forms.push(format!("{scheme}:{rest}"));
            forms.push(rest.to_string());
        }
    }

    if trimmed.contains("://") {
        let redacted = crate::config::db_backend::redact_url(trimmed);
        if redacted != trimmed && redacted != "<invalid-url>" {
            forms.push(redacted);
        }
    }

    debug_assert!(forms.len() <= MAX_REFERENCE_FORMS);
    forms
}

/// Upper bound on the forms [`derive_scalar_forms`] can return.
const MAX_SCALAR_FORMS: usize = 2;

/// The canonical rendering of a resolved value that config parsing turns into a
/// typed scalar.
///
/// `EnvConfig` does not echo most values as written; it parses them and then
/// logs the parsed result. `FERRUM_DB_POOL_STATEMENT_TIMEOUT_SECONDS_FILE=03601`
/// is warned about as `configured=3601`, and `FERRUM_TLS_NO_VERIFY_FILE=1` is
/// rendered `true` — neither of which is the string that was materialized, so
/// neither would match an exact-value candidate.
///
/// Only the two canonicalizations Ferrum actually performs are reproduced: the
/// boolean spellings `EnvValue for bool`/`AutoBool` accept (`true`/`1`,
/// `false`/`0`, case-insensitive after `trim()`), and integer/float
/// normalization through `Display`, which is what strips leading zeros, a `+`
/// sign, and exponent notation. Both are derived candidates and so carry the
/// 3-byte minimum, which is why a bare `1` contributes `true` but not `1`
/// itself — the exact value already covers that, without the minimum.
fn derive_scalar_forms(value: &str) -> Vec<String> {
    let mut forms: Vec<String> = Vec::new();
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return forms;
    }

    match trimmed.to_ascii_lowercase().as_str() {
        "true" | "1" => forms.push("true".to_string()),
        "false" | "0" => forms.push("false".to_string()),
        _ => {}
    }

    if let Ok(integer) = trimmed.parse::<i128>() {
        forms.push(integer.to_string());
    } else if let Ok(float) = trimmed.parse::<f64>()
        && float.is_finite()
    {
        forms.push(float.to_string());
    }

    debug_assert!(forms.len() <= MAX_SCALAR_FORMS);
    forms
}

/// The body of `value` as it appears inside a JSON string literal, or `None`
/// when escaping is a no-op (the overwhelmingly common case, and already
/// covered by the unescaped candidate).
fn json_escaped_body(value: &str) -> Option<String> {
    let encoded = serde_json::to_string(value).ok()?;
    let body = encoded.strip_prefix('"')?.strip_suffix('"')?;
    (body != value).then(|| body.to_string())
}

/// Pre-built, deduplicated, longest-first candidate set plus a first-byte
/// screen.
struct RedactionPlan {
    /// Non-empty strings ordered longest-first, so the scan below yields the
    /// longest match at any position.
    candidates: Vec<String>,
    /// `first_bytes[b]` is true when some candidate starts with byte `b`.
    /// Without it every position in every log record would run the full
    /// candidate list; with it the common no-match position costs one indexed
    /// bool load.
    first_bytes: [bool; 256],
    /// The resolved values *as materialized*, plus their `trim()`ed forms.
    ///
    /// Kept separate from `candidates` because it answers a different question —
    /// see [`is_external_secret_value`]. `candidates` mixes in derived rewrites
    /// and is searched for *inside* a message, which is sound for removing a
    /// secret from text but is not evidence of where a string came *from*.
    /// Nothing in this set is ever substring-matched, so it needs no minimum
    /// length and arms nothing.
    exact_values: std::collections::BTreeSet<String>,
    /// [`WITHHELD_LOG_RECORD`] with its own field values already redacted
    /// against `candidates`. Computed once here rather than per withheld
    /// record, which keeps the fail-closed path allocation-cheap and, more
    /// importantly, keeps it from depending on anything but the fixed template.
    withheld_record: String,
}

impl RedactionPlan {
    /// Minimum length for a *derived* candidate.
    ///
    /// The value exactly as materialized has no minimum — it is the secret, and
    /// neither does its JSON-escaped body, which is the same secret in the only
    /// other form a record can carry it in (see [`Self::build`]). A
    /// derived fragment shorter than this (a one-letter namespace entry, say)
    /// carries no meaningful secret content while matching constantly, which
    /// would shred every diagnostic the operator needs to read. Same threshold,
    /// and same reasoning, as `MIN_REDACTABLE_REFERENCE_LEN` in
    /// `secrets::registry`.
    ///
    /// The minimum applies to **every** derived form, with no same-length
    /// exemption. Equal length is not equal content: an external value of `Db`
    /// derives `db`, and `db` matches text that `Db` never would — `dbname`,
    /// `mongodb`, half the words in a database diagnostic. Admitting a rewrite
    /// "because the exact value is already a candidate at that length" is
    /// therefore unsound; it arms a *different* two-byte string process-wide
    /// and shreds unrelated diagnostics, which is exactly the blind
    /// short-substring corruption this minimum exists to prevent.
    ///
    /// The cost is real and is paid elsewhere: a whole-value transformation
    /// below the minimum (`FERRUM_MODE_FILE=DB` lowercased to `db`, `trim()` of
    /// a padded one-character value, a short list segment, or a short
    /// canonical port `080`/` 80` → `80`) is the only rendering an operator
    /// sees and the textual pass cannot cover it. Those sites withhold
    /// **key-tied** instead — [`report_env_field`] / [`report_env_fields`] /
    /// [`report_env_assignment`], `config::env_config_macro::invalid_env_value`,
    /// and `config::env_config::OperatingMode::resolve` — which is exact on
    /// provenance and does not depend on length at all. A new hand-written
    /// validator that re-renders a value must do the same rather than rely on
    /// widening this filter.
    const MIN_DERIVED_CANDIDATE_LEN: usize = 3;

    fn build<I: IntoIterator<Item = String>>(values: I) -> Self {
        let mut candidates: Vec<String> = Vec::new();
        let mut exact_values: std::collections::BTreeSet<String> =
            std::collections::BTreeSet::new();
        for value in values {
            if value.is_empty() {
                continue;
            }
            // Provenance set: the value as materialized, and the same value with
            // surrounding whitespace removed, because a configuration reader may
            // trim before storing what it was handed. Both are the whole secret;
            // no derived form joins them (see `is_external_secret_value`).
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                exact_values.insert(trimmed.to_string());
            }
            exact_values.insert(value.clone());
            candidates.push(value.clone());
            // The JSON-escaped body of the value *as materialized* is another
            // exact representation of the same secret, not a transformed
            // fragment, so it carries no minimum either. Without this, an exact
            // value whose escaped body is shorter than the derived minimum —
            // a one-character control such as tab (`\t`), carriage return
            // (`\r`), backspace (`\b`), or form feed (`\f`) — is present in a
            // serialized record only in its escaped form, which the filter
            // below drops. `contains_candidate` would then find nothing, the
            // record would never be parsed, and the secret would be emitted.
            // Unlike `"` or `\n`, those bytes need not produce an incidental
            // structural match to rescue the screen.
            if let Some(escaped) = json_escaped_body(&value) {
                candidates.push(escaped);
            }
            candidates.extend(
                derive_candidates(&value)
                    .into_iter()
                    .filter(|derived| derived.len() >= Self::MIN_DERIVED_CANDIDATE_LEN),
            );
        }
        // Distinct candidates only: two keys holding the same secret describe
        // one span, and a duplicate would otherwise be scanned (and charged
        // for) twice.
        candidates.sort_unstable();
        candidates.dedup();
        candidates.sort_by_key(|candidate| std::cmp::Reverse(candidate.len()));

        let mut first_bytes = [false; 256];
        for candidate in &candidates {
            if let Some(&byte) = candidate.as_bytes().first() {
                first_bytes[byte as usize] = true;
            }
        }

        let mut plan = Self {
            candidates,
            first_bytes,
            exact_values,
            withheld_record: String::new(),
        };
        // The fail-closed replacement is a record like any other: an exact
        // secret with no minimum length can equal one of the template's own
        // field values (`WARN`, `ferrum_edge::secrets`, `secret`, `values`), and
        // emitting the template verbatim would then disclose it on the one path
        // whose entire purpose is not to. Structural redaction rewrites those
        // values and leaves the schema keys and JSON syntax alone, exactly as
        // for a real record. Reserialization of a compile-time-constant valid
        // JSON object cannot fail, but the fallback is a minimal object rather
        // than the template so that "cannot sanitize" never means "emit
        // unsanitized".
        // Redacted as a tracing-envelope record, which is what it is: a fixed
        // literal carrying the formatter's own `level`/`target`/`message` root
        // keys. That keeps the notice's shape stable for log pipelines while
        // still scrubbing its values.
        let withheld_record = plan
            .redact_json_record(WITHHELD_LOG_RECORD, EnvelopePosition::TracingRoot)
            .unwrap_or_else(|| MINIMAL_WITHHELD_LOG_RECORD.to_string());
        plan.withheld_record = withheld_record;
        plan
    }

    /// Whole-value provenance: is this string one of the resolved values?
    ///
    /// A set lookup, not a scan. Nothing here participates in substring
    /// matching, which is what lets it skip the derived-candidate minimum
    /// entirely — see [`is_external_secret_value`].
    fn is_exact_value(&self, value: &str) -> bool {
        self.exact_values.contains(value)
    }

    /// Allocation-free "is there anything to do here?" screen.
    ///
    /// [`redact_log_record`] runs per emitted record, and in a process that
    /// *does* use external secrets the overwhelming majority of records still
    /// contain no resolved value. This answers that question with the same
    /// first-byte screen [`Self::redact`] uses and without parsing, copying, or
    /// allocating, so only records that actually carry a value pay for the
    /// JSON round trip.
    fn contains_candidate(&self, text: &str) -> bool {
        let bytes = text.as_bytes();
        // Byte indexing is safe against UTF-8 boundaries here: every candidate
        // is valid UTF-8, so its first byte is a leading byte, and a leading
        // byte can never equal a continuation byte. A byte-prefix match
        // therefore cannot start mid-character.
        bytes.iter().enumerate().any(|(index, byte)| {
            self.first_bytes[*byte as usize]
                && self
                    .candidates
                    .iter()
                    .any(|candidate| bytes[index..].starts_with(candidate.as_bytes()))
        })
    }

    /// Parse one serialized log record, redact its values, and reserialize.
    ///
    /// `None` when the record is not well-formed JSON or cannot be
    /// reserialized; the caller withholds the record rather than emitting
    /// anything derived from it. See [`redact_log_record`] for why this is
    /// structural rather than a text pass.
    fn redact_json_record(&self, text: &str, root: EnvelopePosition) -> Option<String> {
        let mut document: LogJson = serde_json::from_str(text).ok()?;
        self.redact_json_value(&mut document, root);
        serde_json::to_string(&document).ok()
    }

    /// Redact values in place, leaving JSON structure alone and rewriting only
    /// those keys that `position` does not mark as tracing-envelope structure.
    fn redact_json_value(&self, value: &mut LogJson, position: EnvelopePosition) {
        // A matched scalar is replaced *after* the match, so the borrow of
        // `value` taken by the pattern has ended by the time it is reassigned.
        let scalar_matches = match value {
            LogJson::String(text) => {
                let redacted = match self.redact(text) {
                    std::borrow::Cow::Owned(owned) => Some(owned),
                    std::borrow::Cow::Borrowed(_) => None,
                };
                if let Some(redacted) = redacted {
                    *text = redacted;
                }
                false
            }
            LogJson::Array(items) => {
                for item in items.iter_mut() {
                    // An array element is never an envelope position: the
                    // formatter emits the envelope as objects only.
                    self.redact_json_value(item, EnvelopePosition::Dynamic);
                }
                false
            }
            // Keys are redacted too, because access records put runtime and
            // operator-supplied strings in key position (plugin `metadata`
            // maps, `log_schema` `rename:`/`static_fields:`/flatten prefixes).
            // Only tracing-envelope positions are exempt, and only in a record
            // the fmt layer produced; see `EnvelopePosition` and the contract
            // on `redact_log_record`.
            LogJson::Object(entries) => {
                // A key that carries a resolved value collapses to the
                // placeholder, and so could several keys in one object. JSON
                // objects with duplicate keys are ambiguous, so the first such
                // entry wins and later ones are dropped: losing a field is
                // acceptable, emitting an ambiguous record is not. An entry
                // whose key already *equals* the placeholder occupies the slot
                // as well, so a crafted key cannot force a collision that
                // re-admits a second redacted entry.
                let mut placeholder_key_taken = false;
                entries.retain_mut(|(key, entry)| {
                    if key.as_str() == EXTERNAL_SECRET_PLACEHOLDER {
                        if placeholder_key_taken {
                            return false;
                        }
                        placeholder_key_taken = true;
                        self.redact_json_value(entry, position.child(key));
                        return true;
                    }
                    if !position.exempts(key) && self.contains_candidate(key) {
                        if placeholder_key_taken {
                            return false;
                        }
                        placeholder_key_taken = true;
                        // The value is dropped rather than redacted in place.
                        // A key built from a resolved value routinely names
                        // material of the same provenance beneath it, and the
                        // key is gone, so retaining the subtree would leave a
                        // value no operator can attribute and that the scan
                        // may not match in full.
                        *key = EXTERNAL_SECRET_PLACEHOLDER.to_string();
                        *entry = LogJson::String(EXTERNAL_SECRET_PLACEHOLDER.to_string());
                        return true;
                    }
                    self.redact_json_value(entry, position.child(key));
                    true
                });
                false
            }
            // Scalars are unquoted in the record, so a resolved port or flag
            // is matched against its rendered form. A hit replaces the whole
            // scalar; partially rewriting a number would produce either a
            // different number or invalid JSON.
            LogJson::Bool(flag) => self.contains_candidate(if *flag { "true" } else { "false" }),
            LogJson::Number(number) => self.contains_candidate(&number.to_string()),
            // `null` is a rendered scalar exactly like `true` and `918273645`:
            // a resolved value of `null` that a validator echoes into a field
            // serialized as a JSON null is present in the record verbatim, so
            // leaving it alone would emit the secret's own representation.
            LogJson::Null => self.contains_candidate("null"),
        };
        if scalar_matches {
            *value = LogJson::String(EXTERNAL_SECRET_PLACEHOLDER.to_string());
        }
    }

    /// Single left-to-right pass over `message`, substituting the longest
    /// matching candidate at each position.
    ///
    /// The cursor only ever advances — past a matched candidate, or by one
    /// character — so every byte of the original is examined once and no
    /// generated placeholder text re-enters matching. Output is therefore
    /// bounded by `message.chars().count() * EXTERNAL_SECRET_PLACEHOLDER.len()`
    /// regardless of how many candidates exist or how short they are, and the
    /// work is `O(message.len() * candidates.len() * longest_candidate.len())`
    /// worst case, `O(message.len())` when nothing matches.
    ///
    /// Borrowed output on no match, so an unaffected log record is not copied.
    fn redact<'a>(&self, message: &'a str) -> std::borrow::Cow<'a, str> {
        let mut out: Option<String> = None;
        // Start of the not-yet-copied literal run, and the scan position.
        let mut copied = 0usize;
        let mut cursor = 0usize;

        while cursor < message.len() {
            let rest = &message[cursor..];

            // A span some earlier pass already redacted. `validate` filters the
            // returned error and then the log sink filters the whole record, so
            // without this the second pass would shred the first pass's
            // placeholders on every candidate that is a substring of the
            // placeholder itself (`value`, `external`, `source`, `a`) — bounded,
            // but it turns a readable diagnostic into noise. Skipping keeps
            // redaction idempotent.
            //
            // Overridden by a candidate at least as long as the placeholder, so
            // a resolved value that happens to *contain* the placeholder text
            // cannot use it as a shield.
            if rest.starts_with(EXTERNAL_SECRET_PLACEHOLDER)
                && !self.candidates.iter().any(|candidate| {
                    candidate.len() >= EXTERNAL_SECRET_PLACEHOLDER.len()
                        && rest.starts_with(candidate.as_str())
                })
            {
                // Left in the not-yet-copied literal run, so it is emitted
                // verbatim.
                cursor += EXTERNAL_SECRET_PLACEHOLDER.len();
                continue;
            }

            let first = rest.as_bytes()[0];
            if self.first_bytes[first as usize]
                && let Some(matched) = self
                    .candidates
                    .iter()
                    .find(|candidate| rest.starts_with(candidate.as_str()))
            {
                let out = out.get_or_insert_with(|| String::with_capacity(message.len()));
                out.push_str(&message[copied..cursor]);
                out.push_str(EXTERNAL_SECRET_PLACEHOLDER);
                cursor += matched.len();
                copied = cursor;
                continue;
            }
            // Advance a whole character, so `cursor` only ever sits on a
            // character boundary and the slicing above cannot panic on
            // multi-byte input.
            match rest.chars().next() {
                Some(next) => cursor += next.len_utf8(),
                None => break,
            }
        }

        match out {
            Some(mut out) => {
                out.push_str(&message[copied..]);
                std::borrow::Cow::Owned(out)
            }
            None => std::borrow::Cow::Borrowed(message),
        }
    }
}

// Azure Key Vault credential injection + reference parsing are exposed so the
// data-plane fetch path can be exercised against a local fake Key Vault with a
// pre-acquired bearer token (no Entra ID round trip). `AzureCredentials`
// carries `from_static_token()` for that injection.
#[cfg(feature = "secrets-azure")]
pub use azure::{
    AzureCredentials, AzureSecret, apply_tls_version_option as azure_apply_tls_version_option,
    parse_keyvault_reference as azure_parse_keyvault_reference,
};

/// Candidate derivation is deliberately private — the whole point of
/// [`RedactionPlan`] is that no caller can hand it a different candidate set —
/// and arming the process-wide plan is a one-shot `OnceLock`, so the external
/// suite can only exercise a single fixture set per test binary. These assert
/// the *individual* derivations directly, which keeps them from having to arm
/// candidates like `true` process-wide (that would rewrite unrelated boolean
/// assertions in every other test in the binary). End-to-end coverage that the
/// derived forms actually reach a diagnostic lives in
/// `tests/unit/secrets/redaction_tests.rs`.
#[cfg(test)]
mod derivation_tests {
    use super::{derive_reference_forms, derive_scalar_forms};

    #[test]
    fn provider_source_rendering_of_a_uri_is_derived() {
        // `SecretBackend::source` renders the completed fetch with one colon
        // and no `//`. TLS material now stamps the provider-only redacted id
        // instead, but single-key callers still report this shape, so the
        // derivation must keep covering it.
        let forms = derive_reference_forms("vault://secret/data/gw#cert");
        assert!(forms.contains(&"vault:secret/data/gw#cert".to_string()));
        assert!(forms.contains(&"secret/data/gw#cert".to_string()));
    }

    #[test]
    fn a_uri_query_is_dropped_the_way_cert_source_uri_drops_it() {
        let forms = derive_reference_forms("vault://secret/data/gw?version=3");
        // The identifier `CertSourceUri::parse` keeps...
        assert!(forms.contains(&"vault:secret/data/gw".to_string()));
        // ...and the value as written, which some sites echo whole.
        assert!(forms.contains(&"vault:secret/data/gw?version=3".to_string()));
    }

    #[test]
    fn file_uri_contributes_its_scheme_stripped_path() {
        let forms = derive_reference_forms("file:///run/secrets/cert.pem");
        assert!(
            forms.contains(&"/run/secrets/cert.pem".to_string()),
            "TLS validation reports a file source by bare path: {forms:?}"
        );
    }

    #[test]
    fn credential_redacted_url_form_is_derived() {
        let forms = derive_reference_forms("mongodb://user:pass@secret-host/db?tls=true");
        assert!(
            forms
                .iter()
                .any(|form| form.contains("secret-host") && !form.contains("pass")),
            "the credential-redacted rendering still exposes host/path: {forms:?}"
        );
    }

    #[test]
    fn non_uri_values_derive_no_reference_forms() {
        for value in ["plain-secret", "/run/secrets/token", "not a url at all"] {
            assert!(
                derive_reference_forms(value).is_empty(),
                "{value} produced spurious reference candidates"
            );
        }
    }

    #[test]
    fn invalid_url_sentinel_is_never_admitted_as_a_candidate() {
        // Redacting `<invalid-url>` out of unrelated diagnostics would be a
        // pure loss: it is a fixed marker, not derived from the value.
        for value in ["://", "http://[", "scheme://"] {
            assert!(
                !derive_reference_forms(value).contains(&"<invalid-url>".to_string()),
                "{value} admitted the invalid-url sentinel"
            );
        }
    }

    #[test]
    fn canonical_number_and_boolean_renderings_are_derived() {
        // `configured=3601` after typed parsing, not the `03601` materialized.
        assert!(derive_scalar_forms("03601").contains(&"3601".to_string()));
        assert!(derive_scalar_forms(" 42 ").contains(&"42".to_string()));
        // `FERRUM_TLS_NO_VERIFY=1` renders as `true`.
        assert!(derive_scalar_forms("1").contains(&"true".to_string()));
        assert!(derive_scalar_forms("0").contains(&"false".to_string()));
        assert!(derive_scalar_forms("TRUE").contains(&"true".to_string()));
    }

    #[test]
    fn non_scalar_and_non_finite_values_derive_nothing() {
        for value in ["", "   ", "not-a-number", "inf", "NaN"] {
            assert!(
                derive_scalar_forms(value).is_empty(),
                "{value} produced spurious scalar candidates"
            );
        }
    }

    #[test]
    fn derivation_stays_within_its_declared_bounds() {
        // The `debug_assert!`s inside each function are the live bound; this
        // pins the worst case that exercises every branch at once.
        let both = "https://user:pass@host/path?query=1";
        assert!(derive_reference_forms(both).len() <= super::MAX_REFERENCE_FORMS);
        assert!(derive_scalar_forms("1").len() <= super::MAX_SCALAR_FORMS);
    }
}

#[cfg(all(test, any(feature = "secrets-aws", feature = "secrets-vault")))]
mod tests {
    use super::split_reference_field;

    #[test]
    fn split_reference_field_handles_optional_suffix() {
        assert_eq!(
            split_reference_field("secret/data/app#password"),
            ("secret/data/app", Some("password"))
        );
        assert_eq!(
            split_reference_field("secret/data/app"),
            ("secret/data/app", None)
        );
    }
}
