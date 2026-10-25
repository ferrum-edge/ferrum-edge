//! Shared PII detection/redaction primitives for the AI plugin family.
//!
//! `ai_prompt_shield`, `ai_response_guard`, and `ai_transcript_audit` all need
//! the same built-in PII regexes. Historically each guard plugin carried its
//! own byte-identical copy of the pattern table; this module is the single
//! source of truth so a pattern fix or addition lands in every consumer at
//! once.
//!
//! The [`PiiRedactor`] here is used by `ai_transcript_audit` to redact captured
//! request/response excerpts before they leave the process. The two guard
//! plugins keep their existing detection/redaction state machines and source
//! their pattern strings from [`builtin_pii_pattern`]. [`PiiRedactor`] and
//! `ai_response_guard` additionally confirm each match with
//! [`builtin_pii_validator`] (the `credit_card` Luhn checksum).

use std::sync::OnceLock;

use crate::fips::approved::{HmacSha256, HmacSha256Key};
use crate::fips::backend::rand::SecureRandom;
use regex::{Regex, RegexSet};

/// Process-wide random HMAC key used when no `hash_secret` is configured.
///
/// Generated once per process and shared by every [`PiiRedactor`] built
/// without a secret, so the documented "hashes correlate within one process
/// lifetime" guarantee holds across config reloads and multiple plugin
/// instances — a per-construction key would silently break correlation on
/// every reload. Never logged or exported.
fn fallback_hmac_key(plugin_name: &str) -> Result<&'static [u8; 32], String> {
    static FALLBACK_KEY: OnceLock<[u8; 32]> = OnceLock::new();
    if let Some(key) = FALLBACK_KEY.get() {
        return Ok(key);
    }
    let mut key = [0u8; 32];
    crate::fips::backend::rand::SystemRandom::new()
        .fill(&mut key)
        .map_err(|_| format!("{plugin_name}: failed to generate a random redaction hash key"))?;
    // Two concurrent constructions may both generate; `get_or_init` makes one
    // winner and both callers use the stored key.
    Ok(FALLBACK_KEY.get_or_init(|| key))
}

/// Built-in PII pattern definitions shared by the AI plugins.
///
/// Returns the regex source for a built-in pattern name, or `None` for an
/// unknown name (callers treat that as a hard config error). Keep this table in
/// sync with the documented pattern set in `docs/plugins.md`.
///
/// Coverage, per pattern:
///
/// - `credit_card`: 16–19 digit Visa (`4`), Mastercard (`51`–`55` and the
///   `2221`–`2720` 2-series), Discover (`6011`, `644`–`649`, `65`), UnionPay
///   (`62`), and JCB (`3528`–`3589`) numbers in 4-digit groups; 15-digit
///   American Express (`34`/`37`) contiguous, in its printed 4-6-5 grouping, or
///   in 4-4-4-3 groups; and 14-digit Diners Club (`300`–`305`, `36`, `38`, `39`)
///   contiguous or 4-6-4. Groups may be separated by `-`, `.`, or whitespace.
///   The regex is a candidate shape only: consumers that can confirm a match
///   apply [`builtin_pii_validator`] (a Luhn checksum) so ordinary long
///   reference numbers are not reported.
/// - `api_key`: a `sk`/`pk`/`rk`/`api`/`key`/`token`/`secret`/`password`
///   prefix, up to three short hyphen/underscore segments (`sk-proj-…`,
///   `sk-ant-api03-…`, `sk-svcacct-…`), a run of at least 20 alphanumerics,
///   and every further `-`/`_` segment of the same token, so redaction removes
///   the whole credential rather than its first segment. GitHub
///   (`ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_`, `github_pat_`), Google (`AIza`), and
///   Slack (`xox[abposr]-`) token formats are covered too.
/// - `ip_address`: dotted-quad IPv4 with every octet in `0`–`255` (leading
///   zeros allowed), plus IPv6 in full eight-group form or `::`-compressed form
///   with at least three groups. A bare `::`, a leading-`::` address such as
///   `::1`, and two-group compressions such as `fe80::1` are deliberately not
///   matched: they are indistinguishable from `Type::member` paths in code.
/// - `iban`: an IBAN-registry country code, two check digits, and an 11–30
///   character BBAN, either compact or printed in space-separated groups of
///   four (`GB29 NWBK 6016 1331 9268 19`).
pub fn builtin_pii_pattern(name: &str) -> Option<&'static str> {
    match name {
        "ssn" => Some(r"\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b"),
        "credit_card" => Some(concat!(
            r"\b(?:",
            r"(?:4\d{3}|5[1-5]\d{2}|2(?:22[1-9]|2[3-9]\d|[3-6]\d{2}|7[01]\d|720)",
            r"|6(?:011|5\d{2}|4[4-9]\d|2\d{2})|35(?:2[89]|[3-8]\d))",
            r"(?:[-.\s]?\d{4}){3}(?:[-.\s]?\d{1,3})?",
            r"|3[47]\d{2}(?:[-.\s]?\d{6}[-.\s]?\d{5}|(?:[-.\s]?\d{4}){2}[-.\s]?\d{3})",
            r"|3(?:0[0-5]|[689]\d)\d[-.\s]?\d{6}[-.\s]?\d{4}",
            r")\b",
        )),
        "email" => Some(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        "phone_us" => Some(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
        "api_key" => Some(concat!(
            r"\b(?:",
            r"(?:sk|pk|rk|api|key|token|secret|password)(?:[-_][A-Za-z0-9]{1,10}){0,3}",
            r"[-_]?[A-Za-z0-9]{20,}(?:[-_][A-Za-z0-9]+)*",
            r"|gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,}",
            r"|AIza[0-9A-Za-z_-]{35}|xox[abposr]-[A-Za-z0-9-]{10,}",
            r")\b",
        )),
        "aws_key" => Some(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
        "ip_address" => Some(concat!(
            r"\b(?:",
            r"(?:(?:25[0-5]|2[0-4]\d|1\d\d|0?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|0?\d?\d)",
            r"|(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}",
            r"|(?:[0-9A-Fa-f]{1,4}:){1,5}[0-9A-Fa-f]{1,4}::[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){0,4}",
            r"|[0-9A-Fa-f]{1,4}::[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){1,5}",
            r")\b",
        )),
        "iban" => Some(concat!(
            r"\b(?:AD|AE|AL|AT|AZ|BA|BE|BG|BH|BI|BR|BY|CH|CR|CY|CZ|DE|DJ|DK|DO|EE|EG|ES",
            r"|FI|FK|FO|FR|GB|GE|GI|GL|GR|GT|HR|HU|IE|IL|IQ|IS|IT|JO|KW|KZ|LB|LC|LI|LT",
            r"|LU|LV|LY|MC|MD|ME|MK|MN|MR|MT|MU|NI|NL|NO|OM|PK|PL|PS|PT|QA|RO|RS|RU|SA",
            r"|SC|SD|SE|SI|SK|SM|SO|ST|SV|TL|TN|TR|UA|VA|VG|XK|YE)\d{2}",
            r"(?:[A-Z0-9]{11,30}|(?: [A-Z0-9]{4}){2,7}(?: [A-Z0-9]{1,4})?)\b",
        )),
        _ => None,
    }
}

/// Post-match validator for a built-in pattern, or `None` when every regex
/// match of that pattern is a finding.
///
/// A regex can only describe the SHAPE of some identifiers. `credit_card`
/// carries a Luhn checksum, which a consumer that can inspect the matched text
/// applies so a 16-digit order or tracking number with a card-like prefix is
/// not reported, rejected, or redacted. A consumer that only runs the regex
/// (detection without per-match confirmation) stays correct, just broader.
pub fn builtin_pii_validator(name: &str) -> Option<fn(&str) -> bool> {
    match name {
        "credit_card" => Some(luhn_valid_card_number),
        _ => None,
    }
}

/// Luhn checksum over the digits of a `credit_card` match.
///
/// Separators the pattern admits (`-`, `.`, any whitespace) are skipped; any
/// other character — including a non-ASCII digit the Unicode `\d` class
/// accepted — makes the candidate invalid. Card numbers are 13–19 digits.
pub fn luhn_valid_card_number(candidate: &str) -> bool {
    let mut sum = 0u32;
    let mut digits = 0usize;
    let mut double = false;
    for ch in candidate.chars().rev() {
        if ch == '-' || ch == '.' || ch.is_whitespace() {
            continue;
        }
        // `char::to_digit` recognizes ASCII digits only.
        let Some(mut digit) = ch.to_digit(10) else {
            return false;
        };
        if double {
            digit *= 2;
            if digit > 9 {
                digit -= 9;
            }
        }
        sum += digit;
        digits += 1;
        double = !double;
    }
    (13..=19).contains(&digits) && sum.is_multiple_of(10)
}

struct CompiledPattern {
    name: String,
    regex: Regex,
    /// Built-in post-match validator ([`builtin_pii_validator`]); a match it
    /// refuses is not PII and is left unredacted.
    validator: Option<fn(&str) -> bool>,
    /// `placeholder_template` with `{type}` substituted with `name`, rendered
    /// once so redaction does not re-render per call. Used verbatim (no
    /// `$`-expansion) in non-hashing mode.
    placeholder: String,
}

/// A compiled set of PII patterns plus a redaction policy.
///
/// Redaction replaces every match with a placeholder. When `hash_values` is set
/// the placeholder embeds a **keyed** HMAC-SHA256 prefix of the matched
/// substring (`[REDACTED:<type>:<hmac-prefix>]`) so identical values stay
/// correlatable across records without the raw value ever being stored. The
/// digest is keyed because most built-in PII value spaces (SSNs, US phone
/// numbers, credit cards) are small enough to brute-force offline from an
/// unsalted hash: with `hash_secret` the key is operator-provided (hashes are
/// stable fleet-wide); without it a process-wide random key is used (see
/// [`fallback_hmac_key`] — shared by every redactor built without a secret,
/// across config reloads and plugin instances), so hashes correlate within one
/// process lifetime but can never be dictionary-attacked by whoever holds the
/// exported records.
pub struct PiiRedactor {
    patterns: Vec<CompiledPattern>,
    detection_set: RegexSet,
    hash_values: bool,
    /// Pre-keyed HMAC template, cloned per match (keying an HMAC is the
    /// expensive part; cloning the initialized state is cheap).
    hash_mac: HmacSha256Key,
}

impl PiiRedactor {
    /// Build a redactor from built-in pattern names and custom `(name, regex)`
    /// pairs. Unknown built-ins and regexes that fail to compile are hard
    /// errors, prefixed with `plugin_name`.
    ///
    /// `hash_secret` keys the redacted-value digest. `None` generates a
    /// per-process random key (see the type-level docs for the trade-off).
    pub fn from_config(
        builtins: &[String],
        custom: &[(String, String)],
        placeholder_template: &str,
        hash_values: bool,
        hash_secret: Option<&str>,
        plugin_name: &str,
    ) -> Result<Self, String> {
        let mut patterns = Vec::with_capacity(builtins.len() + custom.len());

        for name in builtins {
            let Some(regex_str) = builtin_pii_pattern(name) else {
                return Err(format!(
                    "{plugin_name}: `redaction.builtins` unknown built-in redaction pattern {name:?}"
                ));
            };
            let regex = Regex::new(regex_str).map_err(|_| {
                format!(
                    "{plugin_name}: `redaction.builtins` failed to compile built-in redaction pattern {name:?} (invalid regex or complexity limit exceeded)"
                )
            })?;
            patterns.push(CompiledPattern {
                placeholder: placeholder_template.replace("{type}", name),
                name: name.clone(),
                regex,
                validator: builtin_pii_validator(name),
            });
        }

        for (index, (name, regex_str)) in custom.iter().enumerate() {
            let regex = Regex::new(regex_str).map_err(|_| {
                format!(
                    "{plugin_name}: `redaction.custom_patterns[{index}].regex` failed to compile custom redaction pattern {name:?} (invalid regex or complexity limit exceeded)"
                )
            })?;
            patterns.push(CompiledPattern {
                placeholder: placeholder_template.replace("{type}", name),
                name: name.clone(),
                regex,
                validator: None,
            });
        }

        let detection_set = RegexSet::new(patterns.iter().map(|pattern| pattern.regex.as_str()))
            .map_err(|_| {
                format!(
                    "{plugin_name}: `redaction.builtins` / `redaction.custom_patterns` detection set is invalid or too complex"
                )
            })?;

        let key: &[u8] = match hash_secret {
            Some(secret) => secret.as_bytes(),
            None => fallback_hmac_key(plugin_name)?,
        };
        let hash_mac = HmacSha256Key::new_from_slice(key).map_err(|_| {
            // HMAC-SHA256 accepts keys of any length, so this is unreachable in
            // practice; surface it as a config error rather than panic.
            format!("{plugin_name}: failed to initialize the redaction hash key")
        })?;

        Ok(Self {
            patterns,
            detection_set,
            hash_values,
            hash_mac,
        })
    }

    /// Keyed HMAC-SHA256 hex digest of `bytes`, using the same key as the
    /// redacted-value placeholders (`hash_secret` when configured, else the
    /// per-process random key). Exported body hashes must be keyed for the same
    /// reason placeholder digests are: a plain SHA-256 of a mostly-predictable
    /// payload (a fixed JSON wrapper around one secret) is an offline
    /// brute-force oracle for the secret.
    pub fn keyed_hash_hex(&self, bytes: &[u8]) -> String {
        let mut mac = self.hash_mac.begin();
        mac.update(bytes);
        hex::encode(mac.finalize().into_bytes())
    }

    /// A fresh incremental hasher sharing the same key as
    /// [`keyed_hash_hex`](Self::keyed_hash_hex), for hashing streamed bodies
    /// chunk-by-chunk without buffering them.
    pub fn keyed_hasher(&self) -> KeyedBodyHasher {
        KeyedBodyHasher(self.hash_mac.begin())
    }

    /// Redact every PII span in `text`. Returns the input unchanged when nothing
    /// matches, so the common no-PII path is a single `RegexSet` scan.
    pub fn redact(&self, text: &str) -> String {
        if self.patterns.is_empty() || !self.detection_set.is_match(text) {
            return text.to_string();
        }

        let mut result = text.to_string();
        for pattern in &self.patterns {
            let hash_values = self.hash_values;
            let name = pattern.name.as_str();
            let placeholder = pattern.placeholder.as_str();
            let validator = pattern.validator;
            let replaced = pattern
                .regex
                .replace_all(&result, |caps: &regex::Captures| {
                    // A shape-only match the built-in validator refuses (a
                    // card-shaped number failing its Luhn checksum) is not
                    // PII; keep it verbatim.
                    if validator.is_some_and(|valid| !valid(&caps[0])) {
                        return caps[0].to_string();
                    }
                    if hash_values {
                        // Never emit the raw matched value — only a keyed-hash
                        // prefix so identical secrets remain correlatable
                        // without being brute-forceable offline.
                        let mut mac = self.hash_mac.begin();
                        mac.update(caps[0].as_bytes());
                        format!(
                            "[REDACTED:{name}:{}]",
                            hex_prefix(&mac.finalize().into_bytes(), 12)
                        )
                    } else {
                        placeholder.to_string()
                    }
                })
                .into_owned();
            result = replaced;
        }

        result
    }
}

/// Incremental keyed HMAC-SHA256 hasher over a streamed body (see
/// [`PiiRedactor::keyed_hasher`]). Consumed by `finalize_hex`.
pub struct KeyedBodyHasher(HmacSha256);

impl KeyedBodyHasher {
    pub fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }

    pub fn finalize_hex(self) -> String {
        hex::encode(self.0.finalize().into_bytes())
    }
}

/// Lowercase hex of the first `hex_chars` characters of `bytes`.
fn hex_prefix(bytes: &[u8], hex_chars: usize) -> String {
    let mut hex = hex::encode(bytes);
    hex.truncate(hex_chars);
    hex
}
