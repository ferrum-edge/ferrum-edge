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
//! plugins keep their existing detection/redaction state machines and only
//! source their pattern strings from [`builtin_pii_pattern`].

use regex::{Regex, RegexSet};

/// Built-in PII pattern definitions shared by the AI plugins.
///
/// Returns the regex source for a built-in pattern name, or `None` for an
/// unknown name (callers treat that as a hard config error). Keep this table in
/// sync with the documented pattern set in `docs/plugins.md`.
pub fn builtin_pii_pattern(name: &str) -> Option<&'static str> {
    match name {
        "ssn" => Some(r"\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b"),
        "credit_card" => Some(
            r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[-.\s]?\d{4}[-.\s]?\d{4}[-.\s]?\d{0,4}\b",
        ),
        "email" => Some(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        "phone_us" => Some(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
        "api_key" => Some(r"\b(?:sk|pk|api|key|token|secret|password)[-_]?[A-Za-z0-9]{20,}\b"),
        "aws_key" => Some(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
        "ip_address" => Some(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"),
        "iban" => Some(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?\d{0,16})\b"),
        _ => None,
    }
}

/// The names of every built-in PII pattern, in a stable order. Useful for
/// documentation, validation, and "all built-ins" config shortcuts.
pub const BUILTIN_PII_PATTERN_NAMES: &[&str] = &[
    "ssn",
    "credit_card",
    "email",
    "phone_us",
    "api_key",
    "aws_key",
    "ip_address",
    "iban",
];

struct CompiledPattern {
    name: String,
    regex: Regex,
    /// `placeholder_template` with `{type}` substituted with `name`, rendered
    /// once so redaction does not re-render per call. Used verbatim (no
    /// `$`-expansion) in non-hashing mode.
    placeholder: String,
}

/// Outcome of a redaction pass.
pub struct RedactionOutcome {
    /// The redacted text (equal to the input when nothing matched).
    pub text: String,
    /// Number of individual PII spans that were replaced.
    pub matches: usize,
}

/// A compiled set of PII patterns plus a redaction policy.
///
/// Redaction replaces every match with a placeholder. When `hash_values` is set
/// the placeholder embeds a stable SHA-256 prefix of the matched substring
/// (`[REDACTED:<type>:<sha256-prefix>]`) so identical values stay correlatable
/// across records without the raw value ever being stored.
pub struct PiiRedactor {
    patterns: Vec<CompiledPattern>,
    detection_set: RegexSet,
    hash_values: bool,
}

impl PiiRedactor {
    /// Build a redactor from built-in pattern names and custom `(name, regex)`
    /// pairs. Unknown built-ins and regexes that fail to compile are hard
    /// errors, prefixed with `plugin_name`.
    pub fn from_config(
        builtins: &[String],
        custom: &[(String, String)],
        placeholder_template: &str,
        hash_values: bool,
        plugin_name: &str,
    ) -> Result<Self, String> {
        let mut patterns = Vec::with_capacity(builtins.len() + custom.len());

        for name in builtins {
            let Some(regex_str) = builtin_pii_pattern(name) else {
                return Err(format!(
                    "{plugin_name}: unknown built-in redaction pattern '{name}'"
                ));
            };
            let regex = Regex::new(regex_str).map_err(|error| {
                format!(
                    "{plugin_name}: failed to compile built-in redaction pattern '{name}': {error}"
                )
            })?;
            patterns.push(CompiledPattern {
                placeholder: placeholder_template.replace("{type}", name),
                name: name.clone(),
                regex,
            });
        }

        for (name, regex_str) in custom {
            let regex = Regex::new(regex_str).map_err(|error| {
                format!(
                    "{plugin_name}: failed to compile custom redaction pattern '{name}': {error}"
                )
            })?;
            patterns.push(CompiledPattern {
                placeholder: placeholder_template.replace("{type}", name),
                name: name.clone(),
                regex,
            });
        }

        let detection_set = RegexSet::new(patterns.iter().map(|pattern| pattern.regex.as_str()))
            .map_err(|error| {
                format!("{plugin_name}: failed to build redaction detection set: {error}")
            })?;

        Ok(Self {
            patterns,
            detection_set,
            hash_values,
        })
    }

    /// Whether any patterns are configured. A redactor with no patterns is a
    /// pass-through.
    pub fn has_patterns(&self) -> bool {
        !self.patterns.is_empty()
    }

    /// Redact every PII span in `text`. Returns the input unchanged (with a
    /// zero match count) when nothing matches, so the common no-PII path is a
    /// single `RegexSet` scan.
    pub fn redact(&self, text: &str) -> RedactionOutcome {
        if self.patterns.is_empty() || !self.detection_set.is_match(text) {
            return RedactionOutcome {
                text: text.to_string(),
                matches: 0,
            };
        }

        let mut result = text.to_string();
        let mut matches = 0usize;
        for pattern in &self.patterns {
            let hash_values = self.hash_values;
            let name = pattern.name.as_str();
            let placeholder = pattern.placeholder.as_str();
            let replaced = pattern
                .regex
                .replace_all(&result, |caps: &regex::Captures| {
                    matches += 1;
                    if hash_values {
                        // Never emit the raw matched value — only a stable hash
                        // prefix so identical secrets remain correlatable.
                        format!(
                            "[REDACTED:{name}:{}]",
                            sha256_hex_prefix(caps[0].as_bytes(), 12)
                        )
                    } else {
                        placeholder.to_string()
                    }
                })
                .into_owned();
            result = replaced;
        }

        RedactionOutcome {
            text: result,
            matches,
        }
    }
}

/// Lowercase hex of the first `hex_chars` characters of the SHA-256 of `bytes`.
fn sha256_hex_prefix(bytes: &[u8], hex_chars: usize) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    let mut hex = hex::encode(digest);
    hex.truncate(hex_chars);
    hex
}
