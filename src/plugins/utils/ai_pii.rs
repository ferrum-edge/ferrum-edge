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

use std::sync::OnceLock;

use hmac::{Hmac, KeyInit, Mac};
use regex::{Regex, RegexSet};
use ring::rand::SecureRandom;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

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
    ring::rand::SystemRandom::new()
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

struct CompiledPattern {
    name: String,
    regex: Regex,
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
    hash_mac: HmacSha256,
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

        let key: &[u8] = match hash_secret {
            Some(secret) => secret.as_bytes(),
            None => fallback_hmac_key(plugin_name)?,
        };
        let hash_mac = HmacSha256::new_from_slice(key).map_err(|_| {
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
        let mut mac = self.hash_mac.clone();
        mac.update(bytes);
        hex::encode(mac.finalize().into_bytes())
    }

    /// A fresh incremental hasher sharing the same key as
    /// [`keyed_hash_hex`](Self::keyed_hash_hex), for hashing streamed bodies
    /// chunk-by-chunk without buffering them.
    pub fn keyed_hasher(&self) -> KeyedBodyHasher {
        KeyedBodyHasher(self.hash_mac.clone())
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
            let replaced = pattern
                .regex
                .replace_all(&result, |caps: &regex::Captures| {
                    if hash_values {
                        // Never emit the raw matched value — only a keyed-hash
                        // prefix so identical secrets remain correlatable
                        // without being brute-forceable offline.
                        let mut mac = self.hash_mac.clone();
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
