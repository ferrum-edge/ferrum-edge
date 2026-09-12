//! Header lookup helpers for auth plugins reading credentials from request headers.
//!
//! `RequestContext::materialize_headers()` decodes field values as UTF-8, so
//! the folded map cannot answer a visible-ASCII question and omits values that
//! are not valid UTF-8 at all. Auth plugins must not treat a present but
//! non-materialized (or non-conforming) field line as absent.
//!
//! Two decode policies exist. Do not mix them up:
//!
//! - [`lookup_configured_header`] admits only visible ASCII + HTAB, matching
//!   `HeaderValue::to_str()`. Use this for RFC-bound credential grammars
//!   (`Authorization` Basic/Bearer, HMAC digest, JWT compact, LDAP Basic). A
//!   non-ASCII value there is malformed, not a legitimate credential.
//! - [`lookup_configured_header_utf8`] admits any valid UTF-8, including
//!   non-ASCII. Use this for operator-chosen opaque API keys (`key_auth`),
//!   which already succeed as query parameters. Invalid UTF-8 is
//!   [`ConfiguredUtf8HeaderLookup::InvalidUtf8`], never
//!   [`ConfiguredUtf8HeaderLookup::Absent`].

use std::borrow::Cow;

use crate::plugins::{RequestContext, repeated_request_header_separator};

/// Result of a visible-ASCII configured-header lookup.
///
/// Produced only by [`lookup_configured_header`]. Non-ASCII UTF-8 is
/// [`Self::PresentNonMaterialized`], not [`Self::Value`].
pub(crate) enum ConfiguredHeaderLookup<'a> {
    Absent,
    /// Borrowed for the common single-field-line case; repeated field lines
    /// allocate only when they actually need folding.
    Value(Cow<'a, str>),
    /// Raw field line(s) exist but cannot be represented as one visible-ASCII
    /// value. The field is PRESENT and malformed for this grammar — never absent.
    PresentNonMaterialized,
}

/// Result of a UTF-8 configured-header lookup.
///
/// Produced only by [`lookup_configured_header_utf8`]. Valid non-ASCII UTF-8
/// is [`Self::Value`]. Invalid UTF-8 is [`Self::InvalidUtf8`], never
/// [`Self::Absent`].
pub(crate) enum ConfiguredUtf8HeaderLookup<'a> {
    Absent,
    /// Borrowed for the common single-field-line case; repeated field lines
    /// allocate only when they actually need folding.
    Value(Cow<'a, str>),
    /// Raw field line(s) exist but are not valid UTF-8.
    InvalidUtf8,
}

enum DecodedHeader<'a> {
    Absent,
    Value(Cow<'a, str>),
    Undecodable,
}

/// Look up a configured header as visible ASCII + HTAB.
///
/// This matches `HeaderValue::to_str()`, which is STRICTER than
/// `materialize_headers()` (UTF-8). RFC-bound auth plugins (`basic_auth`,
/// `hmac_auth`, `jwt_auth`, `ldap_auth`, plus JWKS/OAuth2 bearer extraction)
/// must use this entry point, and must read the retained raw map rather than
/// the folded one so an obs-text field line is reported as malformed instead of
/// being parsed. For operator-chosen UTF-8 API keys, use
/// [`lookup_configured_header_utf8`] instead.
pub(crate) fn lookup_configured_header<'a>(
    ctx: &'a RequestContext,
    lower: &'a str,
    original: Option<&'a str>,
) -> ConfiguredHeaderLookup<'a> {
    match lookup_with_decoder(ctx, lower, original, visible_ascii_header_value) {
        DecodedHeader::Absent => ConfiguredHeaderLookup::Absent,
        DecodedHeader::Value(value) => ConfiguredHeaderLookup::Value(value),
        DecodedHeader::Undecodable => ConfiguredHeaderLookup::PresentNonMaterialized,
    }
}

/// Look up a configured header as UTF-8, including non-ASCII.
///
/// `key_auth` is the only current caller: an operator-chosen API key such as
/// `ユニコード-api-key-value-32chars-min` is stored as UTF-8 and already works
/// as a query parameter. The header path must accept the same bytes. Do not
/// use this for RFC-bound `Authorization` credentials; those stay on
/// [`lookup_configured_header`].
pub(crate) fn lookup_configured_header_utf8<'a>(
    ctx: &'a RequestContext,
    lower: &'a str,
    original: Option<&'a str>,
) -> ConfiguredUtf8HeaderLookup<'a> {
    match lookup_with_decoder(ctx, lower, original, utf8_header_value) {
        DecodedHeader::Absent => ConfiguredUtf8HeaderLookup::Absent,
        DecodedHeader::Value(value) => ConfiguredUtf8HeaderLookup::Value(value),
        DecodedHeader::Undecodable => ConfiguredUtf8HeaderLookup::InvalidUtf8,
    }
}

fn lookup_with_decoder<'a>(
    ctx: &'a RequestContext,
    lower: &'a str,
    original: Option<&'a str>,
    decode_line: fn(&[u8]) -> Option<&str>,
) -> DecodedHeader<'a> {
    // Retained raw field lines are authoritative. The folded map joins repeated
    // lines and is decoded under a looser policy than this lookup's, so
    // consulting it first would let a conforming line mask a hostile sibling.
    if ctx.has_raw_headers() {
        for name in [Some(lower), original] {
            let Some(name) = name else {
                continue;
            };
            if let Some(decoded) = raw_header_field_lines(ctx, name, decode_line) {
                return decoded;
            }
        }
    }

    if let Some(value) = ctx
        .headers
        .get(lower)
        .or_else(|| original.and_then(|orig| ctx.headers.get(orig)))
    {
        return DecodedHeader::Value(Cow::Borrowed(value.as_str()));
    }

    DecodedHeader::Absent
}

fn raw_header_field_lines<'a>(
    ctx: &'a RequestContext,
    name: &'a str,
    decode_line: fn(&[u8]) -> Option<&str>,
) -> Option<DecodedHeader<'a>> {
    let separator = repeated_request_header_separator(name);
    let mut values = ctx.raw_header_value_bytes(name);
    let first = values.next()?;
    let Some(first) = decode_line(first) else {
        return Some(DecodedHeader::Undecodable);
    };
    let Some(second) = values.next() else {
        return Some(DecodedHeader::Value(Cow::Borrowed(first)));
    };

    let mut out = String::with_capacity(first.len() + separator.len() + second.len());
    out.push_str(first);
    for bytes in std::iter::once(second).chain(values) {
        let Some(value) = decode_line(bytes) else {
            return Some(DecodedHeader::Undecodable);
        };
        out.push_str(separator);
        out.push_str(value);
    }
    Some(DecodedHeader::Value(Cow::Owned(out)))
}

fn visible_ascii_header_value(bytes: &[u8]) -> Option<&str> {
    // Keep this boundary identical to `HeaderValue::to_str()`: SP through `~`,
    // plus HTAB. Merely checking UTF-8 would admit non-ASCII Unicode here, and
    // an RFC-bound credential grammar (base64, JWT compact, structured digest)
    // has no obs-text spelling — such bytes are malformed credential material,
    // not a legitimate credential.
    if !bytes
        .iter()
        .all(|byte| (*byte >= 0x20 && *byte < 0x7f) || *byte == b'\t')
    {
        return None;
    }
    std::str::from_utf8(bytes).ok()
}

/// Any valid UTF-8, including non-ASCII. Contrast [`visible_ascii_header_value`].
fn utf8_header_value(bytes: &[u8]) -> Option<&str> {
    std::str::from_utf8(bytes).ok()
}
