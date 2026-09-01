//! Decode/normalization pass for WAF body and query-value scanning.
//!
//! The body regex set runs over raw bytes, so a payload hidden behind an
//! encoding the rules never see slips through: JSON `<script>`,
//! HTML `&lt;script&gt;`, or form `%3Cscript%3E`. `decoded_variants_with_residual`
//! returns up to [`MAX_VARIANTS`] normalized forms of a value (deduped, and
//! excluding the raw input which the caller scans separately) so the same rule
//! set matches the decoded payload without per-rule changes. Query components
//! share that pipeline via [`canonical_query_component_views`].
//!
//! Decoders are deliberately content-type-agnostic: an attacker controls the
//! declared `Content-Type`, so we apply every transformation regardless. Each
//! decoder borrows its input when there is nothing to decode, so plain bodies
//! produce zero variants and zero allocations.

use std::borrow::Cow;

use percent_encoding::percent_decode_str;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Utf16Endian {
    Little,
    Big,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Utf32Endian {
    Little,
    Big,
}

/// Maximum number of normalized variants produced per value (excluding the
/// raw input). Bounds body-scan cost at `O(VARIANTS × bytes × rules)` for a
/// single inspection view; the underlying `RegexSet` matching is linear so
/// this is a hard multiplier. A bare `charset=utf-16` / `utf-32` with no BOM
/// may produce up to [`MAX_WIDE_CHARSET_VIEWS`] transcoded views and still
/// scans the raw/lossy view, so that path's worst case is
/// `O((1 + MAX_WIDE_CHARSET_VIEWS) × (1 + MAX_VARIANTS) × bytes × rules)`.
/// That is a deliberate bound for an uncommon Content-Type, not an unbounded
/// expansion — do not raise this cap to "make room" for more endians.
const MAX_VARIANTS: usize = 4;

/// Cap on UTF-16 / UTF-32 inspection views of one body. Explicit little/big
/// names and BOMs resolve to one view. Bare `utf-16` / `utf-32` without a
/// BOM tries both endiannesses; successful views are kept up to this cap.
const MAX_WIDE_CHARSET_VIEWS: usize = 2;
const MAX_NUMERIC_ENTITY_DIGITS: usize = 16;

/// Maximum decode rounds in [`layered_decode_inner`]. Each round peels at most one
/// percent layer plus one unicode/HTML layer, so a token stacked deeper than
/// this many percent layers is not fully reduced. The cap is a deliberate cost
/// guard against decompression-style blowups; deeper stacks are flagged as an
/// encoding-evasion residual rather than decoded indefinitely (see the residual
/// flag returned by [`decoded_variants_with_residual`]).
const MAX_DECODE_ROUNDS: usize = 3;

/// Produce normalized decodings of `text` distinct from the raw input, and
/// report whether the layered decode left an actively-decoding residual.
///
/// The caller already scans the raw bytes; these variants surface payloads
/// hidden behind percent-, HTML-entity-, and JSON/JS-unicode encoding,
/// including stacked combinations via the fully layered decode.
///
/// The second return value is the residual flag: a payload deliberately stacked
/// deeper than [`MAX_DECODE_ROUNDS`] (e.g. quad-or-deeper percent-encoding) is
/// not reduced to its literal injection token within the cap, so the body regex
/// set never sees the decoded payload. Callers surface this as an
/// encoding-evasion signal so deeply-stacked body encodings are flagged the
/// same way URL double-encoding is, instead of being silently forwarded. It is
/// precise: true only when decoding genuinely did not converge within the cap,
/// not merely because a literal `%`/`&` survived in an already-decoded body
/// (which would false-positive on benign text). The variant set and the
/// residual flag share a single layered decode pass rather than running it
/// twice.
pub(super) fn decoded_variants_with_residual(text: &str) -> (Vec<String>, bool) {
    if !has_decodable_marker(text) {
        return (Vec::new(), false);
    }

    // Layered decode catches stacked encodings (e.g. percent-encoded HTML
    // entities). The single-layer decodes are kept as well because a layered
    // percent-decode can mangle a body that merely contains a literal `%`,
    // and we still want the JSON/HTML-only decode to fire in that case.
    let (layered, converged) = layered_decode_inner(text);
    let candidates = [
        Cow::Owned(layered),
        unicode_unescape(text),
        html_entity_decode(text),
        percent_decode_plus(text),
    ];

    let mut out: Vec<String> = Vec::new();
    for candidate in candidates {
        if out.len() >= MAX_VARIANTS {
            break;
        }
        if candidate.as_ref() != text && !out.iter().any(|existing| existing == candidate.as_ref())
        {
            out.push(candidate.into_owned());
        }
    }
    (out, !converged)
}

/// Zero, one, or two UTF-8 inspection views of a UTF-16 / UTF-32 body.
///
/// Ordinary UTF-8 produces [`WideCharsetViews::empty`] — no heap allocation.
/// A resolved endianness (explicit `utf-16le` / `utf-32be`, or a BOM) yields
/// one view. A bare `charset=utf-16` / `utf-32` with no BOM tries both
/// endiannesses and keeps each successful view, capped at
/// [`MAX_WIDE_CHARSET_VIEWS`], and still asks the scanner to keep the
/// raw/lossy view (`include_lossy`).
pub(super) struct WideCharsetViews {
    views: [Option<String>; MAX_WIDE_CHARSET_VIEWS],
    include_lossy: bool,
}

impl WideCharsetViews {
    pub(super) fn empty() -> Self {
        Self {
            views: [None, None],
            include_lossy: false,
        }
    }

    fn resolved(text: String) -> Self {
        Self {
            views: [Some(text), None],
            include_lossy: false,
        }
    }

    /// Two candidate readings of the same bytes that the declaration does not
    /// disambiguate: either endianness of a bare `utf-16` / `utf-32`, or the
    /// UTF-32LE / UTF-16LE split of a `FF FE 00 00` prefix.
    fn unresolved(first: Option<String>, second: Option<String>) -> Self {
        let mut out = Self::from_endians(first, second);
        // Lossy fallback is used whenever there is no transcoded view. When
        // at least one candidate decoded, still keep that raw/lossy scan so an
        // ambiguous body cannot drop it.
        out.include_lossy = !out.is_empty();
        out
    }

    fn from_endians(little: Option<String>, big: Option<String>) -> Self {
        match (little, big) {
            (None, None) => Self::empty(),
            (Some(text), None) | (None, Some(text)) => Self::resolved(text),
            (Some(little), Some(big)) if little == big => Self::resolved(little),
            (Some(little), Some(big)) => Self {
                views: [Some(little), Some(big)],
                include_lossy: false,
            },
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.views.iter().all(Option::is_none)
    }

    pub(super) fn include_lossy(&self) -> bool {
        self.include_lossy
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = &str> {
        self.views.iter().filter_map(|view| view.as_deref())
    }
}

/// Decode already-admitted UTF-16 / UTF-32 request bodies into inspection
/// views.
///
/// This helper does not decide whether a body is eligible for WAF inspection;
/// the request content-type/multipart/binary gates run before the scanner. It
/// only creates the text views used by active request-body rules. Ordinary
/// UTF-8 bodies return [`WideCharsetViews::empty`] without allocating.
///
/// UTF-32 BOMs are recognized first (see [`utf32_bom`]): a UTF-32LE BOM is
/// `FF FE 00 00` and would otherwise be misread as a UTF-16LE BOM. When a
/// charset declares the UTF-16 or UTF-32 family without an endianness and
/// without a BOM, both endiannesses are decoded; a view that is not a
/// multiple of the code-unit width, is truncated, or contains surrogate-range
/// / above-`U+10FFFF` units is omitted so the caller retains its existing
/// lossy raw-byte scan for that endian.
pub(super) fn decode_wide_charset_body_views(
    body: &[u8],
    content_type: Option<&str>,
) -> WideCharsetViews {
    if charset_is_unspecified_utf32(content_type) && utf32_bom(body).is_none() {
        return WideCharsetViews::unresolved(
            decode_utf32(body, Utf32Endian::Little),
            decode_utf32(body, Utf32Endian::Big),
        );
    }
    // `FF FE 00 00` is simultaneously a UTF-32LE BOM and a UTF-16LE BOM
    // followed by U+0000. Unicode makes UTF-32LE the correct reading, and
    // `utf16_bom` defers to it — but a backend without UTF-32 support reads
    // exactly the same bytes as UTF-16LE, so committing to one view would
    // leave the other unscanned. Unless the charset names the UTF-32 family
    // (in which case the declaration, not the BOM, settles it), scan both and
    // keep the raw/lossy view as well. `00 00 FE FF` (UTF-32BE) is not a
    // UTF-16 BOM prefix and is therefore unambiguous.
    if matches!(utf32_bom(body), Some((Utf32Endian::Little, _)))
        && !charset_declares_utf32_family(content_type)
    {
        return WideCharsetViews::unresolved(
            decode_utf32(&body[4..], Utf32Endian::Little),
            decode_utf16(&body[2..], Utf16Endian::Little),
        );
    }
    if let Some(text) = decode_utf32_body(body, content_type) {
        return WideCharsetViews::resolved(text);
    }
    if charset_is_unspecified_utf16(content_type) && utf16_bom(body).is_none() {
        return WideCharsetViews::unresolved(
            decode_utf16(body, Utf16Endian::Little),
            decode_utf16(body, Utf16Endian::Big),
        );
    }
    match decode_utf16_body(body, content_type) {
        Some(text) => WideCharsetViews::resolved(text),
        None => WideCharsetViews::empty(),
    }
}

/// Decode an already-admitted request body when its UTF-16 endianness is
/// resolved (explicit `charset` or a BOM). Bare `charset=utf-16` with no BOM
/// is handled by [`decode_wide_charset_body_views`] instead of inventing an
/// endianness here.
fn decode_utf16_body(body: &[u8], content_type: Option<&str>) -> Option<String> {
    let bom = utf16_bom(body);
    let declared = declared_utf16_endian(content_type, bom.map(|(endian, _)| endian));
    let (endian, skip) = match (declared, bom) {
        (Some(declared), Some((bom_endian, skip))) if declared == bom_endian => (declared, skip),
        (Some(_), Some(_)) => return None,
        (Some(declared), None) => (declared, 0),
        (None, Some((bom_endian, skip))) => (bom_endian, skip),
        (None, None) => return None,
    };
    decode_utf16(&body[skip..], endian)
}

/// Decode an already-admitted request body when its UTF-32 endianness is
/// resolved (explicit `charset` or a BOM). Bare `charset=utf-32` with no BOM
/// is handled by [`decode_wide_charset_body_views`] instead of inventing an
/// endianness here.
fn decode_utf32_body(body: &[u8], content_type: Option<&str>) -> Option<String> {
    let bom = utf32_bom(body);
    let declared = declared_utf32_endian(content_type, bom.map(|(endian, _)| endian));
    let (endian, skip) = match (declared, bom) {
        (Some(declared), Some((bom_endian, skip))) if declared == bom_endian => (declared, skip),
        (Some(_), Some(_)) => return None,
        (Some(declared), None) => (declared, 0),
        (None, Some((bom_endian, skip))) => (bom_endian, skip),
        (None, None) => return None,
    };
    decode_utf32(&body[skip..], endian)
}

/// First `charset` parameter of a Content-Type. Duplicate `charset=`
/// parameters are treated as unspecified (return `None`) so a conflicting
/// pair cannot pick an endianness.
fn charset_value(content_type: Option<&str>) -> Option<&str> {
    let content_type = content_type?;
    let mut declared = None;
    for parameter in content_type.split(';').skip(1) {
        let Some((name, raw_value)) = parameter.split_once('=') else {
            continue;
        };
        if !name.trim().eq_ignore_ascii_case("charset") {
            continue;
        }
        if declared.is_some() {
            return None;
        }
        declared = Some(raw_value.trim().trim_matches('"'));
    }
    declared
}

fn charset_is_unspecified_utf16(content_type: Option<&str>) -> bool {
    charset_value(content_type).is_some_and(|value| {
        value.eq_ignore_ascii_case("utf-16") || value.eq_ignore_ascii_case("utf16")
    })
}

fn charset_is_unspecified_utf32(content_type: Option<&str>) -> bool {
    charset_value(content_type).is_some_and(|value| {
        value.eq_ignore_ascii_case("utf-32") || value.eq_ignore_ascii_case("utf32")
    })
}

fn declared_utf16_endian(
    content_type: Option<&str>,
    bom_endian: Option<Utf16Endian>,
) -> Option<Utf16Endian> {
    let value = charset_value(content_type)?;
    if value.eq_ignore_ascii_case("utf-16le") || value.eq_ignore_ascii_case("utf16le") {
        Some(Utf16Endian::Little)
    } else if value.eq_ignore_ascii_case("utf-16be")
        || value.eq_ignore_ascii_case("utf16be")
        || value.eq_ignore_ascii_case("unicodefffe")
    {
        Some(Utf16Endian::Big)
    } else if value.eq_ignore_ascii_case("utf-16") || value.eq_ignore_ascii_case("utf16") {
        bom_endian
    } else {
        None
    }
}

fn utf16_bom(body: &[u8]) -> Option<(Utf16Endian, usize)> {
    // A UTF-32LE BOM is `FF FE 00 00` and therefore also starts with the
    // UTF-16LE BOM `FF FE`. Consult the 4-byte marks first so a UTF-32LE
    // body is never misdecoded as UTF-16LE (issue #4455). UTF-32BE
    // (`00 00 FE FF`) is not a UTF-16 BOM; the same guard keeps both
    // 4-byte marks in one place.
    if utf32_bom(body).is_some() {
        return None;
    }
    if body.starts_with(&[0xFF, 0xFE]) {
        Some((Utf16Endian::Little, 2))
    } else if body.starts_with(&[0xFE, 0xFF]) {
        Some((Utf16Endian::Big, 2))
    } else {
        None
    }
}

fn declared_utf32_endian(
    content_type: Option<&str>,
    bom_endian: Option<Utf32Endian>,
) -> Option<Utf32Endian> {
    let value = charset_value(content_type)?;
    if value.eq_ignore_ascii_case("utf-32le") || value.eq_ignore_ascii_case("utf32le") {
        Some(Utf32Endian::Little)
    } else if value.eq_ignore_ascii_case("utf-32be") || value.eq_ignore_ascii_case("utf32be") {
        Some(Utf32Endian::Big)
    } else if value.eq_ignore_ascii_case("utf-32") || value.eq_ignore_ascii_case("utf32") {
        // Bare `utf-32` without a BOM is endian-unspecified. The dual-endian
        // path in [`decode_wide_charset_body_views`] handles that case before
        // this helper is consulted. When a BOM is present, use it; otherwise
        // return `None` so this helper does not invent an endianness.
        bom_endian
    } else {
        None
    }
}

/// Whether the declared charset names the UTF-32 family at all (bare
/// `utf-32` or an explicit endianness). A body whose charset says UTF-32 is
/// read as UTF-32 by any backend honouring the declaration, so its BOM is not
/// ambiguous; one with no UTF-32 declaration is.
fn charset_declares_utf32_family(content_type: Option<&str>) -> bool {
    declared_utf32_endian(content_type, Some(Utf32Endian::Little)).is_some()
}

fn utf32_bom(body: &[u8]) -> Option<(Utf32Endian, usize)> {
    if body.starts_with(&[0xFF, 0xFE, 0x00, 0x00]) {
        Some((Utf32Endian::Little, 4))
    } else if body.starts_with(&[0x00, 0x00, 0xFE, 0xFF]) {
        Some((Utf32Endian::Big, 4))
    } else {
        None
    }
}

fn decode_utf16(payload: &[u8], endian: Utf16Endian) -> Option<String> {
    if !payload.len().is_multiple_of(2) {
        return None;
    }
    // UTF-8 output is at most 3/2 of the UTF-16 wire length.
    let mut output = String::with_capacity(payload.len().saturating_mul(3) / 2);
    // The even-length guard above leaves no remainder, so `.0` is the whole body.
    let (pairs, _) = payload.as_chunks::<2>();
    let units = pairs.iter().map(|pair| match endian {
        Utf16Endian::Little => u16::from_le_bytes(*pair),
        Utf16Endian::Big => u16::from_be_bytes(*pair),
    });
    for decoded in char::decode_utf16(units) {
        output.push(decoded.ok()?);
    }
    Some(output)
}

fn decode_utf32(payload: &[u8], endian: Utf32Endian) -> Option<String> {
    if !payload.len().is_multiple_of(4) {
        return None;
    }
    // Each UTF-32 code unit is 4 wire bytes; UTF-8 is at most 4 bytes per
    // scalar, so the inspection view never exceeds the already-clamped body.
    let mut output = String::with_capacity(payload.len());
    // The multiple-of-4 guard above leaves no remainder, so `.0` is the
    // whole body. Decode directly into `output`; no intermediate buffer.
    let (quads, _) = payload.as_chunks::<4>();
    for quad in quads {
        let unit = match endian {
            Utf32Endian::Little => u32::from_le_bytes(*quad),
            Utf32Endian::Big => u32::from_be_bytes(*quad),
        };
        // UTF-32 has no surrogate pairs. Code units in the surrogate range
        // or above U+10FFFF are malformed; fail closed rather than pushing
        // U+FFFD and forwarding the rest.
        if (0xD800..=0xDFFF).contains(&unit) || unit > 0x10FFFF {
            return None;
        }
        output.push(char::from_u32(unit)?);
    }
    Some(output)
}

/// Canonical inspection views of one query name or value.
///
/// Callers must split the raw query on `&` and `=` *before* calling this so
/// `%26` / `%3D` cannot smuggle extra pairs. Encoded structural octets inside a
/// *value* (`%2f`, `%3f`, `%23`) are decoded: they are payload, not URI
/// delimiters. Path canonicalization (which refuses encoded `/`) is not used.
/// The original request bytes are not modified.
pub(super) struct CanonicalQueryViews<'a> {
    primary: Cow<'a, str>,
    variants: Vec<String>,
}

impl CanonicalQueryViews<'_> {
    pub(super) fn iter(&self) -> impl Iterator<Item = &str> {
        std::iter::once(self.primary.as_ref()).chain(self.variants.iter().map(String::as_str))
    }
}

/// Bounded query-component normalization shared by query-value rules and by
/// built-in FullUrl FE-PATHTRAV/LFI signatures that opt into a compile-time
/// canonical-query-value mirror. Category labels do not select this path.
///
/// `primary` is one percent-decode plus `+`→space (the historical query-value
/// view). Additional views are the same layered decode used for body XSS,
/// capped at [`MAX_DECODE_ROUNDS`], so `%252f` reduces to `/` while a stack
/// deeper than the cap is not fully peeled. Variants identical to `primary`
/// are dropped to avoid duplicate scans.
pub(super) fn canonical_query_component_views(raw: &str) -> CanonicalQueryViews<'_> {
    let primary = percent_decode_plus(raw);
    let (mut variants, _) = decoded_variants_with_residual(raw);
    variants.retain(|variant| variant != primary.as_ref());
    CanonicalQueryViews { primary, variants }
}

fn has_decodable_marker(text: &str) -> bool {
    text.as_bytes()
        .iter()
        .any(|byte| matches!(byte, b'%' | b'+' | b'\\' | b'&'))
}

/// One round of the layered decode: percent, then unicode, then HTML entity.
fn decode_round(text: &str) -> String {
    let percent = percent_decode_plus(text).into_owned();
    let unicode = unicode_unescape(&percent).into_owned();
    html_entity_decode(&unicode).into_owned()
}

/// Run the layered decode and report whether it reached a fixed point within
/// [`MAX_DECODE_ROUNDS`]. Returns `(decoded, converged)`; `converged == false`
/// means the value was still actively decoding when the round cap was reached,
/// i.e. it carries an encoding stacked deeper than the cap can peel.
///
/// Convergence is judged by whether the *last* round made progress, not merely
/// by exhausting the iteration count: a payload that finishes decoding on the
/// final allowed round (e.g. triple percent-encoding with a 3-round cap) has
/// converged and must not be reported as a residual.
fn layered_decode_inner(text: &str) -> (String, bool) {
    let mut current = text.to_string();
    let mut converged = true;
    for round in 0..MAX_DECODE_ROUNDS {
        let next = decode_round(&current);
        if next == current {
            // Reached a fixed point before the cap — fully reduced.
            break;
        }
        current = next;
        // The last permitted round still changed the value; if a further round
        // would change it again the payload is stacked deeper than the cap.
        if round + 1 == MAX_DECODE_ROUNDS {
            converged = decode_round(&current) == current;
        }
    }
    (current, converged)
}

/// Percent-decode (`%XX`) and translate `+` to space (form-encoding). Lossy on
/// invalid UTF-8 sequences, which is fine for pattern detection.
fn percent_decode_plus(text: &str) -> Cow<'_, str> {
    if !text.as_bytes().contains(&b'%') {
        if text.as_bytes().contains(&b'+') {
            return Cow::Owned(text.replace('+', " "));
        }
        return Cow::Borrowed(text);
    }
    let decoded = percent_decode_str(text).decode_utf8_lossy();
    if decoded.as_bytes().contains(&b'+') {
        Cow::Owned(decoded.replace('+', " "))
    } else {
        decoded
    }
}

/// Decode JSON/JavaScript unicode escapes: `\uXXXX` (with surrogate pairs),
/// `\u{XXXX}`, and `\xXX`. Unrecognized escapes keep their literal backslash.
fn unicode_unescape(text: &str) -> Cow<'_, str> {
    let bytes = text.as_bytes();
    if !bytes.contains(&b'\\') {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            if let Some((cp, consumed)) = decode_escape(&bytes[i + 1..]) {
                push_cp(&mut out, cp);
                i += 1 + consumed;
                continue;
            }
            out.push('\\');
            i += 1;
            continue;
        }
        let len = utf8_char_len(bytes[i]);
        let end = (i + len).min(bytes.len());
        out.push_str(&text[i..end]);
        i = end;
    }
    Cow::Owned(out)
}

/// Parse a single backslash escape from `after` (the bytes following `\`).
/// Returns the decoded code point and the number of bytes consumed from
/// `after`.
fn decode_escape(after: &[u8]) -> Option<(u32, usize)> {
    match after.first()? {
        b'u' | b'U' => {
            if after.get(1) == Some(&b'{') {
                let rel = after[2..].iter().position(|&c| c == b'}')?;
                let hex = &after[2..2 + rel];
                if hex.is_empty() || hex.len() > 6 {
                    return None;
                }
                Some((hex_n(hex)?, 2 + rel + 1))
            } else {
                let unit = hex4(after.get(1..5)?)?;
                if (0xD800..=0xDBFF).contains(&unit)
                    && after.get(5) == Some(&b'\\')
                    && matches!(after.get(6), Some(b'u') | Some(b'U'))
                    && let Some(low) = after.get(7..11).and_then(hex4)
                    && (0xDC00..=0xDFFF).contains(&low)
                {
                    let cp = 0x10000 + (((unit as u32 - 0xD800) << 10) | (low as u32 - 0xDC00));
                    return Some((cp, 11));
                }
                Some((unit as u32, 5))
            }
        }
        b'x' | b'X' => Some((hex2(after.get(1..3)?)? as u32, 3)),
        _ => None,
    }
}

/// Decode HTML entities: numeric (`&#NN;`, `&#xHH;`) and a small named set
/// covering the characters that compose injection syntax.
fn html_entity_decode(text: &str) -> Cow<'_, str> {
    let bytes = text.as_bytes();
    if !bytes.contains(&b'&') {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'&' {
            if let Some((value, consumed)) = decode_entity(&bytes[i + 1..]) {
                match value {
                    EntityVal::Cp(cp) => push_cp(&mut out, cp),
                    EntityVal::Str(s) => out.push_str(s),
                }
                i += 1 + consumed;
                continue;
            }
            out.push('&');
            i += 1;
            continue;
        }
        let len = utf8_char_len(bytes[i]);
        let end = (i + len).min(bytes.len());
        out.push_str(&text[i..end]);
        i = end;
    }
    Cow::Owned(out)
}

enum EntityVal {
    Cp(u32),
    Str(&'static str),
}

/// Parse a single HTML entity from `after` (the bytes following `&`).
/// Returns the decoded value and bytes consumed from `after` (including `;`).
fn decode_entity(after: &[u8]) -> Option<(EntityVal, usize)> {
    if after.first() == Some(&b'#') {
        let (radix, start) = if matches!(after.get(1), Some(b'x') | Some(b'X')) {
            (16u32, 2usize)
        } else {
            (10u32, 1usize)
        };
        let mut j = start;
        // Keep this bounded while still accepting leading-zero padded entities.
        while j < after.len() && after[j] != b';' && j - start < MAX_NUMERIC_ENTITY_DIGITS {
            j += 1;
        }
        if j >= after.len() || after[j] != b';' || j == start {
            return None;
        }
        let digits = &after[start..j];
        let cp = if radix == 16 {
            hex_n(digits)?
        } else {
            dec_n(digits)?
        };
        Some((EntityVal::Cp(cp), j + 1))
    } else {
        let mut j = 0;
        while j < after.len() && after[j] != b';' && j < 10 {
            j += 1;
        }
        if j >= after.len() || after[j] != b';' {
            return None;
        }
        let name = &after[..j];
        let s = if name.eq_ignore_ascii_case(b"lt") {
            "<"
        } else if name.eq_ignore_ascii_case(b"gt") {
            ">"
        } else if name.eq_ignore_ascii_case(b"amp") {
            "&"
        } else if name.eq_ignore_ascii_case(b"quot") {
            "\""
        } else if name.eq_ignore_ascii_case(b"apos") {
            "'"
        } else if name.eq_ignore_ascii_case(b"sol") {
            "/"
        } else if name.eq_ignore_ascii_case(b"colon") {
            ":"
        } else if name.eq_ignore_ascii_case(b"lpar") {
            "("
        } else if name.eq_ignore_ascii_case(b"rpar") {
            ")"
        } else if name.eq_ignore_ascii_case(b"period") {
            "."
        } else if name.eq_ignore_ascii_case(b"excl") {
            "!"
        } else if name.eq_ignore_ascii_case(b"equals") {
            "="
        } else if name.eq_ignore_ascii_case(b"grave") {
            "`"
        } else if name.eq_ignore_ascii_case(b"dollar") {
            "$"
        } else if name.eq_ignore_ascii_case(b"lbrace") {
            "{"
        } else if name.eq_ignore_ascii_case(b"rbrace") {
            "}"
        } else if name.eq_ignore_ascii_case(b"nbsp") {
            " "
        } else if name.eq_ignore_ascii_case(b"tab") {
            "\t"
        } else if name.eq_ignore_ascii_case(b"newline") {
            "\n"
        } else {
            return None;
        };
        Some((EntityVal::Str(s), j + 1))
    }
}

#[inline]
fn push_cp(out: &mut String, cp: u32) {
    out.push(char::from_u32(cp).unwrap_or('\u{FFFD}'));
}

#[inline]
fn utf8_char_len(first: u8) -> usize {
    if first < 0x80 {
        1
    } else if first >> 5 == 0b110 {
        2
    } else if first >> 4 == 0b1110 {
        3
    } else if first >> 3 == 0b11110 {
        4
    } else {
        1
    }
}

#[inline]
fn hex_digit(c: u8) -> Option<u32> {
    match c {
        b'0'..=b'9' => Some((c - b'0') as u32),
        b'a'..=b'f' => Some((c - b'a' + 10) as u32),
        b'A'..=b'F' => Some((c - b'A' + 10) as u32),
        _ => None,
    }
}

fn hex_n(bytes: &[u8]) -> Option<u32> {
    let mut value = 0u32;
    for &c in bytes {
        value = value.checked_mul(16)?.checked_add(hex_digit(c)?)?;
    }
    Some(value)
}

fn hex4(bytes: &[u8]) -> Option<u16> {
    if bytes.len() != 4 {
        return None;
    }
    Some(hex_n(bytes)? as u16)
}

fn hex2(bytes: &[u8]) -> Option<u8> {
    if bytes.len() != 2 {
        return None;
    }
    Some(hex_n(bytes)? as u8)
}

fn dec_n(bytes: &[u8]) -> Option<u32> {
    let mut value = 0u32;
    for &c in bytes {
        if !c.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add((c - b'0') as u32)?;
    }
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unicode_unescape_decodes_json_payload() {
        assert_eq!(unicode_unescape(r"<script>"), "<script>");
        assert_eq!(unicode_unescape(r"${jndi"), "${jndi");
    }

    #[test]
    fn unicode_unescape_handles_surrogate_pairs_and_braces() {
        assert_eq!(unicode_unescape(r"😀"), "\u{1F600}");
        assert_eq!(unicode_unescape(r"\u{3c}script"), "<script");
        assert_eq!(unicode_unescape(r"\x3cscript"), "<script");
    }

    #[test]
    fn unicode_unescape_preserves_unknown_escapes_and_plain_text() {
        assert!(matches!(unicode_unescape("plain text"), Cow::Borrowed(_)));
        assert_eq!(unicode_unescape(r"a\nb\qc"), r"a\nb\qc");
    }

    #[test]
    fn html_entity_decode_named_and_numeric() {
        assert_eq!(html_entity_decode("&lt;script&gt;"), "<script>");
        assert_eq!(html_entity_decode("&LT;script&GT;"), "<script>");
        assert_eq!(html_entity_decode("&#60;script&#62;"), "<script>");
        assert_eq!(
            html_entity_decode("&#000000060;script&#000000062;"),
            "<script>"
        );
        assert_eq!(html_entity_decode("&#x3c;script&#x3e;"), "<script>");
        assert!(matches!(
            html_entity_decode("no entities"),
            Cow::Borrowed(_)
        ));
    }

    #[test]
    fn percent_decode_plus_decodes_form_encoding() {
        assert_eq!(percent_decode_plus("%3Cscript%3E"), "<script>");
        assert_eq!(percent_decode_plus("a+b"), "a b");
        assert!(matches!(percent_decode_plus("plain"), Cow::Borrowed(_)));
    }

    #[test]
    fn decoded_variants_skips_raw_and_dedups() {
        // Plain text yields no variants (raw is scanned by the caller).
        assert!(variants("nothing to decode").is_empty());
        // A stacked encoding is recovered by the layered decode.
        let decoded = variants("%26lt%3Bscript%26gt%3B");
        assert!(decoded.iter().any(|v| v == "<script>"));
        assert!(decoded.len() <= MAX_VARIANTS);
    }

    #[test]
    fn plain_text_has_no_decodable_markers() {
        assert!(!has_decodable_marker("nothing to decode"));
        assert!(has_decodable_marker("%3Cscript%3E"));
        assert!(has_decodable_marker("&lt;script&gt;"));
        assert!(has_decodable_marker(r"\u003cscript\u003e"));
        assert!(has_decodable_marker("a+b"));
    }

    fn residual(text: &str) -> bool {
        decoded_variants_with_residual(text).1
    }

    fn variants(text: &str) -> Vec<String> {
        decoded_variants_with_residual(text).0
    }

    #[test]
    fn residual_encoding_only_fires_beyond_the_round_cap() {
        // No markers / plain text: never a residual.
        assert!(!residual("nothing to decode"));
        // A literal `%`/`&` that does not actually decode further must NOT be
        // reported (precision: avoid false positives on benign text).
        assert!(!residual("100% sure & done"));

        // Single / double / triple percent-encoding all fully reduce within the
        // 3-round cap, so none is a residual. In particular the triple case
        // finishes on the *last* allowed round and must not be misreported.
        assert!(!residual("%3Cscript%3E"));
        assert!(!residual("%253Cscript%253E"));
        assert!(!residual("%25253Cscript%25253E"));

        // Quad-or-deeper percent-encoding is still encoded after the cap, so it
        // is flagged as an encoding-evasion residual.
        assert!(residual("%2525253Cscript"));
        assert!(residual("%252525253Cscript"));
    }

    #[test]
    fn layered_decode_reduces_within_cap_and_caps_deep_stacks() {
        // The decoded value a caller scans: a within-cap stack reduces fully,
        // and a beyond-cap stack reduces by exactly MAX_DECODE_ROUNDS layers
        // (leaving residual encoding the caller flags as evasion).
        assert_eq!(layered_decode_inner("%25253Cx").0, "<x");
        assert_eq!(layered_decode_inner("%2525253Cx").0, "%3Cx");
    }

    #[test]
    fn decoded_variants_recovers_escaped_script() {
        // `\x`-escaped `<script>` — the raw byte scan never sees the tag.
        let decoded = variants(r"{q:\x3cscript\x3ealert(1)}");
        assert!(decoded.iter().any(|v| v.contains("<script>")));
    }

    #[test]
    fn decoded_variants_redecodes_unicode_escaped_html_entities() {
        let decoded = variants(r#"\u0026lt;script\u0026gt;"#);
        assert!(decoded.iter().any(|v| v.contains("<script>")));
    }
}
