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

/// Maximum hex digits inside a braced `\u{...}` escape (Rust/JS both cap a
/// scalar value at six). The terminator search in [`decode_escape`] is bounded
/// by this before it scans, so an unterminated candidate costs constant work
/// rather than a suffix scan the caller then repeats one byte later.
const MAX_BRACED_ESCAPE_HEX_DIGITS: usize = 6;

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
/// one view. A reading the declaration does not settle — a bare
/// `charset=utf-16` / `utf-32` with no BOM, an ambiguous `FF FE 00 00`
/// prefix, or a charset that disagrees with the BOM — yields both candidate
/// views, capped at [`MAX_WIDE_CHARSET_VIEWS`]. The scanner always keeps the
/// raw/lossy view and its transformations alongside these additional views.
pub(super) struct WideCharsetViews {
    views: [Option<String>; MAX_WIDE_CHARSET_VIEWS],
    /// The body declares a charset this WAF cannot transcode at all (UTF-7,
    /// ISO-2022-*, HZ-GB-2312, EBCDIC). Its encoded form can hide ASCII text
    /// from the raw scan, so the caller reports it rather than treating the
    /// wire bytes as cover text.
    uninspectable_charset: bool,
}

impl WideCharsetViews {
    pub(super) fn empty() -> Self {
        Self {
            views: [None, None],
            uninspectable_charset: false,
        }
    }

    fn resolved(text: String) -> Self {
        Self {
            views: [Some(text), None],
            uninspectable_charset: false,
        }
    }

    /// Two candidate readings of the same bytes that the declaration does not
    /// disambiguate: either endianness of a bare `utf-16` / `utf-32`, the
    /// UTF-32LE / UTF-16LE split of a `FF FE 00 00` prefix, or a declared
    /// charset that disagrees with the BOM. Both readings are scanned, and
    /// the raw/lossy view is kept as well so an ambiguous body never loses
    /// coverage it had before transcoding.
    fn unresolved(first: String, second: String) -> Self {
        if first == second {
            return Self::resolved(first);
        }
        Self {
            views: [Some(first), Some(second)],
            uninspectable_charset: false,
        }
    }

    /// Whether the declared charset is one the WAF cannot transcode; see
    /// [`UNINSPECTABLE_CHARSET_LABELS`].
    pub(super) fn uninspectable_charset(&self) -> bool {
        self.uninspectable_charset
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = &str> {
        self.views.iter().filter_map(|view| view.as_deref())
    }
}

/// Charsets whose encoded form can hide ASCII text from a raw byte scan and
/// which this WAF does not transcode: the UTF-7 family (`+ADw-script+AD4-`
/// is `<script>`), the ISO-2022 / HZ escape-shift families, and EBCDIC.
///
/// The list is deliberately explicit rather than the inverse of an allowlist:
/// inverting one would flag `iso-8859-1`, `windows-1252`, Shift_JIS, GBK, and
/// Big5, all of which keep ASCII as ASCII and scan correctly today.
const UNINSPECTABLE_CHARSET_LABELS: &[&str] = &[
    // UTF-7
    "utf-7",
    "unicode-1-1-utf-7",
    "csunicode11utf7",
    // ISO-2022 / HZ escape-shift encodings
    "iso-2022-jp",
    "iso-2022-kr",
    "iso-2022-cn",
    "csiso2022jp",
    "csiso2022kr",
    "hz-gb-2312",
    // EBCDIC
    "ibm037",
    "cp037",
    "ibm500",
    "cp500",
    "ibm1047",
    "cp1047",
    "ebcdic-cp-us",
];

fn charset_is_uninspectable(content_type: Option<&str>) -> bool {
    charset_value(content_type).is_some_and(|value| {
        UNINSPECTABLE_CHARSET_LABELS
            .iter()
            .any(|label| value.eq_ignore_ascii_case(label))
    })
}

/// How a wide-charset body's endianness resolves.
enum WideEndian<E> {
    /// Neither a declared charset of this family nor a BOM: no view.
    Unknown,
    /// One authoritative reading: decode `body[skip..]` with this endianness.
    Resolved(E, usize),
    /// The declared charset and the BOM disagree. Neither reading can be
    /// discarded: the declaration is what a backend honouring `Content-Type`
    /// uses (reading the BOM bytes as ordinary text), while the BOM is what a
    /// BOM-sniffing parser uses.
    Conflict {
        declared: E,
        bom_endian: E,
        skip: usize,
    },
}

/// Decode already-admitted UTF-16 / UTF-32 bodies into inspection
/// views.
///
/// This helper does not decide whether a body is eligible for WAF inspection;
/// the direction-specific content-type/multipart/binary gates run first. It
/// only creates views used by active body rules and encoding specials.
/// Ordinary UTF-8 returns [`WideCharsetViews::empty`] without allocating.
///
/// UTF-32 BOMs are recognized first (see [`utf32_bom`]): a UTF-32LE BOM is
/// `FF FE 00 00` and would otherwise be misread as a UTF-16LE BOM. When a
/// charset declares the UTF-16 or UTF-32 family without an endianness and
/// without a BOM, both endiannesses are decoded. When a declared endianness
/// disagrees with the BOM, both readings are decoded as well — dropping the
/// views on a disagreement is exactly the bypass an attacker constructs by
/// prefixing a `charset=utf-16le` payload with `FE FF`.
///
/// Decoding itself is lossy (`U+FFFD` substitution), so a single malformed
/// code unit cannot disable inspection of an otherwise readable body.
pub(super) fn decode_wide_charset_body_views(
    body: &[u8],
    content_type: Option<&str>,
) -> WideCharsetViews {
    let mut views = wide_charset_body_views(body, content_type);
    if charset_is_uninspectable(content_type) {
        views.uninspectable_charset = true;
    }
    views
}

fn wide_charset_body_views(body: &[u8], content_type: Option<&str>) -> WideCharsetViews {
    // With no declaration or BOM, require the NUL placement of two ASCII
    // UTF-16 units or one ASCII UTF-32 unit in the first four octets. Do not
    // infer a charset from arbitrary interior NULs or try every binary body.
    // The signature selects only a width; retain both endians and raw text,
    // using the same fixed view cap as a bare declared wide charset.
    if charset_value(content_type).is_none()
        && utf32_bom(body).is_none()
        && utf16_bom(body).is_none()
        && let [a, b, c, d, ..] = body
    {
        let ascii = |byte: u8| byte != 0 && byte.is_ascii();
        if (*a == 0 && *b == 0 && *c == 0 && ascii(*d))
            || (ascii(*a) && *b == 0 && *c == 0 && *d == 0)
        {
            return WideCharsetViews::unresolved(
                decode_utf32(body, Utf32Endian::Little),
                decode_utf32(body, Utf32Endian::Big),
            );
        }
        if (*a == 0 && ascii(*b) && *c == 0 && ascii(*d))
            || (ascii(*a) && *b == 0 && ascii(*c) && *d == 0)
        {
            return WideCharsetViews::unresolved(
                decode_utf16(body, Utf16Endian::Little),
                decode_utf16(body, Utf16Endian::Big),
            );
        }
    }
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
    match resolve_utf32_body(body, content_type) {
        WideEndian::Resolved(endian, skip) => {
            return WideCharsetViews::resolved(decode_utf32(&body[skip..], endian));
        }
        WideEndian::Conflict {
            declared,
            bom_endian,
            skip,
        } => {
            return WideCharsetViews::unresolved(
                // The declaration-honouring reading decodes the whole body,
                // BOM bytes included: that is what the backend sees.
                decode_utf32(body, declared),
                decode_utf32(&body[skip..], bom_endian),
            );
        }
        WideEndian::Unknown => {}
    }
    if charset_is_unspecified_utf16(content_type) && utf16_bom(body).is_none() {
        return WideCharsetViews::unresolved(
            decode_utf16(body, Utf16Endian::Little),
            decode_utf16(body, Utf16Endian::Big),
        );
    }
    match resolve_utf16_body(body, content_type) {
        WideEndian::Resolved(endian, skip) => {
            WideCharsetViews::resolved(decode_utf16(&body[skip..], endian))
        }
        WideEndian::Conflict {
            declared,
            bom_endian,
            skip,
        } => WideCharsetViews::unresolved(
            decode_utf16(body, declared),
            decode_utf16(&body[skip..], bom_endian),
        ),
        WideEndian::Unknown => WideCharsetViews::empty(),
    }
}

/// Resolve the UTF-16 endianness of an already-admitted request body from its
/// explicit `charset` and/or BOM. Bare `charset=utf-16` with no BOM is
/// handled by [`wide_charset_body_views`] instead of inventing an endianness
/// here; a body with neither signal is [`WideEndian::Unknown`], which is what
/// keeps an ordinary UTF-8 body allocation-free.
fn resolve_utf16_body(body: &[u8], content_type: Option<&str>) -> WideEndian<Utf16Endian> {
    let bom = utf16_bom(body);
    let declared = declared_utf16_endian(content_type, bom.map(|(endian, _)| endian));
    match (declared, bom) {
        (Some(declared), Some((bom_endian, skip))) if declared == bom_endian => {
            WideEndian::Resolved(declared, skip)
        }
        (Some(declared), Some((bom_endian, skip))) => WideEndian::Conflict {
            declared,
            bom_endian,
            skip,
        },
        (Some(declared), None) => WideEndian::Resolved(declared, 0),
        (None, Some((bom_endian, skip))) => WideEndian::Resolved(bom_endian, skip),
        (None, None) => WideEndian::Unknown,
    }
}

/// UTF-32 counterpart of [`resolve_utf16_body`].
fn resolve_utf32_body(body: &[u8], content_type: Option<&str>) -> WideEndian<Utf32Endian> {
    let bom = utf32_bom(body);
    let declared = declared_utf32_endian(content_type, bom.map(|(endian, _)| endian));
    match (declared, bom) {
        (Some(declared), Some((bom_endian, skip))) if declared == bom_endian => {
            WideEndian::Resolved(declared, skip)
        }
        (Some(declared), Some((bom_endian, skip))) => WideEndian::Conflict {
            declared,
            bom_endian,
            skip,
        },
        (Some(declared), None) => WideEndian::Resolved(declared, 0),
        (None, Some((bom_endian, skip))) => WideEndian::Resolved(bom_endian, skip),
        (None, None) => WideEndian::Unknown,
    }
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
    // WHATWG encoding index: every UTF-16LE label, so `charset=unicode` or
    // `charset=ucs-2` cannot slip past the transcoder that `utf-16le` hits.
    if value.eq_ignore_ascii_case("utf-16le")
        || value.eq_ignore_ascii_case("utf16le")
        || value.eq_ignore_ascii_case("unicode")
        || value.eq_ignore_ascii_case("unicodefeff")
        || value.eq_ignore_ascii_case("ucs-2")
        || value.eq_ignore_ascii_case("iso-10646-ucs-2")
        || value.eq_ignore_ascii_case("csunicode")
    {
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

/// Decode `payload` as UTF-16, substituting `U+FFFD` for every ill-formed
/// code unit and for a trailing odd byte.
///
/// Decoding is deliberately lossy. WHATWG `TextDecoder`, `new String(b,
/// "UTF-16LE")`, and .NET `Encoding.Unicode` all substitute and keep parsing,
/// so a backend still sees the rest of the payload; refusing the view instead
/// would let one hostile code unit disable text inspection of an otherwise
/// readable body — the same rationale the lossy UTF-8 path already applies.
fn decode_utf16(payload: &[u8], endian: Utf16Endian) -> String {
    // UTF-8 output is at most 3/2 of the UTF-16 wire length, plus at most one
    // replacement character for a dangling odd byte.
    let mut output = String::with_capacity(payload.len().saturating_mul(3) / 2 + 3);
    let (pairs, remainder) = payload.as_chunks::<2>();
    let units = pairs.iter().map(|pair| match endian {
        Utf16Endian::Little => u16::from_le_bytes(*pair),
        Utf16Endian::Big => u16::from_be_bytes(*pair),
    });
    for decoded in char::decode_utf16(units) {
        output.push(decoded.unwrap_or(char::REPLACEMENT_CHARACTER));
    }
    if !remainder.is_empty() {
        output.push(char::REPLACEMENT_CHARACTER);
    }
    output
}

/// Decode `payload` as UTF-32, substituting `U+FFFD` for every code unit in
/// the surrogate range `U+D800..=U+DFFF` or above `U+10FFFF`, and for a
/// trailing partial code unit.
///
/// Lossy for the same reason as [`decode_utf16`]: one malformed unit must not
/// be able to turn off body-text inspection for the rest of the payload.
fn decode_utf32(payload: &[u8], endian: Utf32Endian) -> String {
    // Each UTF-32 code unit is 4 wire bytes; UTF-8 is at most 4 bytes per
    // scalar, so the inspection view never exceeds the already-clamped body
    // (plus one replacement character for a trailing partial unit).
    let mut output = String::with_capacity(payload.len() + 3);
    let (quads, remainder) = payload.as_chunks::<4>();
    for quad in quads {
        let unit = match endian {
            Utf32Endian::Little => u32::from_le_bytes(*quad),
            Utf32Endian::Big => u32::from_be_bytes(*quad),
        };
        // `char::from_u32` already rejects the surrogate range and anything
        // above U+10FFFF, which UTF-32 cannot encode.
        output.push(char::from_u32(unit).unwrap_or(char::REPLACEMENT_CHARACTER));
    }
    if !remainder.is_empty() {
        output.push(char::REPLACEMENT_CHARACTER);
    }
    output
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
                // Bound the terminator search BEFORE scanning. The caller
                // advances a single byte per refused candidate, so searching
                // the whole remaining slice for `}` here made a run of `\u{`
                // quadratic in client-controlled text. A valid escape can only
                // carry `MAX_BRACED_ESCAPE_HEX_DIGITS` hex digits, so a `}`
                // further out is an over-width candidate either way and is
                // refused after constant work.
                let limit = MAX_BRACED_ESCAPE_HEX_DIGITS + 1;
                let window = &after[2..after.len().min(2 + limit)];
                let rel = window.iter().position(|&c| c == b'}')?;
                let hex = &window[..rel];
                if hex.is_empty() {
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
    fn braced_unicode_escape_refuses_an_over_width_candidate_in_constant_work() {
        // Six hex digits is the ceiling, so the widest valid escape decodes...
        assert_eq!(unicode_unescape(r"\u{10FFFF}"), "\u{10FFFF}");
        // ...and a seventh digit is refused, leaving the literal backslash.
        assert_eq!(unicode_unescape(r"\u{1000000}"), r"\u{1000000}");
        // A terminator beyond the ceiling is refused without being searched
        // for: `decode_escape` never inspects past the bounded window.
        assert_eq!(decode_escape(b"u{1234567}"), None);
        assert_eq!(decode_escape(b"u{}"), None);
        assert_eq!(decode_escape(b"u{3c}"), Some((0x3c, 5)));
    }

    #[test]
    fn unterminated_braced_escapes_do_not_scan_the_whole_remaining_input() {
        // The caller advances one byte per refused candidate, so an unbounded
        // terminator search here is quadratic in client-controlled text. This
        // input is a pure passthrough after the bound; before it, the same
        // input cost ~10^11 byte comparisons (GHSA-27g8-5rv5-m3pf).
        let payload = r"\u{".repeat(350_000);
        let started = std::time::Instant::now();
        let decoded = unicode_unescape(&payload);
        assert_eq!(decoded, payload);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(10),
            "bounded escape parsing must stay linear, took {:?}",
            started.elapsed()
        );
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
