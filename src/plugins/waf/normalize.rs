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
///
/// Five is one slot per candidate [`decoded_variants`] builds (the layered
/// decode, its second-to-last round, and the three single-layer decodes), so
/// padding a value with unrelated escapes cannot push a view out of the set.
const MAX_VARIANTS: usize = 5;

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
    decoded_variants(text, StringEscapes::All)
}

/// Decoded variants of a string a JSON parser already unescaped (a JSON-path
/// rule's value). The single-character escapes (`\n`, `\"`, `\\`, …) were
/// resolved once by that parser, so they are not resolved a second time —
/// `C:\new` in the parsed value stays a backslash and an `n`. The residual
/// flag is not reported: JSON-path rules do not raise encoding evasion.
pub(super) fn decoded_json_value_variants(text: &str) -> Vec<String> {
    decoded_variants(text, StringEscapes::CodePointsOnly).0
}

fn decoded_variants(text: &str, escapes: StringEscapes) -> (Vec<String>, bool) {
    if !has_decodable_marker(text) {
        return (Vec::new(), false);
    }

    // Layered decode catches stacked encodings (e.g. percent-encoded HTML
    // entities). Its second-to-last round is kept too when it holds a `+`:
    // the last round turns every `+` into a space, so `%252B` would otherwise
    // only ever be seen as a space, never as the `+` a double-decoding
    // application reads. The single-layer decodes are kept as well because a
    // layered percent-decode can mangle a body that merely contains a literal
    // `%`, and we still want the JSON/HTML-only decode to fire in that case.
    let layered = layered_decode_inner(text, escapes);
    let candidates = [
        Some(layered.decoded),
        layered.intermediate.map(Cow::Owned),
        Some(string_unescape(text, escapes)),
        Some(html_entity_decode(text)),
        Some(percent_decode_plus(text)),
    ];

    let mut out: Vec<String> = Vec::new();
    for candidate in candidates.into_iter().flatten() {
        if out.len() >= MAX_VARIANTS {
            break;
        }
        if candidate.as_ref() != text && !out.iter().any(|existing| existing == candidate.as_ref())
        {
            out.push(candidate.into_owned());
        }
    }
    (out, !layered.converged)
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

/// A query parameter's name as the application reads it: one percent-decode
/// plus `+`→space, the primary view of [`canonical_query_component_views`].
/// Field exclusions compare configured names against this. A name holding a
/// `%u` escape is left as written: only IIS-style parsers decode `%u`, so for
/// most backends `%u0068tml` is not `html`, and decoding it would let a
/// payload hide under an excluded name while landing in another parameter.
pub(super) fn query_component_name(raw: &str) -> Cow<'_, str> {
    if raw
        .as_bytes()
        .windows(2)
        .any(|pair| pair[0] == b'%' && (pair[1] | 0x20) == b'u')
    {
        return Cow::Borrowed(raw);
    }
    percent_decode_plus(raw)
}

/// Inspection views of one `name=value` cookie crumb:
///
/// * the percent decode with `+` → space (PHP `urldecode`, Rails);
/// * when that is itself still percent-encoded, the layered percent decode
///   capped at [`MAX_DECODE_ROUNDS`], plus its second-to-last round when that
///   holds a `+`, since the last round turns the `+` a `%252B` yields into a
///   space;
/// * when the crumb holds both `%` and `+`, the percent decode that keeps `+`
///   (Express `cookie-parser`, which uses `decodeURIComponent`);
/// * when the value (split from the raw crumb at its first `=`, as Express
///   splits it, then decoded) starts with `j:`, that Express reading with its
///   `\uXXXX` / `\u{...}` / `\xXX` escapes and its `\"`, `\'`, `\/`, `\\`
///   escapes resolved, because `cookie-parser` runs `JSON.parse` on such a
///   value.
///
/// Callers split the `Cookie` header on `;` first, so `%3B` cannot forge an
/// extra crumb. JSON control escapes and HTML entities are not cookie
/// encodings: a `j:` JSON cookie whose string holds `\n` is a backslash and
/// an `n` to the view that models it, so the control-character rule is not
/// handed a line feed only a different decoder would produce. A crumb with
/// nothing to decode costs no allocation.
pub(super) fn canonical_cookie_views(raw: &str) -> CanonicalQueryViews<'_> {
    let primary = percent_decode_plus(raw);
    let mut variants = Vec::new();
    if let Cow::Owned(first) = &primary {
        let mut rounds: [Option<String>; 2] = [None, None];
        for _ in 1..MAX_DECODE_ROUNDS {
            let current = rounds[1].as_deref().unwrap_or(first.as_str());
            let next = match percent_decode_plus(current) {
                Cow::Owned(next) => next,
                Cow::Borrowed(_) => break,
            };
            rounds = [rounds[1].take(), Some(next)];
        }
        let [intermediate, last] = rounds;
        variants.extend(intermediate.filter(|round| round.contains('+')));
        variants.extend(last);
    }
    let plus_kept = raw.contains('+').then(|| percent_decode(raw, false));
    let express = plus_kept.as_deref().unwrap_or(&primary);
    if let Some(json) = json_cookie_view(raw, express) {
        variants.push(json);
    }
    if let Some(Cow::Owned(plus_kept)) = plus_kept {
        variants.push(plus_kept);
    }
    CanonicalQueryViews { primary, variants }
}

/// The `JSON.parse` reading of `express`, the Express-decoded text of the
/// cookie crumb `raw`, or `None` when the crumb is not a `j:` JSON cookie or
/// has no escape to resolve.
///
/// Express splits the raw crumb at its first `=` and decodes only the value,
/// so `a%3Db=j:…` is a `j:` value to it even though the decoded crumb reads
/// `a=b=j:…`.
fn json_cookie_view(raw: &str, express: &str) -> Option<String> {
    let (_, value) = raw.split_once('=')?;
    let value = value.trim();
    let value = value.strip_prefix('"').unwrap_or(value);
    if !percent_decode(value, false).starts_with("j:") {
        return None;
    }
    match string_unescape(express, StringEscapes::JsonCookie) {
        Cow::Owned(decoded) if decoded != express => Some(decoded),
        _ => None,
    }
}

/// Whether any decoder could change `text`. Runs over every inspected body, so
/// it uses the SIMD `memchr` searchers rather than a byte-at-a-time loop: a
/// body with no marker at all — the common case — costs two vectorised passes.
fn has_decodable_marker(text: &str) -> bool {
    let bytes = text.as_bytes();
    memchr::memchr3(b'%', b'+', b'\\', bytes).is_some() || memchr::memchr(b'&', bytes).is_some()
}

/// One round of the layered decode: percent, then unicode, then HTML entity.
///
/// Each stage borrows when it has nothing to decode, and a borrowed stage
/// hands its input straight to the next one, so a round over text that only
/// one stage touches allocates once rather than three times. A round that
/// changes nothing returns `Cow::Borrowed`, which is how
/// [`layered_decode_inner`] recognises a fixed point without comparing the
/// (up to `max_scan_bytes`-sized) strings.
fn decode_round(text: &str, escapes: StringEscapes) -> Cow<'_, str> {
    let percent = percent_decode_plus(text);
    let unicode = chain_stage(percent, |text| string_unescape(text, escapes));
    chain_stage(unicode, html_entity_decode)
}

/// Apply `stage` to `input`, keeping `input` (and its borrow of the round's
/// original text) when the stage decoded nothing.
fn chain_stage<'a>(input: Cow<'a, str>, stage: impl Fn(&str) -> Cow<'_, str>) -> Cow<'a, str> {
    let decoded = match stage(&input) {
        Cow::Borrowed(_) => None,
        Cow::Owned(decoded) => Some(decoded),
    };
    decoded.map_or(input, Cow::Owned)
}

/// Result of [`layered_decode_inner`].
struct LayeredDecode<'a> {
    /// The value after the last round that changed it, borrowed when no round
    /// changed it.
    decoded: Cow<'a, str>,
    /// The value before the last permitted round, kept only when that round
    /// changed it and the value holds a `+`. The last round turns every `+`
    /// into a space, so this is where a double-encoded `%252B` still reads as
    /// `+`; any other change the last round makes only reveals more.
    intermediate: Option<String>,
    /// `false` when the value was still actively decoding when the round cap
    /// was reached, i.e. it carries an encoding stacked deeper than the cap
    /// can peel.
    converged: bool,
}

/// Run the layered decode and report whether it reached a fixed point within
/// [`MAX_DECODE_ROUNDS`].
///
/// Convergence is judged by whether the *last* round made progress, not merely
/// by exhausting the iteration count: a payload that finishes decoding on the
/// final allowed round (e.g. triple percent-encoding with a 3-round cap) has
/// converged and must not be reported as a residual.
///
/// These decoders never lengthen their input when they decode something, so a
/// stage returns `Cow::Owned` exactly when it changed the text and a round that
/// returns `Cow::Borrowed` is a fixed point. The equality check below is kept as
/// a belt-and-braces guard; for a genuinely changed round it usually fails on
/// the length comparison before touching the bytes.
fn layered_decode_inner(text: &str, escapes: StringEscapes) -> LayeredDecode<'_> {
    let mut current = Cow::Borrowed(text);
    let mut intermediate = None;
    let mut converged = true;
    for round in 0..MAX_DECODE_ROUNDS {
        let next = match decode_round(&current, escapes) {
            Cow::Owned(next) if next != *current => next,
            // Reached a fixed point before the cap — fully reduced.
            _ => break,
        };
        let previous = std::mem::replace(&mut current, Cow::Owned(next));
        // The last permitted round still changed the value; if a further round
        // would peel another real layer the payload is stacked deeper than the
        // cap. Backslash-run collapsing alone is not such a layer.
        if round + 1 == MAX_DECODE_ROUNDS {
            intermediate = previous.contains('+').then(|| previous.into_owned());
            converged = !has_pending_decode(&current);
        }
    }
    LayeredDecode {
        decoded: current,
        intermediate,
        converged,
    }
}

/// Percent-decode (`%XX` and `%uXXXX`) and translate `+` to space
/// (form-encoding) in a single pass. Lossy on invalid UTF-8 sequences, which
/// is fine for pattern detection.
///
/// `%uXXXX` is not RFC 3986 percent-encoding, but IIS / classic ASP decode it
/// in the query string and form body, and JavaScript `unescape()` decodes it
/// too, so `%u003cscript%u003e` reaches such an application as `<script>`.
///
/// One pass matches the form decoders this models: only a literal `+` is a
/// space, so `%2B` and `%u002B` decode to `+`, and a `%u0025` yields a literal
/// `%` that is not decoded again within the same round (the layered decode's
/// next round handles deliberate stacking). A lone surrogate code unit becomes
/// `U+FFFD`. Text with nothing to decode is returned without copying.
fn percent_decode_plus(text: &str) -> Cow<'_, str> {
    percent_decode(text, true)
}

/// [`percent_decode_plus`], with `+` kept as `+` unless `plus_is_space`
/// (`decodeURIComponent` semantics). Nothing is allocated unless the text
/// holds an escape that actually decodes.
fn percent_decode(text: &str, plus_is_space: bool) -> Cow<'_, str> {
    let bytes = text.as_bytes();
    let mut first = 0;
    while first < bytes.len() && !percent_decodes_at(&bytes[first..], plus_is_space) {
        first += 1;
    }
    if first == bytes.len() {
        return Cow::Borrowed(text);
    }
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    out.extend_from_slice(&bytes[..first]);
    let mut i = first;
    while i < bytes.len() {
        let rest = &bytes[i..];
        if plus_is_space && rest[0] == b'+' {
            out.push(b' ');
            i += 1;
        } else if let Some(unit) = percent_u_unit(rest) {
            let ch = char::from_u32(unit).unwrap_or(char::REPLACEMENT_CHARACTER);
            let mut buf = [0u8; 4];
            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
            i += 6;
        } else if let Some(octet) = percent_octet(rest) {
            out.push(octet);
            i += 3;
        } else {
            out.push(rest[0]);
            i += 1;
        }
    }
    let decoded = match String::from_utf8(out) {
        Ok(decoded) => decoded,
        Err(err) => String::from_utf8_lossy(err.as_bytes()).into_owned(),
    };
    Cow::Owned(decoded)
}

/// Whether [`percent_decode`] rewrites the bytes at the start of `rest`.
fn percent_decodes_at(rest: &[u8], plus_is_space: bool) -> bool {
    match rest.first() {
        Some(b'+') => plus_is_space,
        Some(b'%') => percent_u_unit(rest).is_some() || percent_octet(rest).is_some(),
        _ => false,
    }
}

/// The code unit of a well-formed `%uXXXX` escape at the start of `bytes`.
fn percent_u_unit(bytes: &[u8]) -> Option<u32> {
    match bytes {
        [b'%', b'u' | b'U', digits @ ..] => hex_n(digits.get(..4)?),
        _ => None,
    }
}

/// The octet of a well-formed `%XX` escape at the start of `bytes`.
fn percent_octet(bytes: &[u8]) -> Option<u8> {
    match bytes {
        [b'%', digits @ ..] => hex2(digits.get(..2)?),
        _ => None,
    }
}

/// Whether one more decode round would still peel a percent, `\u` / `\x`,
/// or HTML-entity layer from `text`. This is the residual probe applied after
/// the last permitted round of [`layered_decode_inner`].
///
/// Two kinds of change are deliberately not counted: `+` → space, and the
/// JSON / JavaScript single-character escapes (`\n`, `\"`, `\\`, …). A run
/// of backslashes halves on every round, so ordinary multiply-stringified
/// JSON, doubly escaped UNC paths, and regex or LaTeX source would otherwise
/// still be "decoding" at the cap without hiding anything the other decoders
/// would reveal.
///
/// A code-point escape body behind a run of backslashes of *any* length is
/// pending: each round halves the run, so later rounds reach the escape
/// however deep it is stacked (16 backslashes then `u003c` is `<` five
/// decodes later). Which escapes count depends on their form (see
/// [`code_point_escape_hides_syntax`]): any deep `\u` escape of ASCII does,
/// while `\x64` in a Windows path or `\u00e9` in stringified text does not.
fn has_pending_decode(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let rest = &bytes[i..];
        match rest[0] {
            b'%' if percent_u_unit(rest).is_some() || percent_octet(rest).is_some() => {
                return true;
            }
            b'\\' => {
                // Skip the whole run so every byte is visited once.
                let run = rest.iter().take_while(|&&byte| byte == b'\\').count();
                if code_point_escape_hides_syntax(&rest[run..]) {
                    return true;
                }
                i += run;
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    html_entity_decode(text).as_ref() != text
}

/// Whether the `\uXXXX` (or surrogate pair), `\u{...}`, or `\xXX` escape
/// body at the start of `after` (the bytes following a backslash) is one a
/// signature could miss while it stays encoded.
///
/// * `\u` / `\u{...}`: any ASCII character, or a C1 control. JSON and
///   JavaScript serializers never write ASCII as a `\u` escape, so a deep
///   `\u0073elect` or `<\u0073cript>` is evasion in itself even though it
///   yields a letter.
/// * `\xXX`: ASCII punctuation (quotes, angle brackets, slashes, …), a space
///   (a SQL token separator), or an ASCII control (CR/LF, NUL, tab). `\x` is
///   not a JSON escape: it shows up as literal text in Windows paths (`\x64`,
///   `bin\x86\Release`), regex source, and hex dumps, so letters, digits, and
///   C1 bytes are not counted.
fn code_point_escape_hides_syntax(after: &[u8]) -> bool {
    let unicode = match after.first() {
        Some(b'u' | b'U') => true,
        Some(b'x' | b'X') => false,
        _ => return false,
    };
    let Some(ch) = decode_escape(after).and_then(|(cp, _)| char::from_u32(cp)) else {
        return false;
    };
    if unicode {
        ch.is_ascii() || ch.is_control()
    } else {
        ch.is_ascii_punctuation() || ch == ' ' || ch.is_ascii_control()
    }
}

fn is_single_char_escape(byte: u8) -> bool {
    matches!(
        byte,
        b'n' | b't' | b'r' | b'f' | b'b' | b'v' | b'/' | b'"' | b'\'' | b'\\'
    )
}

/// Which backslash escapes [`string_unescape`] resolves.
#[derive(Clone, Copy)]
enum StringEscapes {
    /// Raw request or response text: every JSON / JavaScript escape.
    All,
    /// A value a JSON parser already unescaped: only the code-point escapes
    /// (`\uXXXX`, `\u{...}`, `\xXX`) that model a second, application-level
    /// decode. The single-character escapes were resolved once already.
    CodePointsOnly,
    /// An Express `j:` cookie value `JSON.parse` reads: the code-point escapes
    /// and the escapes that yield a quote, slash, or backslash (`\"`, `\'`,
    /// `\/`, `\\`). The control escapes (`\n`, `\r`, `\t`, `\b`, `\f`, `\v`)
    /// stay a backslash and a letter, so the control-character rule is not
    /// handed a line feed from a cookie.
    JsonCookie,
}

impl StringEscapes {
    fn decode(self, after: &[u8]) -> Option<(u32, usize)> {
        let escape = decode_escape(after)?;
        let single_char = after.first().copied().is_some_and(is_single_char_escape);
        match self {
            Self::CodePointsOnly if single_char => None,
            Self::JsonCookie if single_char && escape.0 < 0x20 => None,
            Self::All | Self::CodePointsOnly | Self::JsonCookie => Some(escape),
        }
    }
}

/// Decode JSON/JavaScript string escapes: `\uXXXX` (with surrogate pairs),
/// `\u{XXXX}`, `\xXX`, and the single-character escapes (`\n`, `\t`, `\r`,
/// `\f`, `\b`, `\v`, `\/`, `\"`, `\'`, `\\`). Unrecognized escapes keep
/// their literal backslash. `escapes` narrows the set for text a JSON parser
/// already unescaped once (see [`StringEscapes`]).
///
/// Borrows unless at least one escape actually decodes: a body full of escapes
/// this decoder does not recognise is returned untouched rather than copied.
/// Literal text between escapes is copied in whole runs located with `memchr`,
/// not one character at a time.
///
/// The single-character escapes are not cosmetic. A JSON or JavaScript parser
/// resolves them before the application sees the value, so
/// `{"q":"1 union\tselect"}` reaches a SQL sink as `union<TAB>select`,
/// `\"1\"=\"1` as `"1"="1`, and `file:\/\/\/etc\/passwd` as
/// `file:///etc/passwd` — while the raw bytes carry a backslash where every
/// signature expects whitespace, a quote, or a slash.
fn string_unescape(text: &str, escapes: StringEscapes) -> Cow<'_, str> {
    decode_runs(text, b'\\', |after| {
        escapes
            .decode(after)
            .map(|(cp, consumed)| (EntityVal::Cp(cp), consumed))
    })
}

/// Shared run-copying driver for the backslash-escape and HTML-entity
/// decoders.
///
/// `marker` is the ASCII byte that can start an escape. Everything between
/// markers is copied as one slice; `decode` is offered the bytes after each
/// marker and returns the decoded value plus how many of those bytes it
/// consumed, or `None` to leave the marker as literal text. Markers and every
/// byte an escape consumes are ASCII, so every slice boundary is a UTF-8
/// character boundary. Returns `Cow::Borrowed` when nothing decoded.
fn decode_runs(
    text: &str,
    marker: u8,
    decode: impl Fn(&[u8]) -> Option<(EntityVal, usize)>,
) -> Cow<'_, str> {
    let bytes = text.as_bytes();
    let Some(mut i) = memchr::memchr(marker, bytes) else {
        return Cow::Borrowed(text);
    };
    let mut out: Option<String> = None;
    // Start of the literal run not yet copied into `out`.
    let mut copied = 0;
    loop {
        match decode(&bytes[i + 1..]) {
            Some((value, consumed)) => {
                let out = out.get_or_insert_with(|| String::with_capacity(text.len()));
                out.push_str(&text[copied..i]);
                match value {
                    EntityVal::Cp(cp) => push_cp(out, cp),
                    EntityVal::Str(decoded) => out.push_str(decoded),
                }
                i += 1 + consumed;
                copied = i;
            }
            // The marker stays literal and joins the pending run.
            None => i += 1,
        }
        match bytes.get(i..).and_then(|rest| memchr::memchr(marker, rest)) {
            Some(offset) => i += offset,
            None => break,
        }
    }
    match out {
        Some(mut out) => {
            out.push_str(&text[copied..]);
            Cow::Owned(out)
        }
        None => Cow::Borrowed(text),
    }
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
        b'n' => Some((u32::from(b'\n'), 1)),
        b't' => Some((u32::from(b'\t'), 1)),
        b'r' => Some((u32::from(b'\r'), 1)),
        b'f' => Some((0x0C, 1)),
        b'b' => Some((0x08, 1)),
        b'v' => Some((0x0B, 1)),
        // `\\` must consume both backslashes so `\\u003c` reads as the
        // literal text `\u003c`, exactly as a JSON parser reads it; the
        // layered decode's next round still reduces a deliberate double
        // escape.
        escaped @ (b'/' | b'"' | b'\'' | b'\\') => Some((u32::from(*escaped), 1)),
        _ => None,
    }
}

/// Decode HTML entities: numeric (`&#NN;`, `&#xHH;`) and a small named set
/// covering the characters that compose injection syntax.
///
/// Borrows unless at least one entity actually decodes, and copies literal
/// runs in bulk; see [`decode_runs`].
fn html_entity_decode(text: &str) -> Cow<'_, str> {
    decode_runs(text, b'&', decode_entity)
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

    fn unicode_unescape(text: &str) -> Cow<'_, str> {
        string_unescape(text, StringEscapes::All)
    }

    #[test]
    fn unicode_unescape_decodes_json_payload() {
        let encoded = format!("{}u003cscript{}u003e", '\\', '\\');
        assert_eq!(unicode_unescape(&encoded), "<script>");
        assert_eq!(unicode_unescape(r"${jndi"), "${jndi");
    }

    #[test]
    fn unicode_unescape_borrows_when_no_escape_decodes() {
        assert!(matches!(unicode_unescape(r"C:\q\z\k"), Cow::Borrowed(_)));
        assert_eq!(unicode_unescape(r"日本\q\u003c\z"), r"日本\q<\z");
    }

    #[test]
    fn unicode_unescape_handles_surrogate_pairs_and_braces() {
        let surrogate_pair = format!("{}uD83D{}uDE00", '\\', '\\');
        assert_eq!(unicode_unescape(&surrogate_pair), "😀");
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
        assert_eq!(unicode_unescape(r"a\qc\zd"), r"a\qc\zd");
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
        // A marker that never forms an entity is literal text: the input is
        // returned as-is rather than copied, and literal runs between real
        // entities survive intact.
        assert!(matches!(
            html_entity_decode("AT&T & Co; R&D"),
            Cow::Borrowed(_)
        ));
        assert_eq!(
            html_entity_decode("Fish &amp; chips &amp chips &#x3c;b&gt; 日本 & more"),
            "Fish & chips &amp chips <b> 日本 & more"
        );
    }

    #[test]
    fn percent_decode_plus_decodes_form_encoding() {
        assert_eq!(percent_decode_plus("%3Cscript%3E"), "<script>");
        assert_eq!(percent_decode_plus("a+b"), "a b");
        assert!(matches!(percent_decode_plus("plain"), Cow::Borrowed(_)));
        // Only a valid escape costs a copy.
        assert!(matches!(percent_decode_plus("1%zz%u1"), Cow::Borrowed(_)));
        assert!(matches!(percent_decode("a+b", false), Cow::Borrowed(_)));
        assert_eq!(percent_decode("a+b%2B", false), "a+b+");
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

    fn reference_decode_runs(
        text: &str,
        marker: u8,
        decode: impl Fn(&[u8]) -> Option<(EntityVal, usize)>,
    ) -> String {
        let bytes = text.as_bytes();
        let mut output = String::with_capacity(text.len());
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] == marker
                && let Some((value, consumed)) = decode(&bytes[index + 1..])
            {
                match value {
                    EntityVal::Cp(cp) => push_cp(&mut output, cp),
                    EntityVal::Str(decoded) => output.push_str(decoded),
                }
                index += consumed + 1;
            } else {
                let ch = text[index..]
                    .chars()
                    .next()
                    .expect("index is within the UTF-8 input");
                output.push(ch);
                index += ch.len_utf8();
            }
        }
        output
    }

    fn reference_has_decodable_marker(text: &str) -> bool {
        text.bytes().any(|byte| matches!(byte, b'%' | b'+' | b'\\' | b'&'))
    }

    #[test]
    fn run_decoders_and_prefilters_match_reference_implementations() {
        let slash = '\\';
        let cases = vec![
            "mixed %3c%3E and plus+ signs".to_string(),
            "%u003cscript%U003E".to_string(),
            "&lt;script&gt; &#60; &#x3e;".to_string(),
            format!("JS {slash}u003c and {slash}x3E"),
            format!(
                "overlong %u12345 and truncated %zz %u12 and {slash}u{{1234567}} {slash}x"
            ),
            "ends with %3c".to_string(),
            "日本%3c😀&lt;".to_string(),
            "plain text without markers".to_string(),
        ];

        for text in &cases {
            let expected_marker = reference_has_decodable_marker(text);
            assert_eq!(has_decodable_marker(text), expected_marker, "{text:?}");

            let expected_js = reference_decode_runs(text, b'\\', |after| {
                StringEscapes::All
                    .decode(after)
                    .map(|(cp, consumed)| (EntityVal::Cp(cp), consumed))
            });
            assert_eq!(
                string_unescape(text, StringEscapes::All),
                expected_js,
                "{text:?}"
            );

            let expected_html = reference_decode_runs(text, b'&', decode_entity);
            assert_eq!(html_entity_decode(text), expected_html, "{text:?}");
        }

        let patterns = [r"(?i)<script", r"union\s+select", r"%[0-9a-f]{2}"];
        let regex_set = regex::RegexSet::new(patterns).expect("valid test patterns");
        let regexes: Vec<_> = patterns
            .iter()
            .map(|pattern| regex::Regex::new(pattern).expect("valid test pattern"))
            .collect();
        let regex_cases = cases.iter().map(String::as_str).chain([
            "<SCRIPT>alert(1)",
            "1 union\tselect",
            "literal %3c",
            "日本語の文章",
            "",
        ]);
        for text in regex_cases {
            let reference = regexes.iter().any(|regex| regex.is_match(text));
            assert_eq!(regex_set.is_match(text), reference, "{text:?}");
            assert_eq!(
                regex_set.matches(text).iter().next().is_some(),
                reference,
                "{text:?}"
            );
        }
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
        let within_cap = layered_decode_inner("%25253Cx", StringEscapes::All);
        assert_eq!(within_cap.decoded, "<x");
        let beyond_cap = layered_decode_inner("%2525253Cx", StringEscapes::All);
        assert_eq!(beyond_cap.decoded, "%3Cx");
        // Nothing to decode: the input is borrowed through every round.
        let plain = layered_decode_inner("100% sure & done", StringEscapes::All);
        assert!(matches!(plain.decoded, Cow::Borrowed(_)));
        assert!(plain.converged);
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
