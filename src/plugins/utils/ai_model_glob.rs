//! Anchored `*`-only glob matching for AI provider `model_patterns`.
//!
//! `ai_stream_router` (and, historically, `ai_federation`) route a request by
//! matching the client's `model` against operator-configured globs. Both halves
//! of that contract live here so the plugins that consume it cannot drift:
//!
//! 1. **Anchoring.** A pattern matches the WHOLE model name. There is no
//!    "starts-with" mode.
//! 2. **Forbidden bytes.** A `*` window may not consume a URL-structural
//!    separator or whitespace, so a permissive `gemini-*` cannot smuggle
//!    `gemini-../foo:streamGenerateContent` past selection and into a provider
//!    path.
//!
//! Issue #5255 (`ai_federation`) and issues #5297 / #5392 (`ai_stream_router`)
//! were one defect in two copies: the matcher consumed the FIRST occurrence of
//! each literal segment and then demanded that the cursor had already reached
//! the end of the input, so `*mini` rejected `mini-mini` — an ordinary model
//! name answered with a `404`, or handed to a different provider by a catch-all
//! fallback.

/// Bytes a `*` window may never consume.
///
/// URL-structural separators (path, query, and fragment introducers plus the
/// alternate path separator) and whitespace have no business in a model
/// identifier. Compare with fnmatch(3), where `*` does not cross `/`.
pub const GLOB_WILDCARD_FORBIDDEN_BYTES: &[u8] = b"/?#&\\ \t\n\r";

/// Longest input the floating-literal reachability sweep will consider.
///
/// That sweep allocates one bitmap the size of the input, so an unbounded
/// `model` read straight from a request body would otherwise let a client
/// choose the allocation. Real model identifiers are two orders of magnitude
/// below this bound, and a pattern with no interior literal — `gpt-*`,
/// `*mini`, `claude-*-v2` — never reaches the sweep at all.
const MAX_INTERIOR_SWEEP_INPUT_BYTES: usize = 4096;

/// Whether a byte may never be consumed by a `*` window.
///
/// Every member of [`GLOB_WILDCARD_FORBIDDEN_BYTES`] is ASCII, so the matcher
/// decides a window byte by byte and never has to slice a `str` at a position
/// it has not proven to be a character boundary.
fn glob_byte_is_forbidden(byte: u8) -> bool {
    GLOB_WILDCARD_FORBIDDEN_BYTES.contains(&byte)
}

/// Anchored glob match supporting only `*` as a wildcard.
///
/// `*` matches any sequence of characters EXCEPT those listed in
/// [`GLOB_WILDCARD_FORBIDDEN_BYTES`]. The pattern is implicitly anchored to the
/// start and end of `input`, and the literal segments between `*` markers must
/// appear in order without overlapping.
///
/// The leading and trailing literals are ANCHORED, so they are stripped
/// directly. What remains floats, and is decided by the reachability sweep in
/// [`glob_interior_matches`] rather than by consuming the FIRST occurrence of
/// each literal: first-occurrence consumption is not a glob.
pub fn matches_model_glob(pattern: &str, input: &str) -> bool {
    let Some((prefix, after_first)) = pattern.split_once('*') else {
        // No wildcard — exact match.
        return pattern == input;
    };
    // Everything strictly between the FIRST and LAST `*`; a single-wildcard
    // pattern has no interior at all.
    let (interior, suffix) = after_first.rsplit_once('*').unwrap_or(("", after_first));

    let input = input.as_bytes();
    let Some(rest) = input.strip_prefix(prefix.as_bytes()) else {
        return false;
    };
    // Stripping the suffix from what the prefix left also rejects a
    // prefix/suffix pair that would have to overlap to both fit.
    let Some(middle) = rest.strip_suffix(suffix.as_bytes()) else {
        return false;
    };

    glob_interior_matches(interior, middle)
}

/// Match the pattern text between the first and last `*` against the input the
/// anchored prefix and suffix left behind.
///
/// The token sequence here always both starts and ends with a `*` window, so
/// the interior literals float. Reachability is swept forward one token at a
/// time over a bitmap of input positions: every position the pattern can
/// legally have reached stays live, so a literal that also occurs earlier in
/// the input can still be matched at the position that satisfies the anchors.
/// Cost is bounded by pattern length × [`MAX_INTERIOR_SWEEP_INPUT_BYTES`], and
/// the single bitmap allocation happens only for a pattern that actually has an
/// interior literal.
fn glob_interior_matches(interior: &str, middle: &[u8]) -> bool {
    let mut literals = interior
        .split('*')
        .filter(|part| !part.is_empty())
        .peekable();
    if literals.peek().is_none() {
        // One `*` window spans the whole remainder.
        return !middle.iter().copied().any(glob_byte_is_forbidden);
    }
    if middle.len() > MAX_INTERIOR_SWEEP_INPUT_BYTES {
        return false;
    }

    let mut reachable = vec![false; middle.len() + 1];
    if let Some(start) = reachable.first_mut() {
        *start = true;
    }
    for literal in literals {
        glob_expand_wildcard(&mut reachable, middle);
        glob_advance_literal(&mut reachable, middle, literal.as_bytes());
        if !reachable.iter().any(|live| *live) {
            return false;
        }
    }
    glob_expand_wildcard(&mut reachable, middle);
    reachable.last().copied().unwrap_or(false)
}

/// Extend every live position through one `*` window.
///
/// A window may consume any run of bytes containing none of
/// [`GLOB_WILDCARD_FORBIDDEN_BYTES`], so a forbidden byte closes the window and
/// only a later live position can reopen one. Without this, `gemini-*` would
/// match `gemini-../foo:streamGenerateContent` and let the dispatcher route a
/// path-traversing model to a real Gemini provider.
fn glob_expand_wildcard(reachable: &mut [bool], middle: &[u8]) {
    let mut open = false;
    for (index, slot) in reachable.iter_mut().enumerate() {
        if *slot {
            open = true;
        } else if open {
            *slot = true;
        }
        if glob_byte_blocks_window(middle, index) {
            open = false;
        }
    }
}

/// Whether the byte the `*` window would have to consume to advance past
/// `index` is forbidden. The final position has no byte after it.
fn glob_byte_blocks_window(middle: &[u8], index: usize) -> bool {
    let Some(byte) = middle.get(index) else {
        return false;
    };
    glob_byte_is_forbidden(*byte)
}

/// Consume one literal segment from every position that can currently reach it.
///
/// Walked in DESCENDING order so a match may write its end position into a slot
/// this sweep has already cleared, which keeps the whole match on one bitmap.
/// Interior literals are never empty, so the write always lands ahead of the
/// read.
fn glob_advance_literal(reachable: &mut [bool], middle: &[u8], literal: &[u8]) {
    for index in (0..reachable.len()).rev() {
        let mut matched = false;
        if let Some(slot) = reachable.get_mut(index) {
            matched = *slot && glob_literal_at(middle, index, literal);
            *slot = false;
        }
        if !matched {
            continue;
        }
        if let Some(slot) = reachable.get_mut(index + literal.len()) {
            *slot = true;
        }
    }
}

/// Whether `literal` occurs in `middle` starting exactly at `index`.
fn glob_literal_at(middle: &[u8], index: usize, literal: &[u8]) -> bool {
    let Some(tail) = middle.get(index..) else {
        return false;
    };
    let Some(candidate) = tail.get(..literal.len()) else {
        return false;
    };
    candidate == literal
}
