//! Shared pre-parse XML bounds.
//!
//! Every XML consumer in the gateway (`body_validator`, `soap_ws_security`,
//! `openapi_validator`) hands attacker-controlled bytes to `roxmltree`. Bounding
//! that work takes three layers, because no single one is sufficient:
//!
//! 1. **Pre-parse nesting-depth screen** — [`xml_nesting_depth_within_limit`],
//!    applied to the raw bytes *before* `roxmltree` sees them. Before 0.21.2,
//!    `roxmltree`'s tokenizer recursed once per open element, so a deeply
//!    nested document overflowed the tokio worker stack *inside*
//!    `Document::parse_with_options`, before any `NodesLimitReached` error,
//!    and under `panic = "abort"` that is a process kill on the request path.
//!    Since 0.21.2 it parses element content iteratively, so the parser no
//!    longer spends stack per nesting level. The screen stays anyway: it
//!    refuses a hostile document before any tree is allocated, it caps the
//!    depth the consumers' recursive post-parse walkers can be handed, and
//!    it keeps the request path stack-safe if a later parser change
//!    reintroduces recursion. It runs on the bytes, never on a parsed tree.
//! 2. **Parser node limit** (`ParsingOptions::nodes_limit`) — bounds the arena a
//!    pathologically *wide* document can allocate. Each consumer keeps its own
//!    value.
//! 3. **Post-parse walk budget** — each consumer's own recursive walkers
//!    (`soap_ws_security`'s `MAX_CANONICALIZATION_DEPTH`, `openapi_validator`'s
//!    threaded depth argument) re-apply a depth ceiling as defence in depth.
//!
//! [`XML_MAX_NESTING_DEPTH`] is the fixed value for layer 1. It is deliberately
//! not operator-tunable: it is a stack-safety floor, not a policy knob.

/// Maximum element nesting depth accepted by the pre-parse screen.
///
/// Real SOAP, SAML, and schema-described documents stay far below this; the
/// value is a fixed ceiling on the nesting a consumer and its recursive
/// post-parse walkers ever see, applied before the parser runs.
pub const XML_MAX_NESTING_DEPTH: usize = 256;

/// Single pass over the raw document bytes rejecting element nesting deeper
/// than `max_depth`, run *before* the document reaches `roxmltree`. Every
/// delimiter inspected is ASCII, so byte indexing cannot split a UTF-8
/// sequence. Constructs that may legally contain a bare `<` or `>` (comments,
/// CDATA, processing instructions, DOCTYPE, quoted attribute values) are
/// skipped rather than counted, so a legitimate document is never rejected.
/// An unterminated construct simply ends the scan; `roxmltree` rejects such a
/// document itself.
pub fn xml_nesting_depth_within_limit(body: &str, max_depth: usize) -> bool {
    let bytes = body.as_bytes();
    let mut index = 0usize;
    let mut depth = 0usize;
    while index < bytes.len() {
        if bytes[index] != b'<' {
            index += 1;
            continue;
        }
        let rest = &bytes[index..];
        if rest.starts_with(b"<!--") {
            match find_subslice(&bytes[index + 4..], b"-->") {
                Some(offset) => index += 4 + offset + 3,
                None => return true,
            }
            continue;
        }
        if rest.starts_with(b"<![CDATA[") {
            match find_subslice(&bytes[index + 9..], b"]]>") {
                Some(offset) => index += 9 + offset + 3,
                None => return true,
            }
            continue;
        }
        if rest.starts_with(b"<?") {
            match find_subslice(&bytes[index + 2..], b"?>") {
                Some(offset) => index += 2 + offset + 2,
                None => return true,
            }
            continue;
        }
        if rest.starts_with(b"<!") {
            // DOCTYPE and friends. Skipping conservatively cannot make the
            // screen unsound: a consumer that forbids DTDs has `roxmltree`
            // reject the document regardless, and one that allows them applies
            // its own entity policy.
            match bytes[index + 2..].iter().position(|byte| *byte == b'>') {
                Some(offset) => index += 2 + offset + 1,
                None => return true,
            }
            continue;
        }
        if rest.starts_with(b"</") {
            depth = depth.saturating_sub(1);
            match bytes[index + 2..].iter().position(|byte| *byte == b'>') {
                Some(offset) => index += 2 + offset + 1,
                None => return true,
            }
            continue;
        }
        depth += 1;
        if depth > max_depth {
            return false;
        }
        // Advance to the tag's closing `>`, quote-aware: a `>` inside a quoted
        // attribute value does not terminate the tag.
        let mut cursor = index + 1;
        let mut quote: Option<u8> = None;
        let mut last_significant: Option<u8> = None;
        let mut terminated = false;
        while cursor < bytes.len() {
            let byte = bytes[cursor];
            match quote {
                Some(open) => {
                    if byte == open {
                        quote = None;
                    }
                    last_significant = Some(byte);
                }
                None => {
                    if byte == b'"' || byte == b'\'' {
                        quote = Some(byte);
                        last_significant = Some(byte);
                    } else if byte == b'>' {
                        terminated = true;
                        break;
                    } else if !byte.is_ascii_whitespace() {
                        last_significant = Some(byte);
                    }
                }
            }
            cursor += 1;
        }
        if !terminated {
            return true;
        }
        if last_significant == Some(b'/') {
            // Self-closing element: it opened and closed in one tag.
            depth = depth.saturating_sub(1);
        }
        index = cursor + 1;
    }
    true
}

/// First index of `needle` within `haystack`, or `None`.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Unqualified attribute lookup for `roxmltree` nodes.
///
/// Since roxmltree 0.21, `Node::attribute("name")` (and `has_attribute` /
/// `attribute_node`) match the local name in *any* namespace and return the
/// first match, so `attribute("ID")` also returns a prefixed `x:ID` that
/// precedes the unqualified `ID`. XML attributes never inherit a default
/// namespace, and WS-Security, SAML, and XML-Signature define the attributes
/// read here (`ID`, `URI`, `Algorithm`, ...) as unqualified, so a prefixed
/// look-alike must not be read in their place. Use a `(namespace, local)`
/// tuple with `attribute` for a namespaced attribute.
pub trait UnqualifiedAttribute<'a> {
    /// Value of the attribute named `local` that has no namespace.
    fn unqualified_attribute(&self, local: &str) -> Option<&'a str>;
}

impl<'a, 'input: 'a> UnqualifiedAttribute<'a> for roxmltree::Node<'a, 'input> {
    fn unqualified_attribute(&self, local: &str) -> Option<&'a str> {
        self.attributes()
            .find(|attribute| attribute.namespace().is_none() && attribute.name() == local)
            .map(|attribute| attribute.value())
    }
}
