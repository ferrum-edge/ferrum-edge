//! `ETag` / `If-Match` conditional writes for full-replacement admin resources.
//!
//! `PUT` on proxies, upstreams, consumers, and plugin configs replaces the whole
//! resource, so a client that submits an editor opened before someone else's
//! accepted change does not merely omit that change — it reverts it. `GET`
//! returns a strong `ETag` for the stored representation; a `PUT` or `DELETE`
//! carrying `If-Match` is refused with `412 Precondition Failed` unless the
//! resource still has that representation.
//!
//! # Atomicity
//!
//! The comparison is made against the row read by the write path *after* it
//! acquires the durable namespace config admission lease, and the write commits
//! while that lease is still held. Every admin writer of these four resource
//! families — CRUD, `/batch`, `/restore`, API-spec import, credential
//! endpoints, and namespace registry operations — takes the same lease, so no
//! supported writer can commit between the comparison and the write, including
//! one on another control-plane replica.
//!
//! # Tag derivation
//!
//! The tag is an HMAC-SHA-256 over a canonical (key-sorted) JSON rendering of
//! the full stored resource, keyed by a subkey derived from the admin JWT
//! secret. It is keyed rather than a plain digest because the representation
//! includes values a role may not be allowed to read (plugin-config secrets,
//! consumer credential material): an unkeyed digest would be an offline oracle
//! for guessing a redacted value. Replicas that accept the same admin tokens
//! share the secret and therefore agree on tags.

use crate::fips::approved::HmacSha256Key;
use serde_json::Value;

/// Domain-separation label for the tag subkey. Bump the version to invalidate
/// every outstanding tag when the canonical form changes.
const ETAG_SUBKEY_LABEL: &[u8] = b"ferrum-edge/admin-resource-etag/v1";

/// Bytes of the MAC kept in the tag. 128 bits is ample: forging a match would
/// require the key, and accidental collision is negligible at this width.
const ETAG_TAG_BYTES: usize = 16;

/// A parsed `If-Match` request header (RFC 9110 §13.1.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum IfMatch {
    /// `If-Match: *` — the resource must currently exist.
    Any,
    /// A list of entity-tags. Weak tags are retained so they can be refused:
    /// `If-Match` uses strong comparison, and a weak tag never matches.
    Tags(Vec<EntityTag>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EntityTag {
    pub weak: bool,
    pub opaque: String,
}

impl IfMatch {
    /// Strong comparison against the resource's current tag.
    ///
    /// `current` is `None` when the resource exists but no tag can be computed
    /// for it (for example an undecodable row being repaired in-band). `*` still
    /// matches — the resource exists — but a specific tag cannot be verified
    /// and therefore does not.
    pub(crate) fn matches(&self, current: Option<&str>) -> bool {
        match self {
            IfMatch::Any => true,
            IfMatch::Tags(tags) => current.is_some_and(|current| {
                tags.iter()
                    .any(|tag| !tag.weak && tag.opaque.as_str() == current)
            }),
        }
    }
}

/// Parse every `If-Match` field line on the request.
///
/// Returns `Ok(None)` when the header is absent. A present but malformed or
/// empty header is an error rather than "no precondition": a client that sent
/// one expects its write to be conditional, and silently treating it as
/// unconditional would reintroduce exactly the overwrite it was guarding
/// against.
pub(crate) fn parse_if_match(headers: &hyper::HeaderMap) -> Result<Option<IfMatch>, String> {
    let mut values = headers.get_all(hyper::header::IF_MATCH).iter().peekable();
    if values.peek().is_none() {
        return Ok(None);
    }
    let mut any = false;
    let mut tags = Vec::new();
    for value in values {
        let text = value
            .to_str()
            .map_err(|_| "If-Match header must be visible ASCII".to_string())?;
        parse_if_match_field(text, &mut any, &mut tags)?;
    }
    match (any, tags.is_empty()) {
        (true, true) => Ok(Some(IfMatch::Any)),
        (true, false) => Err("If-Match '*' cannot be combined with entity-tags".to_string()),
        (false, true) => Err("If-Match header must not be empty".to_string()),
        (false, false) => Ok(Some(IfMatch::Tags(tags))),
    }
}

fn parse_if_match_field(
    text: &str,
    any: &mut bool,
    tags: &mut Vec<EntityTag>,
) -> Result<(), String> {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b' ' | b'\t' | b',' => {
                i += 1;
                continue;
            }
            b'*' => {
                *any = true;
                i += 1;
            }
            _ => {
                let weak = bytes[i..].starts_with(b"W/");
                if weak {
                    i += 2;
                }
                if bytes.get(i) != Some(&b'"') {
                    return Err("If-Match entity-tags must be quoted".to_string());
                }
                i += 1;
                let start = i;
                while i < bytes.len() && bytes[i] != b'"' {
                    // etagc = %x21 / %x23-7E / obs-text; `to_str` already
                    // excluded obs-text, so only controls and space remain.
                    if bytes[i] <= b' ' || bytes[i] == 0x7f {
                        return Err("If-Match entity-tag contains an invalid character".to_string());
                    }
                    i += 1;
                }
                if i >= bytes.len() {
                    return Err("If-Match entity-tag is missing its closing quote".to_string());
                }
                tags.push(EntityTag {
                    weak,
                    opaque: text[start..i].to_string(),
                });
                i += 1;
            }
        }
        // Each list member must be followed by whitespace, a comma, or the end.
        while i < bytes.len() && matches!(bytes[i], b' ' | b'\t') {
            i += 1;
        }
        if i < bytes.len() && bytes[i] != b',' {
            return Err("If-Match list members must be comma-separated".to_string());
        }
    }
    Ok(())
}

/// Derive the tag key from the admin JWT secret. `None` when no secret is
/// configured, in which case no tags are issued and any `If-Match` other than
/// `*` cannot be satisfied.
pub(crate) fn etag_key(jwt_secret: &str) -> Option<HmacSha256Key> {
    if jwt_secret.is_empty() {
        return None;
    }
    let mut derive =
        crate::fips::approved::HmacSha256::new_from_slice(jwt_secret.as_bytes()).ok()?;
    derive.update(ETAG_SUBKEY_LABEL);
    HmacSha256Key::new_from_slice(derive.finalize().as_ref()).ok()
}

/// The opaque part of the strong tag for one stored resource (no quotes).
///
/// The resource kind, namespace, and id are bound into the MAC so a tag issued
/// for one resource can never satisfy a precondition on another, even if their
/// bodies are identical.
pub(crate) fn resource_etag(
    key: &HmacSha256Key,
    resource_kind: &str,
    namespace: &str,
    id: &str,
    representation: &Value,
) -> String {
    let mut canonical = String::new();
    write_canonical_json(representation, &mut canonical);
    let mut mac = key.begin();
    for part in [resource_kind, namespace, id] {
        mac.update((part.len() as u64).to_be_bytes());
        mac.update(part.as_bytes());
    }
    mac.update(canonical.as_bytes());
    hex::encode(&mac.finalize().as_ref()[..ETAG_TAG_BYTES])
}

/// Quote an opaque tag for the `ETag` response header.
pub(crate) fn quoted(opaque: &str) -> String {
    format!("\"{opaque}\"")
}

/// Render JSON with object keys in sorted order, independent of the
/// `serde_json` map implementation any dependency may select through feature
/// unification. Arrays keep their order; callers normalize arrays whose stored
/// order is not meaningful before calling.
fn write_canonical_json(value: &Value, out: &mut String) {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_unstable_by(|a, b| a.0.cmp(b.0));
            out.push('{');
            for (index, (key, value)) in entries.into_iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String(key.clone()).to_string());
                out.push(':');
                write_canonical_json(value, out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_canonical_json(item, out);
            }
            out.push(']');
        }
        scalar => out.push_str(&scalar.to_string()),
    }
}
