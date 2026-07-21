//! Shared synthetic-response wire semantics for H1/H2/H3.
//!
//! Plugin short-circuits and gateway reject writers must agree on when a final
//! response may carry content bytes. HEAD responses keep representation
//! metadata (including `Content-Length`) but never emit a message body.
//! Statuses 204/205/304 never carry content.

use std::collections::HashMap;

/// Statuses that must not carry a message body (RFC 9110).
#[inline]
pub fn status_forbids_response_body(status: u16) -> bool {
    matches!(status, 204 | 205 | 304)
}

/// Whether the wire response must omit content bytes for this method/status.
#[inline]
pub fn synthetic_response_omits_body(method: &str, status: u16) -> bool {
    method.eq_ignore_ascii_case("HEAD") || status_forbids_response_body(status)
}

/// Prepare headers and report whether the caller must omit content bytes.
///
/// For `HEAD`, preserves (or installs) `Content-Length` equal to the
/// representation size that a GET would have returned, then returns `true`.
/// For 204/205/304, strips `Content-Length` and returns `true`. All other
/// responses leave headers unchanged and return `false`. The caller clears or
/// substitutes its body only when this returns `true`, avoiding a body clone on
/// the ordinary response path.
///
/// H1 note: Hyper still synthesizes `Content-Length: 0` for ordinary empty
/// bodies on status 205 (it special-cases only 204/304). Reject finalizers
/// must select a status-aware empty body so 205 does not re-advertise length
/// on the wire.
pub fn prepare_synthetic_response_wire(
    method: &str,
    status: u16,
    headers: &mut HashMap<String, String>,
    representation_len: usize,
) -> bool {
    if !synthetic_response_omits_body(method, status) {
        return false;
    }

    // HEAD keeps representation metadata unless the status itself forbids a
    // body; 204/205/304 (including HEAD+those statuses) strip Content-Length.
    if method.eq_ignore_ascii_case("HEAD") && !status_forbids_response_body(status) {
        if !headers
            .keys()
            .any(|name| name.eq_ignore_ascii_case("content-length"))
        {
            headers.insert("content-length".to_string(), representation_len.to_string());
        }
    } else {
        remove_content_length(headers);
    }

    true
}

fn remove_content_length(headers: &mut HashMap<String, String>) {
    headers.retain(|name, _| !name.eq_ignore_ascii_case("content-length"));
}
