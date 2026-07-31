//! Shared synthetic-response wire semantics for H1/H2/H3.
//!
//! Plugin short-circuits, size-limit fast paths, and gateway reject writers must
//! agree on when a final response may carry content bytes. HEAD responses keep
//! representation metadata (including `Content-Length`) but never emit a
//! message body. Informational `1xx` responses and statuses 204/205/304 never
//! carry content (RFC 9110 §6.4.1 / §15.2).

use std::collections::HashMap;

/// Statuses that must not carry a message body (RFC 9110).
#[inline]
pub fn status_forbids_response_body(status: u16) -> bool {
    matches!(status, 204 | 205 | 304) || (100..200).contains(&status)
}

/// Whether the request METHOD alone forbids content bytes on the response.
///
/// `HEAD` is the only such method: its response carries the same header section
/// a `GET` would have (representation metadata included) but no message body
/// (RFC 9110 §9.3.2). Kept as one predicate so the final client-wire framing
/// boundary ([`crate::proxy::headers::ClientResponseFraming::for_streaming_response`])
/// and [`synthetic_response_omits_body`] cannot disagree about which methods are
/// body-less.
#[inline]
pub fn request_method_omits_response_body(method: &str) -> bool {
    method.eq_ignore_ascii_case("HEAD")
}

/// Whether the wire response must omit content bytes for this method/status.
///
/// Shared across H1/H2/H3 so response-size and synthetic-response paths cannot
/// drift on body presence.
#[inline]
pub fn synthetic_response_omits_body(method: &str, status: u16) -> bool {
    request_method_omits_response_body(method) || status_forbids_response_body(status)
}

/// Prepare headers and report whether the caller must omit content bytes.
///
/// For `HEAD`, preserves (or installs) `Content-Length` equal to the
/// representation size that a GET would have returned, then returns `true`.
/// For `1xx` and 204/205/304, strips `Content-Length` and returns `true`. All
/// other responses leave headers unchanged and return `false`. The caller
/// clears or substitutes its body only when this returns `true`, avoiding a
/// body clone on the ordinary response path.
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
    // body; 1xx/204/205/304 (including HEAD+those statuses) strip Content-Length.
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
