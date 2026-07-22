//! Shared synthetic-response wire semantics.

use ferrum_edge::plugins::utils::synthetic_response::{
    prepare_synthetic_response_wire, status_forbids_response_body, synthetic_response_omits_body,
};
use std::collections::HashMap;

#[test]
fn head_and_no_body_statuses_omit_wire_content() {
    assert!(synthetic_response_omits_body("HEAD", 503));
    assert!(synthetic_response_omits_body("head", 200));
    assert!(synthetic_response_omits_body("GET", 204));
    assert!(synthetic_response_omits_body("GET", 205));
    assert!(synthetic_response_omits_body("GET", 304));
    assert!(synthetic_response_omits_body("GET", 100));
    assert!(synthetic_response_omits_body("GET", 101));
    assert!(!synthetic_response_omits_body("GET", 503));
    assert!(!synthetic_response_omits_body("GET", 206));
    assert!(status_forbids_response_body(204));
    assert!(status_forbids_response_body(103));
    assert!(!status_forbids_response_body(503));
}

#[test]
fn prepare_head_keeps_representation_content_length() {
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    let body = br#"{"message":"down"}"#;
    assert!(prepare_synthetic_response_wire(
        "HEAD",
        503,
        &mut headers,
        body.len()
    ));
    assert_eq!(
        headers.get("content-length").map(String::as_str),
        Some("18")
    );
    assert_eq!(
        headers.get("content-type").map(String::as_str),
        Some("application/json")
    );
}

#[test]
fn prepare_head_preserves_existing_content_length_case_insensitively() {
    let mut headers = HashMap::new();
    headers.insert("Content-Length".to_string(), "18".to_string());
    assert!(prepare_synthetic_response_wire(
        "HEAD",
        503,
        &mut headers,
        0
    ));
    assert_eq!(
        headers.get("Content-Length").map(String::as_str),
        Some("18")
    );
    assert_eq!(headers.len(), 1, "must not add a case-variant duplicate");
}

#[test]
fn prepare_no_body_status_strips_content_length() {
    for status in [100u16, 204, 205, 304] {
        let mut headers = HashMap::new();
        headers.insert("content-length".to_string(), "99".to_string());
        assert!(
            prepare_synthetic_response_wire("GET", status, &mut headers, 1),
            "status {status}"
        );
        assert!(
            !headers
                .keys()
                .any(|k| k.eq_ignore_ascii_case("content-length")),
            "status {status} must drop Content-Length"
        );
    }
}

#[test]
fn prepare_get_with_body_is_passthrough() {
    let mut headers = HashMap::new();
    assert!(!prepare_synthetic_response_wire(
        "GET",
        503,
        &mut headers,
        b"payload".len()
    ));
    assert!(headers.is_empty());
}
