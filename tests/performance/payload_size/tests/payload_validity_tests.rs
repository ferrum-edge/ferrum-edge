//! Format-validity contract for structured payload generators (issue #6472).
//!
//! The generators promise structurally valid content at approximately the
//! requested size. Sizing must be done by adjusting in-field padding, never
//! by truncating serialized syntax: JSON/GraphQL envelopes must parse, XML
//! and SOAP documents must keep their closing tags, NDJSON must contain
//! only whole newline-terminated records, and SSE must contain only whole
//! blank-line-terminated events.

use payload_size_perf::payload_gen::{ContentType, SIZES, generate_payload};

#[test]
fn json_and_graphql_payloads_parse_at_every_documented_size() {
    for &size in SIZES {
        for ct in [ContentType::Json, ContentType::Graphql] {
            let payload = generate_payload(ct, size);
            assert_eq!(payload.len(), size, "{ct:?} at {size} must be exact");
            let parsed: Result<serde_json::Value, _> = serde_json::from_slice(&payload);
            assert!(parsed.is_ok(), "{ct:?} at {size} must parse: {parsed:?}");
        }
    }
}

#[test]
fn xml_and_soap_payloads_keep_their_closing_syntax() {
    for &size in SIZES {
        let xml = generate_payload(ContentType::Xml, size);
        assert_eq!(xml.len(), size, "xml at {size} must be exact");
        let xml = std::str::from_utf8(&xml).expect("xml payload is UTF-8");
        assert!(xml.starts_with("<?xml"), "xml at {size} keeps its header");
        assert!(xml.ends_with("</root>"), "xml at {size} keeps its footer");
        assert_eq!(
            xml.matches("<record id=").count(),
            xml.matches("</record>").count(),
            "xml at {size} records must be balanced"
        );

        let soap = generate_payload(ContentType::SoapXml, size);
        assert_eq!(soap.len(), size, "soap-xml at {size} must be exact");
        let soap = std::str::from_utf8(&soap).expect("soap payload is UTF-8");
        assert!(
            soap.ends_with("</soap:Envelope>"),
            "soap-xml at {size} keeps its footer"
        );
        assert_eq!(
            soap.matches("<ws:DataItem id=").count(),
            soap.matches("</ws:DataItem>").count(),
            "soap-xml at {size} items must be balanced"
        );
    }
}

#[test]
fn ndjson_payloads_contain_only_whole_records() {
    for &size in SIZES {
        let payload = generate_payload(ContentType::Ndjson, size);
        assert!(payload.len() <= size, "ndjson at {size} must not overshoot");
        assert!(
            size - payload.len() < 256,
            "ndjson at {size} shortfall {} exceeds one empty record",
            size - payload.len()
        );
        let text = std::str::from_utf8(&payload).expect("ndjson payload is UTF-8");
        assert!(text.ends_with('\n'), "ndjson at {size} ends with newline");
        for line in text.lines() {
            let parsed: Result<serde_json::Value, _> = serde_json::from_str(line);
            assert!(parsed.is_ok(), "ndjson record at {size} must parse");
        }
    }
}

#[test]
fn sse_payloads_contain_only_whole_events() {
    for &size in SIZES {
        let payload = generate_payload(ContentType::Sse, size);
        assert!(payload.len() <= size, "sse at {size} must not overshoot");
        assert!(
            size - payload.len() < 256,
            "sse at {size} shortfall {} exceeds one empty event",
            size - payload.len()
        );
        let text = std::str::from_utf8(&payload).expect("sse payload is UTF-8");
        assert!(text.ends_with("\n\n"), "sse at {size} ends with blank line");
        for event in text.split("\n\n").filter(|event| !event.is_empty()) {
            let data = event
                .lines()
                .find_map(|line| line.strip_prefix("data: "))
                .expect("every sse event carries a data line");
            let parsed: Result<serde_json::Value, _> = serde_json::from_str(data);
            assert!(parsed.is_ok(), "sse data at {size} must parse");
        }
    }
}

#[test]
fn multipart_payloads_keep_the_closing_boundary() {
    for &size in SIZES {
        let payload = generate_payload(ContentType::MultipartFormData, size);
        assert_eq!(payload.len(), size, "multipart at {size} must be exact");
        let tail = &payload[payload.len().saturating_sub(64)..];
        let tail = String::from_utf8_lossy(tail);
        assert!(
            tail.contains("------PayloadBenchBoundary7MA4YWxkTrZu0gW--"),
            "multipart at {size} keeps its closing boundary"
        );
    }
}
