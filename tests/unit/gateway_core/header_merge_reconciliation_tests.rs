//! The raw request block is a replay snapshot; the plugin map is authoritative.
//! Keep the former two-pass boundary as a test oracle while the runtime fuses
//! its raw assertion/removal scans. The oracle deliberately allocates a folded
//! string, independently of the runtime's allocation-free value comparison.

use std::collections::HashMap;

use ferrum_edge::plugins::RequestContext;
use ferrum_edge::proxy::headers::{
    merge_proxy_headers_and_strip_for_grpc, merge_proxy_headers_preserving_repeated,
};
use http::{HeaderMap, HeaderName, HeaderValue};

fn materialize(raw: &HeaderMap) -> HashMap<String, String> {
    let mut ctx = RequestContext::new("127.0.0.1".into(), "POST".into(), "/".into());
    ctx.set_raw_headers(raw.clone());
    ctx.materialize_headers();
    ctx.headers
}

fn raw_assertion_name(name: &str) -> bool {
    // Independent spelling of the pre-change consumer/identity predicate.
    // GeoIP's raw strip intentionally recognizes only its canonical spelling;
    // the earlier ingress/post-plugin boundary handles backend-folded aliases.
    let folded = name.to_ascii_lowercase().replace('_', "-");
    folded.starts_with("x-consumer-")
        || folded == "x-authenticated-identity"
        || name == "x-geo-country"
}

fn legacy_two_pass_merge(raw: &HeaderMap, authoritative: &HashMap<String, String>) -> HeaderMap {
    let mut headers = raw.clone();
    let assertions: Vec<_> = headers
        .keys()
        .filter(|name| raw_assertion_name(name.as_str()))
        .cloned()
        .collect();
    for name in assertions {
        headers.remove(name);
    }
    let removed: Vec<_> = headers
        .keys()
        .filter(|name| !authoritative.contains_key(name.as_str()))
        .cloned()
        .collect();
    for name in removed {
        headers.remove(name);
    }
    for (name, expected) in authoritative {
        let values: Option<Vec<_>> = headers
            .get_all(name.as_str())
            .iter()
            .map(|value| std::str::from_utf8(value.as_bytes()).ok())
            .collect();
        let separator = if name.eq_ignore_ascii_case("cookie") {
            "; "
        } else {
            ", "
        };
        let unchanged = values
            .filter(|values| !values.is_empty())
            .is_some_and(|values| values.join(separator) == *expected);
        if unchanged {
            continue;
        }
        if let Ok(name) = HeaderName::from_bytes(name.as_bytes()) {
            headers.remove(&name);
            if let Ok(value) = HeaderValue::from_str(expected) {
                headers.insert(name, value);
            }
        }
    }
    headers
}

fn field_lines(headers: &HeaderMap, name: &str) -> Vec<Vec<u8>> {
    headers
        .get_all(name)
        .iter()
        .map(|value| value.as_bytes().to_vec())
        .collect()
}

#[test]
fn fused_scan_matches_legacy_boundary_for_names_values_and_plugin_mutations() {
    let names = [
        "x-app",
        "cookie",
        "grpc-tags-bin",
        "set-cookie",
        "x-consumer-username",
        "X_Consumer-Groups",
        "x-authenticated-identity",
        "X_Authenticated_Identity",
        "x-geo-country",
        "x_geo_country",
        "x-path-param-id",
    ];
    let values: &[&[&[u8]]] = &[
        &[],
        &[b""],
        &[b"one"],
        &[b"one", b"two"],
        &[b"", b"two", b""],
        &["café".as_bytes(), "naïve".as_bytes()],
        &[b"\xff", b"visible"],
        &[b"visible", b"\xff"],
    ];
    for name in names {
        for lines in values {
            let mut raw = HeaderMap::new();
            raw.append("x-control", HeaderValue::from_static("first"));
            raw.append("x-control", HeaderValue::from_static("second"));
            for line in *lines {
                raw.append(
                    HeaderName::from_bytes(name.as_bytes()).unwrap(),
                    HeaderValue::from_bytes(line).unwrap(),
                );
            }
            let canonical = name.to_ascii_lowercase();
            for mutation in 0..6 {
                let mut authoritative = materialize(&raw);
                match mutation {
                    0 => {}
                    1 => {
                        authoritative.remove(&canonical);
                    }
                    2 => {
                        authoritative.insert(canonical.clone(), "gateway-or-plugin".into());
                    }
                    3 => {
                        authoritative.insert(canonical.clone(), "invalid\nreplacement".into());
                    }
                    4 => {
                        authoritative.remove(&canonical);
                        authoritative.insert(name.to_ascii_uppercase(), "mixed-case".into());
                    }
                    5 => {
                        authoritative.insert(canonical.clone(), "one, two".into());
                        authoritative.insert("bad header name".into(), "ignored".into());
                    }
                    _ => unreachable!(),
                }
                let expected = legacy_two_pass_merge(&raw, &authoritative);
                let mut actual = raw.clone();
                merge_proxy_headers_preserving_repeated(&mut actual, &authoritative);
                assert_eq!(
                    actual, expected,
                    "name={name}, lines={lines:?}, mutation={mutation}"
                );
            }
        }
    }
}

#[test]
fn fused_scan_strips_all_raw_assertion_lines_before_equal_gateway_overlay() {
    for name in [
        "x-consumer-username",
        "x_consumer_groups",
        "x-authenticated-identity",
        "x_authenticated_identity",
        "x-geo-country",
    ] {
        let mut raw = HeaderMap::new();
        raw.append(name, HeaderValue::from_static("one"));
        raw.append(name, HeaderValue::from_static("two"));
        let authoritative = HashMap::from([(name.to_string(), "one, two".to_string())]);

        merge_proxy_headers_preserving_repeated(&mut raw, &authoritative);

        assert_eq!(
            field_lines(&raw, name),
            vec![b"one, two".to_vec()],
            "{name}"
        );
    }
}

#[test]
fn fused_scan_keeps_unchanged_repeated_metadata_and_cookie_octets() {
    let mut raw = HeaderMap::new();
    for (name, values) in [
        ("cookie", ["session=a", "theme=b"]),
        ("grpc-tags-bin", ["AQID", "BAUG"]),
        ("x-note", ["café", "naïve"]),
        ("set-cookie", ["a=1; Path=/", "b=2; Path=/"]),
    ] {
        for value in values {
            raw.append(name, HeaderValue::from_bytes(value.as_bytes()).unwrap());
        }
    }
    let authoritative = materialize(&raw);
    assert_eq!(authoritative["cookie"], "session=a; theme=b");
    let pristine = raw.clone();

    merge_proxy_headers_preserving_repeated(&mut raw, &authoritative);

    assert_eq!(raw, pristine);
    for name in ["cookie", "grpc-tags-bin", "x-note", "set-cookie"] {
        assert_eq!(field_lines(&raw, name).len(), 2, "{name}");
    }
}

#[test]
fn fused_scan_replays_removals_and_invalid_replacements_without_mutating_snapshot() {
    let mut snapshot = HeaderMap::new();
    for name in ["x-remove", "x-invalid", "x-replace", "x-keep"] {
        snapshot.append(name, HeaderValue::from_static("first"));
        snapshot.append(name, HeaderValue::from_static("second"));
    }
    snapshot.insert("x-consumer-role", HeaderValue::from_static("forged"));
    snapshot.insert("x-geo-country", HeaderValue::from_static("forged"));
    snapshot.insert("x-non-utf8", HeaderValue::from_bytes(b"\xff").unwrap());
    let pristine = snapshot.clone();
    let mut authoritative = materialize(&snapshot);
    authoritative.remove("x-remove");
    authoritative.insert("x-invalid".into(), "invalid\r\nvalue".into());
    authoritative.insert("x-replace".into(), "final-value".into());
    authoritative.insert("x-consumer-username".into(), "verified".into());
    for _ in 0..3 {
        let mut outbound = snapshot.clone();
        merge_proxy_headers_preserving_repeated(&mut outbound, &authoritative);

        for absent in [
            "x-remove",
            "x-invalid",
            "x-consumer-role",
            "x-geo-country",
            "x-non-utf8",
        ] {
            assert!(!outbound.contains_key(absent), "{absent}");
        }
        assert_eq!(outbound["x-replace"], "final-value");
        assert_eq!(outbound["x-consumer-username"], "verified");
        assert_eq!(field_lines(&outbound, "x-keep").len(), 2);
        assert_eq!(snapshot, pristine);
    }
}

#[test]
fn fused_scan_still_strips_final_grpc_union_after_plugin_replacement() {
    let mut raw = HeaderMap::new();
    raw.insert("connection", HeaderValue::from_static("x-old-hop"));
    raw.insert("x-old-hop", HeaderValue::from_static("now-end-to-end"));
    raw.insert("x-new-hop", HeaderValue::from_static("must-strip"));
    raw.insert("x-consumer-role", HeaderValue::from_static("forged"));
    let mut authoritative = materialize(&raw);
    authoritative.insert("connection".into(), "x-new-hop".into());
    authoritative.insert("te".into(), "trailers".into());
    authoritative.insert("proxy-authorization".into(), "must-strip".into());
    authoritative.insert("x-consumer-username".into(), "verified".into());

    merge_proxy_headers_and_strip_for_grpc(&mut raw, &authoritative);

    for absent in [
        "connection",
        "x-new-hop",
        "proxy-authorization",
        "x-consumer-role",
    ] {
        assert!(!raw.contains_key(absent), "{absent}");
    }
    assert_eq!(raw["x-old-hop"], "now-end-to-end");
    assert_eq!(raw["te"], "trailers");
    assert_eq!(raw["x-consumer-username"], "verified");
}
