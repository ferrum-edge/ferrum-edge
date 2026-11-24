//! Issue #6899: plugin-written case variants must have one reading at every
//! authorization/materialization/backend boundary, independent of hash order.

use std::collections::HashMap;

use ferrum_edge::plugins::RequestContext;
use ferrum_edge::proxy::headers::{
    SecondaryRequestHostPolicy, canonicalize_request_header_map, filter_secondary_request_headers,
    merge_proxy_headers_preserving_repeated,
};
use ferrum_edge::proxy::refresh_backend_gateway_assertion_headers;
use http::HeaderMap;

const INSERTION_ORDERS: [[usize; 3]; 6] = [
    [0, 1, 2],
    [0, 2, 1],
    [1, 0, 2],
    [1, 2, 0],
    [2, 0, 1],
    [2, 1, 0],
];

fn variant_map(names: [&str; 3], order: [usize; 3]) -> HashMap<String, String> {
    let values = ["first", "second", "lowercase"];
    order
        .into_iter()
        .map(|index| (names[index].to_owned(), values[index].to_owned()))
        .collect()
}

#[test]
fn list_variants_fold_in_key_order_with_the_wire_separator() {
    for (names, separator) in [
        (["X-Tenant", "x-TENANT", "x-tenant"], ", "),
        (["Accept", "aCCEPT", "accept"], ", "),
        (["Expect", "eXPECT", "expect"], ", "),
        (["Cookie", "cOOKIE", "cookie"], "; "),
    ] {
        for order in INSERTION_ORDERS {
            for include_lowercase in [false, true] {
                let mut headers = variant_map(names, order);
                if !include_lowercase {
                    headers.remove(names[2]);
                }
                canonicalize_request_header_map(&mut headers);
                let expected = if include_lowercase {
                    ["first", "second", "lowercase"].join(separator)
                } else {
                    ["first", "second"].join(separator)
                };
                assert_eq!(headers, HashMap::from([(names[2].to_owned(), expected)]));
                let once = headers.clone();
                canonicalize_request_header_map(&mut headers);
                assert_eq!(headers, once, "folding must be idempotent");
            }
        }
    }
}

#[test]
fn singleton_variants_prefer_lowercase_then_the_smallest_key() {
    for names in [
        ["Authorization", "aUTHORIZATION", "authorization"],
        ["Host", "hOST", "host"],
        ["Content-Type", "cONTENT-TYPE", "content-type"],
        ["Content-Length", "cONTENT-LENGTH", "content-length"],
        ["Grpc-Timeout", "gRPC-TIMEOUT", "grpc-timeout"],
        ["Traceparent", "tRACEPARENT", "traceparent"],
    ] {
        for order in INSERTION_ORDERS {
            for include_lowercase in [false, true] {
                let mut headers = variant_map(names, order);
                if !include_lowercase {
                    headers.remove(names[2]);
                }
                canonicalize_request_header_map(&mut headers);
                assert_eq!(
                    headers,
                    HashMap::from([(
                        names[2].to_owned(),
                        if include_lowercase {
                            "lowercase"
                        } else {
                            "first"
                        }
                        .to_owned(),
                    )]),
                );
            }
        }
    }
}

#[test]
fn duplicate_free_maps_keep_their_existing_storage_and_spelling() {
    let mut headers = HashMap::from([
        ("x-tenant".to_owned(), "one".to_owned()),
        ("X-Unique".to_owned(), "two".to_owned()),
    ]);
    let capacity = headers.capacity();
    let original: Vec<_> = headers
        .iter()
        .map(|(name, value)| (name.clone(), name.as_ptr(), value.as_ptr()))
        .collect();
    canonicalize_request_header_map(&mut headers);
    assert_eq!(headers.capacity(), capacity);
    for (name, key_ptr, value_ptr) in original {
        let (key, value) = headers.get_key_value(&name).unwrap();
        assert_eq!(key.as_ptr(), key_ptr);
        assert_eq!(value.as_ptr(), value_ptr);
    }
}

#[test]
fn materialization_folds_plugin_variants_even_after_the_raw_map_was_materialized() {
    for with_raw in [false, true] {
        for already_materialized in [false, true] {
            let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/".into());
            if with_raw {
                let mut raw = HeaderMap::new();
                raw.insert("x-untouched", "wire".parse().unwrap());
                ctx.set_raw_headers(raw);
            }
            if already_materialized {
                ctx.materialize_headers();
            }
            ctx.headers = variant_map(["X-Tenant", "x-TENANT", "x-tenant"], [2, 0, 1]);
            ctx.materialize_headers();
            assert_eq!(
                ctx.headers.get("x-tenant").unwrap(),
                "first, second, lowercase"
            );
            assert!(!ctx.headers.contains_key("X-Tenant"));
            assert!(!ctx.headers.contains_key("x-TENANT"));
            // A repeated materialization cannot resurrect a removed raw field.
            ctx.headers.remove("x-untouched");
            ctx.materialize_headers();
            assert!(!ctx.headers.contains_key("x-untouched"));
        }
    }
}

#[test]
fn egress_merge_folds_variants_and_preserves_unchanged_repeated_lines() {
    for order in INSERTION_ORDERS {
        let mut proxy_headers = variant_map(["X-Tenant", "x-TENANT", "x-tenant"], order);
        proxy_headers.insert("x-repeat".into(), "one, two".into());
        proxy_headers.insert("Authorization".into(), "chosen".into());
        proxy_headers.insert("aUTHORIZATION".into(), "discarded".into());
        let mut raw = HeaderMap::new();
        raw.append("x-repeat", "one".parse().unwrap());
        raw.append("x-repeat", "two".parse().unwrap());
        raw.insert("x-tenant", "pristine".parse().unwrap());
        raw.insert("authorization", "pristine".parse().unwrap());
        raw.insert("x-removed", "pristine".parse().unwrap());

        merge_proxy_headers_preserving_repeated(&mut raw, &proxy_headers);

        assert_eq!(raw["x-tenant"], "first, second, lowercase");
        assert_eq!(raw.get_all("x-tenant").iter().count(), 1);
        assert_eq!(raw["authorization"], "chosen");
        assert_eq!(raw.get_all("authorization").iter().count(), 1);
        let repeated: Vec<_> = raw
            .get_all("x-repeat")
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(repeated, ["one", "two"]);
        assert!(!raw.contains_key("x-removed"));
    }
}

#[test]
fn an_invalid_selected_singleton_cannot_resurrect_another_variant_or_raw_value() {
    let proxy_headers = HashMap::from([
        (
            "Authorization".to_owned(),
            "valid-losing-variant".to_owned(),
        ),
        ("authorization".to_owned(), "invalid\r\nvalue".to_owned()),
    ]);
    let mut raw = HeaderMap::new();
    raw.insert("authorization", "pristine".parse().unwrap());
    merge_proxy_headers_preserving_repeated(&mut raw, &proxy_headers);
    assert!(!raw.contains_key("authorization"));
}

#[test]
fn backend_refresh_and_secondary_requests_use_the_same_folded_map() {
    let ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/".into());
    let mut headers = variant_map(["X-Tenant", "x-TENANT", "x-tenant"], [1, 2, 0]);
    let secondary =
        filter_secondary_request_headers(&headers, SecondaryRequestHostPolicy::Strip, true, &[]);
    assert_eq!(
        secondary,
        [("x-tenant".to_owned(), "first, second, lowercase".to_owned())]
    );
    refresh_backend_gateway_assertion_headers(&ctx, &mut headers);
    assert_eq!(headers, secondary.into_iter().collect::<HashMap<_, _>>());
}
