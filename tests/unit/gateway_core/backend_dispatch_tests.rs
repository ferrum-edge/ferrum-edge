use ferrum_edge::config::types::HttpFlavor;
use ferrum_edge::proxy::backend_dispatch::detect_http_flavor;
use http::Request;

#[test]
fn detect_http_flavor_classifies_http3_extended_connect_websocket_as_websocket() {
    let mut req = Request::builder()
        .method("CONNECT")
        .uri("https://example.com/socket")
        .version(hyper::Version::HTTP_3)
        .body(())
        .unwrap();
    req.extensions_mut()
        .insert(hyper::ext::Protocol::from_static("websocket"));

    assert_eq!(detect_http_flavor(&req), HttpFlavor::WebSocket);
}

#[test]
fn detect_http_flavor_keeps_non_websocket_http3_connect_plain() {
    let mut req = Request::builder()
        .method("CONNECT")
        .uri("https://example.com/socket")
        .version(hyper::Version::HTTP_3)
        .body(())
        .unwrap();
    req.extensions_mut()
        .insert(hyper::ext::Protocol::from_static("connect-udp"));

    assert_eq!(detect_http_flavor(&req), HttpFlavor::Plain);
}

#[test]
fn detect_http_flavor_still_classifies_http2_extended_connect_websocket_as_websocket() {
    let mut req = Request::builder()
        .method("CONNECT")
        .uri("https://example.com/socket")
        .version(hyper::Version::HTTP_2)
        .body(())
        .unwrap();
    req.extensions_mut()
        .insert(hyper::ext::Protocol::from_static("websocket"));

    assert_eq!(detect_http_flavor(&req), HttpFlavor::WebSocket);
}

// ---------------------------------------------------------------------------
// gRPC vs gRPC-Web disambiguation
//
// `application/grpc` is exactly 16 bytes, so a 16-byte prefix match would
// accept `application/grpc-web*` too. These tests nail down the byte-17
// gate that separates native gRPC (`+`/`;`/end-of-string) from gRPC-Web
// (`-`), which is a DIFFERENT wire format (trailer frame embedded in the
// body, not HTTP/2 trailers).
// ---------------------------------------------------------------------------

fn http_post(content_type: &str) -> Request<()> {
    Request::builder()
        .method("POST")
        .uri("https://example.com/pkg.Service/Method")
        .header("content-type", content_type)
        .body(())
        .unwrap()
}

#[test]
fn detect_http_flavor_classifies_native_grpc_as_grpc() {
    assert_eq!(
        detect_http_flavor(&http_post("application/grpc")),
        HttpFlavor::Grpc
    );
}

#[test]
fn detect_http_flavor_classifies_grpc_proto_variant_as_grpc() {
    assert_eq!(
        detect_http_flavor(&http_post("application/grpc+proto")),
        HttpFlavor::Grpc
    );
}

#[test]
fn detect_http_flavor_classifies_grpc_with_charset_param_as_grpc() {
    assert_eq!(
        detect_http_flavor(&http_post("application/grpc;charset=utf-8")),
        HttpFlavor::Grpc
    );
}

#[test]
fn detect_http_flavor_classifies_grpc_with_space_before_param_as_grpc() {
    // RFC 9110 allows OWS before the `;` — byte 16 is a space, not `-`.
    assert_eq!(
        detect_http_flavor(&http_post("application/grpc ;q=1")),
        HttpFlavor::Grpc
    );
}

#[test]
fn detect_http_flavor_does_not_misclassify_grpc_web_as_grpc() {
    // Regression test: a 16-byte prefix match alone would classify
    // `application/grpc-web` as Grpc. Byte 16 is `-`, so the flavor
    // must fall through to Plain — routing gRPC-Web via the native
    // gRPC backend pool would hang waiting on HTTP/2 trailers that
    // never arrive (gRPC-Web carries trailers in the body).
    assert_eq!(
        detect_http_flavor(&http_post("application/grpc-web")),
        HttpFlavor::Plain
    );
}

#[test]
fn detect_http_flavor_does_not_misclassify_grpc_web_proto_as_grpc() {
    assert_eq!(
        detect_http_flavor(&http_post("application/grpc-web+proto")),
        HttpFlavor::Plain
    );
}

#[test]
fn detect_http_flavor_does_not_misclassify_grpc_web_text_as_grpc() {
    assert_eq!(
        detect_http_flavor(&http_post("application/grpc-web-text")),
        HttpFlavor::Plain
    );
}

#[test]
fn detect_http_flavor_does_not_misclassify_grpc_web_text_proto_as_grpc() {
    assert_eq!(
        detect_http_flavor(&http_post("application/grpc-web-text+proto")),
        HttpFlavor::Plain
    );
}

#[test]
fn detect_http_flavor_treats_grpc_web_case_insensitively() {
    assert_eq!(
        detect_http_flavor(&http_post("Application/GRPC-Web+PROTO")),
        HttpFlavor::Plain
    );
}

#[test]
fn detect_http_flavor_treats_native_grpc_case_insensitively() {
    assert_eq!(
        detect_http_flavor(&http_post("Application/GRPC+Proto")),
        HttpFlavor::Grpc
    );
}

#[test]
fn detect_http_flavor_non_grpc_content_type_is_plain() {
    assert_eq!(
        detect_http_flavor(&http_post("application/json")),
        HttpFlavor::Plain
    );
    assert_eq!(
        detect_http_flavor(&http_post("text/plain")),
        HttpFlavor::Plain
    );
}
