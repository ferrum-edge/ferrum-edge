use ferrum_edge::plugins::compression::CompressionPlugin;
use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext};
use serde_json::json;
use std::collections::HashMap;

fn make_plugin(config: serde_json::Value) -> CompressionPlugin {
    CompressionPlugin::new(&config).unwrap()
}

fn make_ctx(accept_encoding: Option<&str>) -> RequestContext {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/test".to_string(),
    );
    if let Some(ae) = accept_encoding {
        ctx.headers
            .insert("accept-encoding".to_string(), ae.to_string());
    }
    ctx
}

// ────────────────────── Config defaults ──────────────────────

#[test]
fn test_default_config() {
    let plugin = make_plugin(json!({}));
    assert_eq!(plugin.name(), "compression");
    assert_eq!(
        plugin.priority(),
        ferrum_edge::plugins::priority::COMPRESSION
    );
    assert!(plugin.requires_response_body_buffering());
    assert!(!plugin.modifies_request_body()); // decompress_request defaults false
}

#[test]
fn test_decompress_request_config() {
    let plugin = make_plugin(json!({"decompress_request": true}));
    assert!(plugin.modifies_request_body());
    assert!(plugin.modifies_request_headers());
}

// ────────────────────── Accept-Encoding negotiation ──────────────────────

#[tokio::test]
async fn test_selects_gzip_from_accept_encoding() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_ctx(Some("gzip"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), "1000".to_string());

    let result = plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(resp_headers.get("content-encoding").unwrap(), "gzip");
    assert_eq!(resp_headers.get("vary").unwrap(), "Accept-Encoding");
    assert!(!resp_headers.contains_key("content-length")); // removed
}

#[tokio::test]
async fn test_selects_brotli_from_accept_encoding() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_ctx(Some("br"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "text/html".to_string());
    resp_headers.insert("content-length".to_string(), "5000".to_string());

    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    assert_eq!(resp_headers.get("content-encoding").unwrap(), "br");
}

#[tokio::test]
async fn test_prefers_higher_quality_algorithm() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_ctx(Some("gzip;q=0.5, br;q=1.0"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), "1000".to_string());

    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    assert_eq!(resp_headers.get("content-encoding").unwrap(), "br");
}

#[tokio::test]
async fn test_server_preference_breaks_ties() {
    // gzip is first in default config, so it wins on tie
    let plugin = make_plugin(json!({}));
    let mut ctx = make_ctx(Some("gzip, br"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), "1000".to_string());

    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    assert_eq!(resp_headers.get("content-encoding").unwrap(), "gzip");

    // Now with brotli first in config
    let plugin = make_plugin(json!({"algorithms": ["br", "gzip"]}));
    let mut ctx = make_ctx(Some("gzip, br"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), "1000".to_string());

    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    assert_eq!(resp_headers.get("content-encoding").unwrap(), "br");
}

#[tokio::test]
async fn test_wildcard_accept_encoding() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_ctx(Some("*"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), "1000".to_string());

    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    // Should pick first configured algorithm (gzip by default)
    assert_eq!(resp_headers.get("content-encoding").unwrap(), "gzip");
}

#[tokio::test]
async fn test_q_zero_rejects_algorithm() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_ctx(Some("gzip;q=0, br"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), "1000".to_string());

    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    assert_eq!(resp_headers.get("content-encoding").unwrap(), "br");
}

// ────────────────────── Skip conditions ──────────────────────

#[tokio::test]
async fn test_skips_204_no_content() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_ctx(Some("gzip"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());

    plugin.after_proxy(&mut ctx, 204, &mut resp_headers).await;
    assert!(!resp_headers.contains_key("content-encoding"));
}

#[tokio::test]
async fn test_skips_304_not_modified() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_ctx(Some("gzip"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());

    plugin.after_proxy(&mut ctx, 304, &mut resp_headers).await;
    assert!(!resp_headers.contains_key("content-encoding"));
}

#[tokio::test]
async fn test_skips_already_compressed() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_ctx(Some("gzip"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-encoding".to_string(), "br".to_string());

    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    // Should keep existing content-encoding, not overwrite
    assert_eq!(resp_headers.get("content-encoding").unwrap(), "br");
}

#[tokio::test]
async fn test_skips_non_compressible_content_type() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_ctx(Some("gzip"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "image/png".to_string());
    resp_headers.insert("content-length".to_string(), "5000".to_string());

    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    assert!(!resp_headers.contains_key("content-encoding"));
}

#[tokio::test]
async fn test_skips_below_min_content_length() {
    let plugin = make_plugin(json!({"min_content_length": 1000}));
    let mut ctx = make_ctx(Some("gzip"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), "500".to_string());

    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    assert!(!resp_headers.contains_key("content-encoding"));
}

#[tokio::test]
async fn test_skips_etag_when_disable_on_etag() {
    let plugin = make_plugin(json!({"disable_on_etag": true}));
    let mut ctx = make_ctx(Some("gzip"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), "1000".to_string());
    resp_headers.insert("etag".to_string(), "\"abc123\"".to_string());

    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    assert!(!resp_headers.contains_key("content-encoding"));
}

#[tokio::test]
async fn test_allows_etag_when_disable_on_etag_false() {
    let plugin = make_plugin(json!({"disable_on_etag": false}));
    let mut ctx = make_ctx(Some("gzip"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), "1000".to_string());
    resp_headers.insert("etag".to_string(), "\"abc123\"".to_string());

    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    assert_eq!(resp_headers.get("content-encoding").unwrap(), "gzip");
}

#[tokio::test]
async fn test_skips_no_accept_encoding() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_ctx(None);
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), "1000".to_string());

    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    assert!(!resp_headers.contains_key("content-encoding"));
}

// ────────────────────── Vary header ──────────────────────

#[tokio::test]
async fn test_vary_header_appended_to_existing() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_ctx(Some("gzip"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), "1000".to_string());
    resp_headers.insert("vary".to_string(), "Origin".to_string());

    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    assert_eq!(resp_headers.get("vary").unwrap(), "Origin, Accept-Encoding");
}

#[tokio::test]
async fn test_vary_header_not_duplicated() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_ctx(Some("gzip"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), "1000".to_string());
    resp_headers.insert("vary".to_string(), "Accept-Encoding".to_string());

    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    assert_eq!(resp_headers.get("vary").unwrap(), "Accept-Encoding");
}

// ────────────────────── Remove Accept-Encoding ──────────────────────

#[tokio::test]
async fn test_removes_accept_encoding_from_backend_request() {
    let plugin = make_plugin(json!({"remove_accept_encoding": true}));
    let mut ctx = make_ctx(Some("gzip, br"));
    let mut headers = HashMap::new();
    headers.insert("accept-encoding".to_string(), "gzip, br".to_string());

    plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(!headers.contains_key("accept-encoding"));
    // But the original is saved in metadata for after_proxy
    assert!(ctx.metadata.contains_key("compression:accept_encoding"));
}

#[tokio::test]
async fn test_preserves_accept_encoding_when_disabled() {
    let plugin = make_plugin(json!({"remove_accept_encoding": false}));
    let mut ctx = make_ctx(Some("gzip"));
    let mut headers = HashMap::new();
    headers.insert("accept-encoding".to_string(), "gzip".to_string());

    plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(headers.contains_key("accept-encoding"));
}

// ────────────────────── Response compression (gzip) ──────────────────────

#[tokio::test]
async fn test_gzip_response_compression_roundtrip() {
    let plugin = make_plugin(json!({"min_content_length": 10}));

    // Use a repetitive body large enough that gzip overhead is worthwhile
    let original = r#"{"users":[{"name":"alice","email":"alice@example.com","role":"admin"},{"name":"bob","email":"bob@example.com","role":"user"},{"name":"charlie","email":"charlie@example.com","role":"user"},{"name":"dave","email":"dave@example.com","role":"moderator"},{"name":"eve","email":"eve@example.com","role":"user"},{"name":"frank","email":"frank@example.com","role":"admin"},{"name":"grace","email":"grace@example.com","role":"user"},{"name":"heidi","email":"heidi@example.com","role":"user"}]}"#.as_bytes();

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-encoding".to_string(), "gzip".to_string());

    let compressed = plugin
        .transform_response_body(original, Some("application/json"), &resp_headers)
        .await
        .expect("should compress");

    assert!(compressed.len() < original.len());

    // Verify it decompresses back to original
    use flate2::read::GzDecoder;
    use std::io::Read;
    let mut decoder = GzDecoder::new(&compressed[..]);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed).unwrap();
    assert_eq!(decompressed, original);
}

// ────────────────────── Response compression (brotli) ──────────────────────

#[tokio::test]
async fn test_brotli_response_compression_roundtrip() {
    let plugin = make_plugin(json!({"min_content_length": 10}));

    let original = b"Hello, this is a test body that should be compressed with brotli encoding!";

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-encoding".to_string(), "br".to_string());

    let compressed = plugin
        .transform_response_body(original, Some("text/html"), &resp_headers)
        .await
        .expect("should compress");

    assert!(compressed.len() < original.len());

    // Verify it decompresses back to original
    let mut decompressed = Vec::new();
    brotli::BrotliDecompress(&mut &compressed[..], &mut decompressed).unwrap();
    assert_eq!(decompressed, original);
}

// ────────────────────── Response: skip tiny bodies in transform ──────────

#[tokio::test]
async fn test_skips_compression_for_tiny_body_in_transform() {
    let plugin = make_plugin(json!({"min_content_length": 256}));

    let tiny_body = b"small";

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-encoding".to_string(), "gzip".to_string());

    let result = plugin
        .transform_response_body(tiny_body, Some("application/json"), &resp_headers)
        .await;
    assert!(result.is_none());
}

// ────────────────────── Request decompression (gzip) ──────────────────────

#[tokio::test]
async fn test_gzip_request_decompression() {
    let plugin = make_plugin(json!({"decompress_request": true}));

    let original = b"Hello, this is a gzip-compressed request body!";

    // Compress with gzip
    use flate2::write::GzEncoder;
    use std::io::Write;
    let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(original).unwrap();
    let compressed = encoder.finish().unwrap();

    let mut headers = HashMap::new();
    headers.insert("content-encoding".to_string(), "gzip".to_string());

    let decompressed = plugin
        .transform_request_body(&compressed, Some("application/json"), &headers)
        .await
        .expect("should decompress");

    assert_eq!(decompressed, original);
}

#[tokio::test]
async fn test_before_proxy_strips_client_supplied_internal_marker() {
    // A client must not be able to inject the gateway-internal marker
    // `x-ferrum-original-content-encoding` to coerce decompression attempts
    // on plaintext bodies.
    let plugin = make_plugin(json!({"decompress_request": true}));
    let mut ctx = make_ctx(None);
    let mut headers = HashMap::new();
    headers.insert(
        "x-ferrum-original-content-encoding".to_string(),
        "gzip".to_string(),
    );

    plugin.before_proxy(&mut ctx, &mut headers).await;

    assert!(
        !headers.contains_key("x-ferrum-original-content-encoding"),
        "client-supplied internal marker must be stripped"
    );
    assert!(
        !ctx.metadata.contains_key("compression:request_encoding"),
        "no real content-encoding was present; metadata must not be set"
    );

    // transform_request_body should NOT attempt decompression on a plaintext
    // body when only the client-supplied marker was present (now removed).
    let result = plugin
        .transform_request_body(b"plaintext body", Some("application/json"), &headers)
        .await;
    assert!(result.is_none());
}

// ────────────────────── Request decompression (brotli) ──────────────────────

#[tokio::test]
async fn test_brotli_request_decompression() {
    let plugin = make_plugin(json!({"decompress_request": true}));

    let original = b"Hello, this is a brotli-compressed request body!";

    // Compress with brotli
    let mut compressed = Vec::new();
    let params = brotli::enc::BrotliEncoderParams::default();
    brotli::BrotliCompress(&mut &original[..], &mut compressed, &params).unwrap();

    let mut headers = HashMap::new();
    headers.insert("content-encoding".to_string(), "br".to_string());

    let decompressed = plugin
        .transform_request_body(&compressed, Some("application/json"), &headers)
        .await
        .expect("should decompress");

    assert_eq!(decompressed, original);
}

#[tokio::test]
async fn test_request_decompression_disabled_by_default() {
    let plugin = make_plugin(json!({})); // decompress_request defaults false

    let mut headers = HashMap::new();
    headers.insert("content-encoding".to_string(), "gzip".to_string());

    let result = plugin
        .transform_request_body(b"some compressed data", Some("application/json"), &headers)
        .await;
    assert!(result.is_none());
}

#[tokio::test]
async fn test_request_decompression_zip_bomb_protection() {
    let plugin = make_plugin(json!({
        "decompress_request": true,
        "max_decompressed_request_size": 100
    }));

    // Create a gzip payload that decompresses to > 100 bytes
    use flate2::write::GzEncoder;
    use std::io::Write;
    let big_body = vec![b'A'; 200];
    let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&big_body).unwrap();
    let compressed = encoder.finish().unwrap();

    let mut headers = HashMap::new();
    headers.insert("content-encoding".to_string(), "gzip".to_string());

    // Should fail (return None) due to size limit
    let result = plugin
        .transform_request_body(&compressed, Some("application/json"), &headers)
        .await;
    assert!(result.is_none());
}

// ────────────────────── Content type matching ──────────────────────

#[tokio::test]
async fn test_content_type_with_charset() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_ctx(Some("gzip"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert(
        "content-type".to_string(),
        "application/json; charset=utf-8".to_string(),
    );
    resp_headers.insert("content-length".to_string(), "1000".to_string());

    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    assert_eq!(resp_headers.get("content-encoding").unwrap(), "gzip");
}

#[tokio::test]
async fn test_custom_content_types() {
    let plugin = make_plugin(json!({
        "content_types": ["application/vnd.api+json", "text/csv"]
    }));
    let mut ctx = make_ctx(Some("gzip"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    // Standard JSON should NOT match custom whitelist
    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), "1000".to_string());

    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    assert!(!resp_headers.contains_key("content-encoding"));

    // Custom type should match
    let mut ctx = make_ctx(Some("gzip"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert(
        "content-type".to_string(),
        "application/vnd.api+json".to_string(),
    );
    resp_headers.insert("content-length".to_string(), "1000".to_string());

    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    assert_eq!(resp_headers.get("content-encoding").unwrap(), "gzip");
}

// ────────────────────── before_proxy: request decompression header cleanup ─

#[tokio::test]
async fn test_before_proxy_strips_content_encoding_for_decompression() {
    let plugin = make_plugin(json!({"decompress_request": true}));
    let mut ctx = make_ctx(Some("gzip"));
    let mut headers = HashMap::new();
    headers.insert("content-encoding".to_string(), "gzip".to_string());
    headers.insert("content-length".to_string(), "42".to_string());

    plugin.before_proxy(&mut ctx, &mut headers).await;

    assert!(!headers.contains_key("content-encoding"));
    assert!(!headers.contains_key("content-length"));
    assert_eq!(
        ctx.metadata.get("compression:request_encoding").unwrap(),
        "gzip"
    );
}

// ────────────────────── End-to-end: full lifecycle ──────────────────────

#[tokio::test]
async fn test_full_response_compression_lifecycle_gzip() {
    let plugin = make_plugin(json!({"min_content_length": 10}));
    let mut ctx = make_ctx(Some("gzip, br;q=0.8"));

    // before_proxy: save Accept-Encoding, strip from backend request
    let mut proxy_headers = HashMap::new();
    proxy_headers.insert("accept-encoding".to_string(), "gzip, br;q=0.8".to_string());
    plugin.before_proxy(&mut ctx, &mut proxy_headers).await;
    assert!(!proxy_headers.contains_key("accept-encoding"));

    // after_proxy: negotiate algorithm, set response headers
    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), "5000".to_string());
    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    assert_eq!(resp_headers.get("content-encoding").unwrap(), "gzip");

    // transform_response_body: compress
    let body = br#"{"users":[{"name":"alice","email":"alice@example.com","role":"admin"},{"name":"bob","email":"bob@example.com","role":"user"},{"name":"charlie","email":"charlie@example.com","role":"user"},{"name":"dave","email":"dave@example.com","role":"moderator"},{"name":"eve","email":"eve@example.com","role":"user"},{"name":"frank","email":"frank@example.com","role":"admin"},{"name":"grace","email":"grace@example.com","role":"user"},{"name":"heidi","email":"heidi@example.com","role":"user"}]}"#;
    let compressed = plugin
        .transform_response_body(body, Some("application/json"), &resp_headers)
        .await
        .expect("should compress");
    assert!(compressed.len() < body.len());

    // Verify roundtrip
    use flate2::read::GzDecoder;
    use std::io::Read;
    let mut decoder = GzDecoder::new(&compressed[..]);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed).unwrap();
    assert_eq!(decompressed, body);
}

// ────────────────────── should_buffer_request_body ──────────────────────

#[test]
fn test_should_buffer_only_when_content_encoding_present() {
    let plugin = make_plugin(json!({"decompress_request": true}));

    let ctx_with_ce = {
        let mut ctx = make_ctx(None);
        ctx.headers
            .insert("content-encoding".to_string(), "gzip".to_string());
        ctx
    };
    assert!(plugin.should_buffer_request_body(&ctx_with_ce));

    let ctx_without_ce = make_ctx(None);
    assert!(!plugin.should_buffer_request_body(&ctx_without_ce));
}

// ────────────────────── Algorithm-only config ──────────────────────

#[tokio::test]
async fn test_gzip_only_config() {
    let plugin = make_plugin(json!({"algorithms": ["gzip"]}));
    let mut ctx = make_ctx(Some("br, gzip"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), "1000".to_string());

    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    // Should pick gzip since brotli isn't configured
    assert_eq!(resp_headers.get("content-encoding").unwrap(), "gzip");
}

#[tokio::test]
async fn test_brotli_only_config() {
    let plugin = make_plugin(json!({"algorithms": ["br"]}));
    let mut ctx = make_ctx(Some("gzip, br"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), "1000".to_string());

    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    assert_eq!(resp_headers.get("content-encoding").unwrap(), "br");
}

#[tokio::test]
async fn test_no_matching_algorithm() {
    let plugin = make_plugin(json!({"algorithms": ["gzip"]}));
    let mut ctx = make_ctx(Some("br")); // client only wants brotli
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), "1000".to_string());

    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    assert!(!resp_headers.contains_key("content-encoding"));
}
