//! Allocation/share-identity coverage for cached synthetic rejection bodies.
//!
//! Cached producers retain immutable `Bytes`. Rejection normalization must keep
//! that shared storage across the synthetic boundary and into the final
//! client-visible body unless a later response-body transform truly mutates.

use bytes::Bytes;
use ferrum_edge::_test_support::{
    finalize_plugin_rejection_without_committed_hooks_for_test,
    finalize_synthetic_response_for_test,
};
use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext};
use std::collections::HashMap;
use std::sync::Arc;

fn large_cached_body() -> Bytes {
    // Large enough that an accidental per-hit `to_vec()` would be obvious in
    // share-identity checks, without relying on global allocator hooks.
    Bytes::from(vec![0x5au8; 256 * 1024])
}

fn binary_headers() -> HashMap<String, String> {
    HashMap::from([(
        "content-type".to_string(),
        "application/octet-stream".to_string(),
    )])
}

#[tokio::test]
async fn reject_normalization_shares_cached_bytes_without_copy() {
    let cached = large_cached_body();
    let cached_ptr = cached.as_ptr() as usize;
    let mut ctx = RequestContext::new(
        "203.0.113.10".to_string(),
        "GET".to_string(),
        "/specz".into(),
    );
    let rejection = PluginResult::RejectBinary {
        status_code: 200,
        body: cached.clone(),
        headers: binary_headers(),
    };

    let finalized =
        finalize_plugin_rejection_without_committed_hooks_for_test(&[], &mut ctx, rejection).await;

    match finalized {
        PluginResult::RejectBinary {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 200);
            assert_eq!(body.len(), cached.len());
            assert_eq!(
                body.as_ptr() as usize,
                cached_ptr,
                "ordinary cached synthetic hits must share the retained Bytes allocation"
            );
        }
        other => panic!("expected RejectBinary, got {other:?}"),
    }
}

#[tokio::test]
async fn concurrent_cached_hits_share_one_retained_allocation() {
    let cached = large_cached_body();
    let cached_ptr = cached.as_ptr() as usize;
    let mut joins = Vec::new();
    for _ in 0..8 {
        let body = cached.clone();
        joins.push(tokio::spawn(async move {
            let mut ctx = RequestContext::new(
                "203.0.113.10".to_string(),
                "GET".to_string(),
                "/cached".into(),
            );
            let rejection = PluginResult::RejectBinary {
                status_code: 200,
                body,
                headers: binary_headers(),
            };
            let finalized = finalize_plugin_rejection_without_committed_hooks_for_test(
                &[],
                &mut ctx,
                rejection,
            )
            .await;
            match finalized {
                PluginResult::RejectBinary { body, .. } => body.as_ptr() as usize,
                other => panic!("expected RejectBinary, got {other:?}"),
            }
        }));
    }

    for join in joins {
        let ptr = join.await.expect("task join");
        assert_eq!(ptr, cached_ptr);
    }
}

struct RewriteBodyPlugin;

#[async_trait::async_trait]
impl Plugin for RewriteBodyPlugin {
    /// Test producer: declares the bounded-construction contract so the
    /// buffered phases reserve a window for it (GHSA-pwcm-6rh8-f2gh).
    fn response_body_production(&self) -> ferrum_edge::plugins::ResponseBodyProduction {
        ferrum_edge::plugins::ResponseBodyProduction::BoundedByRetainedCeiling
    }
    fn name(&self) -> &str {
        "test_rewrite_body"
    }

    fn requires_response_body_buffering(&self) -> bool {
        true
    }

    fn should_buffer_response_body(&self, _ctx: &RequestContext) -> bool {
        true
    }

    async fn transform_response_body(
        &self,
        body: &[u8],
        _content_type: Option<&str>,
        _response_headers: &HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        let mut rewritten = body.to_vec();
        rewritten.extend_from_slice(b"|rewritten");
        Some(rewritten)
    }
}

#[tokio::test]
async fn transform_composition_copies_only_on_write() {
    let cached = large_cached_body();
    let cached_ptr = cached.as_ptr() as usize;
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(RewriteBodyPlugin)];
    let mut ctx = RequestContext::new("203.0.113.10".to_string(), "GET".to_string(), "/api".into());
    let mut status = 200u16;
    let mut headers = binary_headers();
    let mut body = cached.clone();

    finalize_synthetic_response_for_test(&plugins, &mut ctx, &mut status, &mut headers, &mut body)
        .await;

    assert_eq!(status, 200);
    assert!(body.ends_with(b"|rewritten"));
    assert_ne!(
        body.as_ptr() as usize,
        cached_ptr,
        "a mutating transform must take ownership / copy-on-write rather than mutating shared cache storage"
    );
    // Cached producer retention stays intact for later hits.
    assert_eq!(cached.as_ptr() as usize, cached_ptr);
    assert_eq!(cached.len(), 256 * 1024);
}

#[tokio::test]
async fn head_no_body_finalization_drops_shared_body_bytes() {
    let cached = large_cached_body();
    let mut ctx = RequestContext::new(
        "203.0.113.10".to_string(),
        "HEAD".to_string(),
        "/specz".into(),
    );
    let mut status = 200u16;
    let mut headers = binary_headers();
    headers.insert("content-length".to_string(), cached.len().to_string());
    let mut body = cached.clone();

    finalize_synthetic_response_for_test(&[], &mut ctx, &mut status, &mut headers, &mut body).await;

    assert!(body.is_empty(), "HEAD must omit content bytes");
    assert_eq!(
        headers.get("content-length").map(String::as_str),
        Some((256 * 1024).to_string().as_str()),
        "HEAD keeps representation Content-Length"
    );
}

#[tokio::test]
async fn status_204_no_body_finalization_strips_length_and_bytes() {
    let cached = large_cached_body();
    let mut ctx = RequestContext::new(
        "203.0.113.10".to_string(),
        "GET".to_string(),
        "/empty".into(),
    );
    let mut status = 204u16;
    let mut headers = binary_headers();
    headers.insert("content-length".to_string(), cached.len().to_string());
    let mut body = cached.clone();

    finalize_synthetic_response_for_test(&[], &mut ctx, &mut status, &mut headers, &mut body).await;

    assert!(body.is_empty());
    assert!(
        !headers
            .keys()
            .any(|name| name.eq_ignore_ascii_case("content-length")),
        "204 must drop Content-Length"
    );
}

#[test]
fn reject_parts_preserve_reject_binary_bytes_without_to_vec() {
    let src = include_str!("../../../src/proxy/mod.rs");
    let start = src
        .find("pub(crate) fn plugin_result_into_reject_parts(")
        .expect("shared reject normalizer must remain present");
    let body = &src[start..];
    let end = body
        .find("\nfn reject_result_to_backend_response(")
        .or_else(|| body.find("\npub(crate) fn reject_result_to_backend_response("))
        .unwrap_or(800);
    let fn_src = &body[..end];
    assert!(
        fn_src.contains("PluginResult::RejectBinary"),
        "RejectBinary arm must remain in the shared normalizer"
    );
    assert!(
        !fn_src.contains("body.to_vec()"),
        "RejectBinary must not force a per-hit Vec copy at the rejection boundary"
    );
    assert!(
        fn_src.contains("body,"),
        "RejectBinary body must move/share Bytes through RejectedResponseParts"
    );
}

#[test]
fn shared_finalizer_and_protocols_keep_bytes_no_body_drop() {
    let proxy_src = include_str!("../../../src/proxy/mod.rs");
    let h3_src = include_str!("../../../src/http3/server.rs");
    let finalizer_start = proxy_src
        .find("pub(crate) async fn apply_reject_after_proxy_and_synthetic_body_hooks(")
        .expect("shared reject finalizer must remain present");
    let finalizer = &proxy_src[finalizer_start..];
    let finalizer_end = finalizer
        .find("pub(crate) struct AfterProxyReject")
        .expect("shared reject finalizer boundary must remain present");
    let finalizer = &finalizer[..finalizer_end];
    assert!(
        finalizer.contains("*body = Bytes::new();"),
        "HEAD/204/205/304 finalization must drop shared body bytes with Bytes::new()"
    );
    assert!(
        !finalizer.contains("body.clear();"),
        "no-body finalization must not clear-in-place and retain capacity"
    );
    assert!(
        h3_src.contains("reject.body = Bytes::new();"),
        "H3 streaming after_proxy rejects must use the same Bytes capacity drop"
    );
    assert!(
        include_str!("../../../src/retry.rs").contains("Buffered(Bytes)"),
        "buffered responses must retain Bytes so cached synthetic delivery stays shareable"
    );
}

#[test]
fn cached_producers_return_reject_binary_bytes_clones() {
    // The four producers named by GHSA-5fp3-pp5p-c4gh must keep returning
    // `RejectBinary` with a cheap `Bytes` clone — never a forced `to_vec()` of
    // the retained entry — so the shared normalizer can share storage.
    for (path, markers) in [
        (
            include_str!("../../../src/plugins/spec_expose.rs"),
            &["PluginResult::RejectBinary {", "body:"][..],
        ),
        (
            include_str!("../../../src/plugins/response_caching.rs"),
            &["PluginResult::RejectBinary {", "body: entry.body.clone()"][..],
        ),
        (
            include_str!("../../../src/plugins/request_deduplication.rs"),
            &["PluginResult::RejectBinary {", "body: cached.body.clone()"][..],
        ),
        (
            include_str!("../../../src/plugins/ai_semantic_cache.rs"),
            &["PluginResult::RejectBinary {", "body: entry.body.clone()"][..],
        ),
    ] {
        for marker in markers {
            assert!(
                path.contains(marker),
                "cached synthetic producer must keep Bytes reject surface ({marker})"
            );
        }
    }

    // Local and Redis replay/hit arms must both remain Bytes-clone based.
    let dedup = include_str!("../../../src/plugins/request_deduplication.rs");
    assert!(
        dedup.matches("body: cached.body.clone()").count() >= 1,
        "request_deduplication local/Redis replay must clone retained Bytes"
    );
    let semantic = include_str!("../../../src/plugins/ai_semantic_cache.rs");
    assert!(
        semantic.matches("body: entry.body.clone()").count() >= 2,
        "ai_semantic_cache local and Redis hits must clone retained Bytes"
    );
}

#[tokio::test]
async fn slow_client_retains_shared_handle_while_peers_replay() {
    let cached = large_cached_body();
    let cached_ptr = cached.as_ptr() as usize;

    // Simulate a slow recipient holding its response Bytes while other hits
    // continue to share the same retained allocation.
    let mut slow_ctx = RequestContext::new(
        "203.0.113.10".to_string(),
        "GET".to_string(),
        "/slow".into(),
    );
    let slow = finalize_plugin_rejection_without_committed_hooks_for_test(
        &[],
        &mut slow_ctx,
        PluginResult::RejectBinary {
            status_code: 200,
            body: cached.clone(),
            headers: binary_headers(),
        },
    )
    .await;
    let PluginResult::RejectBinary {
        body: slow_body, ..
    } = slow
    else {
        panic!("expected RejectBinary");
    };
    assert_eq!(slow_body.as_ptr() as usize, cached_ptr);

    for _ in 0..4 {
        let mut ctx = RequestContext::new(
            "203.0.113.11".to_string(),
            "GET".to_string(),
            "/peer".into(),
        );
        let peer = finalize_plugin_rejection_without_committed_hooks_for_test(
            &[],
            &mut ctx,
            PluginResult::RejectBinary {
                status_code: 200,
                body: cached.clone(),
                headers: binary_headers(),
            },
        )
        .await;
        let PluginResult::RejectBinary { body, .. } = peer else {
            panic!("expected RejectBinary");
        };
        assert_eq!(body.as_ptr() as usize, cached_ptr);
    }

    // Slow client still holds the shared allocation.
    assert_eq!(slow_body.as_ptr() as usize, cached_ptr);
    assert_eq!(slow_body.len(), cached.len());
}
