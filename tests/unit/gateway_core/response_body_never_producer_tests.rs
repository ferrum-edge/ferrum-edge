//! Issue #6289 — `ResponseBodyProduction::Never` is a PER-PLUGIN contract.
//!
//! Both buffered producer phases (`normalize_response_body_for_inspection` and
//! the buffered response transform phase) open ONE retained-response window
//! when any chain member may produce. A plugin that declared `Never` but
//! returns `Some` anyway must be refused even when a producing peer opened that
//! window and the replacement would fit inside it: nothing was reserved on its
//! account. These tests drive the real sinks with mixed declarations, plus the
//! pure-Never and valid bounded-producer controls.

use std::collections::HashMap;
use std::sync::Arc;

use ferrum_edge::_test_support::{
    RESPONSE_BUFFER_OVERLOAD_BODY, RESPONSE_BUFFER_OVERLOAD_STATUS,
    gateway_capacity_response_selected_for_test, stamp_original_response_metadata_for_test,
    transform_buffered_response_body_with_deadline_full_for_test,
};
use ferrum_edge::plugins::{Plugin, RequestContext, ResponseBodyProduction};

const BACKEND_BODY: &[u8] = b"backend representation";
const NEVER_REPLACEMENT: &[u8] = b"never";
const BOUNDED_REPLACEMENT: &[u8] = b"bounded";

/// Declares `Never` but returns a small replacement from both producer hooks —
/// the contract-breaking custom override the issue describes.
struct NeverButProduces;

#[async_trait::async_trait]
impl Plugin for NeverButProduces {
    fn name(&self) -> &str {
        "never_but_produces"
    }

    fn response_body_production(&self) -> ResponseBodyProduction {
        ResponseBodyProduction::Never
    }

    async fn normalize_response_body_with_context(
        &self,
        _ctx: &mut RequestContext,
        _response_status: u16,
        _body: &[u8],
        _content_type: Option<&str>,
        _response_headers: &HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        Some(NEVER_REPLACEMENT.to_vec())
    }

    async fn transform_response_body_with_context(
        &self,
        _ctx: &mut RequestContext,
        _body: &[u8],
        _content_type: Option<&str>,
        _response_headers: &HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        Some(NEVER_REPLACEMENT.to_vec())
    }
}

/// Declares `Never` and honours it.
struct NeverNoop;

#[async_trait::async_trait]
impl Plugin for NeverNoop {
    fn name(&self) -> &str {
        "never_noop"
    }

    fn response_body_production(&self) -> ResponseBodyProduction {
        ResponseBodyProduction::Never
    }
}

/// A declared bounded producer whose replacement fits any retained ceiling.
struct BoundedProducer;

#[async_trait::async_trait]
impl Plugin for BoundedProducer {
    fn name(&self) -> &str {
        "bounded_producer"
    }

    fn response_body_production(&self) -> ResponseBodyProduction {
        ResponseBodyProduction::BoundedByRetainedCeiling
    }

    async fn normalize_response_body_with_context(
        &self,
        _ctx: &mut RequestContext,
        _response_status: u16,
        _body: &[u8],
        _content_type: Option<&str>,
        _response_headers: &HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        Some(BOUNDED_REPLACEMENT.to_vec())
    }

    async fn transform_response_body_with_context(
        &self,
        _ctx: &mut RequestContext,
        _body: &[u8],
        _content_type: Option<&str>,
        _response_headers: &HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        Some(BOUNDED_REPLACEMENT.to_vec())
    }
}

fn make_ctx() -> RequestContext {
    RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/resource".to_string(),
    )
}

fn backend_headers() -> HashMap<String, String> {
    HashMap::from([
        ("content-type".to_string(), "text/plain".to_string()),
        ("content-length".to_string(), BACKEND_BODY.len().to_string()),
    ])
}

struct Outcome {
    status: u16,
    body: bytes::Bytes,
    capacity_terminal: bool,
}

async fn run_normalize(plugins: Vec<Arc<dyn Plugin>>) -> (bool, Outcome) {
    let mut ctx = make_ctx();
    let mut status = 200u16;
    let mut headers = backend_headers();
    let mut body = bytes::Bytes::from_static(BACKEND_BODY);
    let normalized = ferrum_edge::plugins::normalize_response_body_for_inspection(
        &plugins,
        &mut ctx,
        &mut status,
        &mut headers,
        &mut body,
        &[],
    )
    .await;
    (
        normalized,
        Outcome {
            status,
            body,
            capacity_terminal: gateway_capacity_response_selected_for_test(&ctx),
        },
    )
}

async fn run_transform(plugins: Vec<Arc<dyn Plugin>>) -> ((bool, bool), Outcome) {
    let mut ctx = make_ctx();
    let mut status = 200u16;
    let mut headers = backend_headers();
    stamp_original_response_metadata_for_test(&mut ctx, status, &headers);
    let mut body = bytes::Bytes::from_static(BACKEND_BODY);
    let result = transform_buffered_response_body_with_deadline_full_for_test(
        &plugins,
        &mut ctx,
        &mut status,
        &mut headers,
        &mut body,
        None,
        false,
    )
    .await;
    (
        result,
        Outcome {
            status,
            body,
            capacity_terminal: gateway_capacity_response_selected_for_test(&ctx),
        },
    )
}

fn assert_refused(outcome: &Outcome, context: &str) {
    assert_eq!(
        outcome.status, RESPONSE_BUFFER_OVERLOAD_STATUS,
        "{context}: a Never plugin's replacement must be refused, not installed"
    );
    assert_eq!(
        outcome.body,
        bytes::Bytes::from_static(RESPONSE_BUFFER_OVERLOAD_BODY.as_bytes()),
        "{context}: the refusal is the shared gateway capacity terminal"
    );
    assert_ne!(outcome.body.as_ref(), NEVER_REPLACEMENT);
    assert!(
        outcome.capacity_terminal,
        "{context}: the capacity terminal must be marked authoritative"
    );
}

// ---------------------------------------------------------------------------
// Normalization sink.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn normalize_refuses_a_never_replacement_after_a_producing_peer() {
    let (normalized, outcome) =
        run_normalize(vec![Arc::new(BoundedProducer), Arc::new(NeverButProduces)]).await;
    assert!(normalized);
    assert_refused(&outcome, "normalize, producer then Never");
}

#[tokio::test]
async fn normalize_refuses_a_never_replacement_ahead_of_a_producing_peer() {
    let (normalized, outcome) =
        run_normalize(vec![Arc::new(NeverButProduces), Arc::new(BoundedProducer)]).await;
    assert!(normalized);
    assert_refused(&outcome, "normalize, Never then producer");
}

#[tokio::test]
async fn normalize_refuses_a_never_replacement_in_a_pure_never_chain() {
    let (normalized, outcome) = run_normalize(vec![Arc::new(NeverButProduces)]).await;
    assert!(normalized);
    assert_refused(&outcome, "normalize, pure Never");
}

#[tokio::test]
async fn normalize_still_installs_a_bounded_peer_beside_an_honest_never_plugin() {
    for plugins in [
        vec![
            Arc::new(NeverNoop) as Arc<dyn Plugin>,
            Arc::new(BoundedProducer),
        ],
        vec![
            Arc::new(BoundedProducer) as Arc<dyn Plugin>,
            Arc::new(NeverNoop),
        ],
    ] {
        let (normalized, outcome) = run_normalize(plugins).await;
        assert!(
            normalized,
            "the bounded producer's replacement is installed"
        );
        assert_eq!(outcome.status, 200);
        assert_eq!(outcome.body.as_ref(), BOUNDED_REPLACEMENT);
        assert!(!outcome.capacity_terminal);
    }
}

// ---------------------------------------------------------------------------
// Transform sink.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn transform_refuses_a_never_replacement_after_a_producing_peer() {
    let (result, outcome) =
        run_transform(vec![Arc::new(BoundedProducer), Arc::new(NeverButProduces)]).await;
    assert_eq!(result, (true, true));
    assert_refused(&outcome, "transform, producer then Never");
}

#[tokio::test]
async fn transform_refuses_a_never_replacement_ahead_of_a_producing_peer() {
    let (result, outcome) =
        run_transform(vec![Arc::new(NeverButProduces), Arc::new(BoundedProducer)]).await;
    assert_eq!(result, (true, true));
    assert_refused(&outcome, "transform, Never then producer");
}

#[tokio::test]
async fn transform_refuses_a_never_replacement_in_a_pure_never_chain() {
    let (result, outcome) = run_transform(vec![Arc::new(NeverButProduces)]).await;
    assert_eq!(result, (true, true));
    assert_refused(&outcome, "transform, pure Never");
}

#[tokio::test]
async fn transform_still_installs_a_bounded_peer_beside_an_honest_never_plugin() {
    for plugins in [
        vec![
            Arc::new(NeverNoop) as Arc<dyn Plugin>,
            Arc::new(BoundedProducer),
        ],
        vec![
            Arc::new(BoundedProducer) as Arc<dyn Plugin>,
            Arc::new(NeverNoop),
        ],
    ] {
        let (result, outcome) = run_transform(plugins).await;
        assert_eq!(result, (false, true), "the bounded rewrite is installed");
        assert_eq!(outcome.status, 200);
        assert_eq!(outcome.body.as_ref(), BOUNDED_REPLACEMENT);
        assert!(!outcome.capacity_terminal);
    }
}
