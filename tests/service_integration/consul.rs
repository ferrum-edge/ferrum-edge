//! Consul service-discovery integration tests.
//!
//! These register service instances in a live Consul dev agent and assert that
//! [`ConsulDiscoverer::discover`] parses the real health-API output correctly —
//! the JSON-parsing path (Service-vs-Node address fallback, port/weight/tag
//! extraction, the `passing=true` health filter, per-tag filtering) that the
//! inline unit tests cannot reach because they only cover `build_url`.

use std::time::Duration;

use ferrum_edge::config::types::UpstreamTarget;
use ferrum_edge::service_discovery::ServiceDiscoverer;
use ferrum_edge::service_discovery::consul::ConsulDiscoverer;
use serde_json::json;

use crate::common::containers::{
    ConsulContainer, fail_in_ci_else_skip, start_consul_dev_container,
};

/// Start Consul or self-skip (locally) / hard-fail (CI).
async fn consul(test: &str) -> Option<ConsulContainer> {
    match start_consul_dev_container().await {
        Ok(c) => Some(c),
        Err(e) => {
            fail_in_ci_else_skip(test, "Consul", &e);
            None
        }
    }
}

fn discoverer(
    addr: &str,
    service: &str,
    tag: Option<&str>,
    healthy_only: bool,
) -> ConsulDiscoverer {
    ConsulDiscoverer::new(
        reqwest::Client::new(),
        addr.to_string(),
        service.to_string(),
        None, // datacenter
        tag.map(str::to_string),
        healthy_only,
        None, // ACL token
        1,    // default weight
    )
}

/// Poll `discover()` until at least `min` targets appear (catalog propagation
/// after registration is near-instant in dev mode, but allow a brief window).
async fn discover_eventually(d: &ConsulDiscoverer, min: usize) -> Vec<UpstreamTarget> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let past = tokio::time::Instant::now() >= deadline;
        match d.discover().await {
            Ok(t) if t.len() >= min || past => return t.targets().to_vec(),
            Err(_) if past => return Vec::new(),
            _ => tokio::time::sleep(Duration::from_millis(200)).await,
        }
    }
}

#[tokio::test]
async fn consul_discovers_service_with_explicit_address_weight_and_tags() {
    let Some(consul) =
        consul("consul_discovers_service_with_explicit_address_weight_and_tags").await
    else {
        return;
    };

    consul
        .register_service(json!({
            "ID": "web-1",
            "Name": "web",
            "Address": "10.10.0.5",
            "Port": 8080,
            "Tags": ["v1", "canary"],
            "Weights": { "Passing": 3, "Warning": 1 }
        }))
        .await
        .expect("register web");

    let d = discoverer(&consul.addr, "web", None, false);
    let targets = discover_eventually(&d, 1).await;

    assert_eq!(targets.len(), 1, "expected one instance, got {targets:?}");
    let t = &targets[0];
    assert_eq!(t.host, "10.10.0.5");
    assert_eq!(t.port, 8080);
    // Consul service weight (Passing) overrides the discoverer default.
    assert_eq!(t.weight, 3);
    assert_eq!(t.tags.get("consul_tag_0").map(String::as_str), Some("v1"));
    assert_eq!(
        t.tags.get("consul_tag_1").map(String::as_str),
        Some("canary")
    );
}

#[tokio::test]
async fn consul_falls_back_to_node_address_when_service_address_empty() {
    let Some(consul) = consul("consul_falls_back_to_node_address_when_service_address_empty").await
    else {
        return;
    };

    // No explicit Address → Service.Address is empty in the health response and
    // the discoverer must fall back to the Node address.
    consul
        .register_service(json!({ "ID": "api-1", "Name": "api", "Port": 9090 }))
        .await
        .expect("register api");

    let d = discoverer(&consul.addr, "api", None, false);
    let targets = discover_eventually(&d, 1).await;

    assert_eq!(targets.len(), 1, "expected one instance, got {targets:?}");
    let t = &targets[0];
    assert!(
        !t.host.is_empty(),
        "node-address fallback should yield a non-empty host, got {t:?}"
    );
    assert_eq!(t.port, 9090);
    // No Weights registered → discoverer default (1) applies.
    assert_eq!(t.weight, 1);
}

#[tokio::test]
async fn consul_healthy_only_returns_checkless_passing_instance() {
    let Some(consul) = consul("consul_healthy_only_returns_checkless_passing_instance").await
    else {
        return;
    };

    // A service with no health checks is treated as passing by Consul, so the
    // `passing=true` filter (healthy_only) must still return it.
    consul
        .register_service(json!({
            "ID": "svc-1",
            "Name": "svc",
            "Address": "10.0.0.9",
            "Port": 80
        }))
        .await
        .expect("register svc");

    let d = discoverer(&consul.addr, "svc", None, true);
    let targets = discover_eventually(&d, 1).await;

    assert_eq!(
        targets.len(),
        1,
        "expected one passing instance, got {targets:?}"
    );
    assert_eq!(targets[0].host, "10.0.0.9");
}

#[tokio::test]
async fn consul_filters_instances_by_tag() {
    let Some(consul) = consul("consul_filters_instances_by_tag").await else {
        return;
    };

    consul
        .register_service(json!({
            "ID": "multi-blue",
            "Name": "multi",
            "Address": "10.0.0.1",
            "Port": 1,
            "Tags": ["blue"]
        }))
        .await
        .expect("register blue");
    consul
        .register_service(json!({
            "ID": "multi-green",
            "Name": "multi",
            "Address": "10.0.0.2",
            "Port": 2,
            "Tags": ["green"]
        }))
        .await
        .expect("register green");

    // Without a tag filter both instances are visible.
    let all = discoverer(&consul.addr, "multi", None, false);
    let all_targets = discover_eventually(&all, 2).await;
    assert_eq!(
        all_targets.len(),
        2,
        "expected both instances, got {all_targets:?}"
    );

    // The `tag=green` query parameter must narrow it to one.
    let green = discoverer(&consul.addr, "multi", Some("green"), false);
    let green_targets = discover_eventually(&green, 1).await;
    assert_eq!(
        green_targets.len(),
        1,
        "expected only green, got {green_targets:?}"
    );
    assert_eq!(green_targets[0].host, "10.0.0.2");
    assert_eq!(green_targets[0].port, 2);
}

#[tokio::test]
async fn consul_unknown_service_returns_empty() {
    let Some(consul) = consul("consul_unknown_service_returns_empty").await else {
        return;
    };

    let d = discoverer(&consul.addr, "does-not-exist", None, false);
    let targets = d
        .discover()
        .await
        .expect("discover should succeed with empty result");
    assert!(targets.is_empty(), "expected no targets, got {targets:?}");
}
