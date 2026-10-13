//! Istio VirtualService matcher conformance.
//!
//! Each test exercises one matcher predicate type (uri / headers / method /
//! authority / sourceNamespace / ignoreUriCase / fault) by translating a minimal
//! `VirtualService` through `translate_k8s_objects` and then driving the
//! resulting `mesh_route_dispatch` (or `request_termination`) plugin to assert
//! it routes / rejects / falls through as Istio operators expect.
//!
//! Coverage decisions:
//!   - Only the canonical "happy path" per predicate gets a test — the K8s
//!     translator unit-test crate already covers the long-tail edge cases.
//!     The conformance suite proves operator-visible Istio parity exists, not
//!     that every off-by-one is correct.
//!   - Each test registers exactly one feature into the matrix. A single test
//!     covering two features would force operators to read the test body to
//!     learn which assertion proved which feature.

use std::collections::HashMap;

use ferrum_edge::config::types::PluginConfig;
use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::identity::spiffe::{SpiffeId, TrustDomain};
use ferrum_edge::plugins::mesh_route_dispatch::MeshRouteDispatch;
use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext};
use serde_json::{Value, json};

use crate::conformance::registry::{Maturity, Status};

const CATEGORY: &str = "istio_virtual_service";

fn options() -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        "default".to_string(),
        TrustDomain::new("cluster.local").expect("test trust domain"),
    )
}

fn virtual_service(spec: Value) -> K8sObject {
    K8sObject {
        api_version: "networking.istio.io/v1beta1".to_string(),
        kind: "VirtualService".to_string(),
        metadata: K8sMetadata {
            name: "vs-under-test".to_string(),
            namespace: "default".to_string(),
            ..K8sMetadata::default()
        },
        spec,
        status: Value::Object(serde_json::Map::new()),
    }
}

/// Translate the VS and return the `mesh_route_dispatch` plugin config on the
/// canonical "/" proxy (the dispatch plugin sits on a single proxy when the
/// VS has only URI-style routes).
///
/// Returns `None` if the translation produced no dispatch plugin (e.g. when
/// the translator emitted a `request_termination` instead because all
/// predicates are unsupported).
fn dispatch_plugin_for_host_only(translation_input: &[K8sObject]) -> Option<PluginConfig> {
    let result = translate_k8s_objects(translation_input, options()).expect("translation succeeds");
    result
        .config
        .plugin_configs
        .into_iter()
        .find(|p| p.plugin_name == "mesh_route_dispatch")
}

fn ctx(method: &str, path: &str) -> RequestContext {
    RequestContext::new(
        "127.0.0.1".to_string(),
        method.to_string(),
        path.to_string(),
    )
}

/// Find an emitted `cors` plugin in a translation result.
fn cors_plugin_for(translation_input: &[K8sObject]) -> Option<PluginConfig> {
    let result = translate_k8s_objects(translation_input, options()).expect("translation succeeds");
    result
        .config
        .plugin_configs
        .into_iter()
        .find(|p| p.plugin_name == "cors")
}

/// VS field: `http[].corsPolicy`. Translated to a proxy-scoped `cors` plugin
/// when its origins are representable (`allowOrigins[]` `exact`/`prefix`/`regex`
/// `StringMatch` / legacy `allowOrigin`). GA: this is the common-case CORS
/// surface Istio operators set on a route. Malformed/unknown origin matchers,
/// un-compilable or over-complex regexes, over-budget matcher lists/values, and
/// credentialed exact `*` combinations are left unprojected (deferred), not
/// silently approximated. Credentialed opaque exact `null` and effectively
/// universal prefix/regex matchers are deferred the same way (issue #4269).
#[test]
fn vs_cors_policy_translated() {
    register_feature!(
        category = CATEGORY,
        feature = "http[].corsPolicy",
        status = Status::Supported,
        maturity = Maturity::Ga,
        notes = "Translated to a proxy-scoped `cors` plugin (allowOrigins[] exact/prefix/regex StringMatch / legacy allowOrigin, allowMethods/allowHeaders/exposeHeaders/maxAge/allowCredentials/unmatchedPreflights). Exact origins project onto the plugin's LITERAL {exact} matcher, so wildcard-shaped and noncanonical exacts keep their source semantics instead of being widened or deferred; omitted unmatchedPreflights preserves Istio FORWARD; uncredentialed exact `*` preserves allow-all, while credentialed exact `*`, opaque exact `null`, and effectively universal prefix/regex stay deferred instead of losing credentials or reflecting arbitrary origins.",
    );
    let cors = cors_plugin_for(&[virtual_service(json!({
        "hosts": ["api.example.com"],
        "http": [{
            "route": [{"destination": {"host": "echo.default.svc.cluster.local", "port": {"number": 8080}}}],
            "corsPolicy": {
                "allowOrigins": [{"exact": "https://app.example.com"}],
                "allowMethods": ["GET", "POST"],
                "allowHeaders": ["X-Request-Id"],
                "exposeHeaders": ["X-Trace-Id"],
                "maxAge": "24h",
                "allowCredentials": true
            }
        }]
    }))])
    .expect("corsPolicy with exact origins must emit a cors plugin");

    // Proxy-scoped to the route's proxy.
    assert_eq!(cors.scope, ferrum_edge::config::types::PluginScope::Proxy);
    assert!(
        cors.proxy_id.is_some(),
        "cors plugin must be proxy-scoped to the route"
    );

    // Fields mapped from Istio CRD camelCase to the cors plugin's snake_case.
    assert_eq!(
        cors.config["allowed_origins"],
        json!([{"exact": "https://app.example.com"}]),
        "Istio exact origins project onto the plugin's LITERAL matcher, never \
         its canonicalizing plain-string form"
    );
    assert_eq!(cors.config["allowed_methods"], json!(["GET", "POST"]));
    assert_eq!(cors.config["allowed_headers"], json!(["X-Request-Id"]));
    assert_eq!(cors.config["exposed_headers"], json!(["X-Trace-Id"]));
    assert_eq!(cors.config["max_age"].as_u64(), Some(86400)); // 24h -> seconds
    assert_eq!(cors.config["allow_credentials"].as_bool(), Some(true));
    assert_eq!(cors.config["unmatched_preflights"], json!("forward"));

    // The emitted config must construct a valid cors plugin.
    ferrum_edge::plugins::validate_plugin_config("cors", &cors.config)
        .expect("emitted cors config is valid");
}

/// A `corsPolicy` whose origins use `regex` / `prefix` `StringMatch` matchers is
/// projected onto the extended `cors` plugin (the Istio matcher shapes map to
/// the plugin's `{prefix}` / `{regex}` `allowed_origins` entries, matched as a
/// literal prefix / RE2 full match respectively).
#[test]
fn vs_cors_policy_regex_and_prefix_origins_projected() {
    register_feature!(
        category = CATEGORY,
        feature = "http[].corsPolicy regex/prefix origins",
        status = Status::Supported,
        notes = "regex/prefix origin matchers project onto the cors plugin's {prefix}/{regex} allowed_origins entries (literal prefix / RE2 full match), compiled once at config construction/reload under explicit byte/complexity/count bounds. An un-compilable, over-complex, or over-budget matcher stays deferred.",
    );
    let cors = cors_plugin_for(&[virtual_service(json!({
        "hosts": ["api.example.com"],
        "http": [{
            "route": [{"destination": {"host": "echo.default.svc.cluster.local", "port": {"number": 8080}}}],
            "corsPolicy": {"allowOrigins": [
                {"regex": "https://.*\\.example\\.com"},
                {"prefix": "https://app."}
            ]}
        }]
    }))])
    .expect("regex/prefix-origin corsPolicy must emit a cors plugin");

    assert_eq!(
        cors.config["allowed_origins"],
        json!([
            {"regex": "https://.*\\.example\\.com"},
            {"prefix": "https://app."}
        ]),
        "Istio StringMatch origins map to the cors plugin's object matcher form"
    );
    assert_eq!(cors.config["allowed_methods"], json!([]));
    assert_eq!(cors.config["allowed_headers"], json!([]));
    assert_eq!(cors.config["exposed_headers"], json!([]));
    assert!(cors.config.get("max_age").is_none());
    assert_eq!(cors.config["unmatched_preflights"], json!("forward"));

    // The emitted config must construct a valid cors plugin (regex compiles,
    // matchers are accepted).
    ferrum_edge::plugins::validate_plugin_config("cors", &cors.config)
        .expect("emitted cors config with prefix/regex origins is valid");
}

#[test]
fn vs_cors_policy_preserves_unmatched_modes_and_exact_wildcard() {
    for (source, projected) in [
        (None, "forward"),
        (Some("UNSPECIFIED"), "forward"),
        (Some("FORWARD"), "forward"),
        (Some("IGNORE"), "ignore"),
    ] {
        let mut policy = json!({
            "allowOrigins": [{"exact": "*"}]
        });
        if let Some(source) = source {
            policy["unmatchedPreflights"] = json!(source);
        }
        let cors = cors_plugin_for(&[virtual_service(json!({
            "hosts": ["api.example.com"],
            "http": [{
                "route": [{"destination": {"host": "echo.default.svc.cluster.local", "port": {"number": 8080}}}],
                "corsPolicy": policy
            }]
        }))])
        .expect("Istio wildcard and unmatched mode must translate");
        assert_eq!(cors.config["allowed_origins"], json!([{"exact": "*"}]));
        assert_eq!(cors.config["unmatched_preflights"], json!(projected));
        assert_eq!(cors.config["allowed_methods"], json!([]));
        assert_eq!(cors.config["allowed_headers"], json!([]));
        assert!(cors.config.get("max_age").is_none());
        ferrum_edge::plugins::validate_plugin_config("cors", &cors.config)
            .expect("projected CORS config is valid");
    }

    // Issue #3254: a wildcard-SHAPED exact is now projected LITERALLY. It must
    // reach the plugin as `{"exact": "*.example.com"}` — the plain-string form
    // would be read as native wildcard-subdomain syntax and authorize every
    // subdomain the source never matched.
    let wildcard_shaped = cors_plugin_for(&[virtual_service(json!({
        "hosts": ["api.example.com"],
        "http": [{
            "route": [{"destination": {"host": "echo.default.svc.cluster.local", "port": {"number": 8080}}}],
            "corsPolicy": {
                "allowOrigins": [{"exact": "*.example.com"}],
                "unmatchedPreflights": "FORWARD"
            }
        }]
    }))])
    .expect("wildcard-shaped exacts translate literally");
    assert_eq!(
        wildcard_shaped.config["allowed_origins"],
        json!([{"exact": "*.example.com"}]),
        "a wildcard-shaped exact must stay a literal matcher, never native wildcard syntax"
    );
    ferrum_edge::plugins::validate_plugin_config("cors", &wildcard_shaped.config)
        .expect("literal wildcard-shaped exact config is valid");

    assert!(
        cors_plugin_for(&[virtual_service(json!({
            "hosts": ["api.example.com"],
            "http": [{
                "route": [{"destination": {"host": "echo.default.svc.cluster.local", "port": {"number": 8080}}}],
                "corsPolicy": {
                    "allowOrigins": [{"exact": "https://app.example"}],
                    "unmatchedPreflights": "ALLOW"
                }
            }]
        }))])
        .is_none(),
        "unknown unmatchedPreflights modes must remain deferred"
    );

    assert!(
        cors_plugin_for(&[virtual_service(json!({
            "hosts": ["api.example.com"],
            "http": [{
                "route": [{"destination": {"host": "echo.default.svc.cluster.local", "port": {"number": 8080}}}],
                "corsPolicy": {
                    "allowOrigins": [{"exact": "https://app.example"}],
                    "allowCredentials": "true"
                }
            }]
        }))])
        .is_none(),
        "a malformed allowCredentials value must remain deferred"
    );

    // A noncanonical exact is likewise preserved verbatim instead of being
    // widened to the browser serialization (`https://app.example.com`).
    let noncanonical = cors_plugin_for(&[virtual_service(json!({
        "hosts": ["api.example.com"],
        "http": [{
            "route": [{"destination": {"host": "echo.default.svc.cluster.local", "port": {"number": 8080}}}],
            "corsPolicy": {
                "allowOrigins": [{"exact": "https://app.example.com:443"}]
            }
        }]
    }))])
    .expect("noncanonical exacts translate literally");
    assert_eq!(
        noncanonical.config["allowed_origins"],
        json!([{"exact": "https://app.example.com:443"}]),
        "a noncanonical exact must stay literal rather than widen to its canonical origin"
    );
    ferrum_edge::plugins::validate_plugin_config("cors", &noncanonical.config)
        .expect("literal noncanonical exact config is valid");
}

/// A `corsPolicy` `regex` origin matcher that does not compile cannot be
/// projected into a valid `cors` plugin, so the translator leaves it
/// unprojected (no cors plugin emitted, surfaced as a deferred field) rather
/// than emitting a config that would fail validation — routing still applies.
#[test]
fn vs_cors_policy_uncompilable_regex_origin_not_projected() {
    register_feature!(
        category = CATEGORY,
        feature = "http[].corsPolicy uncompilable regex origin",
        status = Status::Deferred,
        notes = "An un-compilable, over-complex, or over-budget origin matcher is fail-closed: left unprojected (deferred) and reported in status.deferred_fields, never emitted as an invalid plugin config, truncated, or approximated.",
    );
    let oversized = "a".repeat(600);
    let too_many: Vec<serde_json::Value> = (0..65)
        .map(|i| json!({"exact": format!("https://app{i}.example.com")}))
        .collect();
    for origins in [
        // Unbalanced group → invalid RE2.
        json!([{"regex": "https://(example"}]),
        // Beyond the explicit AST nesting bound.
        json!([{"regex": "((((((((((((((((((((((((((((a))))))))))))))))))))))))))))"}]),
        // Beyond the explicit per-matcher byte bound.
        json!([{"regex": &oversized}]),
        json!([{"exact": &oversized}]),
        json!([{"prefix": &oversized}]),
        // Beyond the explicit matcher-count bound.
        json!(too_many),
    ] {
        assert!(
            cors_plugin_for(&[virtual_service(json!({
                "hosts": ["api.example.com"],
                "http": [{
                    "route": [{"destination": {"host": "echo.default.svc.cluster.local", "port": {"number": 8080}}}],
                    "corsPolicy": {"allowOrigins": origins}
                }]
            }))])
            .is_none(),
            "an unrepresentable origin matcher must not emit a cors plugin: {origins}"
        );
    }
}

/// Credentialed opaque `null` and effectively universal prefix/regex origin
/// matchers cannot be projected: they would reflect an arbitrary origin with
/// credentials. Exact `*` keeps the documented deferral; these matchers are
/// refused the same way rather than silently dropping credentials (issue
/// #4269).
#[test]
fn vs_cors_policy_credentialed_universal_matcher_not_projected() {
    register_feature!(
        category = CATEGORY,
        feature = "http[].corsPolicy credentialed opaque/universal origin",
        status = Status::Deferred,
        notes = "allowCredentials plus opaque exact null or an effectively universal prefix/regex is fail-closed: left unprojected (deferred) rather than reflecting arbitrary origins with credentials or silently dropping credentials.",
    );
    for origins in [
        json!([{"exact": "null"}]),
        json!([{"prefix": "https://"}]),
        json!([{"prefix": "h"}]),
        json!([{"prefix": "chrome-extension://"}]),
        // Issues #4521 / #4522: a bare `scheme://host` prefix is matched with
        // an unbounded `starts_with`, and a hostname-character-class regex is
        // scheme-universal — neither constrains the host.
        json!([{"prefix": "https://app.example.com"}]),
        json!([{"prefix": "https://app."}]),
        json!([{"regex": "https://[\\w.-]+"}]),
        json!([{"regex": ".*"}]),
        json!([{"regex": "https://.*"}]),
        json!([{"regex": "null"}]),
        // Public-suffix-wide regexes cannot prove a pinned host.
        json!([{"regex": "^https://[a-z]{2,}\\.com$"}]),
        json!([{"regex": "https://[a-z]+\\.biz"}]),
    ] {
        assert!(
            cors_plugin_for(&[virtual_service(json!({
                "hosts": ["api.example.com"],
                "http": [{
                    "route": [{"destination": {"host": "echo.default.svc.cluster.local", "port": {"number": 8080}}}],
                    "corsPolicy": {
                        "allowOrigins": origins,
                        "allowCredentials": true
                    }
                }]
            }))])
            .is_none(),
            "credentialed universal matcher must not emit a cors plugin: {origins}"
        );
    }

    let projected = cors_plugin_for(&[virtual_service(json!({
        "hosts": ["api.example.com"],
        "http": [{
            "route": [{"destination": {"host": "echo.default.svc.cluster.local", "port": {"number": 8080}}}],
            "corsPolicy": {
                "allowOrigins": [{"prefix": "https://app.example.com:"}],
                "allowCredentials": true
            }
        }]
    }))])
    .expect("credentialed host-bounded `scheme://host:` prefix must still project");
    assert_eq!(projected.config["allow_credentials"], json!(true));
}

/// A `corsPolicy` `allowOrigins[]` entry that is not a single-key
/// `exact`/`prefix`/`regex` `StringMatch` — here a valid `prefix` plus an extra
/// non-string `regex` key — is a malformed matcher. It must be fail-closed
/// (left unprojected / deferred), not silently approximated by dropping the bad
/// key, so the translator, the `cors` plugin, and the deferred-field status
/// writer all agree it is unrepresentable.
#[test]
fn vs_cors_policy_malformed_origin_matcher_not_projected() {
    register_feature!(
        category = CATEGORY,
        feature = "http[].corsPolicy malformed origin matcher",
        status = Status::Deferred,
        notes = "A StringMatch origin matcher with extra/unknown or non-string keys is fail-closed: left unprojected (deferred), never approximated by dropping the bad key.",
    );
    assert!(
        cors_plugin_for(&[virtual_service(json!({
            "hosts": ["api.example.com"],
            "http": [{
                "route": [{"destination": {"host": "echo.default.svc.cluster.local", "port": {"number": 8080}}}],
                "corsPolicy": {"allowOrigins": [{"prefix": "https://app.", "regex": 123}]}
            }]
        }))])
        .is_none(),
        "a malformed (multi/extra-key) origin matcher must not emit a cors plugin"
    );
}

/// VS `spec.tls[]` L4 routing → passthrough TCP stream proxy keyed by SNI
/// (encrypted bytes forwarded, no TLS termination), reusing the gateway /
/// east-west stream + SNI machinery.
#[test]
fn vs_tls_l4_sni_passthrough() {
    register_feature!(
        category = CATEGORY,
        feature = "spec.tls[] SNI L4 routing",
        status = Status::Supported,
        notes = "Passthrough TCP proxy keyed by sniHosts. L4 predicates (sourceLabels/sourceSubnets/destinationSubnets/gateways/sourceNamespace) compile onto Proxy.stream_match; weighted multi-destination splits materialize an upstream-backed stream proxy.",
    );
    let result = translate_k8s_objects(
        &[virtual_service(json!({
            "hosts": ["secure.example.com"],
            "tls": [{
                "match": [{"sniHosts": ["secure.example.com"], "port": 8443}],
                "route": [{"destination": {"host": "backend.default.svc.cluster.local", "port": {"number": 8443}}}]
            }]
        }))],
        options(),
    )
    .expect("tls[] L4 translates");
    let proxy = result
        .config
        .proxies
        .iter()
        .find(|p| p.listen_port == Some(8443))
        .expect("tls[] materializes a passthrough proxy");
    assert!(proxy.passthrough, "tls[] SNI routing is passthrough");
    assert_eq!(proxy.hosts, vec!["secure.example.com".to_string()]);
    assert_eq!(proxy.backend_host, "backend.default.svc.cluster.local");
}

/// VS `spec.tcp[]` L4 routing → plain TCP stream proxy keyed by `listen_port`.
#[test]
fn vs_tcp_l4_port_routing() {
    register_feature!(
        category = CATEGORY,
        feature = "spec.tcp[] L4 routing",
        status = Status::Supported,
        notes = "Plain TCP proxy keyed by listen_port. L4 predicates (sourceLabels/sourceSubnets/destinationSubnets/gateways/sourceNamespace) compile onto Proxy.stream_match; weighted multi-destination splits materialize an upstream-backed stream proxy.",
    );
    let result = translate_k8s_objects(
        &[virtual_service(json!({
            "hosts": ["db.example.com"],
            "tcp": [{
                "match": [{"port": 3306}],
                "route": [{"destination": {"host": "mysql.default.svc.cluster.local", "port": {"number": 3306}}}]
            }]
        }))],
        options(),
    )
    .expect("tcp[] L4 translates");
    let proxy = result
        .config
        .proxies
        .iter()
        .find(|p| p.listen_port == Some(3306))
        .expect("tcp[] materializes a stream proxy");
    assert!(!proxy.passthrough, "plain tcp[] is not passthrough");
    assert_eq!(proxy.backend_host, "mysql.default.svc.cluster.local");
    assert_eq!(proxy.backend_port, 3306);
}

/// VS `tcp[]` weighted multi-destination splits materialize an upstream-backed
/// stream proxy with relative WRR weights.
#[test]
fn vs_tcp_l4_weighted_multi_destination() {
    register_feature!(
        category = CATEGORY,
        feature = "spec.tcp[]/tls[] weighted multi-destination",
        status = Status::Supported,
        notes = "Weighted L4 routes materialize istio-vs-l4-upstream-* with WRR; zero-weight legs skipped; all-zero splits materialize a fail-closed blackhole backend; invalid weights/subset/missing ports fail closed; upstreams ride MeshSlice for reload/delete.",
    );
    let result = translate_k8s_objects(
        &[virtual_service(json!({
            "hosts": ["db.example.com"],
            "tcp": [{
                "match": [{"port": 3306}],
                "route": [
                    {"destination": {"host": "mysql-v1.default.svc.cluster.local", "port": {"number": 3306}}, "weight": 80},
                    {"destination": {"host": "mysql-v2.default.svc.cluster.local", "port": {"number": 3306}}, "weight": 20}
                ]
            }]
        }))],
        options(),
    )
    .expect("weighted tcp[] L4 translates");
    let proxy = result
        .config
        .proxies
        .iter()
        .find(|p| p.listen_port == Some(3306))
        .expect("tcp[] materializes a stream proxy");
    let upstream = result
        .config
        .upstreams
        .iter()
        .find(|u| proxy.upstream_id.as_deref() == Some(u.id.as_str()))
        .expect("weighted L4 upstream");
    assert_eq!(upstream.targets.len(), 2);
    assert_eq!(upstream.targets[0].weight, 80);
    assert_eq!(upstream.targets[1].weight, 20);
    assert_eq!(
        upstream.algorithm,
        ferrum_edge::config::types::LoadBalancerAlgorithm::WeightedRoundRobin
    );
}

/// VS `tcp[]`/`tls[]` L4 match predicates compile onto `Proxy.stream_match`
/// (AND within one match, OR across match blocks / candidates) and are
/// evaluated from trustworthy connection metadata at accept time.
#[test]
fn vs_l4_stream_match_predicates() {
    register_feature!(
        category = CATEGORY,
        feature = "tcp[]/tls[] L4 match predicates",
        status = Status::Supported,
        notes = "sourceLabels, sourceSubnets, destinationSubnets, gateways, and sourceNamespace compile onto Proxy.stream_match; missing evidence denies; malformed values fail closed at translation.",
    );
    let result = translate_k8s_objects(
        &[virtual_service(json!({
            "hosts": ["db.example.com"],
            "tcp": [{
                "match": [{
                    "port": 3306,
                    "sourceLabels": {"app": "billing"},
                    "sourceNamespace": "prod",
                    "sourceSubnets": ["10.0.0.0/8"],
                    "destinationSubnets": ["192.168.0.0/16"],
                    "gateways": ["mesh"]
                }],
                "route": [{"destination": {"host": "mysql.default.svc.cluster.local", "port": {"number": 3306}}}]
            }]
        }))],
        options(),
    )
    .expect("L4 match predicates translate");
    let proxy = result
        .config
        .proxies
        .iter()
        .find(|p| p.listen_port == Some(3306))
        .expect("tcp[] materializes a stream proxy");
    let arm = &proxy
        .stream_match
        .as_ref()
        .expect("stream_match projected")
        .arms[0];
    assert_eq!(
        arm.source_labels.get("app").map(String::as_str),
        Some("billing")
    );
    assert_eq!(arm.source_namespace.as_deref(), Some("prod"));
    assert_eq!(arm.source_subnets, vec!["10.0.0.0/8".to_string()]);
    assert_eq!(arm.destination_subnets, vec!["192.168.0.0/16".to_string()]);
    assert_eq!(arm.gateways, vec!["mesh".to_string()]);

    let err = translate_k8s_objects(
        &[virtual_service(json!({
            "hosts": ["db.example.com"],
            "tcp": [{
                "match": [{"port": 3306, "sourceSubnets": ["not-a-cidr"]}],
                "route": [{"destination": {"host": "mysql.default.svc.cluster.local", "port": {"number": 3306}}}]
            }]
        }))],
        options(),
    )
    .expect_err("malformed sourceSubnets must fail closed");
    assert!(format!("{err}").contains("sourceSubnets"), "got {err}");
}

/// VS predicate: `uri.exact`. The translator collapses this onto a single
/// proxy with an exact-listen-path (`=/path`) match and no dispatch plugin —
/// classical Ferrum routing handles it. The conformance assertion is that
/// the proxy lands with the expected listen_path tier.
#[test]
fn vs_uri_exact_match() {
    register_feature!(
        category = CATEGORY,
        feature = "uri.exact",
        status = Status::Supported,
        notes = "Compiled to a Ferrum proxy with listen_path=`=/path` (exact tier).",
    );
    let result = translate_k8s_objects(
        &[virtual_service(json!({
            "hosts": ["api.example.com"],
            "http": [{
                "match": [{"uri": {"exact": "/health"}}],
                "route": [{"destination": {"host": "echo.default.svc.cluster.local", "port": {"number": 8080}}}]
            }]
        }))],
        options(),
    )
    .expect("translation succeeds");

    let proxy = result
        .config
        .proxies
        .iter()
        .find(|p| p.listen_path.as_deref() == Some("=/health"))
        .expect("VirtualService uri.exact must compile to an exact-tier proxy");
    assert_eq!(proxy.backend_host, "echo.default.svc.cluster.local");
    assert_eq!(proxy.backend_port, 8080);
}

/// VS predicate: `uri.prefix`. Translates to the Ferrum prefix-tier route
/// (no leading sigil).
#[test]
fn vs_uri_prefix_match() {
    register_feature!(
        category = CATEGORY,
        feature = "uri.prefix",
        status = Status::Supported,
        notes = "Compiled to a Ferrum proxy with listen_path=`/prefix` (prefix tier).",
    );
    let result = translate_k8s_objects(
        &[virtual_service(json!({
            "hosts": ["api.example.com"],
            "http": [{
                "match": [{"uri": {"prefix": "/api/v1"}}],
                "route": [{"destination": {"host": "echo.default.svc.cluster.local", "port": {"number": 8080}}}]
            }]
        }))],
        options(),
    )
    .expect("translation succeeds");

    assert!(
        result
            .config
            .proxies
            .iter()
            .any(|p| p.listen_path.as_deref() == Some("/api/v1")),
        "VirtualService uri.prefix must compile to a prefix-tier Ferrum proxy"
    );
}

/// VS predicate: `uri.regex`. Translates to the Ferrum regex-tier route
/// (leading `~`, auto-anchored full-path).
#[test]
fn vs_uri_regex_match() {
    register_feature!(
        category = CATEGORY,
        feature = "uri.regex",
        status = Status::Supported,
        notes = "Compiled to a Ferrum proxy with listen_path=`~pattern` (regex tier).",
    );
    let result = translate_k8s_objects(
        &[virtual_service(json!({
            "hosts": ["api.example.com"],
            "http": [{
                "match": [{"uri": {"regex": "/users/[0-9]+"}}],
                "route": [{"destination": {"host": "echo.default.svc.cluster.local", "port": {"number": 8080}}}]
            }]
        }))],
        options(),
    )
    .expect("translation succeeds");

    assert!(
        result
            .config
            .proxies
            .iter()
            .any(|p| { matches!(p.listen_path.as_deref(), Some(path) if path.starts_with('~')) }),
        "VirtualService uri.regex must compile to a regex-tier Ferrum proxy"
    );
}

/// VS predicate: `headers.X.exact` — T1-B.1 (PR #891). Captured as a
/// `mesh_route_dispatch` rule that routes on header equality.
#[tokio::test]
async fn vs_headers_exact_match() {
    register_feature!(
        category = CATEGORY,
        feature = "headers.X.exact",
        status = Status::Supported,
        notes = "T1-B.1 (PR #891): mesh_route_dispatch rule with case-insensitive header equality.",
    );
    let plugin_config = dispatch_plugin_for_host_only(&[virtual_service(json!({
        "hosts": ["api.example.com"],
        "http": [{
            "match": [{"headers": {"x-canary": {"exact": "v2"}}}],
            "route": [{"destination": {"host": "canary.default.svc.cluster.local", "port": {"number": 8080}}}]
        }]
    }))])
    .expect("mesh_route_dispatch plugin must be emitted for header predicate");

    let dispatch = MeshRouteDispatch::new(&plugin_config.config).expect("plugin config");
    let mut headers = HashMap::from([("x-canary".to_string(), "v2".to_string())]);
    let mut req = ctx("GET", "/anything");
    assert!(matches!(
        dispatch.before_proxy(&mut req, &mut headers).await,
        PluginResult::Continue
    ));
    assert_eq!(
        req.route_override_backend_host.as_deref(),
        Some("canary.default.svc.cluster.local")
    );
}

/// VS predicate: `headers.X.{prefix,regex}` — T1-B.1 (PR #891). First-class
/// `mesh_route_dispatch` predicate that captures the tagged StringMatch shape
/// (`{prefix: "..."}` / `{regex: "..."}`). NOT a fail-closed termination.
#[test]
fn vs_headers_prefix_match() {
    register_feature!(
        category = CATEGORY,
        feature = "headers.X.{prefix,regex}",
        status = Status::Supported,
        notes = "T1-B.1 (PR #891): tagged StringMatch shape compiles into a mesh_route_dispatch rule; regex/prefix arms first-class.",
    );
    let plugin_config = dispatch_plugin_for_host_only(&[virtual_service(json!({
        "hosts": ["api.example.com"],
        "http": [{
            "match": [{"headers": {"x-tenant": {"prefix": "admin-"}}}],
            "route": [{"destination": {"host": "admin.default.svc.cluster.local", "port": {"number": 8080}}}]
        }]
    }))])
    .expect("mesh_route_dispatch plugin must be emitted for prefix header predicate");

    // The translator emits the tagged StringMatch shape; the plugin
    // construction succeeds (regex compiled at config-load time).
    let _ = MeshRouteDispatch::new(&plugin_config.config).expect("plugin loads");
}

/// VS predicate: `method.exact` — T1-B.2 (PR #894). Captured as a
/// `mesh_route_dispatch` rule that restricts method.
#[tokio::test]
async fn vs_method_exact_match() {
    register_feature!(
        category = CATEGORY,
        feature = "method.exact",
        status = Status::Supported,
        notes = "T1-B.2 (PR #894): mesh_route_dispatch rule with method allow-list.",
    );
    let plugin_config = dispatch_plugin_for_host_only(&[virtual_service(json!({
        "hosts": ["api.example.com"],
        "http": [{
            "match": [{"method": {"exact": "GET"}}],
            "route": [{"destination": {"host": "echo.default.svc.cluster.local", "port": {"number": 8080}}}]
        }]
    }))])
    .expect("mesh_route_dispatch plugin must be emitted for method predicate");

    let dispatch = MeshRouteDispatch::new(&plugin_config.config).expect("plugin config");
    let mut headers = HashMap::new();
    let mut get_req = ctx("GET", "/x");
    assert!(matches!(
        dispatch.before_proxy(&mut get_req, &mut headers).await,
        PluginResult::Continue
    ));
    // POST must NOT match — `reject_unmatched: true` lands a 404, matching
    // Envoy's behavior when no Istio VS route matches a request.
    let mut post_req = ctx("POST", "/x");
    let mut post_headers = HashMap::new();
    assert!(matches!(
        dispatch
            .before_proxy(&mut post_req, &mut post_headers)
            .await,
        PluginResult::Reject {
            status_code: 404,
            ..
        }
    ));
}

/// VS predicate: `authority.{exact,prefix,regex}` — T1-B.3 (PR #899). The
/// translator emits the predicate as a first-class `mesh_route_dispatch` rule
/// (`exact` as a bare string for wire back-compat, `prefix` / `regex` as the
/// tagged `StringMatch` shape). The plugin compiles regex once at
/// config-load time. The request hot path resolves raw `Host` / `:authority`
/// once and runs the compiled matcher against it. Istio exact/prefix
/// authority predicates are case-sensitive, and explicit request ports are
/// part of the matched value.
///
/// Sibling rules in the same `match[]` no longer get dropped: a rule with
/// `authority: internal.example.com` and a sibling with `headers.x-canary`
/// both emit as separate dispatch rules with all-of semantics enforced per
/// rule. `reject_unmatched: true` still applies so requests that miss every
/// rule 404.
#[tokio::test]
async fn vs_authority_match() {
    register_feature!(
        category = CATEGORY,
        feature = "authority.{exact,prefix,regex}",
        status = Status::Supported,
        notes = "T1-B.3 (PR #899): authority is a first-class mesh_route_dispatch StringMatch predicate (exact / prefix / regex); regex is compiled once at config-load time; exact/prefix operands match raw Host/:authority case-sensitively including explicit ports; sibling rules continue to emit independently.",
    );
    let result = translate_k8s_objects(
        &[virtual_service(json!({
            "hosts": ["api.example.com"],
            "http": [{
                "match": [
                    {"uri": {"prefix": "/api"}, "headers": {"x-canary": {"exact": "v2"}}},
                    {"uri": {"prefix": "/api"}, "authority": {"exact": "internal.example.com"}}
                ],
                "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}]
            }]
        }))],
        options(),
    )
    .expect("translation succeeds");

    let plugin = result
        .config
        .plugin_configs
        .iter()
        .find(|p| p.plugin_name == "mesh_route_dispatch")
        .expect("dispatch plugin emitted for the authority + header siblings");
    let rules = plugin
        .config
        .get("rules")
        .and_then(Value::as_array)
        .expect("rules array");
    assert_eq!(
        rules.len(),
        2,
        "authority is first-class now (T1-B.3) -- both the header sibling AND the authority-bearing sibling must emit as dispatch rules"
    );
    // The authority predicate emits as a bare string (back-compat with the
    // `Exact` legacy form).
    let authority_rule = rules
        .iter()
        .find(|r| r["match"]["authority"].is_string())
        .expect("authority-bearing rule must be present with the exact-form bare string");
    assert_eq!(
        authority_rule["match"]["authority"].as_str(),
        Some("internal.example.com")
    );
    assert_eq!(
        plugin
            .config
            .get("reject_unmatched")
            .and_then(Value::as_bool),
        Some(true),
        "multi-predicate routes keep reject_unmatched=true -- requests that miss every rule 404 (Envoy parity)",
    );

    // Drive the plugin to prove the matcher fires.
    let dispatch = MeshRouteDispatch::new(&plugin.config).expect("plugin config");

    // Authority match wins: request carries the gated Host.
    let mut matching = ctx("GET", "/api/items");
    let mut matching_headers =
        HashMap::from([("host".to_string(), "internal.example.com".to_string())]);
    assert!(matches!(
        dispatch
            .before_proxy(&mut matching, &mut matching_headers)
            .await,
        PluginResult::Continue
    ));

    // Header sibling wins: request carries the canary header and any Host.
    let mut canary = ctx("GET", "/api/items");
    let mut canary_headers = HashMap::from([
        ("x-canary".to_string(), "v2".to_string()),
        ("host".to_string(), "public.example.com".to_string()),
    ]);
    assert!(matches!(
        dispatch
            .before_proxy(&mut canary, &mut canary_headers)
            .await,
        PluginResult::Continue
    ));

    // No predicate matches: 404 via reject_unmatched.
    let mut miss = ctx("GET", "/api/items");
    let mut miss_headers = HashMap::from([("host".to_string(), "public.example.com".to_string())]);
    assert!(matches!(
        dispatch.before_proxy(&mut miss, &mut miss_headers).await,
        PluginResult::Reject {
            status_code: 404,
            ..
        }
    ));
}

/// VS predicate: `sourceNamespace` — T1-B.4 (PR #903). Restricts a route
/// to callers in a specific Kubernetes namespace, resolved from the peer's
/// SPIFFE ID. Fails closed when no peer identity is present.
#[tokio::test]
async fn vs_source_namespace_match() {
    register_feature!(
        category = CATEGORY,
        feature = "sourceNamespace",
        status = Status::Supported,
        notes = "T1-B.4 (PR #903): exact-only predicate on peer SPIFFE namespace; fails closed when no identity.",
    );
    let plugin_config = dispatch_plugin_for_host_only(&[virtual_service(json!({
        "hosts": ["api.example.com"],
        "http": [{
            "match": [{"uri": {"prefix": "/internal"}, "sourceNamespace": "platform"}],
            "route": [{"destination": {"host": "platform.default.svc.cluster.local", "port": {"number": 8080}}}]
        }]
    }))])
    .expect("mesh_route_dispatch plugin must be emitted for sourceNamespace predicate");

    let dispatch = MeshRouteDispatch::new(&plugin_config.config).expect("plugin config");

    // Matching peer SPIFFE ID encodes ns/platform.
    let mut matching = ctx("GET", "/internal/x");
    matching.peer_spiffe_id = Some(
        SpiffeId::new("spiffe://cluster.local/ns/platform/sa/billing").expect("valid spiffe id"),
    );
    let mut headers = HashMap::new();
    assert!(matches!(
        dispatch.before_proxy(&mut matching, &mut headers).await,
        PluginResult::Continue
    ));

    // Non-matching peer namespace: must fall through to reject_unmatched.
    let mut other_ns = ctx("GET", "/internal/x");
    other_ns.peer_spiffe_id =
        Some(SpiffeId::new("spiffe://cluster.local/ns/other/sa/billing").expect("valid spiffe id"));
    let mut other_headers = HashMap::new();
    assert!(matches!(
        dispatch
            .before_proxy(&mut other_ns, &mut other_headers)
            .await,
        PluginResult::Reject {
            status_code: 404,
            ..
        }
    ));

    // No peer identity at all: fails closed.
    let mut anonymous = ctx("GET", "/internal/x");
    let mut anon_headers = HashMap::new();
    assert!(matches!(
        dispatch
            .before_proxy(&mut anonymous, &mut anon_headers)
            .await,
        PluginResult::Reject {
            status_code: 404,
            ..
        }
    ));
}

/// VS predicate: `ignoreUriCase: true` — T1-B.5 (PR #901). The translator
/// widens the URI's `listen_path` to a case-insensitive regex (`prefix: "/Api"`
/// → `~(?i:/Api.*)`) so the router admits both casings, and emits a
/// `mesh_route_dispatch` rule carrying the original URI predicate +
/// `ignore_uri_case: true`. The plugin re-evaluates with ASCII-only case
/// folding (non-ASCII bytes compare byte-for-byte, matching Istio's
/// documented behavior). A later same-shape case-sensitive `/api` route
/// collapses onto the widened proxy so Ferrum's router preserves Istio route
/// order for that case variant.
#[tokio::test]
async fn vs_ignore_uri_case_routes_both_casings() {
    register_feature!(
        category = CATEGORY,
        feature = "ignoreUriCase: true",
        status = Status::Supported,
        notes = "T1-B.5 (PR #901): exact/prefix URI matches widen to escaped case-insensitive regex listen_paths (for example ~(?i:/Api.*)); the dispatch rule carries the original URI predicate + ignore_uri_case=true; plugin re-evaluates with ASCII-only case folding; same-shape later case variants collapse onto the widened proxy to preserve Istio route order.",
    );
    let result = translate_k8s_objects(
        &[virtual_service(json!({
            "hosts": ["api.example.com"],
            "http": [
                {
                    "match": [{"uri": {"prefix": "/Api"}, "ignoreUriCase": true}],
                    "route": [{"destination": {"host": "canary.default.svc.cluster.local", "port": {"number": 9090}}}]
                },
                {
                    "match": [{"uri": {"prefix": "/api"}}],
                    "route": [{"destination": {"host": "stable.default.svc.cluster.local", "port": {"number": 8080}}}]
                }
            ]
        }))],
        options(),
    )
    .expect("translation succeeds");

    // The selected proxy uses the widened regex listen_path so both `/Api*`
    // and `/api*` hit one hot-router entry. Its default backend is the later
    // stable route; the prior canary route is guarded by the dispatch plugin.
    let widened_listen_path = "~(?i:/Api.*)";
    let stable_proxy = result
        .config
        .proxies
        .iter()
        .find(|p| {
            p.listen_path.as_deref() == Some(widened_listen_path)
                && p.backend_host == "stable.default.svc.cluster.local"
        })
        .expect("same-shape ignoreUriCase route collapses onto widened stable proxy");

    // The dispatch rule carries the URI predicate + `ignore_uri_case` so the
    // plugin can re-evaluate at request time.
    let plugin = result
        .config
        .plugin_configs
        .iter()
        .find(|p| {
            p.plugin_name == "mesh_route_dispatch"
                && p.proxy_id.as_deref() == Some(stable_proxy.id.as_str())
        })
        .expect("mesh_route_dispatch rule emitted for ignoreUriCase branch");
    let match_obj = &plugin.config["rules"][0]["match"];
    assert_eq!(match_obj["uri"]["prefix"].as_str(), Some("/Api"));
    assert_eq!(match_obj["ignore_uri_case"].as_bool(), Some(true));
    assert_eq!(
        plugin.config["rules"][0]["destination"]["backend_host"].as_str(),
        Some("canary.default.svc.cluster.local")
    );

    assert!(
        !result
            .config
            .proxies
            .iter()
            .any(|p| p.listen_path.as_deref() == Some("/api")),
        "the same-shape later route must not remain in the prefix tier"
    );

    // Drive the plugin to prove ASCII case folding works.
    let dispatch = MeshRouteDispatch::new(&plugin.config).expect("plugin config");
    for path in ["/Api/items", "/api/items", "/API/items"] {
        let mut req = ctx("GET", path);
        let mut headers = HashMap::new();
        assert!(
            matches!(
                dispatch.before_proxy(&mut req, &mut headers).await,
                PluginResult::Continue
            ),
            "case-insensitive URI prefix must match {path}"
        );
    }
}

/// VS feature: `http[].fault` (route-local fault injection) — T1-E (PR #896).
/// Each fault block translates to a `mesh_route_dispatch` rule-local fault
/// action. The conformance check is that the translated fault config lands on
/// the matching rule and can reject a matching request.
#[tokio::test]
async fn vs_route_local_fault_injection() {
    register_feature!(
        category = CATEGORY,
        feature = "http[].fault",
        status = Status::Supported,
        notes = "T1-E (PR #896): route-local fault block compiles to a mesh_route_dispatch rule-local fault action.",
    );
    let result = translate_k8s_objects(
        &[virtual_service(json!({
            "hosts": ["api.example.com"],
            "http": [{
                "match": [{"uri": {"prefix": "/chaos"}}],
                "fault": {
                    "abort": {"percentage": {"value": 100.0}, "httpStatus": 503}
                },
                "route": [{"destination": {"host": "chaos.default.svc.cluster.local", "port": {"number": 8080}}}]
            }]
        }))],
        options(),
    )
    .expect("translation succeeds");

    assert!(
        !result
            .config
            .plugin_configs
            .iter()
            .any(|p| p.plugin_name == "fault_injection"),
        "VirtualService http[].fault should be carried by mesh_route_dispatch, not a proxy-scoped fault_injection plugin"
    );
    assert!(
        result
            .config
            .proxies
            .iter()
            .any(|p| p.listen_path.as_deref() == Some("/chaos")),
        "VirtualService uri prefix must still compile to the /chaos proxy route"
    );

    let plugin_config = result
        .config
        .plugin_configs
        .iter()
        .find(|p| p.plugin_name == "mesh_route_dispatch")
        .expect("VirtualService http[].fault must compile to a mesh_route_dispatch plugin");
    let rules = plugin_config
        .config
        .get("rules")
        .and_then(Value::as_array)
        .expect("mesh_route_dispatch rules array");
    let rule = rules.first().expect("fault-bearing dispatch rule");
    let fault = rule.get("fault").expect("rule-local fault action");
    assert_eq!(fault["abort"]["status_code"], 503);
    assert_eq!(fault["abort"]["percentage"], 100.0);

    let dispatch = MeshRouteDispatch::new(&plugin_config.config).expect("plugin config");
    let mut req = ctx("GET", "/chaos/ping");
    let mut headers = HashMap::new();
    assert!(
        matches!(
            dispatch.before_proxy(&mut req, &mut headers).await,
            PluginResult::Reject {
                status_code: 503,
                ..
            }
        ),
        "matching route-local fault must abort the request before proxy dispatch"
    );
}

/// VS feature: `queryParams.X.exact`. Captured as a `mesh_route_dispatch`
/// rule with query-param equality. The rule evaluates the canonical forwarded
/// query and also opts the proxy into decoded `ctx.query_params`
/// materialization for other plugins.
#[tokio::test]
async fn vs_query_params_exact_match() {
    register_feature!(
        category = CATEGORY,
        feature = "queryParams.X.exact",
        status = Status::Supported,
        notes = "mesh_route_dispatch matches the canonical forwarded query and materializes ctx.query_params for sibling plugins.",
    );
    let plugin_config = dispatch_plugin_for_host_only(&[virtual_service(json!({
        "hosts": ["api.example.com"],
        "http": [{
            "match": [{"queryParams": {"variant": {"exact": "beta"}}}],
            "route": [{"destination": {"host": "beta.default.svc.cluster.local", "port": {"number": 8080}}}]
        }]
    }))])
    .expect("mesh_route_dispatch plugin must be emitted for queryParams predicate");

    let dispatch = MeshRouteDispatch::new(&plugin_config.config).expect("plugin config");
    assert!(
        dispatch.requires_decoded_query_params(),
        "queryParams predicate must opt the proxy into decoded query_params"
    );

    let mut req = ctx("GET", "/search");
    req.set_raw_query_string("variant=beta".to_string());
    req.materialize_query_params();
    let mut headers = HashMap::new();
    assert!(matches!(
        dispatch.before_proxy(&mut req, &mut headers).await,
        PluginResult::Continue
    ));
}

/// VS feature: `http[].redirect.port` / `derivePort`. Projects onto
/// `mesh_route_dispatch` `redirect.port` / `redirect.derive_port` and renders
/// `Location` with scheme-default canonicalization. Request-port provenance is
/// the trusted frontend listener port only.
#[tokio::test]
async fn vs_redirect_port_and_derive_port() {
    register_feature!(
        category = CATEGORY,
        feature = "http[].redirect.port",
        status = Status::Supported,
        notes = "Explicit redirect.port and derivePort (FROM_PROTOCOL_DEFAULT / FROM_REQUEST_PORT) project onto mesh_route_dispatch; Location uses trusted orig_dst/frontend_listen_port for FROM_REQUEST_PORT and never X-Forwarded-Port; scheme-default ports are omitted from authority.",
    );

    // Explicit port.
    let plugin_config = dispatch_plugin_for_host_only(&[virtual_service(json!({
        "hosts": ["api.example.com"],
        "http": [{
            "match": [{"uri": {"prefix": "/old"}}],
            "redirect": {
                "uri": "/new",
                "authority": "api.example.com",
                "scheme": "https",
                "port": 8443
            }
        }]
    }))])
    .expect("redirect.port must emit mesh_route_dispatch");
    let dispatch = MeshRouteDispatch::new(&plugin_config.config).expect("plugin config");
    let mut req = ctx("GET", "/old");
    let mut headers = HashMap::new();
    match dispatch.before_proxy(&mut req, &mut headers).await {
        PluginResult::Reject { headers, .. } => {
            assert_eq!(
                headers.get("location").map(String::as_str),
                Some("https://api.example.com:8443/new")
            );
        }
        other => panic!("expected explicit-port redirect, got {other:?}"),
    }

    // FROM_REQUEST_PORT.
    let plugin_config = dispatch_plugin_for_host_only(&[virtual_service(json!({
        "hosts": ["api.example.com"],
        "http": [{
            "match": [{"uri": {"prefix": "/old"}}],
            "redirect": {
                "uri": "/new",
                "scheme": "https",
                "derivePort": "FROM_REQUEST_PORT"
            }
        }]
    }))])
    .expect("derivePort FROM_REQUEST_PORT must emit mesh_route_dispatch");
    let dispatch = MeshRouteDispatch::new(&plugin_config.config).expect("plugin config");
    let mut req = ctx("GET", "/old");
    req.frontend_listen_port = Some(8080);
    let mut headers = HashMap::from([
        ("host".to_string(), "api.example.com".to_string()),
        ("x-forwarded-port".to_string(), "65535".to_string()),
    ]);
    match dispatch.before_proxy(&mut req, &mut headers).await {
        PluginResult::Reject { headers, .. } => {
            assert_eq!(
                headers.get("location").map(String::as_str),
                Some("https://api.example.com:8080/new")
            );
        }
        other => panic!("expected FROM_REQUEST_PORT redirect, got {other:?}"),
    }

    // FROM_PROTOCOL_DEFAULT.
    let plugin_config = dispatch_plugin_for_host_only(&[virtual_service(json!({
        "hosts": ["api.example.com"],
        "http": [{
            "match": [{"uri": {"prefix": "/old"}}],
            "redirect": {
                "uri": "/secure",
                "scheme": "https",
                "derivePort": "FROM_PROTOCOL_DEFAULT"
            }
        }]
    }))])
    .expect("derivePort FROM_PROTOCOL_DEFAULT must emit mesh_route_dispatch");
    let dispatch = MeshRouteDispatch::new(&plugin_config.config).expect("plugin config");
    let mut req = ctx("GET", "/old");
    let mut headers = HashMap::from([("host".to_string(), "api.example.com:8080".to_string())]);
    match dispatch.before_proxy(&mut req, &mut headers).await {
        PluginResult::Reject { headers, .. } => {
            assert_eq!(
                headers.get("location").map(String::as_str),
                Some("https://api.example.com/secure")
            );
        }
        other => panic!("expected FROM_PROTOCOL_DEFAULT redirect, got {other:?}"),
    }
}

/// Translate the VS and return every emitted plugin config.
fn plugins_for(translation_input: &[K8sObject]) -> Vec<PluginConfig> {
    translate_k8s_objects(translation_input, options())
        .expect("translation succeeds")
        .config
        .plugin_configs
}

/// VS field: `http[].headers.{request,response}.{set,add,remove}`. Projected
/// onto every emitted `mesh_route_dispatch` rule and consumed by the
/// auto-attached `request_transformer` / `response_transformer` instances.
///
/// The security-relevant half is `remove`: a dropped
/// `headers.request.remove: [x-internal-auth]` would forward the CLIENT's copy
/// of a header the backend trusts, so the rule must actually strip it before
/// backend dispatch.
#[tokio::test]
async fn vs_request_header_set_add_remove_projects_route_transform() {
    register_feature!(
        category = CATEGORY,
        feature = "http[].headers.request/response",
        status = Status::Supported,
        notes = "set/add/remove project onto each mesh_route_dispatch rule as request_transform / response_transform, with the istio-vs-req-xform-* / istio-vs-resp-xform-* transformer instances auto-attached to the route's proxy (exactly once, and only when a rule carries transforms of that direction). Malformed header names/values and framing-header writes are rejected at translation rather than silently dropped.",
    );

    let input = [virtual_service(json!({
        "hosts": ["api.example.com"],
        "http": [{
            "match": [{"uri": {"prefix": "/api"}}],
            "headers": {
                "request": {
                    "set": {"x-route": "canary"},
                    "add": {"x-tag": "b"},
                    "remove": ["x-internal-auth"]
                },
                "response": {"set": {"x-served-by": "ferrum"}}
            },
            "route": [{"destination": {
                "host": "echo.default.svc.cluster.local",
                "port": {"number": 8080}
            }}]
        }]
    }))];

    let plugins = plugins_for(&input);
    let dispatch = plugins
        .iter()
        .find(|plugin| plugin.plugin_name == "mesh_route_dispatch")
        .expect("header transforms must emit a mesh_route_dispatch plugin");
    let proxy_id = dispatch
        .proxy_id
        .clone()
        .expect("dispatch plugin is proxy-scoped");

    // Both transformer consumers are attached exactly once, with the
    // translator-owned deterministic ids.
    let request_transformers: Vec<&PluginConfig> = plugins
        .iter()
        .filter(|plugin| plugin.plugin_name == "request_transformer")
        .collect();
    let response_transformers: Vec<&PluginConfig> = plugins
        .iter()
        .filter(|plugin| plugin.plugin_name == "response_transformer")
        .collect();
    assert_eq!(request_transformers.len(), 1, "{plugins:?}");
    assert_eq!(response_transformers.len(), 1, "{plugins:?}");
    assert_eq!(
        request_transformers[0].id,
        format!("istio-vs-req-xform-{proxy_id}")
    );
    assert_eq!(
        response_transformers[0].id,
        format!("istio-vs-resp-xform-{proxy_id}")
    );

    // The rule carries the exact transform set.
    let rule = &dispatch.config["rules"][0];
    assert_eq!(
        rule["request_transform"],
        json!([
            {"operation": "update", "target": "header", "key": "x-route", "value": "canary"},
            {"operation": "add", "target": "header", "key": "x-tag", "value": "b"},
            {"operation": "remove", "target": "header", "key": "x-internal-auth"},
        ])
    );
    assert_eq!(
        rule["response_transform"],
        json!([
            {"operation": "update", "target": "header", "key": "x-served-by", "value": "ferrum"},
        ])
    );

    // And the transforms actually apply: the client's `x-internal-auth` is
    // stripped before the backend sees the request.
    let plugin = MeshRouteDispatch::new(&dispatch.config).expect("plugin config");
    let mut req = ctx("GET", "/api/users");
    let mut headers = HashMap::from([
        ("host".to_string(), "api.example.com".to_string()),
        ("x-internal-auth".to_string(), "forged".to_string()),
    ]);
    match plugin.before_proxy(&mut req, &mut headers).await {
        PluginResult::Continue => {}
        other => panic!("expected the route to match and continue, got {other:?}"),
    }
    ferrum_edge::plugins::utils::route_header_transform::finalize_route_override_request_headers(
        &mut req,
        &mut headers,
    );
    assert!(
        !headers.contains_key("x-internal-auth"),
        "headers.request.remove must strip the client header: {headers:?}"
    );
    assert_eq!(headers.get("x-route").map(String::as_str), Some("canary"));
    assert_eq!(headers.get("x-tag").map(String::as_str), Some("b"));

    // Both emitted transformer configs must construct.
    ferrum_edge::plugins::validate_plugin_config(
        "request_transformer",
        &request_transformers[0].config,
    )
    .expect("emitted request_transformer config is valid");
    ferrum_edge::plugins::validate_plugin_config(
        "response_transformer",
        &response_transformers[0].config,
    )
    .expect("emitted response_transformer config is valid");
}

/// A malformed header transform must reject the VirtualService instead of
/// silently losing the whole route's transform set at plugin-construction
/// time — including a security-relevant `remove`.
#[test]
fn vs_malformed_header_transform_fails_closed() {
    for headers in [
        json!({"request": {"set": {"bad header": "x"}}}),
        json!({"request": {"set": {"x-ok": "bad\r\nvalue"}}}),
        json!({"request": {"set": {"x-ok": 42}}}),
        json!({"request": {"set": {"transfer-encoding": "chunked"}}}),
        json!({"response": {"set": {"proxy-authenticate": "Basic"}}}),
        json!({"request": {"remove": ["bad header"]}}),
        json!({"request": {"unknown": {}}}),
        json!({"unknown": {}}),
    ] {
        let error = translate_k8s_objects(
            &[virtual_service(json!({
                "hosts": ["api.example.com"],
                "http": [{
                    "match": [{"uri": {"prefix": "/api"}}],
                    "headers": headers,
                    "route": [{"destination": {
                        "host": "echo.default.svc.cluster.local",
                        "port": {"number": 8080}
                    }}]
                }]
            }))],
            options(),
        )
        .expect_err("an unrepresentable header transform must fail closed");
        assert!(
            error.to_string().contains("VirtualService http[0].headers"),
            "diagnostic should name the field, got: {error}"
        );
    }
}

#[test]
fn vs_request_host_set_projects_to_typed_authority_rewrite() {
    for request_headers in [
        json!({"set": {"Host": "internal.svc", "x-route": "base"}}),
        json!({"set": {":authority": "internal.svc", "x-route": "base"}}),
    ] {
        let plugins = plugins_for(&[virtual_service(json!({
            "hosts": ["api.example.com"],
            "http": [{
                "headers": {"request": request_headers},
                "route": [{"destination": {
                    "host": "echo.default.svc.cluster.local",
                    "port": {"number": 8080}
                }}]
            }]
        }))]);
        let dispatch = plugins
            .iter()
            .find(|plugin| plugin.plugin_name == "mesh_route_dispatch")
            .expect("authority set must emit a mesh_route_dispatch plugin");
        let rule = &dispatch.config["rules"][0];
        assert_eq!(rule["rewrite"]["authority"].as_str(), Some("internal.svc"));
        assert_eq!(
            rule["request_transform"],
            json!([
                {"operation": "update", "target": "header", "key": "x-route", "value": "base"},
            ]),
            "Host/:authority must use the typed rewrite, not the generic transformer"
        );
    }
}

/// A single-destination `http[].route[].headers` block is applied before the
/// route-level block, matching Envoy's weighted-cluster → route ordering so
/// the route-level `set` wins.
#[test]
fn vs_single_destination_route_headers_are_applied() {
    let plugins = plugins_for(&[virtual_service(json!({
        "hosts": ["api.example.com"],
        "http": [{
            "match": [{"uri": {"prefix": "/api"}}],
            "headers": {"request": {"set": {"x-route": "base"}}},
            "route": [{
                "destination": {
                    "host": "echo.default.svc.cluster.local",
                    "port": {"number": 8080}
                },
                "headers": {"request": {"set": {"x-route": "destination"}}}
            }]
        }]
    }))]);
    let dispatch = plugins
        .iter()
        .find(|plugin| plugin.plugin_name == "mesh_route_dispatch")
        .expect("route header transforms must emit a mesh_route_dispatch plugin");

    assert_eq!(
        dispatch.config["rules"][0]["request_transform"],
        json!([
            {"operation": "update", "target": "header", "key": "x-route", "value": "destination"},
            {"operation": "update", "target": "header", "key": "x-route", "value": "base"},
        ]),
        "the route-level block must run after the per-destination block"
    );
}
