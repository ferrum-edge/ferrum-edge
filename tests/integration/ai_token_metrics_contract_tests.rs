//! Cross-module registration and validation contract for ai_token_metrics.

use ferrum_edge::plugins::{ProxyProtocol, create_plugin, validate_plugin_config};
use serde_json::json;

#[test]
fn registration_is_http_only_and_shared_validation_rejects_unknown_keys() {
    let plugin = create_plugin(
        "ai_token_metrics",
        &json!({
            "provider": "openai",
            "metadata_prefix": "tenant.ai",
            "buffer_streaming_responses": true
        }),
    )
    .expect("valid ai_token_metrics config")
    .expect("built-in plugin is registered");

    assert_eq!(plugin.supported_protocols(), &[ProxyProtocol::Http]);
    assert!(plugin.requires_response_body_buffering());

    let error = validate_plugin_config("ai_token_metrics", &json!({"cost_per_promt_token": 0.01}))
        .expect_err("unknown cost key must fail shared reload validation");
    assert!(error.contains("cost_per_promt_token"), "got: {error}");
    assert!(
        error.contains("unknown configuration key(s)"),
        "got: {error}"
    );
}
