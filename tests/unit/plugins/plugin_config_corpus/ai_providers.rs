//! Config contracts for AI provider, guard, metering, and invocation built-ins
//! (issue #6616 sweep).
//!
//! Flat-config plugins in this family (`ai_request_guard`, `ai_semantic_cache`,
//! `ai_prompt_compressor`, `serverless_function`, `request_mirror`,
//! `load_testing`) have no nested object below the root, so their minimal
//! config is the whole contract.
use ferrum_edge::plugins::PluginConfigContract;
use serde_json::json;

pub(super) fn contract(name: &str) -> Option<PluginConfigContract> {
    Some(match name {
        "ai_federation" => PluginConfigContract::closed(vec![json!({
            "providers": [
                {
                    "name": "primary",
                    "provider_type": "openai",
                    "api_key": "sk-test",
                    "model_patterns": ["gpt-*"],
                    "model_mapping": {"gpt-4": "gpt-4o"},
                    "default_model": "gpt-4o",
                    "circuit_breaker": {
                        "failure_threshold": 3,
                        "cooldown_seconds": 30,
                        "success_threshold": 1
                    }
                },
                {
                    "name": "secondary",
                    "provider_type": "openai",
                    "api_key": "sk-test-secondary",
                    "priority": 2
                }
            ],
            "streaming": {
                "enabled": true,
                "max_event_bytes": 262144,
                "read_timeout_seconds": 120
            }
        })])
        // Keys are client-requested model names mapped to provider-native ones.
        .with_free_form_objects(&["providers[].model_mapping"]),
        "ai_stream_router" => PluginConfigContract::closed(vec![json!({
            "providers": [
                {
                    "name": "openai",
                    "provider_type": "openai",
                    "endpoint": "https://api.openai.com/v1/chat/completions",
                    "api_key": "sk-test",
                    "model_patterns": ["gpt-*"],
                    "priority": 1,
                    "allow_plaintext": false,
                    "inherit_backend_tls": false
                },
                {
                    "name": "anthropic",
                    "provider_type": "anthropic",
                    "endpoint": "https://api.anthropic.com/v1/messages",
                    "api_key": "sk-ant-test",
                    "model_patterns": ["claude-*"],
                    "priority": 2,
                    "anthropic_version": "2023-06-01",
                    "default_max_tokens": 1024
                }
            ]
        })]),
        "ai_prompt_shield" => PluginConfigContract::closed(vec![json!({
            "action": "redact",
            "patterns": ["ssn", "email"],
            "custom_patterns": [{"name": "employee_id", "regex": "EMP-[0-9]{6}"}]
        })]),
        "ai_response_guard" => PluginConfigContract::closed(vec![
            json!({
                "action": "redact",
                "pii_patterns": ["email"],
                "custom_pii_patterns": [{"name": "employee_id", "regex": "EMP-[0-9]{6}"}],
                "blocked_patterns": [{"name": "secret_marker", "regex": "TOP-SECRET-[A-Z]+"}],
                "allowlist": {
                    "values": ["support@example.com"],
                    "patterns": ["[a-z]+@example\\.com"]
                }
            }),
            json!({
                "pii_patterns": ["ssn"],
                "grpc": {
                    "descriptor_path": "/etc/ferrum/protos/greeter.binpb",
                    "methods": {
                        "/test.Greeter/SayHello": {
                            "response_type": "test.HelloReply",
                            "text_fields": ["message"]
                        }
                    },
                    "max_message_bytes": 1048576,
                    "max_messages": 64
                }
            }),
        ])
        // Keys are operator-chosen gRPC method paths (`/package.Service/Method`).
        .with_free_form_objects(&["grpc.methods"]),
        "ai_rate_limiter" => PluginConfigContract::closed(vec![
            json!({
                "token_limit": 100000,
                "limit_by": "consumer",
                "consumer_limits": {"alice": 200000},
                "model_limits": {"gpt-4o": 50000}
            }),
            // Redis mode reaches `FailoverLimiter`, whose health observer must
            // start at commit, not construction.
            json!({
                "token_limit": 100000,
                "sync_mode": "redis",
                "redis_url": "redis://127.0.0.1:6379/0"
            }),
        ])
        // Keys are operator-chosen consumer identities and model names.
        .with_free_form_objects(&["consumer_limits", "model_limits"]),
        "ai_token_metrics" => PluginConfigContract::closed(vec![json!({
            "model_pricing": [{
                "model": "gpt-4o*",
                "cost_per_prompt_token": 0.000005,
                "cost_per_completion_token": 0.000015
            }]
        })]),
        _ => return None,
    })
}
