mod admin;
mod build;
mod cli;
mod config;
mod env_lock;
mod gateway_trust_observability_lock;
mod identity;
mod logging_tests;
mod notifications;
mod openapi_yaml_tests;
// The OpenAPI parity tests build plugin fixtures with the shared plugin
// helpers; only the test-free helper module is compiled here (the plugin
// suites live in `unit_plugins_a_tests` / `unit_plugins_b_tests`).
#[allow(dead_code, unused_imports)]
mod plugins {
    #[allow(dead_code)]
    pub(crate) mod plugin_utils;

    pub(crate) use plugin_utils::{
        make_plugin_config_with_json, make_proxy, minimal_plugin_config,
    };
}
mod secrets;
#[allow(dead_code, unused_imports)]
pub(crate) mod tls;
mod util;
