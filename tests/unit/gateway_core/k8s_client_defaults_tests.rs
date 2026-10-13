//! Every Ferrum Kubernetes client keeps kube 3's response read timeout and
//! leaves request retry to its caller (`k8s_controller::with_ferrum_client_defaults`),
//! and kubeconfig errors never carry kubeconfig source text
//! (`k8s_controller::redacted_kube_config_error`).

use std::time::Duration;

use ferrum_edge::k8s_controller::{
    KUBE_CLIENT_READ_TIMEOUT, KUBECONFIG_PARSE_ERROR_REDACTED, redacted_kube_config_error,
    with_ferrum_client_defaults,
};

const SENTINEL_TOKEN: &str = "sentinel-token-7f3c9a";
const SENTINEL_PASSWORD: &str = "sentinel-password-2b8e41";

#[test]
fn client_defaults_restore_the_kube3_read_timeout_and_disable_retry() {
    let mut config = kube::Config::new("https://127.0.0.1:6443".parse().expect("valid URI"));
    config.read_timeout = None;
    config.default_retry = true;

    let config = with_ferrum_client_defaults(config);

    assert_eq!(KUBE_CLIENT_READ_TIMEOUT, Duration::from_secs(295));
    assert_eq!(config.read_timeout, Some(KUBE_CLIENT_READ_TIMEOUT));
    assert!(!config.default_retry);
}

fn malformed_kubeconfig() -> String {
    // `provideClusterInfo` must be a boolean; the credentials sit right next to it.
    format!(
        "apiVersion: v1\n\
         kind: Config\n\
         users:\n\
         - name: u\n\
         \x20 user:\n\
         \x20   token: {SENTINEL_TOKEN}\n\
         \x20   password: {SENTINEL_PASSWORD}\n\
         \x20   exec:\n\
         \x20     command: c\n\
         \x20     apiVersion: client.authentication.k8s.io/v1\n\
         \x20     provideClusterInfo: [not, a, bool]\n"
    )
}

#[test]
fn kubeconfig_parse_errors_are_redacted() {
    let error = kube::config::Kubeconfig::from_yaml(&malformed_kubeconfig())
        .expect_err("malformed kubeconfig must not parse");

    let rendered = redacted_kube_config_error(&error);

    assert_eq!(rendered, KUBECONFIG_PARSE_ERROR_REDACTED);
    assert!(!rendered.contains(SENTINEL_TOKEN));
    assert!(!rendered.contains(SENTINEL_PASSWORD));
}

#[test]
fn a_wrapped_kubeconfig_parse_error_is_redacted_too() {
    let parse = kube::config::Kubeconfig::from_yaml(&malformed_kubeconfig())
        .expect_err("malformed kubeconfig must not parse");
    let wrapped = Wrapper(parse);

    let rendered = redacted_kube_config_error(&wrapped);

    assert_eq!(rendered, KUBECONFIG_PARSE_ERROR_REDACTED);
    assert!(!rendered.contains(SENTINEL_TOKEN));
    assert!(!rendered.contains(SENTINEL_PASSWORD));
}

/// An outer error whose `Display` repeats its source, as kube's own wrappers do.
#[derive(Debug)]
struct Wrapper(kube::config::KubeconfigError);

impl std::fmt::Display for Wrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "failed to load config: {}", self.0)
    }
}

impl std::error::Error for Wrapper {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}
