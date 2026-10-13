//! Every Ferrum Kubernetes client keeps kube 3's response read timeout and
//! leaves request retry to its caller (`k8s_controller::with_ferrum_client_defaults`).

use std::time::Duration;

use ferrum_edge::k8s_controller::{KUBE_CLIENT_READ_TIMEOUT, with_ferrum_client_defaults};

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
