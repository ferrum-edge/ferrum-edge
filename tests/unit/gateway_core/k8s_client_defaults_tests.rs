//! Every Ferrum Kubernetes client keeps kube 3's response read timeout and
//! leaves request retry to its caller (`k8s_controller::with_ferrum_client_defaults`),
//! and kubeconfig errors never carry kubeconfig source text
//! (`k8s_controller::redacted_kube_config_error`).

use std::time::Duration;

use ferrum_edge::k8s_controller::{
    KUBE_AUTH_EXEC_PARSE_ERROR_REDACTED, KUBE_CLIENT_READ_TIMEOUT, KUBECONFIG_PARSE_ERROR_REDACTED,
    redact_kube_auth_error, redacted_kube_config_error, with_ferrum_client_defaults,
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

/// A serde-saphyr error whose rendering would quote the sentinels, obtained
/// through kube (Ferrum has no direct serde-saphyr dependency).
fn saphyr_parse_error() -> kube::config::KubeconfigError {
    kube::config::Kubeconfig::from_yaml(&malformed_kubeconfig())
        .expect_err("malformed kubeconfig must not parse")
}

#[test]
fn exec_plugin_parse_errors_are_redacted_in_the_client_stack() {
    let kube::config::KubeconfigError::Parse(inner) = saphyr_parse_error() else {
        panic!("expected a YAML parse error");
    };
    let auth = kube::client::AuthError::AuthExecParse(*inner);
    let boxed: tower::BoxError = Box::new(auth);

    let mapped = redact_kube_auth_error(boxed);
    let rendered = mapped.to_string();

    assert_eq!(rendered, KUBE_AUTH_EXEC_PARSE_ERROR_REDACTED);
    assert!(!rendered.contains(SENTINEL_TOKEN));
    assert!(!rendered.contains(SENTINEL_PASSWORD));
    assert!(
        mapped.source().is_none(),
        "the redacted error must not chain the original"
    );
    // `kube::Client::send` wraps a middleware error as `Error::Service`.
    let as_kube = kube::Error::Service(mapped).to_string();
    assert!(!as_kube.contains(SENTINEL_TOKEN));
    assert!(!as_kube.contains(SENTINEL_PASSWORD));
}

#[test]
fn unrelated_client_errors_pass_through_unchanged() {
    let original: tower::BoxError = "connection refused".into();
    assert_eq!(
        redact_kube_auth_error(original).to_string(),
        "connection refused"
    );
}

/// Every production Kubernetes client must come from
/// `k8s_controller::build_kube_client_from_config`, which applies the kube 3
/// read timeout / no-retry defaults and the credential-redacting error layer.
#[test]
fn production_kube_clients_use_the_shared_constructor() {
    let forbidden = [
        "kube::Client::try_from",
        "Client::try_default(",
        "ClientBuilder::try_from",
        "Config::infer(",
        "kube::Client::new(",
    ];
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut offenders = Vec::new();
    let mut stack = vec![root];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("read src dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("read source file");
            let is_constructor_home = path.ends_with("k8s_controller/mod.rs");
            for (index, line) in text.lines().enumerate() {
                let code = line.split("//").next().unwrap_or("");
                for needle in forbidden {
                    let hit = code.contains(needle);
                    let allowed = is_constructor_home && needle == "ClientBuilder::try_from";
                    if hit && !allowed {
                        offenders.push(format!(
                            "{}:{}: {}",
                            path.display(),
                            index + 1,
                            line.trim()
                        ));
                    }
                }
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "build Kubernetes clients with k8s_controller::build_kube_client_from_config:\n{}",
        offenders.join("\n")
    );
}

/// kube runs the exec credential plugin while the client is built, so a
/// malformed plugin response surfaces from `build_kube_client_from_config`.
#[cfg(unix)]
#[test]
fn malformed_exec_plugin_output_is_redacted_when_the_client_is_built() {
    use ferrum_edge::k8s_controller::build_kube_client_from_config;

    // `expirationTimestamp` must be a string, so serde-saphyr rejects the
    // document and its error would quote the token next to it.
    let output = format!(
        r#"{{"apiVersion":"client.authentication.k8s.io/v1","kind":"ExecCredential","status":{{"token":"{SENTINEL_TOKEN}","expirationTimestamp":["not-a-time"]}}}}"#
    );
    let mut config = kube::Config::new("https://127.0.0.1:6443".parse().expect("valid URI"));
    config.auth_info.exec = Some(kube::config::ExecConfig {
        api_version: Some("client.authentication.k8s.io/v1".to_string()),
        command: Some("sh".to_string()),
        args: Some(vec!["-c".to_string(), format!("printf '%s' '{output}'")]),
        ..Default::default()
    });

    let Err(error) = build_kube_client_from_config(config) else {
        panic!("malformed exec plugin output must fail client construction");
    };

    assert!(
        error.contains(KUBE_AUTH_EXEC_PARSE_ERROR_REDACTED),
        "expected the redacted exec parse error, got: {error}"
    );
    assert!(!error.contains(SENTINEL_TOKEN), "{error}");
}
