use ferrum_edge::config::types::Upstream;

fn upstream(source: &str) -> Upstream {
    serde_json::from_value(serde_json::json!({
        "id": "module-policy",
        "targets": [{"host": "localhost", "port": 443}],
        "backend_tls_client_cert_path": "/operator/client.crt",
        "backend_tls_client_key_path": source,
    }))
    .expect("upstream fixture")
}

#[cfg(not(feature = "pkcs11"))]
#[test]
fn pkcs11_admission_requires_build_feature() {
    let errors = upstream("pkcs11://key?module=/untrusted/module.so")
        .validate_fields()
        .expect_err("unsupported key source");
    assert!(
        errors
            .iter()
            .any(|error| error.contains("'pkcs11' Cargo feature"))
    );
}

#[cfg(feature = "pkcs11")]
mod enabled {
    use super::*;
    use crate::unit::env_lock::EnvGuard;
    use ferrum_edge::tls::pkcs11::validate_module_source_uri;
    use ferrum_edge::tls::source::{CertSource, MaterialKind};

    const ALLOWED: &str = "FERRUM_PKCS11_MODULE_ALLOWED_PATHS";
    const DEFAULT: &str = "FERRUM_PKCS11_MODULE_PATH";
    const INDIRECT: &str = "FERRUM_PKCS11_TEST_MODULE_INDIRECT";

    fn policy(source: &str) -> anyhow::Result<()> {
        let CertSource::Uri(uri) = CertSource::parse(source, MaterialKind::Key) else {
            panic!("URI fixture");
        };
        validate_module_source_uri(&uri)
    }

    #[test]
    fn module_policy_applies_at_admission_and_runtime_for_every_alias() {
        let env = EnvGuard::new(&[ALLOWED, DEFAULT, INDIRECT]);
        let directory = tempfile::tempdir().unwrap();
        let allowed = directory.path().join("allowed");
        let outside = directory.path().join("allowed-sibling");
        std::fs::create_dir(&allowed).unwrap();
        std::fs::create_dir(&outside).unwrap();
        let inside_module = allowed.join("module.so");
        let outside_module = outside.join("module.so");
        std::fs::write(&inside_module, []).unwrap();
        std::fs::write(&outside_module, []).unwrap();
        env.set(ALLOWED, allowed.to_str().unwrap());
        for option in ["module", "module_path", "module_env"] {
            for (module, admitted) in [(&inside_module, true), (&outside_module, false)] {
                env.set(INDIRECT, module.to_str().unwrap());
                let value = if option == "module_env" {
                    INDIRECT
                } else {
                    module.to_str().unwrap()
                };
                let source = format!("pkcs11://key?{option}={value}");
                let result = upstream(&source).validate_fields();
                assert_eq!(result.is_ok(), admitted, "{result:?}");
                let runtime = policy(&source);
                assert_eq!(runtime.is_ok(), admitted);
                if !admitted {
                    assert!(
                        result
                            .unwrap_err()
                            .iter()
                            .any(|error| error.contains(ALLOWED))
                    );
                    assert!(runtime.unwrap_err().to_string().contains(ALLOWED));
                }
            }
        }

        let source = format!("pkcs11://key?module={}", inside_module.display());
        env.set(ALLOWED, inside_module.to_str().unwrap());
        upstream(&source).validate_fields().unwrap();
        env.set(ALLOWED, outside_module.to_str().unwrap());
        assert!(policy(&source).is_err());
        let snapshot: ferrum_edge::config::types::GatewayConfig =
            serde_json::from_value(serde_json::json!({
                "version": "1",
                "proxies": [],
                "plugin_configs": [],
                "frontend_tls_key_path": source,
                "upstreams": [upstream(&source)],
            }))
            .unwrap();
        let errors = snapshot
            .validate_all_fields(30)
            .expect_err("DP admission must apply local policy to distributed keys");
        assert!(
            errors.iter().any(|error| {
                error.contains("frontend_tls_key_path") && error.contains(ALLOWED)
            })
        );
        assert!(errors.iter().any(|error| {
            error.contains("backend_tls_client_key_path") && error.contains(ALLOWED)
        }));
        for malformed in ["", "relative", "/nonexistent/pkcs11-policy-entry"] {
            env.set(ALLOWED, malformed);
            assert!(policy(&source).is_err());
        }

        env.unset(ALLOWED);
        env.set(DEFAULT, inside_module.to_str().unwrap());
        upstream("pkcs11://key").validate_fields().unwrap();
        policy("pkcs11://key").unwrap();
        for source in [
            source.as_str(),
            "pkcs11://key?module_path=",
            "pkcs11://key?module_env=FERRUM_PKCS11_MODULE_PATH",
        ] {
            assert!(upstream(source).validate_fields().is_err());
            assert!(policy(source).unwrap_err().to_string().contains(ALLOWED));
        }

        #[cfg(unix)]
        {
            env.set(ALLOWED, allowed.to_str().unwrap());
            let link = allowed.join("escape.so");
            std::os::unix::fs::symlink(&outside_module, &link).unwrap();
            assert!(policy(&format!("pkcs11://key?module={}", link.display())).is_err());
            let traversal = allowed.join("../allowed-sibling/module.so");
            assert!(policy(&format!("pkcs11://key?module={}", traversal.display())).is_err());
        }
    }
}
