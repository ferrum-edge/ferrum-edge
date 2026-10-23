use ferrum_edge::startup::render_startup_error;

#[test]
fn fatal_mesh_startup_preserves_every_cause_in_order() {
    let cause = "mesh.workloads[0]: missing field `selector` at line 3 column 7";
    let context = "failed to load localized mesh config from '/tmp/mesh-invalid.yaml'";
    let error = anyhow::anyhow!(cause)
        .context("invalid mesh configuration document")
        .context(context);

    let message = format!("Fatal error: {}", render_startup_error(error, &[]));

    assert_eq!(
        message,
        format!(
            "Fatal error: failed to load localized mesh config from <redacted scalar>: \
             invalid mesh configuration document: {cause}"
        )
    );
}

#[test]
fn startup_sanitizes_each_cause_before_joining() {
    for quote in ['\'', '"'] {
        let error = anyhow::anyhow!("mesh.services[0].cluster_ips[0]: invalid IP address")
            .context(format!("validator rejected {quote}UNREGISTERED_TOKEN"))
            .context("startup rejected `mesh`");
        assert_eq!(
            render_startup_error(error, &[]),
            "startup rejected `mesh`: validator rejected <redacted scalar>: \
             mesh.services[0].cluster_ips[0]: invalid IP address"
        );
    }
}

#[test]
fn startup_withholds_debug_escaped_semantic_values() {
    let value = "prefix'\"UNREGISTERED_TOKEN\\tail\n";
    let error =
        anyhow::anyhow!("`host` {value:?}: invalid hostname").context("configuration rejected");
    assert_eq!(
        render_startup_error(error, &[]),
        "configuration rejected: `host` <redacted scalar>: invalid hostname"
    );
}

#[test]
fn startup_chain_redacts_database_urls_below_safe_contexts() {
    // Synthetic credentials: model a driver cause retained below a safe wrapper.
    let url = "postgres://fixture-user:fixture-password@localhost/db?token=fixture-token";
    let error = anyhow::anyhow!("driver rejected {url}")
        .context("database initialization failed (credentials withheld)")
        .context("failed to start database mode");

    let message = render_startup_error(error, &[url]);

    assert!(message.starts_with("failed to start database mode: database initialization failed"));
    assert!(message.contains("driver rejected postgres://"));
    for credential in ["fixture-user", "fixture-password", "fixture-token"] {
        assert!(
            !message.contains(credential),
            "credential escaped: {message}"
        );
    }
}

#[test]
fn startup_chain_includes_typed_sources_and_single_errors() {
    #[derive(Debug, thiserror::Error)]
    #[error("could not read mesh file")]
    struct ReadFailure(#[source] std::io::Error);

    let error = anyhow::Error::new(ReadFailure(std::io::Error::from(
        std::io::ErrorKind::PermissionDenied,
    )))
    .context("startup refused");
    let message = render_startup_error(error, &[]);
    let cause = std::io::Error::from(std::io::ErrorKind::PermissionDenied).to_string();

    assert!(message.starts_with("startup refused: could not read mesh file: "));
    assert!(message.ends_with(&cause));
    assert_eq!(
        render_startup_error(anyhow::anyhow!("invalid port"), &[]),
        "invalid port"
    );
}

#[test]
fn startup_redacts_quote_bearing_database_urls_before_withholding_spans() {
    for query in [
        "fixture-token'with-tail",
        "fixture-token\"with-tail",
        "fixture-token'\"tail",
    ] {
        let url = format!("postgres://fixture-user:fixture-password@localhost/db?token={query}");
        let error = anyhow::anyhow!("`next.field`: invalid configuration")
            .context(format!("driver rejected {url}"));
        let rendered = render_startup_error(error, &[&url]);
        for credential in [
            "fixture-user",
            "fixture-password",
            "fixture-token",
            "with-tail",
        ] {
            assert!(!rendered.contains(credential), "{rendered}");
        }
        assert_eq!(
            rendered,
            "<redacted diagnostic>: `next.field`: invalid configuration"
        );
    }
}

#[test]
fn destination_rule_port_level_diagnostics_withhold_supplied_numbers() {
    use ferrum_edge::config_sources::k8s::{
        K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
    };
    use ferrum_edge::identity::spiffe::TrustDomain;
    use serde_json::json;

    for (ports, token, reason) in [
        (vec![918273641], "918273641", "between 1 and 65535"),
        (vec![31415, 31415], "31415", "duplicate port"),
    ] {
        let object = K8sObject {
            api_version: "networking.istio.io/v1beta1".to_string(),
            kind: "DestinationRule".to_string(),
            metadata: K8sMetadata {
                name: "fixture".to_string(),
                namespace: "default".to_string(),
                ..Default::default()
            },
            spec: json!({
                "host": "reviews.default.svc.cluster.local",
                "trafficPolicy": {"portLevelSettings": ports.into_iter().map(|port| {
                    json!({"port": {"number": port}})
                }).collect::<Vec<_>>()}
            }),
            status: json!({}),
        };
        let options = K8sTranslationOptions::new(
            "default".to_string(),
            TrustDomain::new("cluster.local").unwrap(),
        );
        let error = translate_k8s_objects(&[object], options).unwrap_err();
        let rendered = render_startup_error(error.into(), &[]);
        assert!(
            rendered.contains("trafficPolicy.portLevelSettings"),
            "{rendered}"
        );
        assert!(rendered.contains(reason), "{rendered}");
        assert!(!rendered.contains(token), "{rendered}");
    }
}

#[test]
fn destination_rule_translation_warning_withholds_document_fields_at_emission() {
    use ferrum_edge::config_sources::k8s::{
        K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
    };
    use ferrum_edge::identity::spiffe::TrustDomain;
    use serde_json::json;

    let logs = DiagnosticLogs::default();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_max_level(tracing::Level::WARN)
        .with_writer(logs.clone())
        .finish();
    crate::diagnostic_test_interest::ensure_interest_floor();
    let _guard = tracing::subscriber::set_default(subscriber);
    let token = "UNREGISTERED_TRANSLATION_5591";
    let object = K8sObject {
        api_version: "networking.istio.io/v1beta1".to_string(),
        kind: "DestinationRule".to_string(),
        metadata: K8sMetadata {
            name: token.to_string(),
            namespace: "default".to_string(),
            ..Default::default()
        },
        spec: json!({
            "host": "reviews.default.svc.cluster.local",
            "trafficPolicy": {"loadBalancer": {"localityLbSetting": {
                "failoverPriority": [token, token]
            }}}
        }),
        status: json!({}),
    };
    let options = K8sTranslationOptions::new(
        "default".to_string(),
        TrustDomain::new("cluster.local").unwrap(),
    );
    translate_k8s_objects(&[object], options).unwrap();
    let output = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    assert!(
        output.contains("failoverPriority contains a duplicate"),
        "{output}"
    );
    assert!(output.contains("index=1"), "{output}");
    assert!(!output.contains(token), "{output}");
}

#[test]
fn early_scalar_helpers_withhold_unregistered_values_and_preserve_secret_placeholders() {
    use ferrum_edge::startup::{quoted_config_value, sanitize_startup_scalar};

    for value in [
        "'UNREGISTERED_ENV5591",
        "a\"UNREGISTERED_ENV5591",
        "918273641",
    ] {
        let cause = format!(
            "FERRUM_MODE {}: unsupported value",
            quoted_config_value("FERRUM_MODE", value)
        );
        let rendered = render_startup_error(anyhow::anyhow!(cause), &[]);
        assert!(rendered.contains("FERRUM_MODE"), "{rendered}");
        assert!(rendered.contains("unsupported value"), "{rendered}");
        assert!(!rendered.contains("UNREGISTERED_ENV5591"), "{rendered}");
        assert!(!rendered.contains("918273641"), "{rendered}");
        assert_eq!(sanitize_startup_scalar(value), "<redacted scalar>");
    }
    assert_eq!(
        sanitize_startup_scalar(ferrum_edge::secrets::EXTERNAL_SECRET_PLACEHOLDER),
        ferrum_edge::secrets::EXTERNAL_SECRET_PLACEHOLDER
    );
}

#[test]
fn istio_semantic_diagnostics_withhold_apostrophe_leading_values() {
    use ferrum_edge::config_sources::k8s::{
        K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
    };
    use ferrum_edge::identity::spiffe::TrustDomain;
    use serde_json::json;

    let token = "UNREGISTERED_ISTIO5591";
    let value = format!("'{token}");
    let mut cases = vec![
        (
            "PeerAuthentication",
            json!({"mtls": {"mode": value}}),
            "mtls.mode",
            "unsupported",
        ),
        (
            "AuthorizationPolicy",
            json!({"action": value}),
            "action",
            "unsupported",
        ),
    ];
    for field in [
        "ipBlocks",
        "notIpBlocks",
        "remoteIpBlocks",
        "notRemoteIpBlocks",
    ] {
        cases.push((
            "AuthorizationPolicy",
            json!({"rules": [{"from": [{"source": {field: [value]}}]}]}),
            field,
            "invalid IP",
        ));
    }
    for field in ["serviceAccounts", "notServiceAccounts"] {
        for malformed in [
            format!("{value}*"),
            format!("{value}/a/b"),
            format!("/{value}"),
        ] {
            cases.push((
                "AuthorizationPolicy",
                json!({"rules": [{"from": [{"source": {field: [malformed]}}]}]}),
                field,
                "must",
            ));
        }
    }
    for (kind, spec, field, reason) in cases {
        let object = K8sObject {
            api_version: "security.istio.io/v1beta1".to_string(),
            kind: kind.to_string(),
            metadata: K8sMetadata {
                name: value.clone(),
                namespace: "default".to_string(),
                ..Default::default()
            },
            spec,
            status: json!({}),
        };
        let options = K8sTranslationOptions::new(
            "default".to_string(),
            TrustDomain::new("cluster.local").unwrap(),
        );
        let error = translate_k8s_objects(&[object], options).unwrap_err();
        let rendered = render_startup_error(error.into(), &[]);
        assert!(rendered.contains(field), "{rendered}");
        assert!(rendered.contains(reason), "{rendered}");
        assert!(!rendered.contains(token), "{rendered}");
    }
}

#[test]
fn cidr_reasons_withhold_prefix_values_and_keep_bounds() {
    use ferrum_edge::modes::mesh::config::{ParsedCidr, validate_mesh_condition_ip_block};

    for (cidr, prefix, reason) in [
        ("192.0.2.1/219", "219", "maximum 32"),
        ("2001:db8::1/219", "219", "maximum 128"),
        ("::ffff:192.0.2.1/87", "87", "at least 96"),
    ] {
        for error in [
            ParsedCidr::parse(cidr).unwrap_err(),
            validate_mesh_condition_ip_block(cidr).unwrap_err(),
        ] {
            let rendered = render_startup_error(anyhow::anyhow!(error), &[]);
            assert!(rendered.contains("prefix"), "{rendered}");
            assert!(rendered.contains(reason), "{rendered}");
            assert!(!rendered.contains(cidr), "{rendered}");
            assert!(!rendered.contains(prefix), "{rendered}");
        }
    }
}

#[cfg(unix)]
#[tokio::test]
async fn cni_startup_failures_withhold_paths_and_keep_watcher_fallback() {
    use ferrum_edge::ebpf::NodeAgentMetrics;
    use ferrum_edge::modes::node_agent_cni_server::{cni_work_channel, spawn_cni_listener};
    use std::os::fd::AsRawFd;
    use std::sync::Arc;
    use std::time::Duration;

    // Current-thread runtime: the spawned listener is polled under this thread's
    // subscriber too. No process-global subscriber or environment mutation.
    for failure in ["parent", "owner", "lock"] {
        let directory = tempfile::tempdir().unwrap();
        let token = "UNREGISTERED_CNI5591";
        let parent = directory.path().join(token);
        if failure == "parent" {
            std::fs::write(&parent, b"occupied").unwrap();
        } else {
            std::fs::create_dir(&parent).unwrap();
        }
        let socket = parent.join("socket");
        let lock_path = parent.join("socket.lock");
        let owner = if failure == "owner" {
            let file = std::fs::File::create(&lock_path).unwrap();
            // SAFETY: file remains owned until after the listener task exits.
            assert_eq!(unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) }, 0);
            Some(file)
        } else {
            if failure == "lock" {
                std::fs::create_dir(&lock_path).unwrap();
            }
            None
        };
        let logs = DiagnosticLogs::default();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .without_time()
            .with_writer(logs.clone())
            .finish();
        crate::diagnostic_test_interest::ensure_interest_floor();
        let _guard = tracing::subscriber::set_default(subscriber);
        let (sender, mut receiver) = cni_work_channel();
        let (_shutdown, shutdown_rx) = tokio::sync::watch::channel(false);
        let task = spawn_cni_listener(
            socket.to_str().unwrap().to_string(),
            sender,
            Arc::new(NodeAgentMetrics::default()),
            shutdown_rx,
        );
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
        assert!(
            receiver.recv().await.is_none(),
            "failed listener must release its queue"
        );
        assert!(
            !socket.exists(),
            "failed listener must not publish a socket"
        );
        if failure == "parent" {
            assert_eq!(std::fs::read(&parent).unwrap(), b"occupied");
        } else {
            assert!(
                lock_path.exists(),
                "ownership failure must preserve the owner path"
            );
        }
        let output = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
        assert!(output.contains("kube-rs watcher"), "{output}");
        let reason = if failure == "owner" {
            "ownership_conflict"
        } else {
            "ownership_io_error"
        };
        assert!(output.contains(reason), "{output}");
        assert!(!output.contains(token), "{output}");
        drop(owner);
    }
}

#[tokio::test]
async fn mongo_failover_emissions_withhold_invalid_options_before_network_io() {
    use ferrum_edge::config::mongo_store::MongoStore;

    // Invalid maxPoolSize is rejected by ClientOptions before any client/socket
    // exists. Exercise the real early failure events without a live database.
    // The values are unregistered: URL credential scrubbing alone is insufficient.
    for value in [
        "'UNREGISTERED_MONGO5591",
        "a\"UNREGISTERED_MONGO5591",
        "918273641999999999999",
        "true",
    ] {
        let logs = DiagnosticLogs::default();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .without_time()
            .with_writer(logs.clone())
            .finish();
        crate::diagnostic_test_interest::ensure_interest_floor();
        let _guard = tracing::subscriber::set_default(subscriber);
        let url = format!("mongodb://localhost/?maxPoolSize={value}");
        let result = MongoStore::connect_with_failover(
            &url,
            "unused",
            None,
            None,
            None,
            Some(1),
            Some(1),
            false,
            None,
            None,
            None,
            false,
            std::slice::from_ref(&url),
        )
        .await;
        let error = result
            .err()
            .expect("invalid options must reject the connection");
        assert!(error.to_string().contains("All MongoDB URLs failed"));
        assert!(error.to_string().contains("Tried 1 failover URL(s)"));
        let output = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
        assert!(
            output.contains("Primary MongoDB connection failed"),
            "{output}"
        );
        assert!(output.contains("Trying 1 failover URL(s)"), "{output}");
        assert!(output.contains("Failover MongoDB #1"), "{output}");
        assert!(output.contains("<redacted scalar>"), "{output}");
        assert!(output.contains("details withheld"), "{output}");
        for withheld in ["UNREGISTERED_MONGO5591", "918273641999999999999", "true"] {
            assert!(!output.contains(withheld), "{output}");
        }
    }
}

#[derive(Clone, Default)]
struct DiagnosticLogs(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for DiagnosticLogs {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for DiagnosticLogs {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}
