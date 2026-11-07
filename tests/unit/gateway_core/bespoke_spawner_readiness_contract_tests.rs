//! Static contract: the per-site policy of every bespoke functional spawner
//! that uses the shared child-bound readiness helpers.
//!
//! `wait_for_child_gateway_readiness` and `wait_for_child_tcp_accept` in
//! `tests/common/gateway_harness.rs` hold the shared mechanism, which is pinned
//! by the `child_readiness_*` / `child_tcp_accept_*` harness tests. What stays
//! at each call site is policy: the startup budget, whether a TCP-accept second
//! stage runs, and that it spends the same absolute deadline. Those choices are
//! intentional (an H3/TLS cold start needs 60 s; a stream or UDP listener treats
//! a probe connection as real traffic), so a "harmonising" edit must fail here.
//!
//! `include_str!` only: no runtime, no gateway.

/// One bespoke spawner's `wait_for_owned_gateway` policy.
struct Site {
    file: &'static str,
    src: &'static str,
    timeout_secs: u64,
    /// `Some(port variable)` when the site waits for a TCP accept after
    /// readiness; `None` when it must not dial its listener at all.
    tcp_stage_port: Option<&'static str>,
    /// Call sites of the local `wait_for_owned_gateway`.
    callers: usize,
}

const SITES: &[Site] = &[
    Site {
        file: "functional_a2a_gateway_grpc_card_test.rs",
        src: include_str!("../../functional/functional_a2a_gateway_grpc_card_test.rs"),
        timeout_secs: 30,
        tcp_stage_port: Some("gateway_port"),
        callers: 1,
    },
    Site {
        file: "functional_grpc_plugins_test.rs",
        src: include_str!("../../functional/functional_grpc_plugins_test.rs"),
        timeout_secs: 30,
        tcp_stage_port: Some("gateway_port"),
        callers: 1,
    },
    Site {
        file: "functional_otel_ldap_test.rs",
        src: include_str!("../../functional/functional_otel_ldap_test.rs"),
        timeout_secs: 30,
        tcp_stage_port: Some("proxy_port"),
        callers: 3,
    },
    Site {
        // 60 s: documented TLS/HTTP3 cold start on loaded runners.
        file: "functional_websocket_test.rs",
        src: include_str!("../../functional/functional_websocket_test.rs"),
        timeout_secs: 60,
        tcp_stage_port: Some("gateway_port"),
        callers: 4,
    },
    Site {
        file: "functional_overload_test.rs",
        src: include_str!("../../functional/functional_overload_test.rs"),
        timeout_secs: 30,
        tcp_stage_port: None,
        callers: 2,
    },
    Site {
        // No probe: passthrough listeners treat every accepted socket as traffic.
        file: "functional_passthrough_test.rs",
        src: include_str!("../../functional/functional_passthrough_test.rs"),
        timeout_secs: 30,
        tcp_stage_port: None,
        callers: 1,
    },
    Site {
        // No probe: the stream listener is UDP/DTLS.
        file: "scripted_backend_udp_tests.rs",
        src: include_str!("../../functional/scripted_backend_udp_tests.rs"),
        timeout_secs: 30,
        tcp_stage_port: None,
        callers: 1,
    },
];

fn squeezed(src: &str) -> String {
    src.chars().filter(|c| !c.is_whitespace()).collect()
}

/// The squeezed body of the site's `async fn wait_for_owned_gateway`.
fn wrapper_body(site: &Site) -> String {
    let start = site
        .src
        .find("async fn wait_for_owned_gateway(")
        .unwrap_or_else(|| panic!("{}: wait_for_owned_gateway must exist", site.file));
    let end = site.src[start..]
        .find("\n}\n")
        .map(|offset| start + offset + 3)
        .unwrap_or_else(|| panic!("{}: wait_for_owned_gateway must end", site.file));
    squeezed(&site.src[start..end])
}

/// Squeezed argument lists of every call to `wait_for_owned_gateway`.
fn caller_args(site: &Site) -> Vec<String> {
    let compact = squeezed(site.src);
    let needle = "wait_for_owned_gateway(";
    let mut args = Vec::new();
    let mut from = 0;
    while let Some(offset) = compact[from..].find(needle) {
        let at = from + offset;
        from = at + needle.len();
        if compact[..at].ends_with("fn") {
            continue; // the definition
        }
        let close = compact[from..]
            .find(')')
            .unwrap_or_else(|| panic!("{}: unterminated call", site.file));
        args.push(compact[from..from + close].to_string());
    }
    args
}

#[test]
fn bespoke_spawner_wrappers_keep_their_timeout_and_second_stage() {
    for site in SITES {
        let body = wrapper_body(site);
        let file = site.file;

        assert!(
            body.contains(&format!(
                "constSTARTUP_TIMEOUT:Duration=Duration::from_secs({});",
                site.timeout_secs
            )),
            "{file}: startup budget must stay {} s",
            site.timeout_secs
        );
        assert_eq!(
            body.matches("from_secs(").count(),
            1,
            "{file}: STARTUP_TIMEOUT must be the only budget"
        );
        assert!(
            body.contains("child:&mut") && body.contains("observability_token:&str"),
            "{file}: the wrapper must take the attempt's child and token"
        );

        let readiness = body
            .find(
                "crate::common::wait_for_child_gateway_readiness(\
                 child,admin_port,observability_token,STARTUP_TIMEOUT",
            )
            .unwrap_or_else(|| {
                panic!("{file}: readiness must forward child, admin port, token and budget")
            });

        match site.tcp_stage_port {
            Some(port) => {
                let deadline = [
                    "letdeadline=std::time::Instant::now()+STARTUP_TIMEOUT;",
                    "letdeadline=Instant::now()+STARTUP_TIMEOUT;",
                ]
                .iter()
                .find_map(|pattern| body.find(*pattern))
                .unwrap_or_else(|| {
                    panic!("{file}: one absolute deadline must be computed from STARTUP_TIMEOUT")
                });
                let tcp = body
                    .find(&format!(
                        "crate::common::wait_for_child_tcp_accept(child,{port},deadline)"
                    ))
                    .unwrap_or_else(|| {
                        panic!("{file}: TCP stage must dial {port} with the shared deadline")
                    });
                assert!(
                    deadline < readiness && readiness < tcp,
                    "{file}: the deadline must be fixed before readiness, and the TCP stage \
                     must follow readiness"
                );
                assert!(
                    body[readiness..tcp].contains(".await?;"),
                    "{file}: a failed readiness stage must not fall through to the TCP stage"
                );
            }
            None => {
                assert!(
                    !body.contains("wait_for_child_tcp_accept")
                        && !body.contains("TcpStream")
                        && !body.contains("deadline"),
                    "{file}: this site must not dial its listener as a readiness probe"
                );
            }
        }
    }
}

#[test]
fn bespoke_spawner_callers_forward_the_attempt_child_and_token() {
    for site in SITES {
        let args = caller_args(site);
        assert_eq!(
            args.len(),
            site.callers,
            "{}: unexpected number of wait_for_owned_gateway callers: {args:?}",
            site.file
        );
        for call in &args {
            assert!(
                call.starts_with("&mut") && call.contains("&observability_token"),
                "{}: every caller must pass the spawned child and this attempt's token, \
                 got ({call})",
                site.file
            );
        }
    }
}

/// A new spawner adopting the shared helper must be classified here.
#[test]
fn every_shared_readiness_adopter_is_in_the_site_table() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/functional");
    let mut adopters = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("read tests/functional") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
            continue;
        }
        let src = std::fs::read_to_string(&path).expect("read functional test source");
        if src.contains("wait_for_child_gateway_readiness(")
            || src.contains("wait_for_child_tcp_accept(")
        {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .expect("utf-8 file name")
                .to_string();
            adopters.push(name);
        }
    }
    adopters.sort();
    let mut table: Vec<String> = SITES.iter().map(|site| site.file.to_string()).collect();
    table.sort();
    assert_eq!(
        adopters, table,
        "every functional spawner using the shared child-bound readiness helpers must have \
         a row in SITES with its timeout and second-stage policy"
    );
}
