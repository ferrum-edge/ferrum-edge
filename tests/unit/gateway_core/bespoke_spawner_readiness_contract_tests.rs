//! Static contract: the per-site policy of every bespoke functional spawner
//! that proves readiness through the shared child-bound helpers.
//!
//! Every site mints a `SpawnedGatewayIdentity` per spawn attempt, applies it
//! to the `Command`, and waits on `wait_for_owned_gateway_identity` (ready
//! `/health`, HTTP 200 from JWT-only `GET /proxies` under the attempt's admin
//! JWT, `Child::try_wait` liveness). The metrics-token `/health` tier alone is
//! not ownership: `FERRUM_METRICS_ALLOWED_CIDRS` grants it to a foreign gateway
//! too (issue #7076). The mechanism is pinned by the harness's
//! `jwt_ownership_*` / `child_tcp_accept_*` tests in
//! `tests/common/gateway_harness.rs`. What stays at each call site is policy:
//! the startup budget, whether a second stage runs, and that a TCP-accept
//! stage spends the same absolute deadline. Those choices are intentional (an
//! H3/TLS cold start needs 60 s; a stream or UDP listener treats a probe
//! connection as real traffic), so a "harmonising" edit must fail here.
//!
//! `include_str!` only: no runtime, no gateway.

/// What a site does after the ownership barrier.
enum SecondStage {
    /// `wait_for_child_tcp_accept(child, <port>, deadline)` on the shared
    /// absolute deadline.
    TcpAccept(&'static str),
    /// The site's own child-bound probe with its own budget (the call text).
    Own(&'static str),
    /// Nothing: the listener must not be dialed as a readiness probe.
    None,
}

/// One bespoke spawner's `wait_for_owned_gateway` policy.
struct Site {
    file: &'static str,
    src: &'static str,
    timeout_secs: u64,
    second_stage: SecondStage,
    /// Call sites of the local `wait_for_owned_gateway`.
    callers: usize,
}

const SITES: &[Site] = &[
    Site {
        file: "functional_a2a_gateway_grpc_card_test.rs",
        src: include_str!("../../functional/functional_a2a_gateway_grpc_card_test.rs"),
        timeout_secs: 30,
        second_stage: SecondStage::TcpAccept("gateway_port"),
        callers: 1,
    },
    Site {
        file: "functional_grpc_plugins_test.rs",
        src: include_str!("../../functional/functional_grpc_plugins_test.rs"),
        timeout_secs: 30,
        second_stage: SecondStage::TcpAccept("gateway_port"),
        callers: 1,
    },
    Site {
        file: "functional_otel_ldap_test.rs",
        src: include_str!("../../functional/functional_otel_ldap_test.rs"),
        timeout_secs: 30,
        second_stage: SecondStage::TcpAccept("proxy_port"),
        callers: 3,
    },
    Site {
        // 60 s: documented TLS/HTTP3 cold start on loaded runners.
        file: "functional_websocket_test.rs",
        src: include_str!("../../functional/functional_websocket_test.rs"),
        timeout_secs: 60,
        second_stage: SecondStage::TcpAccept("gateway_port"),
        callers: 4,
    },
    Site {
        file: "functional_overload_test.rs",
        src: include_str!("../../functional/functional_overload_test.rs"),
        timeout_secs: 30,
        second_stage: SecondStage::None,
        callers: 2,
    },
    Site {
        // No probe: passthrough listeners treat every accepted socket as traffic.
        file: "functional_passthrough_test.rs",
        src: include_str!("../../functional/functional_passthrough_test.rs"),
        timeout_secs: 30,
        second_stage: SecondStage::None,
        callers: 1,
    },
    Site {
        // No probe: the stream listener is UDP/DTLS.
        file: "scripted_backend_udp_tests.rs",
        src: include_str!("../../functional/scripted_backend_udp_tests.rs"),
        timeout_secs: 30,
        second_stage: SecondStage::None,
        callers: 1,
    },
    Site {
        // Separate h2c probe: #7044 kept its own 15 s budget on purpose.
        file: "functional_grpc_test.rs",
        src: include_str!("../../functional/functional_grpc_test.rs"),
        timeout_secs: 15,
        second_stage: SecondStage::Own("wait_for_gateway(child,gateway_port).await"),
        callers: 1,
    },
    Site {
        file: "functional_websocket_limits_test.rs",
        src: include_str!("../../functional/functional_websocket_limits_test.rs"),
        timeout_secs: 15,
        second_stage: SecondStage::TcpAccept("gateway_port"),
        callers: 1,
    },
];

/// Spawners that deliberately keep the health-only
/// `wait_for_child_gateway_readiness` barrier because their scenario cannot
/// enable admin-auth verification: `(file, reason)`. Empty: every bespoke
/// spawner can mint a per-attempt identity.
const HEALTH_ONLY_SITES: &[(&str, &str)] = &[];

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

/// Squeezed argument lists of every call to `wait_for_owned_gateway`, up to
/// the matching close paren (arguments such as `child.child_mut()` nest).
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
        let mut depth = 1usize;
        let close = compact[from..]
            .char_indices()
            .find_map(|(index, c)| {
                match c {
                    '(' => depth += 1,
                    ')' => depth -= 1,
                    _ => {}
                }
                (depth == 0).then_some(index)
            })
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
            body.contains("child:&mutstd::process::Child")
                && body.contains("identity:&crate::common::SpawnedGatewayIdentity"),
            "{file}: the wrapper must take the attempt's child and identity"
        );
        assert!(
            !body.contains("wait_for_child_gateway_readiness")
                && !body.contains("observability_token"),
            "{file}: the token-only health barrier is not ownership (issue #7076)"
        );

        let ownership = body
            .find(
                "crate::common::wait_for_owned_gateway_identity(\
                 child,admin_port,identity,STARTUP_TIMEOUT)",
            )
            .unwrap_or_else(|| {
                panic!(
                    "{file}: the JWT ownership barrier must get the child, admin port, \
                     identity and budget"
                )
            });

        match site.second_stage {
            SecondStage::TcpAccept(port) => {
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
                    deadline < ownership && ownership < tcp,
                    "{file}: the deadline must be fixed before the ownership barrier, and \
                     the TCP stage must follow it"
                );
                assert!(
                    body[ownership..tcp].contains(".await?;"),
                    "{file}: a failed ownership barrier must not fall through to the TCP stage"
                );
            }
            SecondStage::Own(call) => {
                let own = body
                    .find(call)
                    .unwrap_or_else(|| panic!("{file}: second stage must be `{call}`"));
                assert!(
                    ownership < own && body[ownership..own].contains(".await?;"),
                    "{file}: the own probe must run only after the ownership barrier succeeded"
                );
                assert!(
                    !body.contains("wait_for_child_tcp_accept"),
                    "{file}: this site has its own child-bound second stage"
                );
            }
            SecondStage::None => {
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
fn bespoke_spawner_callers_forward_the_attempt_child_and_identity() {
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
                (call.starts_with("&mut") || call.contains(".child_mut()"))
                    && call.contains(",&identity"),
                "{}: every caller must pass the spawned child and this attempt's identity, \
                 got ({call})",
                site.file
            );
        }
    }
}

/// The identity the wrapper checks must be fresh per spawn attempt and be the
/// one the child was started with.
#[test]
fn bespoke_spawners_mint_and_apply_a_per_attempt_identity() {
    for site in SITES {
        let compact = squeezed(site.src);
        assert!(
            compact.contains("SpawnedGatewayIdentity::mint("),
            "{}: each spawn attempt must mint a SpawnedGatewayIdentity",
            site.file
        );
        assert!(
            compact.contains(".apply_to_command(&mut"),
            "{}: the minted identity must be applied to the gateway Command",
            site.file
        );
        assert!(
            !compact.contains("constADMIN_JWT_SECRET"),
            "{}: a constant admin JWT secret is shared by every gateway the suite starts",
            site.file
        );
    }
}

/// Suites that compile `tests/common` and could spawn a gateway. The harness
/// itself (`tests/common`) defines the helpers and is not an adopter.
const ADOPTER_SCAN_ROOTS: &[&str] = &[
    "functional",
    "integration",
    "secrets_functional",
    "service_integration",
];

fn collect_adopters(
    root: &std::path::Path,
    dir: &std::path::Path,
    needle: &str,
    adopters: &mut Vec<String>,
) {
    for entry in std::fs::read_dir(dir).unwrap_or_else(|err| panic!("read {dir:?}: {err}")) {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            collect_adopters(root, &path, needle, adopters);
            continue;
        }
        if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
            continue;
        }
        let src = std::fs::read_to_string(&path).expect("read test source");
        if src.contains(needle) {
            let relative = path
                .strip_prefix(root)
                .expect("scanned path is under tests/")
                .to_str()
                .expect("utf-8 path")
                .replace('\\', "/");
            adopters.push(relative);
        }
    }
}

fn adopters_of(needle: &str) -> Vec<String> {
    let tests_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut adopters = Vec::new();
    for root in ADOPTER_SCAN_ROOTS {
        let dir = tests_dir.join(root);
        if dir.is_dir() {
            collect_adopters(&tests_dir, &dir, needle, &mut adopters);
        }
    }
    adopters.sort();
    adopters
}

/// A new spawner adopting the shared TCP-accept stage must be classified here.
#[test]
fn every_shared_tcp_accept_adopter_is_in_the_site_table() {
    let mut table: Vec<String> = SITES
        .iter()
        .filter(|site| matches!(site.second_stage, SecondStage::TcpAccept(_)))
        .map(|site| format!("functional/{}", site.file))
        .collect();
    table.sort();
    assert_eq!(
        adopters_of("wait_for_child_tcp_accept("),
        table,
        "every spawner using wait_for_child_tcp_accept must have a SITES row with its \
         timeout and the shared-deadline policy"
    );
}

/// The health-only barrier is a documented exception, not a default: a new
/// adopter must justify itself in `HEALTH_ONLY_SITES`.
#[test]
fn health_only_readiness_adopters_are_documented_exceptions() {
    let mut table: Vec<String> = HEALTH_ONLY_SITES
        .iter()
        .map(|(file, reason)| {
            assert!(
                !reason.is_empty(),
                "{file}: a health-only site needs a reason"
            );
            format!("functional/{file}")
        })
        .collect();
    table.sort();
    assert_eq!(
        adopters_of("wait_for_child_gateway_readiness("),
        table,
        "a bespoke spawner should prove ownership with wait_for_owned_gateway_identity; \
         health-only readiness needs a HEALTH_ONLY_SITES row with the reason admin auth \
         cannot be enabled (issue #7076)"
    );
}
