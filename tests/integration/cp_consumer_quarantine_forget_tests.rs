//! A CP full reload that loads a namespace but does not publish it must forget
//! that namespace's clean consumer-quarantine state, so its next consumer
//! change escalates to an authoritative full reload (issue #6060).

use std::collections::HashSet;
use std::sync::Mutex;

use async_trait::async_trait;
use ferrum_edge::config::db_backend::FullConfigLoadPurpose;
use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::grpc::cp_server::CpScope;
use ferrum_edge::modes::control_plane::{
    CpFullLoadSource, load_full_config_multi_with_sequence_for_test,
};

/// Serves a valid snapshot for every namespace except `rejected`, whose
/// snapshot references a missing upstream and fails CP validation.
struct ScriptedSource {
    rejected: &'static str,
    forgotten: Mutex<Vec<String>>,
}

impl ScriptedSource {
    fn new(rejected: &'static str) -> Self {
        Self {
            rejected,
            forgotten: Mutex::new(Vec::new()),
        }
    }

    fn forgotten(&self) -> HashSet<String> {
        self.forgotten.lock().unwrap().iter().cloned().collect()
    }
}

fn snapshot(namespace: &str, valid: bool) -> GatewayConfig {
    let mut proxy = serde_json::json!({
        "id": format!("{namespace}-proxy"),
        "namespace": namespace,
        "listen_path": "/svc",
        "backend_scheme": "http",
        "backend_host": "127.0.0.1",
        "backend_port": 9,
    });
    if !valid {
        proxy["upstream_id"] = serde_json::json!("missing-upstream");
    }
    GatewayConfig {
        proxies: vec![serde_json::from_value(proxy).unwrap()],
        ..Default::default()
    }
}

#[async_trait]
impl CpFullLoadSource for ScriptedSource {
    async fn load_full_config_for_purpose(
        &self,
        namespace: &str,
        _purpose: FullConfigLoadPurpose,
    ) -> Result<GatewayConfig, anyhow::Error> {
        Ok(snapshot(namespace, namespace != self.rejected))
    }

    async fn latest_change_sequence(&self, _namespace: &str) -> Result<u64, anyhow::Error> {
        Ok(7)
    }

    async fn latest_global_change_sequence(&self) -> Result<u64, anyhow::Error> {
        Ok(14)
    }

    fn forget_consumer_quarantine_state(&self, namespace: &str) {
        self.forgotten.lock().unwrap().push(namespace.to_string());
    }
}

fn namespaces() -> Vec<String> {
    vec!["good".to_string(), "bad".to_string()]
}

#[tokio::test]
async fn rejected_namespace_is_forgotten_while_published_ones_keep_their_state() {
    let source = ScriptedSource::new("bad");
    let scope = CpScope::Set(namespaces().into_iter().collect());
    let outcome = load_full_config_multi_with_sequence_for_test(
        &source,
        &namespaces(),
        &GatewayConfig::default(),
        &scope,
        None,
        0,
    )
    .await
    .expect("a rejected namespace keeps last-known-good; the reload still succeeds");
    assert_eq!(outcome.refreshed_namespaces, ["good"]);
    assert_eq!(source.forgotten(), HashSet::from(["bad".to_string()]));
}

#[tokio::test]
async fn aborted_all_scope_reload_forgets_every_loaded_namespace() {
    let source = ScriptedSource::new("bad");
    // A sequenced All-scope reload publishes one store-global revision, so a
    // rejected namespace aborts the whole reload and nothing publishes.
    let result = load_full_config_multi_with_sequence_for_test(
        &source,
        &namespaces(),
        &GatewayConfig::default(),
        &CpScope::All,
        Some("db"),
        0,
    )
    .await;
    assert!(result.is_err(), "the All-scope reload must abort");
    assert_eq!(
        source.forgotten(),
        HashSet::from(["good".to_string(), "bad".to_string()]),
        "a namespace that loaded cleanly but did not publish must not stay marked clean"
    );
}

#[tokio::test]
async fn published_reload_forgets_nothing() {
    let source = ScriptedSource::new("none");
    let outcome = load_full_config_multi_with_sequence_for_test(
        &source,
        &namespaces(),
        &GatewayConfig::default(),
        &CpScope::All,
        Some("db"),
        0,
    )
    .await
    .expect("clean reload");
    let refreshed: HashSet<String> = outcome.refreshed_namespaces.into_iter().collect();
    assert_eq!(
        refreshed,
        HashSet::from(["good".to_string(), "bad".to_string()])
    );
    assert!(source.forgotten().is_empty());
}

/// Database mode's single full-reload publication chokepoint forgets the clean
/// state whenever the loaded snapshot does not go live (rejected update,
/// migration gate, or topology change).
#[test]
fn database_mode_full_reload_chokepoint_forgets_unpublished_snapshots() {
    let source = include_str!("../../src/modes/database.rs");
    let chokepoint = source
        .split("async fn try_publish_full_reload_after_gate(")
        .nth(1)
        .and_then(|rest| rest.split("\nasync fn ").next())
        .expect("try_publish_full_reload_after_gate body");
    let unpublished = chokepoint
        .find("if published != Some(true)")
        .expect("the chokepoint must branch on an unpublished snapshot");
    assert!(
        chokepoint[unpublished..].contains("db.forget_consumer_quarantine_state(namespace)"),
        "an unpublished full reload must forget the namespace's clean quarantine state"
    );
}
