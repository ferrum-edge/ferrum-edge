//! Bounded namespace snapshot representations for conditional backup/restore
//! and deployment authority: stored spec documents are fenced by digest, never
//! materialized as JSON number arrays.

use chrono::{DateTime, Utc};
use ferrum_edge::config::db_backend::{
    ConditionalNamespaceSnapshot, MAX_NAMESPACE_SNAPSHOT_REPRESENTATION_BYTES, SnapshotDigest,
    is_namespace_snapshot_too_large,
};
use ferrum_edge::config::deployment_mutation::{
    DeploymentCommitOutcomeUnknown, DeploymentMutationNotStarted, DeploymentSnapshot,
    StoredEvidence, deployment_commit_unknown, deployment_not_started,
    is_deployment_commit_outcome_unknown, is_deployment_mutation_not_started,
};
use ferrum_edge::config::types::{ApiSpec, GatewayConfig, SpecFormat};
use serde_json::json;

const LARGE_SPEC_BYTES: usize = 6 * 1024 * 1024;

fn spec(id: &str, content: Vec<u8>) -> ApiSpec {
    // A fixed instant: snapshots built by separate calls must be identical,
    // and chrono renders sub-second precision with a value-dependent width.
    let now: DateTime<Utc> = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
    ApiSpec {
        id: id.to_string(),
        namespace: "ferrum".to_string(),
        proxy_id: format!("{id}-proxy"),
        spec_version: "3.0.3".to_string(),
        spec_format: SpecFormat::Json,
        spec_content: content,
        content_encoding: "gzip".to_string(),
        uncompressed_size: 1,
        content_hash: "0".repeat(64),
        title: Some("Large".to_string()),
        info_version: None,
        description: None,
        contact_name: None,
        contact_email: None,
        license_name: None,
        license_identifier: None,
        tags: Vec::new(),
        server_urls: Vec::new(),
        operation_count: 1,
        resource_hash: String::new(),
        external_ref_snapshot: Some(vec![7; 1024]),
        external_ref_digest: Some("digest".to_string()),
        created_at: now,
        updated_at: now,
    }
}

fn snapshot(specs: Vec<ApiSpec>) -> ConditionalNamespaceSnapshot {
    ConditionalNamespaceSnapshot {
        config: GatewayConfig::default(),
        api_specs: specs,
        namespace_record: None,
        change_sequence: 42,
    }
}

/// Compact JSON has exactly the canonical rendering's length; only object key
/// order differs.
fn canonical_len(value: &serde_json::Value) -> usize {
    serde_json::to_vec(value).unwrap().len()
}

#[test]
fn large_spec_documents_are_fenced_by_digest_not_materialized() {
    let large = snapshot(vec![
        spec("b", vec![0xA5; LARGE_SPEC_BYTES]),
        spec("a", vec![0x5A; LARGE_SPEC_BYTES]),
    ]);
    let representation = large.representation().unwrap();
    // Two 6 MiB documents would be tens of MiB as JSON number arrays.
    assert!(
        canonical_len(&representation) < 4096,
        "spec bytes leaked into the representation: {} bytes",
        canonical_len(&representation)
    );
    let specs = representation[5].as_array().unwrap();
    assert_eq!(specs[0]["id"], "a", "specs are sorted by id");
    assert_eq!(specs[0]["spec_content"]["len"], LARGE_SPEC_BYTES);
    assert_eq!(
        specs[0]["spec_content"]["sha256"].as_str().unwrap().len(),
        64
    );
    assert!(!specs[0]["spec_content"].is_array());
    assert_eq!(specs[0]["external_ref_snapshot"]["len"], 1024);
    assert_eq!(representation[7], 42);

    // The streamed digest equals the digest of the materialized form.
    let digest = large.digest().unwrap();
    assert_eq!(
        digest,
        SnapshotDigest::of_representation(&representation).unwrap()
    );

    // One changed stored byte still changes the fence.
    let mut changed_content = vec![0x5A; LARGE_SPEC_BYTES];
    changed_content[LARGE_SPEC_BYTES / 2] = 0x00;
    let changed = snapshot(vec![
        spec("b", vec![0xA5; LARGE_SPEC_BYTES]),
        spec("a", changed_content),
    ]);
    assert_ne!(changed.digest().unwrap(), digest);
    // So does the change watermark alone.
    let mut advanced = snapshot(Vec::new());
    let empty = advanced.digest().unwrap();
    advanced.change_sequence += 1;
    assert_ne!(advanced.digest().unwrap(), empty);
}

#[test]
fn over_bound_representations_are_refused_with_a_typed_error() {
    assert_eq!(
        MAX_NAMESPACE_SNAPSHOT_REPRESENTATION_BYTES,
        64 * 1024 * 1024
    );
    let one = snapshot(vec![spec("a", vec![1; 1024])]);
    let error = one.digest_within(64).unwrap_err();
    assert!(is_namespace_snapshot_too_large(&error), "{error}");
    let within = canonical_len(&one.representation().unwrap());
    assert_eq!(one.digest_within(within).unwrap(), one.digest().unwrap());
    assert!(is_namespace_snapshot_too_large(
        &one.digest_within(within - 1).unwrap_err()
    ));
}

#[test]
fn deployment_digest_streams_the_same_canonical_evidence() {
    let deployment = DeploymentSnapshot::new(
        snapshot(vec![spec("a", vec![9; 2048])]),
        json!({
            "api_specs": [{"spec_content": {"value": {"sha256": "00", "len": 2048}}}],
            "proxies": [],
        }),
    );
    let representation = deployment.representation().unwrap();
    assert_eq!(representation["profile"], "deployment-v1");
    assert_eq!(
        deployment.digest().unwrap(),
        SnapshotDigest::of_representation(&representation).unwrap()
    );
    assert!(is_namespace_snapshot_too_large(
        &deployment.digest_within(16).unwrap_err()
    ));
    // Deployment and namespace digests are distinct domains of the same state.
    assert_ne!(
        deployment.digest().unwrap(),
        deployment.snapshot().digest().unwrap()
    );
}

fn evidence_rows() -> Vec<(&'static str, Vec<serde_json::Value>)> {
    vec![
        (
            "proxies",
            vec![
                json!({"id": {"value": "b"}, "name": {"value": "second"}}),
                json!({"id": {"value": "a"}, "name": {"value": "first"}}),
            ],
        ),
        ("upstreams", Vec::new()),
        (
            "api_specs",
            vec![json!({"spec_content": {"value": {"sha256": "00", "len": 2048}}})],
        ),
    ]
}

fn assemble(
    snapshot: ConditionalNamespaceSnapshot,
    limit: usize,
) -> Result<DeploymentSnapshot, anyhow::Error> {
    let mut evidence = StoredEvidence::for_snapshot_within(snapshot, limit)?;
    for (table, rows) in evidence_rows() {
        for row in rows {
            evidence.push(row)?;
        }
        evidence.end_table(table)?;
    }
    Ok(evidence.finish())
}

#[test]
fn stored_evidence_charges_exactly_the_canonical_deployment_representation() {
    let typed = || snapshot(vec![spec("a", vec![9; 2048])]);
    let max = MAX_NAMESPACE_SNAPSHOT_REPRESENTATION_BYTES;
    let deployment = assemble(typed(), max).unwrap();
    let representation = deployment.representation().unwrap();
    // Rows are ordered by canonical rendering, independent of store order.
    assert_eq!(representation["stored"]["proxies"][0]["id"]["value"], "a");
    assert_eq!(representation["stored"]["upstreams"], json!([]));
    let exact = canonical_len(&representation);
    assert_eq!(
        deployment.digest().unwrap(),
        SnapshotDigest::of_representation(&representation).unwrap()
    );
    // Resuming from the typed prefix hashed during assembly matches a full
    // rendering of the same evidence.
    let rendered = DeploymentSnapshot::new(typed(), deployment.stored.clone());
    assert_eq!(rendered.digest().unwrap(), deployment.digest().unwrap());
    assert_eq!(
        rendered.digest_within(exact).unwrap(),
        deployment.digest_within(exact).unwrap()
    );
    // The running budget refuses exactly what the bounded digest refuses.
    let at_bound = assemble(typed(), exact).unwrap();
    assert_eq!(
        at_bound.digest_within(exact).unwrap(),
        deployment.digest().unwrap()
    );
    let error = assemble(typed(), exact - 1).err().unwrap();
    assert!(is_namespace_snapshot_too_large(&error), "{error}");
    assert!(is_namespace_snapshot_too_large(
        &deployment.digest_within(exact - 1).unwrap_err()
    ));
    // A bound below the already-hashed typed prefix still refuses.
    assert!(is_namespace_snapshot_too_large(
        &deployment.digest_within(16).unwrap_err()
    ));
}

#[test]
fn only_a_tagged_commit_failure_has_an_unknown_deployment_outcome() {
    let statement = anyhow::Error::new(std::io::Error::other("statement failed"));
    assert!(!is_deployment_commit_outcome_unknown(&statement));
    let commit = deployment_commit_unknown(std::io::Error::other("commit failed"));
    assert!(is_deployment_commit_outcome_unknown(&commit));
    // The driver error stays in the chain, and outer context keeps the tag.
    assert!(commit.chain().any(|cause| cause.is::<std::io::Error>()));
    assert!(is_deployment_commit_outcome_unknown(
        &commit.context("outer")
    ));
    let bare = anyhow::Error::new(DeploymentCommitOutcomeUnknown);
    assert!(is_deployment_commit_outcome_unknown(&bare));
}

#[test]
fn only_a_tagged_pre_transaction_failure_is_not_started() {
    let statement = anyhow::Error::new(std::io::Error::other("statement failed"));
    assert!(!is_deployment_mutation_not_started(&statement));
    let failed = anyhow::Error::new(std::io::Error::other("session start failed"));
    let before = deployment_not_started(failed);
    assert!(is_deployment_mutation_not_started(&before));
    // Outer context keeps the pre-transaction tag.
    assert!(is_deployment_mutation_not_started(&before.context("outer")));
    let bare = anyhow::Error::new(DeploymentMutationNotStarted);
    assert!(is_deployment_mutation_not_started(&bare));
}

#[test]
fn stored_evidence_refuses_an_over_bound_typed_snapshot_before_raw_rows() {
    let typed = snapshot(vec![spec("a", vec![9; 2048])]);
    let resources = canonical_len(&typed.representation().unwrap());
    let error = StoredEvidence::for_snapshot_within(typed, resources)
        .err()
        .unwrap();
    assert!(is_namespace_snapshot_too_large(&error), "{error}");

    // A row past the remaining budget is refused when it is pushed.
    let n = resources + 64;
    let typed = snapshot(vec![spec("a", vec![9; 2048])]);
    let mut evidence = StoredEvidence::for_snapshot_within(typed, n).unwrap();
    let row = json!({"value": "x".repeat(128)});
    let error = evidence.push(row).unwrap_err();
    assert!(is_namespace_snapshot_too_large(&error), "{error}");
}

#[test]
fn deployment_representation_by_value_matches_by_reference() {
    let typed = snapshot(vec![spec("a", vec![9; 2048])]);
    let max = MAX_NAMESPACE_SNAPSHOT_REPRESENTATION_BYTES;
    let deployment = assemble(typed, max).unwrap();
    let by_reference = deployment.representation().unwrap();
    let (by_value, typed) = deployment.into_representation().unwrap();
    assert_eq!(by_value, by_reference);
    assert_eq!(typed.api_specs[0].spec_content.len(), 2048);
}
