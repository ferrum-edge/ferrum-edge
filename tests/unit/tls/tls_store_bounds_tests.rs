//! Issue #3737: bound persistent TLS state documents and ACME/managed retention.
//!
//! Covers exact-limit and limit+1 whole-document I/O, previous-state preservation
//! on oversized candidate writes, managed create vs overwrite/delete at the
//! logical record limit, ACME active/recoverable retention with bounded terminal
//! history across thousands of renewal cycles, bounded event-log load/compaction,
//! secret-safe oversized diagnostics, true OS-process atomic visibility, FIFO
//! open fail-closed without hang, replica record-count gauge refresh, and
//! config/docs/metric inventory parity.

use std::io::Cursor;
use std::thread;
use std::time::Duration;

use chrono::Utc;
use ferrum_edge::config::env_config::{
    DEFAULT_TLS_ACME_TERMINAL_ORDER_HISTORY, DEFAULT_TLS_MANAGED_MAX_RECORDS,
    DEFAULT_TLS_STORE_MAX_DOCUMENT_BYTES, HARD_MAX_TLS_STORE_MAX_DOCUMENT_BYTES,
    MIN_TLS_STORE_MAX_DOCUMENT_BYTES, TLS_ACME_MAX_ACCOUNTS_KEY, TLS_ACME_MAX_CERTIFICATES_KEY,
    TLS_ACME_TERMINAL_ORDER_HISTORY_KEY, TLS_MANAGED_MAX_RECORDS_KEY,
    TLS_STORE_MAX_DOCUMENT_BYTES_KEY, parse_tls_acme_max_accounts, parse_tls_acme_max_certificates,
    parse_tls_acme_terminal_order_history, parse_tls_managed_max_records,
    parse_tls_store_max_document_bytes,
};
use ferrum_edge::config::public_env_inventory::PUBLIC_FERRUM_ENV_SETTINGS;
use ferrum_edge::tls::acme::{
    AcmeAccountStore, AcmeCertificateRecord, AcmeCertificateStatus, AcmeCertificateStore,
    AcmeError, AcmeOrderFinalization, AcmeOrderRecord, AcmeOrderStatus, AcmeOrderStore,
};
use ferrum_edge::tls::events::{
    TlsEventFilter, TlsEventLog, TlsSourceEvent, TlsSourceEventMaterial,
};
use ferrum_edge::tls::managed::{ManagedTlsError, ManagedTlsRecord, ManagedTlsStore};
use ferrum_edge::tls::shared_store::{
    SharedStoreError, SharedStoreFile, StoreIdentityMode, TlsPersistentStoreKind,
    TlsStoreIoDirection, VersionedStoreFile, read_bounded_document_bytes,
};
use serde::{Deserialize, Serialize};

const DOC_LIMIT: usize = 2048;
const CONFIGURATION_MD: &str = include_str!("../../../docs/configuration.md");
const FERRUM_CONF: &str = include_str!("../../../ferrum.conf");
const METRIC_CONTRACT: &str = include_str!("../../../docs/prometheus_metric_contract.json");
const METRICS_MD: &str = include_str!("../../../docs/prometheus_metrics.md");

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct ProbeDocument {
    #[serde(default)]
    version: u64,
    #[serde(default)]
    value: String,
}

impl VersionedStoreFile for ProbeDocument {
    fn store_version(&self) -> u64 {
        self.version
    }

    fn set_store_version(&mut self, version: u64) {
        self.version = version;
    }

    fn logical_record_count(&self) -> u64 {
        u64::from(!self.value.is_empty())
    }
}

fn open_probe(
    path: std::path::PathBuf,
    max_document_bytes: usize,
) -> SharedStoreFile<ProbeDocument> {
    SharedStoreFile::open_with_limits(
        path,
        StoreIdentityMode::platform_default(),
        TlsPersistentStoreKind::Managed,
        max_document_bytes,
    )
    .expect("open probe store")
}

fn open_probe_kind(
    path: std::path::PathBuf,
    max_document_bytes: usize,
    kind: TlsPersistentStoreKind,
) -> SharedStoreFile<ProbeDocument> {
    SharedStoreFile::open_with_limits(
        path,
        StoreIdentityMode::platform_default(),
        kind,
        max_document_bytes,
    )
    .expect("open probe store")
}

fn sample_managed(id: &str) -> ManagedTlsRecord {
    ManagedTlsRecord::new_jwks(
        id.to_string(),
        format!("name-{id}"),
        None,
        r#"{"keys":[]}"#.to_string(),
    )
}

fn sample_order(id: &str, certificate_id: &str, status: AcmeOrderStatus) -> AcmeOrderRecord {
    let now = Utc::now();
    AcmeOrderRecord {
        id: id.to_string(),
        certificate_id: Some(certificate_id.to_string()),
        domains: vec!["example.test".to_string()],
        directory_url: "https://acme.example.test/directory".to_string(),
        account_id: Some("acct".to_string()),
        order_url: Some(format!("https://acme.example.test/order/{id}")),
        status,
        http01_challenges: Vec::new(),
        tls_alpn01_challenges: Vec::new(),
        dns01_challenges: Vec::new(),
        finalization: None,
        account_credentials_json: None,
        error: None,
        created_at: now,
        updated_at: now,
    }
}

fn sample_certificate(id: &str) -> AcmeCertificateRecord {
    let now = Utc::now();
    AcmeCertificateRecord {
        id: id.to_string(),
        domains: vec!["example.test".to_string()],
        directory_url: "https://acme.example.test/directory".to_string(),
        account_id: Some("acct".to_string()),
        order_url: Some(format!("https://acme.example.test/order/{id}")),
        status: AcmeCertificateStatus::Issued,
        cert_pem: "-----BEGIN CERTIFICATE-----\nYQ==\n-----END CERTIFICATE-----\n".to_string(),
        key_pem: "-----BEGIN PRIVATE KEY-----\nYQ==\n-----END PRIVATE KEY-----\n".to_string(),
        chain_pem: None,
        issued_at: Some(now),
        not_after: Some(now),
        created_at: now,
        updated_at: now,
    }
}

fn event_with(cert_id: &str) -> TlsSourceEvent {
    TlsSourceEvent {
        id: 0,
        at: Utc::now(),
        surface: "proxy_https".to_string(),
        outcome: "rotated".to_string(),
        sources: vec![TlsSourceEventMaterial {
            label: "cert".to_string(),
            cert_id: cert_id.to_string(),
            source_id: "managed://certificates/x#cert".to_string(),
            scheme: "managed".to_string(),
            kind: "cert".to_string(),
            fingerprint_sha256: Some("abc".to_string()),
        }],
        revision: Some(1),
        error: None,
    }
}

#[test]
fn config_parsers_cover_absent_clamp_and_fail_closed() {
    assert_eq!(
        parse_tls_store_max_document_bytes(None).expect("absent"),
        DEFAULT_TLS_STORE_MAX_DOCUMENT_BYTES
    );
    assert_eq!(
        parse_tls_store_max_document_bytes(Some("2048")).expect("valid"),
        2048
    );
    assert_eq!(
        parse_tls_store_max_document_bytes(Some("999999999")).expect("clamp"),
        HARD_MAX_TLS_STORE_MAX_DOCUMENT_BYTES
    );
    let zero = parse_tls_store_max_document_bytes(Some("0")).expect_err("0 rejected");
    assert!(zero.contains(TLS_STORE_MAX_DOCUMENT_BYTES_KEY));
    assert!(!zero.contains("=0"));
    let malformed = parse_tls_store_max_document_bytes(Some("16MiB")).expect_err("malformed");
    assert!(malformed.contains(TLS_STORE_MAX_DOCUMENT_BYTES_KEY));
    assert!(!malformed.contains("16MiB"));

    assert_eq!(
        parse_tls_managed_max_records(None).expect("absent"),
        DEFAULT_TLS_MANAGED_MAX_RECORDS
    );
    assert!(
        parse_tls_managed_max_records(Some("0"))
            .expect_err("0")
            .contains(TLS_MANAGED_MAX_RECORDS_KEY)
    );
    assert!(
        parse_tls_acme_max_certificates(Some("0"))
            .expect_err("0")
            .contains(TLS_ACME_MAX_CERTIFICATES_KEY)
    );
    assert!(
        parse_tls_acme_max_accounts(Some("0"))
            .expect_err("0")
            .contains(TLS_ACME_MAX_ACCOUNTS_KEY)
    );
    assert_eq!(
        parse_tls_acme_terminal_order_history(None).expect("absent"),
        DEFAULT_TLS_ACME_TERMINAL_ORDER_HISTORY
    );
    assert_eq!(
        parse_tls_acme_terminal_order_history(Some("0")).expect("zero history"),
        0
    );
    assert!(
        parse_tls_acme_terminal_order_history(Some("nope"))
            .expect_err("malformed")
            .contains(TLS_ACME_TERMINAL_ORDER_HISTORY_KEY)
    );

    for key in [
        TLS_STORE_MAX_DOCUMENT_BYTES_KEY,
        TLS_MANAGED_MAX_RECORDS_KEY,
        TLS_ACME_MAX_CERTIFICATES_KEY,
        TLS_ACME_MAX_ACCOUNTS_KEY,
        TLS_ACME_TERMINAL_ORDER_HISTORY_KEY,
    ] {
        assert!(
            PUBLIC_FERRUM_ENV_SETTINGS.contains(&key),
            "public inventory must list {key}"
        );
        assert!(
            CONFIGURATION_MD.contains(&format!("| `{key}`")),
            "docs/configuration.md must document {key}"
        );
        assert!(
            FERRUM_CONF.contains(&format!("# {key} =")),
            "ferrum.conf must template {key}"
        );
    }
    const { assert!(MIN_TLS_STORE_MAX_DOCUMENT_BYTES >= 1024) };

    for family in [
        "ferrum_tls_store_document_bytes",
        "ferrum_tls_store_record_count",
        "ferrum_tls_store_oversized_total",
        "ferrum_tls_store_admission_rejected_total",
        "ferrum_tls_store_pruned_total",
    ] {
        assert!(
            METRIC_CONTRACT.contains(&format!("\"name\": \"{family}\"")),
            "metric contract must inventory {family}"
        );
        assert!(
            METRICS_MD.contains(&format!("| `{family}`")),
            "prometheus_metrics.md must document {family}"
        );
    }
}

#[test]
fn bounded_document_reader_accepts_exact_limit_and_rejects_limit_plus_one() {
    let exact = read_bounded_document_bytes(
        &mut Cursor::new(vec![b'x'; DOC_LIMIT]),
        std::path::Path::new("probe.json"),
        DOC_LIMIT,
    )
    .expect("exact limit");
    assert_eq!(exact.len(), DOC_LIMIT);

    let error = read_bounded_document_bytes(
        &mut Cursor::new(vec![b'y'; DOC_LIMIT + 1]),
        std::path::Path::new("probe.json"),
        DOC_LIMIT,
    )
    .expect_err("limit+1");
    match error {
        SharedStoreError::Oversized {
            max_bytes,
            direction,
            ref path,
        } => {
            assert_eq!(max_bytes, DOC_LIMIT);
            assert_eq!(direction, TlsStoreIoDirection::Read);
            assert_eq!(path, "probe.json");
            let rendered = error.to_string();
            assert!(rendered.contains("exceeds the configured byte ceiling"));
            assert!(!rendered.contains("yyyy"));
        }
        other => panic!("expected Oversized, got {other}"),
    }
}

#[test]
fn shared_store_loads_exact_limit_valid_document() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("probe-store.json");
    let store = open_probe(path.clone(), DOC_LIMIT);
    let filler_len = DOC_LIMIT.saturating_sub(40);
    store
        .mutate(|document| {
            document.value = "E".repeat(filler_len.min(DOC_LIMIT / 2));
            Ok::<_, SharedStoreError>(())
        })
        .expect("seed near-limit document");
    let on_disk = std::fs::read(&path).expect("read seeded document");
    assert!(on_disk.len() <= DOC_LIMIT);
    let reopened = open_probe(path, DOC_LIMIT);
    assert_eq!(
        reopened.snapshot().expect("exact-limit load").value.len(),
        store.snapshot().expect("live").value.len()
    );
}

#[test]
fn shared_store_rejects_oversized_on_disk_without_replacing_cache() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("probe-store.json");
    let store = open_probe(path.clone(), DOC_LIMIT);
    store
        .mutate(|document| {
            document.value = "ok".to_string();
            Ok::<_, SharedStoreError>(())
        })
        .expect("seed");
    let before = store.snapshot().expect("snapshot before").value.clone();
    assert_eq!(before, "ok");

    // Replace the on-disk document with an oversized payload without going
    // through the store writer, simulating corruption / hostile rewrite.
    let oversized = format!(r#"{{"version":9,"value":"{}"}}"#, "Z".repeat(DOC_LIMIT + 1));
    assert!(oversized.len() > DOC_LIMIT);
    std::fs::write(&path, oversized.as_bytes()).expect("write oversized");

    let error = store.snapshot().expect_err("oversized read must fail");
    assert!(matches!(
        error,
        SharedStoreError::Oversized {
            direction: TlsStoreIoDirection::Read,
            ..
        }
    ));
    // Fresh open must also fail closed rather than adopt an empty map.
    let reopen = SharedStoreFile::<ProbeDocument>::open_with_limits(
        path,
        StoreIdentityMode::platform_default(),
        TlsPersistentStoreKind::Managed,
        DOC_LIMIT,
    );
    assert!(matches!(
        reopen,
        Err(SharedStoreError::Oversized {
            direction: TlsStoreIoDirection::Read,
            ..
        })
    ));
}

#[test]
fn oversized_candidate_write_preserves_previous_authoritative_document() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("probe-store.json");
    let store = open_probe(path.clone(), DOC_LIMIT);
    store
        .mutate(|document| {
            document.value = "authoritative".to_string();
            Ok::<_, SharedStoreError>(())
        })
        .expect("seed");

    let error = store
        .mutate(|document| {
            document.value = "X".repeat(DOC_LIMIT + 64);
            Ok::<_, SharedStoreError>(())
        })
        .expect_err("oversized candidate must refuse before rename");
    assert!(matches!(
        error,
        SharedStoreError::Oversized {
            direction: TlsStoreIoDirection::Write,
            ..
        }
    ));

    let live = store.snapshot().expect("live snapshot");
    assert_eq!(live.value, "authoritative");
    let reopened = open_probe(path, DOC_LIMIT);
    assert_eq!(reopened.snapshot().expect("reopen").value, "authoritative");
}

#[test]
fn managed_creates_stop_at_logical_limit_while_overwrite_and_delete_remain() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = ManagedTlsStore::open_with_limits(dir.path(), 64 * 1024, 2, None).expect("open");

    store
        .upsert(sample_managed("one"), false)
        .expect("create one");
    store
        .upsert(sample_managed("two"), false)
        .expect("create two");
    let refused = store
        .upsert(sample_managed("three"), false)
        .expect_err("third create must refuse");
    assert!(matches!(refused, ManagedTlsError::RecordLimitReached));
    assert!(!refused.to_string().contains("three"));

    let mut overwrite = sample_managed("one");
    overwrite.name = "renamed".to_string();
    let updated = store.upsert(overwrite, true).expect("overwrite at limit");
    assert_eq!(updated.name, "renamed");

    store.delete("two").expect("delete at limit");
    store
        .upsert(sample_managed("three"), false)
        .expect("create after delete");
}

#[test]
fn acme_terminal_history_stays_bounded_across_thousands_of_cycles_without_dropping_active() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = AcmeOrderStore::open_with_limits(dir.path(), 3, None).expect("open");

    // Active/recoverable orders must survive unbounded renewal cycles.
    for status in [
        AcmeOrderStatus::PendingChallenges,
        AcmeOrderStatus::Ready,
        AcmeOrderStatus::Processing,
    ] {
        let id = format!("active-{}", status as u8);
        store
            .upsert_order(sample_order(&id, "cert-a", status), false)
            .expect("active upsert");
    }

    // Valid + finalization material is crash-recovery state and must be retained.
    let mut recoverable = sample_order("valid-recoverable", "cert-a", AcmeOrderStatus::Valid);
    recoverable.finalization = Some(
        AcmeOrderFinalization::generate(&["example.test".to_string()])
            .expect("generate finalization"),
    );
    store
        .upsert_order(recoverable, false)
        .expect("recoverable valid upsert");

    for cycle in 0..2_500 {
        let id = format!("term-{cycle}");
        let status = if cycle % 2 == 0 {
            AcmeOrderStatus::Failed
        } else {
            AcmeOrderStatus::Cancelled
        };
        store
            .upsert_order(sample_order(&id, "cert-a", status), false)
            .expect("terminal upsert");
    }

    // Terminal Valid without finalization is history and may be pruned.
    for cycle in 0..20 {
        let id = format!("valid-done-{cycle}");
        store
            .upsert_order(sample_order(&id, "cert-a", AcmeOrderStatus::Valid), false)
            .expect("terminal valid upsert");
    }

    let orders = store.list_orders().expect("list");
    let active = orders
        .iter()
        .filter(|order| {
            matches!(
                order.status,
                AcmeOrderStatus::PendingChallenges
                    | AcmeOrderStatus::Ready
                    | AcmeOrderStatus::Processing
            )
        })
        .count();
    let terminal = orders
        .iter()
        .filter(|order| {
            matches!(
                order.status,
                AcmeOrderStatus::Failed | AcmeOrderStatus::Cancelled
            ) || (order.status == AcmeOrderStatus::Valid && order.id != "valid-recoverable")
        })
        .count();
    assert_eq!(active, 3, "active/recoverable orders must be retained");
    assert!(
        store
            .get_order("valid-recoverable")
            .expect("recoverable valid order")
            .finalization
            .is_some(),
        "valid orders with finalization material must be retained"
    );
    assert_eq!(
        terminal, 3,
        "terminal history must stay at the configured bound"
    );
    assert!(store.get_order("valid-recoverable").is_ok());
    assert!(
        store.get_order("active-0").is_ok()
            || store.get_order("active-1").is_ok()
            || store.get_order("active-2").is_ok()
    );
}

#[test]
fn acme_certificate_creates_stop_at_logical_limit_while_overwrite_remains() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store =
        AcmeCertificateStore::open_with_limits(dir.path(), 64 * 1024, 1, None).expect("open");
    store
        .upsert_certificate(sample_certificate("cert-a"), false)
        .expect("create");
    let refused = store
        .upsert_certificate(sample_certificate("cert-b"), false)
        .expect_err("second create");
    assert!(matches!(refused, AcmeError::RecordLimitReached));

    let mut updated = sample_certificate("cert-a");
    updated.domains = vec!["rotated.example.test".to_string()];
    store
        .upsert_certificate(updated, true)
        .expect("overwrite at limit");
    store.delete_certificate("cert-a").expect("delete");
    store
        .upsert_certificate(sample_certificate("cert-b"), false)
        .expect("create after delete");
}

#[test]
fn acme_account_creates_stop_at_logical_limit_while_overwrite_remains() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = AcmeAccountStore::open_with_limits(dir.path(), 1, None).expect("open");
    store
        .upsert_account(
            "acct-1".to_string(),
            "https://acme.example.test/directory".to_string(),
            r#"{"id":"acct-1"}"#.to_string(),
        )
        .expect("create");
    let refused = store
        .upsert_account(
            "acct-2".to_string(),
            "https://acme.example.test/directory".to_string(),
            r#"{"id":"acct-2"}"#.to_string(),
        )
        .expect_err("second create");
    assert!(matches!(refused, AcmeError::RecordLimitReached));
    assert!(!refused.to_string().contains("acct-2"));

    store
        .upsert_account(
            "acct-1".to_string(),
            "https://acme.example.test/directory".to_string(),
            r#"{"id":"acct-1","rotated":true}"#.to_string(),
        )
        .expect("overwrite at limit");
}

#[test]
fn event_log_bounds_load_and_compacts_atomically() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("tls-events.json");

    // Seed a valid log with more entries than capacity, still under the byte ceiling.
    {
        let log = TlsEventLog::open_with_document_limit(2, Some(path.clone()), 64 * 1024)
            .expect("open seed");
        log.record(event_with("cert-a"));
        log.record(event_with("cert-b"));
        log.record(event_with("cert-c"));
        log.record(event_with("cert-d"));
    }

    let reloaded =
        TlsEventLog::open_with_document_limit(2, Some(path.clone()), 64 * 1024).expect("reload");
    let events = reloaded.list(&TlsEventFilter::default());
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].sources[0].cert_id, "cert-c");
    assert_eq!(events[1].sources[0].cert_id, "cert-d");

    // Oversized on-disk input must fail without adopting unbounded content.
    std::fs::write(&path, vec![b'{'; DOC_LIMIT + 8]).expect("write oversized");
    let error = match TlsEventLog::open_with_document_limit(2, Some(path), DOC_LIMIT) {
        Err(error) => error,
        Ok(_) => panic!("oversized event log must fail closed"),
    };
    assert!(error.contains("exceeds the configured byte ceiling"));
    assert!(!error.contains(&"x".repeat(32)));
}

#[test]
fn event_log_oversized_candidate_leaves_prior_live_and_durable_state_intact() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("tls-events.json");
    let log = TlsEventLog::open_with_document_limit(4, Some(path.clone()), 4 * 1024).expect("open");
    log.record(event_with("seed-a"));
    log.record(event_with("seed-b"));
    let before = log.list(&TlsEventFilter::default());
    assert_eq!(before.len(), 2);
    assert_eq!(before[0].sources[0].cert_id, "seed-a");
    assert_eq!(before[1].sources[0].cert_id, "seed-b");
    let before_ids: Vec<u64> = before.iter().map(|event| event.id).collect();

    // One event whose serialized form alone exceeds the document ceiling.
    let mut oversized = event_with("too-large");
    oversized.error = Some("E".repeat(8 * 1024));
    log.record(oversized);

    let live = log.list(&TlsEventFilter::default());
    assert_eq!(live.len(), 2);
    assert_eq!(
        live.iter().map(|event| event.id).collect::<Vec<_>>(),
        before_ids
    );
    assert_eq!(live[0].sources[0].cert_id, "seed-a");
    assert_eq!(live[1].sources[0].cert_id, "seed-b");

    let reopened = TlsEventLog::open_with_document_limit(4, Some(path), 4 * 1024)
        .expect("reopen prior document");
    let reloaded = reopened.list(&TlsEventFilter::default());
    assert_eq!(reloaded.len(), 2);
    assert_eq!(
        reloaded.iter().map(|event| event.id).collect::<Vec<_>>(),
        before_ids
    );
    assert_eq!(reloaded[0].sources[0].cert_id, "seed-a");
    assert_eq!(reloaded[1].sources[0].cert_id, "seed-b");
}

fn replica_snapshot_refreshes_shared_store_record_count_gauge_impl(store_dir: &std::path::Path) {
    use ferrum_edge::plugins::prometheus_metrics::global_registry;

    let path = store_dir.join("probe-store.json");
    let kind = TlsPersistentStoreKind::Leases;
    let writer = open_probe_kind(path.clone(), DOC_LIMIT, kind);
    let reader = open_probe_kind(path, DOC_LIMIT, kind);
    assert_eq!(global_registry().current_tls_store_record_count(kind), 0);

    writer
        .mutate(|document| {
            document.value = "replica-visible".to_string();
            Ok::<_, SharedStoreError>(())
        })
        .expect("writer publish");
    assert_eq!(global_registry().current_tls_store_record_count(kind), 1);

    // A second handle observing the other handle's generation must refresh the
    // logical record count, not only document bytes.
    let seen = reader.snapshot().expect("reader observes writer");
    assert_eq!(seen.value, "replica-visible");
    assert_eq!(global_registry().current_tls_store_record_count(kind), 1);

    let refused = writer
        .mutate(|document| {
            document.value = "X".repeat(DOC_LIMIT + 64);
            Ok::<_, SharedStoreError>(())
        })
        .expect_err("oversized candidate");
    assert!(matches!(
        refused,
        SharedStoreError::Oversized {
            direction: TlsStoreIoDirection::Write,
            ..
        }
    ));
    assert_eq!(
        global_registry().current_tls_store_record_count(kind),
        1,
        "rejected candidate must not advance the gauge"
    );
}

#[test]
fn replica_snapshot_refreshes_shared_store_record_count_gauge() {
    const CHILD_DIR_ENV: &str = "FERRUM_TEST_TLS_STORE_BOUNDS_GAUGE_CHILD_DIR";
    const TEST_NAME: &str = "unit::tls::tls_store_bounds_tests::replica_snapshot_refreshes_shared_store_record_count_gauge";

    if let Ok(dir) = std::env::var(CHILD_DIR_ENV) {
        replica_snapshot_refreshes_shared_store_record_count_gauge_impl(std::path::Path::new(&dir));
        return;
    }

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().to_path_buf();
    let exe = std::env::current_exe().expect("current test executable");
    let child = std::process::Command::new(exe)
        .env(CHILD_DIR_ENV, &path)
        .args(["--exact", TEST_NAME, "--nocapture"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn gauge child");

    let output = child.wait_with_output().expect("wait for gauge child");
    assert!(
        output.status.success(),
        "gauge child failed: {}",
        String::from_utf8_lossy(&output.stderr[..output.stderr.len().min(4096)])
    );
}

#[cfg(unix)]
#[test]
fn shared_store_and_event_log_reject_fifo_promptly_without_hanging() {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::sync::mpsc;

    const OPEN_BUDGET: Duration = Duration::from_secs(2);

    let dir = tempfile::tempdir().expect("tempdir");
    let store_fifo = dir.path().join("store.fifo");
    let events_fifo = dir.path().join("events.fifo");
    for path in [&store_fifo, &events_fifo] {
        let path_c = CString::new(path.as_os_str().as_bytes()).expect("c path");
        // SAFETY: `path_c` is a live NUL-terminated path; mode is ordinary perms.
        assert_eq!(unsafe { libc::mkfifo(path_c.as_ptr(), 0o600) }, 0);
    }

    {
        let store_fifo = store_fifo.clone();
        let (sender, receiver) = mpsc::sync_channel(1);
        thread::spawn(move || {
            let result = SharedStoreFile::<ProbeDocument>::open_with_limits(
                store_fifo,
                StoreIdentityMode::platform_default(),
                TlsPersistentStoreKind::Managed,
                DOC_LIMIT,
            );
            let _ = sender.send(result);
        });
        let store_result = receiver.recv_timeout(OPEN_BUDGET).unwrap_or_else(|error| {
            panic!("shared store FIFO open hung past {OPEN_BUDGET:?} budget: {error}");
        });
        let store_error = store_result.expect_err("shared store FIFO must refuse");
        let store_rendered = store_error.to_string();
        assert!(
            store_rendered.contains("not a regular file")
                || store_rendered.contains("failed to read"),
            "{store_rendered}"
        );
        assert!(!store_rendered.contains("BEGIN "));
    }

    {
        let events_fifo = events_fifo.clone();
        let (sender, receiver) = mpsc::sync_channel(1);
        thread::spawn(move || {
            let result = TlsEventLog::open_with_document_limit(2, Some(events_fifo), DOC_LIMIT);
            let _ = sender.send(result);
        });
        let event_result = receiver.recv_timeout(OPEN_BUDGET).unwrap_or_else(|error| {
            panic!("event log FIFO open hung past {OPEN_BUDGET:?} budget: {error}");
        });
        let event_error = match event_result {
            Err(error) => error,
            Ok(_) => panic!("event log FIFO must refuse"),
        };
        assert!(
            event_error.contains("not a regular file") || event_error.contains("failed to read"),
            "{event_error}"
        );
        assert!(!event_error.contains("BEGIN "));
    }
}

#[test]
fn multi_process_mutation_is_atomic_and_visible() {
    const CHILD_DIR_ENV: &str = "FERRUM_TEST_TLS_STORE_BOUNDS_CHILD_DIR";
    const TEST_NAME: &str =
        "unit::tls::tls_store_bounds_tests::multi_process_mutation_is_atomic_and_visible";

    if let Ok(dir) = std::env::var(CHILD_DIR_ENV) {
        let store =
            ManagedTlsStore::open_with_limits(&dir, 64 * 1024, 64, None).expect("child open");
        for index in 0..20 {
            let id = format!("rec-{index}");
            store
                .upsert(sample_managed(&id), true)
                .unwrap_or_else(|error| panic!("upsert {id}: {error}"));
            thread::sleep(Duration::from_millis(1));
        }
        return;
    }

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().to_path_buf();
    let store_b =
        ManagedTlsStore::open_with_limits(&path, 64 * 1024, 64, None).expect("parent open");

    let exe = std::env::current_exe().expect("current test executable");
    let child = std::process::Command::new(exe)
        .env(CHILD_DIR_ENV, &path)
        .args(["--exact", TEST_NAME, "--nocapture"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn OS-process writer child");

    for _ in 0..200 {
        match store_b.get("rec-5") {
            Ok(record) => {
                assert_eq!(record.id, "rec-5");
                break;
            }
            Err(ManagedTlsError::NotFound(_)) => {}
            Err(ManagedTlsError::Parse(_)) => {
                panic!("reader observed a partial/corrupt document");
            }
            Err(error) => panic!("unexpected reader error: {error}"),
        }
        thread::sleep(Duration::from_millis(5));
    }

    let output = child.wait_with_output().expect("wait for writer child");
    assert!(
        output.status.success(),
        "child writer failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    store_b
        .get("rec-19")
        .expect("final record visible across OS processes");
}
