use ferrum_edge::_test_support::{
    DbPoolConfig, db_append_connect_timeout, db_diff_removed, parse_auth_mode, parse_protocol,
};
use ferrum_edge::config::types::{AuthMode, BackendProtocol};
use std::collections::HashSet;

// ── append_connect_timeout ───────────────────────────────────────────────────

#[test]
fn test_append_connect_timeout_postgres_no_existing_params() {
    let result = db_append_connect_timeout("postgres://user:pass@localhost/mydb", "postgres", 10);
    assert_eq!(
        result,
        "postgres://user:pass@localhost/mydb?connect_timeout=10"
    );
}

#[test]
fn test_append_connect_timeout_postgres_with_existing_params() {
    let result = db_append_connect_timeout(
        "postgres://user:pass@localhost/mydb?sslmode=require",
        "postgres",
        15,
    );
    assert_eq!(
        result,
        "postgres://user:pass@localhost/mydb?sslmode=require&connect_timeout=15"
    );
}

#[test]
fn test_append_connect_timeout_mysql() {
    let result = db_append_connect_timeout("mysql://user:pass@localhost/mydb", "mysql", 5);
    assert_eq!(result, "mysql://user:pass@localhost/mydb?connect_timeout=5");
}

#[test]
fn test_append_connect_timeout_sqlite_skipped() {
    let result = db_append_connect_timeout("sqlite://mydb.sqlite", "sqlite", 10);
    assert_eq!(result, "sqlite://mydb.sqlite");
}

#[test]
fn test_append_connect_timeout_zero_disabled() {
    let result = db_append_connect_timeout("postgres://user:pass@localhost/mydb", "postgres", 0);
    assert_eq!(result, "postgres://user:pass@localhost/mydb");
}

// ── DbPoolConfig defaults ────────────────────────────────────────────────────

#[test]
fn test_db_pool_config_default() {
    let config = DbPoolConfig::default();
    assert_eq!(config.max_connections, 10);
    assert_eq!(config.min_connections, 1);
    assert_eq!(config.acquire_timeout_seconds, 30);
    assert_eq!(config.idle_timeout_seconds, 600);
    assert_eq!(config.max_lifetime_seconds, 300);
    assert_eq!(config.connect_timeout_seconds, 10);
    assert_eq!(config.statement_timeout_seconds, 30);
}

// ── diff_removed ─────────────────────────────────────────────────────────────

#[test]
fn test_diff_removed_empty_sets() {
    let known = HashSet::new();
    let current = HashSet::new();
    assert!(db_diff_removed(&known, &current).is_empty());
}

#[test]
fn test_diff_removed_no_deletions() {
    let known: HashSet<String> = ["a", "b", "c"].iter().map(|s| s.to_string()).collect();
    let current = known.clone();
    assert!(db_diff_removed(&known, &current).is_empty());
}

#[test]
fn test_diff_removed_all_deleted() {
    let known: HashSet<String> = ["a", "b", "c"].iter().map(|s| s.to_string()).collect();
    let current = HashSet::new();
    let mut removed = db_diff_removed(&known, &current);
    removed.sort();
    assert_eq!(removed, vec!["a", "b", "c"]);
}

#[test]
fn test_diff_removed_partial_deletion() {
    let known: HashSet<String> = ["a", "b", "c"].iter().map(|s| s.to_string()).collect();
    let current: HashSet<String> = ["a", "c"].iter().map(|s| s.to_string()).collect();
    let removed = db_diff_removed(&known, &current);
    assert_eq!(removed, vec!["b"]);
}

#[test]
fn test_diff_removed_current_has_new_ids() {
    let known: HashSet<String> = ["a", "b"].iter().map(|s| s.to_string()).collect();
    let current: HashSet<String> = ["a", "b", "d", "e"].iter().map(|s| s.to_string()).collect();
    assert!(db_diff_removed(&known, &current).is_empty());
}

#[test]
fn test_diff_removed_known_empty_current_has_items() {
    let known = HashSet::new();
    let current: HashSet<String> = ["x", "y"].iter().map(|s| s.to_string()).collect();
    assert!(db_diff_removed(&known, &current).is_empty());
}

#[test]
fn test_diff_removed_mixed_additions_and_deletions() {
    let known: HashSet<String> = ["a", "b", "c"].iter().map(|s| s.to_string()).collect();
    let current: HashSet<String> = ["b", "d", "e"].iter().map(|s| s.to_string()).collect();
    let mut removed = db_diff_removed(&known, &current);
    removed.sort();
    assert_eq!(removed, vec!["a", "c"]);
}

// ── parse_protocol ───────────────────────────────────────────────────────────

#[test]
fn test_parse_protocol_known_values() {
    assert!(matches!(parse_protocol("http"), BackendProtocol::Http));
    assert!(matches!(parse_protocol("https"), BackendProtocol::Https));
    assert!(matches!(parse_protocol("ws"), BackendProtocol::Ws));
    assert!(matches!(parse_protocol("wss"), BackendProtocol::Wss));
    assert!(matches!(parse_protocol("grpc"), BackendProtocol::Grpc));
    assert!(matches!(parse_protocol("grpcs"), BackendProtocol::Grpcs));
    assert!(matches!(parse_protocol("h3"), BackendProtocol::H3));
    assert!(matches!(parse_protocol("tcp"), BackendProtocol::Tcp));
    assert!(matches!(parse_protocol("tcp_tls"), BackendProtocol::TcpTls));
    assert!(matches!(parse_protocol("udp"), BackendProtocol::Udp));
    assert!(matches!(parse_protocol("dtls"), BackendProtocol::Dtls));
}

#[test]
fn test_parse_protocol_case_insensitive() {
    assert!(matches!(parse_protocol("HTTPS"), BackendProtocol::Https));
    assert!(matches!(parse_protocol("Grpc"), BackendProtocol::Grpc));
    assert!(matches!(parse_protocol("H3"), BackendProtocol::H3));
    assert!(matches!(parse_protocol("TCP_TLS"), BackendProtocol::TcpTls));
}

#[test]
fn test_parse_protocol_unknown_defaults_to_http() {
    assert!(matches!(parse_protocol("ftp"), BackendProtocol::Http));
    assert!(matches!(parse_protocol(""), BackendProtocol::Http));
    assert!(matches!(parse_protocol("nonsense"), BackendProtocol::Http));
}

// ── parse_auth_mode ──────────────────────────────────────────────────────────

#[test]
fn test_parse_auth_mode_known_values() {
    assert!(matches!(parse_auth_mode("single"), AuthMode::Single));
    assert!(matches!(parse_auth_mode("multi"), AuthMode::Multi));
}

#[test]
fn test_parse_auth_mode_case_insensitive() {
    assert!(matches!(parse_auth_mode("MULTI"), AuthMode::Multi));
    assert!(matches!(parse_auth_mode("Single"), AuthMode::Single));
}

#[test]
fn test_parse_auth_mode_unknown_defaults_to_single() {
    assert!(matches!(parse_auth_mode("unknown"), AuthMode::Single));
    assert!(matches!(parse_auth_mode(""), AuthMode::Single));
}
