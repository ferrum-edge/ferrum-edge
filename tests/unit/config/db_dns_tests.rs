use ferrum_edge::config::db_loader::DatabaseStore;

#[test]
fn extract_hostname_postgres_url() {
    let url = "postgres://user:pass@db.example.com:5432/ferrum";
    assert_eq!(
        DatabaseStore::extract_db_hostname(url),
        Some("db.example.com".to_string())
    );
}

#[test]
fn extract_hostname_mysql_url() {
    let url = "mysql://root:secret@rds.us-east-1.amazonaws.com:3306/mydb";
    assert_eq!(
        DatabaseStore::extract_db_hostname(url),
        Some("rds.us-east-1.amazonaws.com".to_string())
    );
}

#[test]
fn extract_hostname_returns_none_for_ip_literal() {
    let url = "postgres://user:pass@10.0.0.5:5432/ferrum";
    assert_eq!(DatabaseStore::extract_db_hostname(url), None);
}

#[test]
fn extract_hostname_returns_none_for_ipv6_literal() {
    let url = "postgres://user:pass@[::1]:5432/ferrum";
    assert_eq!(DatabaseStore::extract_db_hostname(url), None);
}

#[test]
fn extract_hostname_returns_none_for_sqlite() {
    let url = "sqlite://ferrum.db";
    assert_eq!(DatabaseStore::extract_db_hostname(url), None);
}

#[test]
fn extract_hostname_returns_none_for_sqlite_memory() {
    let url = "sqlite::memory:";
    assert_eq!(DatabaseStore::extract_db_hostname(url), None);
}

#[test]
fn extract_hostname_with_query_params() {
    let url =
        "postgres://user:pass@db.prod.internal:5432/ferrum?sslmode=verify-full&sslrootcert=/ca.pem";
    assert_eq!(
        DatabaseStore::extract_db_hostname(url),
        Some("db.prod.internal".to_string())
    );
}

#[test]
fn extract_hostname_localhost() {
    let url = "postgres://user:pass@localhost:5432/ferrum";
    assert_eq!(
        DatabaseStore::extract_db_hostname(url),
        Some("localhost".to_string())
    );
}

#[test]
fn extract_hostname_read_replica_url() {
    let url = "postgres://user:pass@replica.us-west-2.rds.amazonaws.com:5432/ferrum";
    assert_eq!(
        DatabaseStore::extract_db_hostname(url),
        Some("replica.us-west-2.rds.amazonaws.com".to_string())
    );
}

#[test]
fn extract_hostname_failover_url() {
    let url = "postgres://user:pass@standby.internal.example.com:5432/ferrum?sslmode=require";
    assert_eq!(
        DatabaseStore::extract_db_hostname(url),
        Some("standby.internal.example.com".to_string())
    );
}

#[test]
fn redact_url_hides_credentials() {
    let url = "postgres://admin:supersecret@db.example.com:5432/ferrum";
    let redacted = DatabaseStore::redact_url(url);
    assert!(!redacted.contains("supersecret"));
    assert!(!redacted.contains("admin"));
    assert!(redacted.contains("db.example.com"));
    assert!(redacted.contains("5432"));
}

#[test]
fn redact_url_no_credentials() {
    let url = "postgres://db.example.com:5432/ferrum";
    let redacted = DatabaseStore::redact_url(url);
    assert!(redacted.contains("db.example.com"));
}

#[test]
fn redact_url_invalid() {
    let redacted = DatabaseStore::redact_url("not-a-url");
    assert_eq!(redacted, "<invalid-url>");
}
