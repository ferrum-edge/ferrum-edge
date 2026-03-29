use ferrum_gateway::config::db_loader::DatabaseStore;

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
