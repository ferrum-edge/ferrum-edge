//! Boundary tests for custom-plugin migration SQL statement splitting (#2995).

use ferrum_edge::config::migrations::{
    CustomPluginMigration, MigrationRunner, split_plugin_migration_statements,
};

fn assert_split(db_type: &str, sql: &str, expected: &[&str]) {
    let got = split_plugin_migration_statements(sql, db_type).expect("split should succeed");
    assert_eq!(got, expected, "db_type={db_type} sql={sql:?}");
}

fn assert_split_err(db_type: &str, sql: &str) {
    let err = split_plugin_migration_statements(sql, db_type).expect_err("split should fail");
    assert!(
        !err.to_string().is_empty(),
        "error message should be non-empty"
    );
}

/// Executable `DELIMITER` client meta-commands must never appear in the
/// returned statement list (SQLx would send them to the server).
fn assert_no_delimiter_directives(statements: &[&str]) {
    for (idx, statement) in statements.iter().enumerate() {
        for (line_no, line) in statement.lines().enumerate() {
            let trimmed = line.trim_start();
            let upper = trimmed.to_ascii_uppercase();
            if let Some(rest) = upper.strip_prefix("DELIMITER") {
                // `DELIMITER` as a directive is followed by whitespace or EOL,
                // not another identifier character (e.g. a column named
                // `delimiter_col` is fine).
                let is_directive = rest.is_empty() || rest.starts_with(|c: char| c.is_whitespace());
                assert!(
                    !is_directive,
                    "statement[{idx}] line {line_no} must not contain an executable DELIMITER directive: {statement:?}"
                );
            }
        }
        let leading = statement
            .trim_start_matches(|c: char| c.is_whitespace())
            .to_ascii_uppercase();
        assert!(
            !leading.starts_with("DELIMITER ")
                && !leading.starts_with("DELIMITER\t")
                && leading != "DELIMITER"
                && !leading.starts_with("DELIMITER;")
                && !leading.starts_with("DELIMITER/")
                && !leading.starts_with("DELIMITER\n"),
            "statement[{idx}] must not begin with a DELIMITER directive: {statement:?}"
        );
    }
}

#[test]
fn splits_basic_multi_statement_sql() {
    assert_split(
        "sqlite",
        "CREATE TABLE t (id TEXT); INSERT INTO t VALUES ('x');",
        &["CREATE TABLE t (id TEXT)", "INSERT INTO t VALUES ('x')"],
    );
}

#[test]
fn preserves_semicolon_inside_single_quoted_string() {
    assert_split(
        "sqlite",
        "INSERT INTO t VALUES ('a;b'); SELECT 1;",
        &["INSERT INTO t VALUES ('a;b')", "SELECT 1"],
    );
}

#[test]
fn preserves_doubled_single_quotes() {
    assert_split(
        "postgres",
        "INSERT INTO t VALUES ('it''s;fine'); SELECT 1;",
        &["INSERT INTO t VALUES ('it''s;fine')", "SELECT 1"],
    );
}

#[test]
fn postgres_and_sqlite_ordinary_strings_do_not_treat_backslash_as_an_escape() {
    let sql = r#"SELECT 'left\'; SELECT 2;"#;
    let expected = &[r#"SELECT 'left\'"#, "SELECT 2"];
    assert_split("postgres", sql, expected);
    assert_split("sqlite", sql, expected);
}

#[test]
fn postgres_escape_strings_preserve_backslash_escaped_quotes_and_semicolons() {
    assert_split(
        "postgres",
        r#"SELECT E'left\';inside'; SELECT 2;"#,
        &[r#"SELECT E'left\';inside'"#, "SELECT 2"],
    );
    assert_split(
        "mysql",
        r#"SELECT 'left\';inside'; SELECT 2;"#,
        &[r#"SELECT 'left\';inside'"#, "SELECT 2"],
    );
}

#[test]
fn preserves_semicolon_inside_double_quoted_identifier() {
    assert_split(
        "postgres",
        r#"SELECT "col;name" FROM t; SELECT 1;"#,
        &[r#"SELECT "col;name" FROM t"#, "SELECT 1"],
    );
}

#[test]
fn preserves_semicolon_inside_backtick_identifier() {
    assert_split(
        "mysql",
        "SELECT `col;name` FROM t; SELECT 1;",
        &["SELECT `col;name` FROM t", "SELECT 1"],
    );
    assert_split(
        "sqlite",
        "SELECT `col;name` FROM t; SELECT 1;",
        &["SELECT `col;name` FROM t", "SELECT 1"],
    );
}

#[test]
fn preserves_semicolon_inside_line_and_block_comments() {
    assert_split(
        "sqlite",
        "SELECT 1; -- comment with ; semicolon\nSELECT 2; /* block; comment */ SELECT 3;",
        &[
            "SELECT 1",
            "-- comment with ; semicolon\nSELECT 2",
            "/* block; comment */ SELECT 3",
        ],
    );
}

#[test]
fn postgres_nested_block_comments_preserve_inner_semicolons() {
    assert_split(
        "postgres",
        "SELECT 1; /* outer; /* inner; */ still outer; */ SELECT 2;",
        &[
            "SELECT 1",
            "/* outer; /* inner; */ still outer; */ SELECT 2",
        ],
    );
}

#[test]
fn mysql_hash_line_comments_are_recognized() {
    assert_split(
        "mysql",
        "SELECT 1; # comment with ; semicolon\nSELECT 2;",
        &["SELECT 1", "# comment with ; semicolon\nSELECT 2"],
    );
}

#[test]
fn mysql_dash_dash_requires_following_whitespace_or_control() {
    assert_split(
        "mysql",
        "SELECT 1--2; SELECT 3;",
        &["SELECT 1--2", "SELECT 3"],
    );
}

#[test]
fn case_inside_begin_end_does_not_close_compound_early() {
    let sql = "CREATE TRIGGER tr AFTER INSERT ON t BEGIN INSERT INTO log SELECT CASE WHEN NEW.id = 1 THEN 'a;b' ELSE 'c' END; END;";
    let statements = split_plugin_migration_statements(sql, "sqlite").unwrap();
    assert_eq!(statements.len(), 1);
    assert!(statements[0].contains("CASE WHEN"));
    assert!(statements[0].contains("END; END") || statements[0].ends_with("END"));
}

#[test]
fn case_expression_end_does_not_break_splitting() {
    assert_split(
        "sqlite",
        "SELECT CASE WHEN x = 1 THEN 'a;b' ELSE 'c' END FROM t; SELECT 2;",
        &[
            "SELECT CASE WHEN x = 1 THEN 'a;b' ELSE 'c' END FROM t",
            "SELECT 2",
        ],
    );
}

#[test]
fn transaction_begin_does_not_swallow_following_statements() {
    // Runner-owned transactions mean authors rarely need this, but `BEGIN;`
    // must not be treated as a compound block opener.
    assert_split(
        "sqlite",
        "BEGIN; CREATE TABLE t (id TEXT); COMMIT;",
        &["BEGIN", "CREATE TABLE t (id TEXT)", "COMMIT"],
    );
    assert_split(
        "postgres",
        "BEGIN /* transaction comment */; CREATE TABLE t (id TEXT); COMMIT;",
        &[
            "BEGIN /* transaction comment */",
            "CREATE TABLE t (id TEXT)",
            "COMMIT",
        ],
    );
    assert_split(
        "postgres",
        "BEGIN ISOLATION LEVEL SERIALIZABLE; SELECT 1; COMMIT;",
        &["BEGIN ISOLATION LEVEL SERIALIZABLE", "SELECT 1", "COMMIT"],
    );
}

#[test]
fn postgres_dollar_quoted_bodies_preserve_internal_semicolons() {
    assert_split(
        "postgres",
        r#"CREATE FUNCTION f() RETURNS void AS $$ BEGIN PERFORM 1; PERFORM 2; END; $$ LANGUAGE plpgsql; SELECT 1;"#,
        &[
            "CREATE FUNCTION f() RETURNS void AS $$ BEGIN PERFORM 1; PERFORM 2; END; $$ LANGUAGE plpgsql",
            "SELECT 1",
        ],
    );
    assert_split(
        "postgres",
        r#"CREATE FUNCTION f() RETURNS text AS $body$ SELECT 'a;b'; $body$ LANGUAGE sql;"#,
        &[r#"CREATE FUNCTION f() RETURNS text AS $body$ SELECT 'a;b'; $body$ LANGUAGE sql"#],
    );
}

#[test]
fn postgres_dollar_quoted_body_handles_non_ascii_without_byte_boundary_panics() {
    assert_split(
        "postgres",
        "CREATE FUNCTION f() RETURNS text AS $body$ SELECT '日本語;é'; $body$ LANGUAGE sql;",
        &["CREATE FUNCTION f() RETURNS text AS $body$ SELECT '日本語;é'; $body$ LANGUAGE sql"],
    );
    assert_split(
        "postgres",
        "CREATE FUNCTION f() RETURNS text AS $é$ SELECT '日本語;é'; $é$ LANGUAGE sql;",
        &["CREATE FUNCTION f() RETURNS text AS $é$ SELECT '日本語;é'; $é$ LANGUAGE sql"],
    );
}

#[test]
fn postgres_dollar_quote_tags_follow_identifier_boundaries() {
    assert_split(
        "postgres",
        "SELECT foo$tag$bar; SELECT $9$not_a_tag; SELECT 3;",
        &["SELECT foo$tag$bar", "SELECT $9$not_a_tag", "SELECT 3"],
    );
}

#[test]
fn concurrently_inside_dollar_quote_stays_in_function_body_statement() {
    let sql = r#"
        CREATE FUNCTION f() RETURNS void AS $$
            -- CREATE INDEX CONCURRENTLY should stay inside this body
            BEGIN PERFORM 1; END;
        $$ LANGUAGE plpgsql;
        CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_t ON t (id);
    "#;
    let statements = split_plugin_migration_statements(sql, "postgres").unwrap();
    assert_eq!(statements.len(), 2);
    assert!(statements[0].contains("CREATE INDEX CONCURRENTLY"));
    assert!(
        strip_leading_upper(statements[1]).starts_with("CREATE INDEX CONCURRENTLY"),
        "{}",
        statements[1]
    );
}

fn strip_leading_upper(sql: &str) -> String {
    sql.split_whitespace()
        .map(str::to_ascii_uppercase)
        .collect::<Vec<_>>()
        .join(" ")
}

#[test]
fn mysql_delimiter_wraps_compound_trigger_body() {
    let sql = r#"
        CREATE TABLE t (id INT);
        DELIMITER //
        CREATE TRIGGER tr BEFORE INSERT ON t FOR EACH ROW
        BEGIN
            SET NEW.id = 1;
        END //
        DELIMITER ;
        INSERT INTO t VALUES (2);
    "#;
    let statements = split_plugin_migration_statements(sql, "mysql").unwrap();
    assert_no_delimiter_directives(&statements);
    assert_eq!(statements.len(), 3);
    assert_eq!(statements[0], "CREATE TABLE t (id INT)");
    assert!(statements[1].contains("SET NEW.id = 1;"));
    assert!(statements[1].trim_end().ends_with("END"));
    assert!(!statements[1].contains("//"));
    assert_eq!(statements[2], "INSERT INTO t VALUES (2)");
}

#[test]
fn mysql_delimiter_meta_commands_are_never_returned() {
    let sql = r#"
        -- leading comment before directive
        DELIMITER //
        CREATE PROCEDURE p1()
        BEGIN
            SET @a = 1;
        END //
        DELIMITER ;

        /* between routines */
        DELIMITER //
        CREATE PROCEDURE p2()
        BEGIN
            SET @b = 2;
        END //
        # hash comment then restore
        DELIMITER ;

        SELECT @a;
    "#;
    let statements = split_plugin_migration_statements(sql, "mysql").unwrap();
    assert_no_delimiter_directives(&statements);
    assert_eq!(statements.len(), 3);
    assert!(
        statements[0]
            .to_ascii_uppercase()
            .starts_with("CREATE PROCEDURE P1"),
        "{}",
        statements[0]
    );
    assert!(statements[0].contains("SET @a = 1;"));
    assert!(statements[0].trim_end().ends_with("END"));
    assert!(!statements[0].ends_with("//"));
    assert!(
        statements[1]
            .to_ascii_uppercase()
            .starts_with("CREATE PROCEDURE P2"),
        "{}",
        statements[1]
    );
    assert!(statements[1].contains("SET @b = 2;"));
    assert_eq!(statements[2], "SELECT @a");
}

#[test]
fn mysql_delimiter_with_surrounding_comments_and_whitespace_has_no_phantoms() {
    let sql = "\n\n  /* prelude */\n  -- skip me\n  DELIMITER //\n  \n  CREATE TRIGGER tr BEFORE INSERT ON t FOR EACH ROW BEGIN SET NEW.id = 1; END //\n  \n  /* trailing */\n  DELIMITER ;\n  -- after restore\n  \n";
    let statements = split_plugin_migration_statements(sql, "mysql").unwrap();
    assert_no_delimiter_directives(&statements);
    assert_eq!(statements.len(), 1);
    assert!(
        statements[0]
            .to_ascii_uppercase()
            .contains("CREATE TRIGGER")
    );
    assert!(statements[0].trim_end().ends_with("END"));
}

#[test]
fn mysql_if_only_routine_without_delimiter_is_rejected() {
    let sql = r#"
        CREATE PROCEDURE p()
        IF true THEN
            SET @x = 1;
        END IF;
    "#;
    let err = split_plugin_migration_statements(sql, "mysql").unwrap_err();
    assert!(
        err.to_string().contains("END IF") || err.to_string().contains("DELIMITER"),
        "got {err}"
    );
}

#[test]
fn mysql_begin_end_compound_without_delimiter_stays_one_statement() {
    let sql = r#"
        CREATE TABLE t (id INT);
        CREATE TRIGGER tr BEFORE INSERT ON t FOR EACH ROW BEGIN SET NEW.id = 1; END;
    "#;
    let statements = split_plugin_migration_statements(sql, "mysql").unwrap();
    assert_eq!(statements.len(), 2);
    assert!(statements[1].contains("SET NEW.id = 1;"));
    assert!(statements[1].trim_end().ends_with("END"));
}

#[test]
fn mysql_end_if_inside_begin_does_not_close_outer_block_early() {
    let sql = r#"
        DELIMITER //
        CREATE PROCEDURE p()
        BEGIN
            IF NEW.id IS NULL THEN
                SET NEW.id = 1;
            END IF;
            SET NEW.id = NEW.id + 1;
        END //
        DELIMITER ;
    "#;
    let statements = split_plugin_migration_statements(sql, "mysql").unwrap();
    assert_no_delimiter_directives(&statements);
    assert_eq!(statements.len(), 1);
    assert!(statements[0].contains("END IF;"));
    assert!(statements[0].contains("SET NEW.id = NEW.id + 1;"));
    assert!(!statements[0].contains("//"));
}

#[test]
fn mysql_single_statement_function_without_begin_is_allowed() {
    assert_split(
        "mysql",
        "CREATE FUNCTION hello(s CHAR(20)) RETURNS CHAR(50) DETERMINISTIC RETURN CONCAT('Hello, ', s);",
        &[
            "CREATE FUNCTION hello(s CHAR(20)) RETURNS CHAR(50) DETERMINISTIC RETURN CONCAT('Hello, ', s)",
        ],
    );
}

#[test]
fn sqlite_trigger_begin_end_preserves_internal_semicolons() {
    assert_split(
        "sqlite",
        "CREATE TABLE t (id TEXT); CREATE TRIGGER tr AFTER INSERT ON t BEGIN INSERT INTO t VALUES ('x'); END;",
        &[
            "CREATE TABLE t (id TEXT)",
            "CREATE TRIGGER tr AFTER INSERT ON t BEGIN INSERT INTO t VALUES ('x'); END",
        ],
    );
}

#[test]
fn rejects_unclosed_quotes_comments_and_dollar_tags() {
    assert_split_err("sqlite", "INSERT INTO t VALUES ('unclosed");
    assert_split_err("sqlite", r#"SELECT "unclosed"#);
    assert_split_err("mysql", "SELECT `unclosed");
    assert_split_err("sqlite", "SELECT 1 /* unclosed");
    assert_split_err(
        "postgres",
        "CREATE FUNCTION f() RETURNS void AS $$ BEGIN PERFORM 1;",
    );
}

#[test]
fn rejects_unclosed_begin_end_block() {
    assert_split_err(
        "sqlite",
        "CREATE TRIGGER tr AFTER INSERT ON t BEGIN INSERT INTO t VALUES ('x');",
    );
}

#[test]
fn rejects_mysql_delimiter_never_restored() {
    let sql = r#"
        DELIMITER //
        CREATE TRIGGER tr BEFORE INSERT ON t FOR EACH ROW BEGIN SET NEW.id = 1; END //
    "#;
    let err = split_plugin_migration_statements(sql, "mysql").unwrap_err();
    assert!(err.to_string().contains("never restored"), "got {err}");
}

#[test]
fn rejects_mysql_malformed_and_trailing_delimiter_directives() {
    assert_split_err("mysql", "DELIMITER\nSELECT 1;");
    assert_split_err("mysql", "DELIMITER // trailing\nSELECT 1;");
    assert_split_err("mysql", "DELIMITER '\nSELECT 1;");
    // Unrestored custom delimiter must fail before any statement executes.
    let err = split_plugin_migration_statements("DELIMITER //\nCREATE TABLE t (id INT)//", "mysql")
        .unwrap_err();
    assert!(err.to_string().contains("never restored"), "got {err}");
}

#[test]
fn delimiter_is_ordinary_sql_on_sqlite() {
    let sql = "DELIMITER //\nSELECT 1;\nDELIMITER ;";
    let sqlite = split_plugin_migration_statements(sql, "sqlite").unwrap();
    assert!(sqlite[0].to_ascii_uppercase().starts_with("DELIMITER"));
}

#[test]
fn mysql_scanner_handles_non_ascii_text_without_byte_boundary_panics() {
    assert_split("mysql", "表名; SELECT 1;", &["表名", "SELECT 1"]);
    assert_split(
        "mysql",
        "DELIMITER //\nCREATE PROCEDURE π() BEGIN SELECT 1; END //\nDELIMITER ;",
        &["CREATE PROCEDURE π() BEGIN SELECT 1; END"],
    );
}

#[test]
fn skips_comment_only_segments() {
    assert_split(
        "sqlite",
        "SELECT 1; -- only a comment\n; /* also comment */; SELECT 2;",
        &["SELECT 1", "SELECT 2"],
    );
}

#[test]
fn trailing_semicolon_does_not_yield_empty_statement() {
    assert_split("sqlite", "SELECT 1;", &["SELECT 1"]);
    assert_split("sqlite", "SELECT 1", &["SELECT 1"]);
}

async fn test_pool() -> sqlx::AnyPool {
    sqlx::any::install_default_drivers();
    sqlx::any::AnyPoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap()
}

async fn setup_core_migrations(pool: &sqlx::AnyPool) {
    let runner = MigrationRunner::new(pool.clone(), "sqlite".to_string());
    runner.run_pending().await.unwrap();
}

#[tokio::test]
async fn semicolon_inside_string_literal_round_trips_on_sqlite() {
    let pool = test_pool().await;
    setup_core_migrations(&pool).await;
    let runner = MigrationRunner::new(pool.clone(), "sqlite".to_string());

    let migrations = vec![(
        "literal_plugin",
        vec![CustomPluginMigration {
            version: 1,
            name: "seed_with_embedded_semicolon",
            checksum: "v1_seed_semicolon_lit",
            sql: r#"
                CREATE TABLE IF NOT EXISTS literal_plugin_data (
                    id TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                INSERT INTO literal_plugin_data (id, value) VALUES ('row1', 'a;b');
            "#,
            sql_postgres: None,
            sql_mysql: None,
        }],
    )];

    let applied = runner.run_plugin_pending(&migrations).await.unwrap();
    assert_eq!(applied.len(), 1);

    let value: String =
        sqlx::query_scalar("SELECT value FROM literal_plugin_data WHERE id = 'row1'")
            .fetch_one(&pool)
            .await
            .expect("seeded row must round-trip");
    assert_eq!(value, "a;b");
}

#[tokio::test]
async fn malformed_sql_fails_before_execution_on_sqlite() {
    let pool = test_pool().await;
    setup_core_migrations(&pool).await;
    let runner = MigrationRunner::new(pool.clone(), "sqlite".to_string());

    let migrations = vec![(
        "bad_plugin",
        vec![CustomPluginMigration {
            version: 1,
            name: "unclosed_string",
            checksum: "v1_unclosed",
            // First statement would create a table; unclosed quote must fail
            // during validation so nothing is applied and no tracking row lands.
            sql: r#"
                CREATE TABLE IF NOT EXISTS bad_plugin_should_not_exist (id TEXT);
                INSERT INTO bad_plugin_should_not_exist VALUES ('unclosed);
            "#,
            sql_postgres: None,
            sql_mysql: None,
        }],
    )];

    let err = runner
        .run_plugin_pending(&migrations)
        .await
        .expect_err("malformed migration must fail closed");
    assert!(
        err.to_string().contains("unclosed"),
        "unexpected error: {err}"
    );

    let table_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'bad_plugin_should_not_exist'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(table_count, 0, "no statement should have executed");

    let tracking_table_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master \
         WHERE type = 'table' AND name = '_ferrum_plugin_migrations'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    if tracking_table_count == 1 {
        let tracking: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM _ferrum_plugin_migrations WHERE plugin_name = 'bad_plugin'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(tracking, 0, "tracking row must not be written");
    } else {
        assert_eq!(
            tracking_table_count, 0,
            "failed migration must not leave an unexpected tracking table state"
        );
    }
}
