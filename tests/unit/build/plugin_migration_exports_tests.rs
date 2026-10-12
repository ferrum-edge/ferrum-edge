//! Regression coverage for custom plugin `plugin_migrations` export discovery
//! in `build.rs` (issue #6168).

#[allow(dead_code)]
mod plugin_migration_exports {
    include!("../../../build/plugin_migration_exports.rs");
}

use plugin_migration_exports::source_defines_plugin_migrations as detects;

#[test]
fn detects_standard_spelling() {
    assert!(detects(
        "pub fn plugin_migrations() -> Vec<CustomPluginMigration> { vec![] }"
    ));
}

#[test]
fn detects_whitespace_and_comments_between_name_and_parens() {
    for source in [
        "pub fn plugin_migrations /* comment */ () -> Vec<M> { vec![] }",
        "pub fn plugin_migrations ()-> Vec<M> { vec![] }",
        "pub fn plugin_migrations\n    // why\n    () -> Vec<M> { vec![] }",
        "pub fn /* a /* nested */ comment */ plugin_migrations() -> Vec<M> { vec![] }",
        "pub\nfn\tplugin_migrations(\n) -> Vec<M> { vec![] }",
    ] {
        assert!(detects(source), "should detect: {source:?}");
    }
}

#[test]
fn detects_raw_identifier_spelling() {
    assert!(detects(
        "pub fn r#plugin_migrations() -> Vec<CustomPluginMigration> { vec![] }"
    ));
}

#[test]
fn detects_after_qualifiers_and_preceding_items() {
    let source = r##"
        //! Plugin docs mentioning `fn plugin_migrations()` in a doc comment.
        use std::collections::HashMap;

        const PATTERN: &str = r#"not "fn" here {"#;
        const BRACE: char = '{';
        const BYTES: &[u8] = b"}}}";

        pub struct Plugin<'a> {
            name: &'a str,
        }

        impl<'a> Plugin<'a> {
            pub fn new(name: &'a str) -> Self {
                Self { name }
            }
        }

        /// Declares migrations.
        #[must_use]
        pub(crate) fn plugin_migrations() -> Vec<CustomPluginMigration> {
            vec![]
        }
    "##;
    assert!(detects(source));
}

#[test]
fn ignores_mentions_in_comments_and_literals() {
    for source in [
        "// pub fn plugin_migrations() -> Vec<M>\n",
        "/* pub fn plugin_migrations() */",
        "/// pub fn plugin_migrations()\npub fn create_plugin() {}",
        r#"const S: &str = "fn plugin_migrations()";"#,
        r##"const S: &str = r#"fn plugin_migrations()"#;"##,
        r#"const S: &[u8] = b"fn plugin_migrations()";"#,
    ] {
        assert!(!detects(source), "should not detect: {source:?}");
    }
}

#[test]
fn ignores_nested_functions_not_reachable_from_collector() {
    for source in [
        "impl Plugin { pub fn plugin_migrations() -> Vec<M> { vec![] } }",
        "mod inner { pub fn plugin_migrations() -> Vec<M> { vec![] } }",
        "pub fn outer() { fn plugin_migrations() {} }",
        "#[cfg(test)] mod tests { fn plugin_migrations() {} }",
    ] {
        assert!(!detects(source), "should not detect: {source:?}");
    }
}

#[test]
fn ignores_other_names() {
    for source in [
        "pub fn plugin_migrations_v2() -> Vec<M> { vec![] }",
        "pub fn my_plugin_migrations() -> Vec<M> { vec![] }",
        "pub fn create_plugin() {} let plugin_migrations = 1;",
        "pub static plugin_migrations: u8 = 0;",
    ] {
        assert!(!detects(source), "should not detect: {source:?}");
    }
}

#[test]
fn braces_inside_literals_do_not_hide_later_top_level_export() {
    let source = r#"
        const OPEN: &str = "{{{";
        const CH: char = '}';
        const ESC: char = '\'';
        pub fn plugin_migrations() -> Vec<M> { vec![] }
    "#;
    assert!(detects(source));
}

#[test]
fn every_shipped_custom_plugin_export_is_detected() {
    for dir in ["custom_plugins", "custom_plugins/examples"] {
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            if source.contains("pub fn plugin_migrations()") {
                assert!(
                    detects(&source),
                    "{} exports plugin_migrations() but the build scan missed it",
                    path.display()
                );
            }
        }
    }
}
