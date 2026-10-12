//! Regression coverage for custom plugin `plugin_migrations` export discovery
//! in `build.rs` (issue #6168).

#[allow(dead_code)]
mod plugin_migration_exports {
    include!("../../../build/plugin_migration_exports.rs");
}

use plugin_migration_exports::plugin_migrations_exported;

fn detects(source: &str) -> bool {
    plugin_migrations_exported(source)
        .unwrap_or_else(|msg| panic!("unexpected scan error for {source:?}: {msg}"))
}

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
fn detects_root_reexport_from_inline_module() {
    for source in [
        "mod inner { pub fn plugin_migrations() -> Vec<M> { vec![] } }\n\
         pub use self::inner::plugin_migrations;",
        "pub use self::inner::plugin_migrations;\n\
         mod inner { pub fn plugin_migrations() -> Vec<M> { vec![] } }",
        "pub use crate::custom_plugins::shared::plugin_migrations;",
        "pub use inner::r#plugin_migrations;\n\
         mod inner { pub fn plugin_migrations() -> Vec<M> { vec![] } }",
        "pub(crate) use self::inner /* why */ :: plugin_migrations ;\n\
         mod inner { pub fn plugin_migrations() -> Vec<M> { vec![] } }",
    ] {
        assert!(detects(source), "should detect: {source:?}");
    }
}

#[test]
fn detects_grouped_and_renamed_root_reexports() {
    for source in [
        "mod inner { pub fn helper() {} pub fn plugin_migrations() -> Vec<M> { vec![] } }\n\
         pub use self::inner::{helper, plugin_migrations};",
        "mod inner { pub fn declare() -> Vec<M> { vec![] } }\n\
         pub use self::inner::declare as plugin_migrations;",
        "mod inner { pub fn declare() -> Vec<M> { vec![] } }\n\
         pub use self::{inner::{declare as plugin_migrations}, other::Thing};",
        "pub use crate::{a::b, c::{d, plugin_migrations}};",
    ] {
        assert!(detects(source), "should detect: {source:?}");
    }
}

#[test]
fn ignores_use_trees_that_do_not_bind_the_name() {
    for source in [
        "use self::plugin_migrations::Thing;",
        "use self::inner::plugin_migrations as declare;",
        "use self::inner::{plugin_migrations as declare, helper};",
        "use std::collections::HashMap;",
        "mod inner { pub use super::other::plugin_migrations; }",
        "pub fn f<'a>(x: &'a str) -> impl Sized + use<'a> { x }\n\
         pub fn plugin_migrations_v2() {}",
    ] {
        assert!(!detects(source), "should not detect: {source:?}");
    }
}

#[test]
fn precise_capture_bound_does_not_hide_later_root_export() {
    let source = "pub fn f<'a>(x: &'a str) -> impl Sized + use<'a> { x }\n\
                  pub fn plugin_migrations() -> Vec<M> { vec![] }";
    assert!(detects(source));
}

#[test]
fn nested_definition_without_root_export_is_a_hard_error() {
    for source in [
        "impl Plugin { pub fn plugin_migrations() -> Vec<M> { vec![] } }",
        "mod inner { pub fn plugin_migrations() -> Vec<M> { vec![] } }",
        "pub fn outer() { fn plugin_migrations() {} }",
        "#[cfg(test)] mod tests { fn plugin_migrations() {} }",
        "mod inner { pub fn plugin_migrations() -> Vec<M> { vec![] } }\n\
         pub use self::inner::plugin_migrations as declare;",
        "mod inner { pub fn plugin_migrations() -> Vec<M> { vec![] } }\n\
         pub use self::inner::*;",
    ] {
        let Err(err) = plugin_migrations_exported(source) else {
            panic!("nested definition must fail the build: {source:?}");
        };
        assert!(
            err.contains("pub use <path>::plugin_migrations;"),
            "error should explain the root re-export fix: {err}"
        );
    }
}

#[test]
fn root_definition_alongside_nested_definition_is_detected() {
    let source = "impl Plugin { fn plugin_migrations(&self) {} }\n\
                  pub fn plugin_migrations() -> Vec<M> { vec![] }";
    assert!(detects(source));
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
