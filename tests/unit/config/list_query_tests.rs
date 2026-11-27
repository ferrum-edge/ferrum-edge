//! Admin list query primitives (`q`, `ids`, collection revisions) shared by
//! every config store and by the cached-config path.

use ferrum_edge::config::list_query::{
    MAX_LIST_IDS, MAX_SEARCH_TERM_BYTES, ResourceListFilter, SQL_LIKE_ESCAPE, SearchTerm,
    collection_revision_from_sequences, parse_list_ids,
};
use ferrum_edge::config::types::{Consumer, PluginConfig, Proxy, Upstream};
use serde_json::json;

fn term(raw: &str) -> SearchTerm {
    SearchTerm::parse(raw)
        .expect("valid term")
        .expect("non-empty term")
}

fn proxy(value: serde_json::Value) -> Proxy {
    serde_json::from_value(value).expect("proxy fixture")
}

#[test]
fn empty_q_means_no_search_and_bounds_are_enforced() {
    assert_eq!(SearchTerm::parse("").unwrap(), None);
    let longest = "a".repeat(MAX_SEARCH_TERM_BYTES);
    assert!(SearchTerm::parse(&longest).unwrap().is_some());
    let too_long = "a".repeat(MAX_SEARCH_TERM_BYTES + 1);
    assert!(SearchTerm::parse(&too_long).is_err());
    // A multi-byte character counts by UTF-8 bytes.
    let multibyte = "é".repeat(MAX_SEARCH_TERM_BYTES / 2 + 1);
    assert!(SearchTerm::parse(&multibyte).is_err());
    for control in ["a\u{0}b", "line\nbreak", "tab\t", "del\u{7f}", "c1\u{85}"] {
        assert!(
            SearchTerm::parse(control).is_err(),
            "control character must be refused: {control:?}"
        );
    }
    // Whitespace is significant and not trimmed.
    assert_eq!(term(" a ").folded(), " a ");
}

#[test]
fn case_folding_is_ascii_only() {
    let t = term("KeY");
    assert_eq!(t.folded(), "key");
    assert!(t.matches("my-KEY-service"));
    assert!(t.matches("monkey"));
    // Kelvin sign (U+212A) folds to `k` under Unicode rules, never here.
    assert!(!t.matches("\u{212A}ey"));
    // Non-ASCII letters compare exactly: no case folding, no accent folding.
    let accented = term("é");
    assert!(accented.matches("café"));
    assert!(!accented.matches("CAFÉ"));
    assert!(!accented.matches("cafe"));
    // NFC vs NFD spellings are different code point sequences.
    assert!(!accented.matches("cafe\u{301}"));
    // A capital non-ASCII letter in the term is not lowercased either.
    assert_eq!(term("É").folded(), "É");
    assert!(!term("É").matches("é"));
}

#[test]
fn sql_like_pattern_escapes_every_metacharacter() {
    assert_eq!(SQL_LIKE_ESCAPE, '!');
    assert_eq!(term("50%").sql_like_pattern(), "%50!%%");
    assert_eq!(term("a_b").sql_like_pattern(), "%a!_b%");
    assert_eq!(term("wow!").sql_like_pattern(), "%wow!!%");
    assert_eq!(term("Mixed\\Case").sql_like_pattern(), "%mixed\\case%");
}

#[test]
fn mongo_regex_is_a_literal_ascii_case_insensitive_matcher() {
    assert_eq!(term("aB.").mongo_regex(), "[aA][bB]\\.");
    assert_eq!(term("é1").mongo_regex(), "é1");
    // Prove the regex agrees with the in-memory rule over a sample set
    // (Rust's regex accepts the same escapes PCRE does for ASCII punctuation).
    let samples = [
        "API.example.com",
        "apixexample",
        "50% off",
        "path/(v1)*",
        "user_name-1",
        "\u{212A}elvin",
        "Kelvin",
        "café",
        "CAFÉ",
        "a+b?c",
        "[x]",
        "{y}",
        "^start$",
        "pipe|bar",
    ];
    for raw in [
        ".example", "50%", "(v1)*", "_name-", "k", "é", "+b?", "[x]", "{y}", "^start$", "|",
    ] {
        let t = term(raw);
        let regex = regex::Regex::new(&t.mongo_regex()).expect("valid regex");
        for sample in samples {
            assert_eq!(
                regex.is_match(sample),
                t.matches(sample),
                "term {raw:?} vs {sample:?}"
            );
        }
    }
}

#[test]
fn host_list_matching_is_per_element() {
    let hosts = vec!["api.example.com".to_string(), "www.example.org".to_string()];
    assert!(term("EXAMPLE.ORG").matches_hosts(&hosts));
    assert!(term("api").matches_hosts(&hosts));
    // Would span the JSON array boundary `","` in SQL storage.
    assert!(!term("com\",\"www").matches_hosts(&hosts));
    assert!(!term("com,www").matches_hosts(&hosts));
    assert!(!term("[").matches_hosts(&hosts));
    assert!(!term("]").can_match_host_list());
    assert!(!term("\\").can_match_host_list());
    assert!(term("*.example").can_match_host_list());
}

#[test]
fn ids_parsing_is_bounded_and_strict() {
    assert_eq!(
        parse_list_ids("a,b.c,d-e_f").unwrap(),
        vec!["a", "b.c", "d-e_f"]
    );
    assert!(parse_list_ids("").is_err());
    assert!(parse_list_ids("a,,b").is_err());
    assert!(parse_list_ids("a,").is_err());
    assert!(parse_list_ids("a,b,a").is_err(), "duplicates are refused");
    assert!(parse_list_ids("bad id").is_err());
    assert!(parse_list_ids("-leading").is_err());
    let max: Vec<String> = (0..MAX_LIST_IDS).map(|i| format!("id{i}")).collect();
    assert_eq!(parse_list_ids(&max.join(",")).unwrap().len(), MAX_LIST_IDS);
    let over: Vec<String> = (0..=MAX_LIST_IDS).map(|i| format!("id{i}")).collect();
    assert!(parse_list_ids(&over.join(",")).is_err());
}

#[test]
fn search_fields_per_kind_match_the_documented_set() {
    let p = proxy(json!({
        "id": "p-1",
        "name": "Orders API",
        "hosts": ["orders.example.com"],
        "listen_path": "/orders/v2",
        "backend_host": "backend.internal",
        "backend_port": 8080
    }));
    let filter = |q: &str| ResourceListFilter {
        search: Some(term(q)),
        ..Default::default()
    };
    assert!(filter("P-1").matches(&p));
    assert!(filter("orders api").matches(&p));
    assert!(filter("/V2").matches(&p));
    assert!(filter("example.com").matches(&p));
    // backend_host is not a search field.
    assert!(!filter("backend.internal").matches(&p));

    let c: Consumer = serde_json::from_value(json!({
        "id": "c-1",
        "username": "Alice@Example.com",
        "custom_id": "CRM-42"
    }))
    .unwrap();
    assert!(filter("alice@").matches(&c));
    assert!(filter("crm-42").matches(&c));
    assert!(filter("C-1").matches(&c));

    let u: Upstream = serde_json::from_value(json!({
        "id": "u-1",
        "name": "Payments Pool",
        "targets": [{"host": "10.0.0.1", "port": 80}]
    }))
    .unwrap();
    assert!(filter("payments").matches(&u));
    assert!(!filter("10.0.0.1").matches(&u));

    let pc: PluginConfig = serde_json::from_value(json!({
        "id": "pc-1",
        "plugin_name": "rate_limiting",
        "scope": "global",
        "config": {"secret_value": "needle"}
    }))
    .unwrap();
    assert!(filter("RATE_").matches(&pc));
    assert!(!filter("needle").matches(&pc), "config is never searched");
}

#[test]
fn viewer_guard_excludes_names_that_may_carry_url_userinfo() {
    let p = proxy(json!({
        "id": "p-2",
        "name": "https://ops:hunter2@example.com",
        "listen_path": "/guarded",
        "backend_host": "backend.internal",
        "backend_port": 8080
    }));
    let unguarded = ResourceListFilter {
        search: Some(term("hunter2")),
        ..Default::default()
    };
    assert!(unguarded.matches(&p));
    let guarded = ResourceListFilter {
        exclude_at_sign_names: true,
        ..unguarded.clone()
    };
    assert!(!guarded.matches(&p));
    // Other fields still match for the guarded role.
    let by_path = ResourceListFilter {
        search: Some(term("guarded")),
        exclude_at_sign_names: true,
        ids: None,
    };
    assert!(by_path.matches(&p));
}

#[test]
fn ids_and_search_combine_with_and() {
    let a = proxy(json!({"id": "a", "name": "alpha", "listen_path": "/a",
        "backend_host": "h", "backend_port": 80}));
    let b = proxy(json!({"id": "b", "name": "beta", "listen_path": "/b",
        "backend_host": "h", "backend_port": 80}));
    let filter = ResourceListFilter {
        search: Some(term("alp")),
        ids: Some(vec!["a".to_string(), "b".to_string()]),
        exclude_at_sign_names: false,
    };
    assert!(filter.matches(&a));
    assert!(!filter.matches(&b));
    assert!(!filter.is_unfiltered());
    assert!(ResourceListFilter::default().is_unfiltered());
}

#[test]
fn collection_revision_prefers_newest_matching_then_oldest_retained() {
    assert_eq!(collection_revision_from_sequences(Some(42), Some(7)), 42);
    assert_eq!(collection_revision_from_sequences(None, Some(7)), 7);
    assert_eq!(collection_revision_from_sequences(None, None), 0);
}
