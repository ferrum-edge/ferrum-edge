//! Schema, compilation-bounds, and evaluation semantics for the declarative
//! per-instance plugin execution trigger (`PluginConfig.trigger`).
//!
//! These tests own the *pure* layer: strict parsing, fail-closed validation, and
//! the deterministic absent / present / multi-value / case rules. The runtime
//! gate (decide-once memoization, phase safety, no-work-on-skip) is covered in
//! `tests/unit/plugins/plugin_trigger_gate_tests.rs`.

use std::net::IpAddr;

use ferrum_edge::config::plugin_trigger::{
    CompiledPluginTrigger, FieldVisitor, PluginTrigger, PluginTriggerProtocol, TriggerFacts,
};

// ---------------------------------------------------------------------------
// Test facts
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Facts {
    http: bool,
    method: Option<String>,
    path: Option<String>,
    host: Option<String>,
    sni: Option<String>,
    protocols: Vec<PluginTriggerProtocol>,
    client_ip: Option<IpAddr>,
    namespace: Option<String>,
    proxy_id: Option<String>,
    listen_port: Option<u16>,
    consumer: Option<String>,
    auth_method: Option<String>,
    spiffe_id: Option<String>,
    headers: Vec<(String, String)>,
    query: Vec<(String, String)>,
    cookies: Vec<(String, String)>,
}

impl Facts {
    fn http() -> Self {
        Self {
            http: true,
            method: Some("GET".to_string()),
            path: Some("/v1/orders".to_string()),
            ..Self::default()
        }
    }

    fn stream() -> Self {
        Self {
            http: false,
            protocols: vec![PluginTriggerProtocol::Tcp],
            ..Self::default()
        }
    }

    fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers
            .push((name.to_ascii_lowercase(), value.to_string()));
        self
    }

    fn with_query(mut self, name: &str, value: &str) -> Self {
        self.query.push((name.to_string(), value.to_string()));
        self
    }

    fn with_cookie(mut self, name: &str, value: &str) -> Self {
        self.cookies.push((name.to_string(), value.to_string()));
        self
    }
}

fn visit_pairs(pairs: &[(String, String)], name: &str, visit: &mut FieldVisitor<'_>) {
    for (candidate, value) in pairs {
        if candidate != name {
            continue;
        }
        if !visit(Some(value)) {
            return;
        }
    }
}

impl TriggerFacts for Facts {
    fn is_http(&self) -> bool {
        self.http
    }
    fn method(&self) -> Option<&str> {
        self.method.as_deref()
    }
    fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }
    fn host(&self) -> Option<&str> {
        self.host.as_deref()
    }
    fn sni(&self) -> Option<&str> {
        self.sni.as_deref()
    }
    fn protocols(&self) -> &[PluginTriggerProtocol] {
        &self.protocols
    }
    fn client_ip(&self) -> Option<IpAddr> {
        self.client_ip
    }
    fn namespace(&self) -> Option<&str> {
        self.namespace.as_deref()
    }
    fn proxy_id(&self) -> Option<&str> {
        self.proxy_id.as_deref()
    }
    fn listen_port(&self) -> Option<u16> {
        self.listen_port
    }
    fn consumer_identity(&self) -> Option<&str> {
        self.consumer.as_deref()
    }
    fn auth_method(&self) -> Option<&str> {
        self.auth_method.as_deref()
    }
    fn spiffe_id(&self) -> Option<&str> {
        self.spiffe_id.as_deref()
    }
    fn for_each_header_value(&self, lower_name: &str, visit: &mut FieldVisitor<'_>) {
        visit_pairs(&self.headers, lower_name, visit);
    }
    fn for_each_query_value(&self, name: &str, visit: &mut FieldVisitor<'_>) {
        visit_pairs(&self.query, name, visit);
    }
    fn for_each_cookie_value(&self, name: &str, visit: &mut FieldVisitor<'_>) {
        visit_pairs(&self.cookies, name, visit);
    }
}

fn parse(yaml_like_json: serde_json::Value) -> PluginTrigger {
    serde_json::from_value(yaml_like_json).expect("trigger parses")
}

fn compile(yaml_like_json: serde_json::Value) -> CompiledPluginTrigger {
    CompiledPluginTrigger::compile(&parse(yaml_like_json)).expect("trigger compiles")
}

fn compile_error(yaml_like_json: serde_json::Value) -> String {
    let trigger: PluginTrigger =
        serde_json::from_value(yaml_like_json).expect("trigger parses structurally");
    match CompiledPluginTrigger::compile(&trigger) {
        Ok(_) => panic!("trigger should have been rejected"),
        Err(error) => error,
    }
}

// ---------------------------------------------------------------------------
// Strict schema
// ---------------------------------------------------------------------------

#[test]
fn unknown_trigger_fields_are_rejected_at_parse_time() {
    let error = serde_json::from_value::<PluginTrigger>(serde_json::json!({
        "when": {"match": {"method": ["GET"]}},
        "unless": {"match": {"method": ["POST"]}}
    }))
    .expect_err("unknown top-level field must be rejected");
    assert!(error.to_string().contains("unless"), "{error}");

    let error = serde_json::from_value::<PluginTrigger>(serde_json::json!({
        "when": {"match": {"header": {"name": "x", "presence": "present", "regex": "a"}}}
    }))
    .expect_err("unknown field-match field must be rejected");
    assert!(error.to_string().contains("regex"), "{error}");
}

#[test]
fn a_node_must_set_exactly_one_branch() {
    for node in [
        serde_json::json!({}),
        serde_json::json!({"all": [{"match": {"method": ["GET"]}}], "any": [{"match": {"method": ["POST"]}}]}),
        serde_json::json!({"not": {"match": {"method": ["GET"]}}, "match": {"method": ["POST"]}}),
    ] {
        let error = compile_error(serde_json::json!({"when": node}));
        assert!(
            error.contains("exactly one of `all`, `any`, `not`, or `match`"),
            "{error}"
        );
    }
}

#[test]
fn empty_all_and_any_lists_are_rejected_rather_than_given_an_implicit_truth_value() {
    for (branch, node) in [
        ("all", serde_json::json!({"all": []})),
        ("any", serde_json::json!({"any": []})),
    ] {
        let error = compile_error(serde_json::json!({"when": node}));
        assert!(error.contains(branch), "{error}");
        assert!(error.contains("at least one child node"), "{error}");
    }
}

#[test]
fn a_match_leaf_must_set_exactly_one_predicate() {
    let error = compile_error(serde_json::json!({
        "when": {"match": {"method": ["GET"], "path": {"prefix": ["/a"]}}}
    }));
    assert!(error.contains("exactly one predicate"), "{error}");

    let error = compile_error(serde_json::json!({"when": {"match": {}}}));
    assert!(error.contains("exactly one predicate"), "{error}");
}

#[test]
fn a_string_match_must_set_exactly_one_of_exact_prefix_regex() {
    let error = compile_error(serde_json::json!({
        "when": {"match": {"path": {"exact": ["/a"], "prefix": ["/b"]}}}
    }));
    assert!(
        error.contains("exactly one of `exact`, `prefix`, or `regex`"),
        "{error}"
    );

    let error = compile_error(serde_json::json!({"when": {"match": {"path": {}}}}));
    assert!(
        error.contains("exactly one of `exact`, `prefix`, or `regex`"),
        "{error}"
    );
}

#[test]
fn absent_presence_cannot_be_combined_with_a_value_comparison() {
    let error = compile_error(serde_json::json!({
        "when": {"match": {"header": {
            "name": "x-tenant", "presence": "absent", "value": {"exact": ["gold"]}
        }}}
    }));
    assert!(error.contains("presence: absent"), "{error}");
    assert!(error.contains("no value to compare"), "{error}");
}

// ---------------------------------------------------------------------------
// Bounds — hostile config fails closed at compile time
// ---------------------------------------------------------------------------

#[test]
fn predicate_tree_depth_is_bounded() {
    let mut node = serde_json::json!({"match": {"method": ["GET"]}});
    for _ in 0..8 {
        node = serde_json::json!({"not": node});
    }
    let error = compile_error(serde_json::json!({"when": node}));
    assert!(error.contains("deeper than the 8-level limit"), "{error}");
}

#[test]
fn predicate_tree_node_count_is_bounded() {
    let children: Vec<_> = (0..64)
        .map(|_| serde_json::json!({"any": [{"match": {"method": ["GET"]}}, {"match": {"method": ["POST"]}}]}))
        .collect();
    let error = compile_error(serde_json::json!({"when": {"all": children}}));
    assert!(error.contains("128-node limit"), "{error}");
}

#[test]
fn value_lists_values_and_field_names_are_bounded() {
    let long_list: Vec<_> = (0..65).map(|index| format!("/p{index}")).collect();
    let error = compile_error(serde_json::json!({
        "when": {"match": {"path": {"prefix": long_list}}}
    }));
    assert!(error.contains("over the 64 limit"), "{error}");

    let error = compile_error(serde_json::json!({
        "when": {"match": {"path": {"exact": ["x".repeat(1025)]}}}
    }));
    assert!(error.contains("over the 1024-byte limit"), "{error}");

    let error = compile_error(serde_json::json!({
        "when": {"match": {"header": {"name": "x".repeat(257)}}}
    }));
    assert!(error.contains("over the 256-byte limit"), "{error}");
}

#[test]
fn regex_source_length_and_program_size_are_bounded() {
    let error = compile_error(serde_json::json!({
        "when": {"match": {"path": {"regex": "a".repeat(513)}}}
    }));
    assert!(error.contains("over the 512-byte limit"), "{error}");

    // Well under the source-length limit but far over the compiled-program
    // ceiling — the size guard, not the length guard, must catch this.
    let error = compile_error(serde_json::json!({
        "when": {"match": {"path": {"regex": "(?:[a-z0-9._~-]{100}){200}"}}}
    }));
    assert!(error.contains("invalid or too large"), "{error}");

    let error = compile_error(serde_json::json!({
        "when": {"match": {"path": {"regex": "[unterminated"}}}
    }));
    assert!(error.contains("invalid or too large"), "{error}");
}

#[test]
fn malformed_cidrs_methods_field_names_and_ports_are_rejected() {
    for (value, needle) in [
        (
            serde_json::json!({"source_cidr": ["10.0.0.0/33"]}),
            "source_cidr",
        ),
        (
            serde_json::json!({"source_cidr": ["not-an-ip"]}),
            "source_cidr",
        ),
        (
            serde_json::json!({"source_cidr": ["::1/129"]}),
            "source_cidr",
        ),
        (serde_json::json!({"source_cidr": []}), "at least one"),
        (
            serde_json::json!({"method": ["GET LIST"]}),
            "valid HTTP token",
        ),
        (
            serde_json::json!({"header": {"name": "bad header"}}),
            "printable ASCII",
        ),
        (
            serde_json::json!({"header": {"name": "bad:header"}}),
            "valid HTTP field name",
        ),
        (serde_json::json!({"listen_port": [0]}), "1-65535"),
    ] {
        let error = compile_error(serde_json::json!({"when": {"match": value}}));
        assert!(error.contains(needle), "expected {needle:?} in {error}");
    }
}

/// A padded field name is REJECTED, never silently normalized into another
/// configured name. `" x-tier "` and `"x-tier"` are different strings, and the
/// documented rule is "printable ASCII without whitespace" — trimming would
/// quietly make an operator's typo address a header they did not write.
#[test]
fn field_names_are_not_trimmed_and_padded_names_are_rejected() {
    for field in ["header", "query", "cookie"] {
        for name in [
            " x-tier", "x-tier ", " x-tier ", "\tx-tier", "x-tier\n", "x tier", " ",
        ] {
            let error = compile_error(serde_json::json!({
                "when": {"match": {field: {"name": name}}}
            }));
            assert!(
                error.contains("printable ASCII"),
                "{field}.name {name:?} should be rejected as non-printable/whitespace, got: {error}"
            );
        }
        // A non-ASCII name — including the replacement character a lossy
        // decoder would produce — is rejected for the same reason.
        let error = compile_error(serde_json::json!({
            "when": {"match": {field: {"name": "\u{FFFD}"}}}
        }));
        assert!(error.contains("printable ASCII"), "{field}: {error}");

        // The unpadded name still compiles, so the rejection is about the
        // padding rather than the name.
        let _accepted = compile(serde_json::json!({
            "when": {"match": {field: {"name": "x-tier"}}}
        }));
    }
}

#[test]
fn plugin_trigger_validate_matches_compilation() {
    let good = parse(serde_json::json!({"when": {"match": {"method": ["GET"]}}}));
    assert!(good.validate().is_ok());

    let bad = parse(serde_json::json!({"when": {"match": {"source_cidr": ["10.0.0.0/33"]}}}));
    assert!(bad.validate().is_err());
}

// ---------------------------------------------------------------------------
// Boolean composition
// ---------------------------------------------------------------------------

#[test]
fn all_any_and_not_compose_as_documented() {
    let trigger = compile(serde_json::json!({
        "when": {"all": [
            {"any": [
                {"match": {"method": ["POST"]}},
                {"match": {"method": ["PUT"]}}
            ]},
            {"not": {"match": {"path": {"prefix": ["/internal"]}}}}
        ]}
    }));

    let mut facts = Facts::http();
    facts.method = Some("POST".to_string());
    facts.path = Some("/v1/orders".to_string());
    assert!(trigger.evaluate(&facts));

    facts.method = Some("GET".to_string());
    assert!(!trigger.evaluate(&facts), "OR branch must reject GET");

    facts.method = Some("PUT".to_string());
    facts.path = Some("/internal/debug".to_string());
    assert!(
        !trigger.evaluate(&facts),
        "NOT branch must reject /internal"
    );
}

// ---------------------------------------------------------------------------
// Absent / present / multi-value / case
// ---------------------------------------------------------------------------

#[test]
fn absent_input_never_satisfies_a_positive_predicate() {
    let trigger = compile(serde_json::json!({
        "when": {"match": {"header": {"name": "x-tenant"}}}
    }));
    assert!(!trigger.evaluate(&Facts::http()));
    assert!(trigger.evaluate(&Facts::http().with_header("X-Tenant", "gold")));

    let absent = compile(serde_json::json!({
        "when": {"match": {"header": {"name": "x-tenant", "presence": "absent"}}}
    }));
    assert!(absent.evaluate(&Facts::http()));
    assert!(!absent.evaluate(&Facts::http().with_header("x-tenant", "gold")));
}

#[test]
fn a_present_but_empty_identity_is_treated_as_absent() {
    let trigger = compile(serde_json::json!({"when": {"match": {"consumer": {}}}}));
    let mut facts = Facts::http();
    facts.consumer = Some(String::new());
    assert!(!trigger.evaluate(&facts));
    facts.consumer = Some("alice".to_string());
    assert!(trigger.evaluate(&facts));

    let absent = compile(serde_json::json!({
        "when": {"match": {"consumer": {"presence": "absent"}}}
    }));
    let mut facts = Facts::http();
    assert!(absent.evaluate(&facts), "no identity is absent");
    facts.consumer = Some(String::new());
    assert!(absent.evaluate(&facts), "empty identity is absent");
    facts.consumer = Some("alice".to_string());
    assert!(!absent.evaluate(&facts));
}

#[test]
fn repeated_field_occurrences_honor_any_and_all_semantics() {
    let any = compile(serde_json::json!({
        "when": {"match": {"header": {
            "name": "x-tier", "value": {"exact": ["gold"]}
        }}}
    }));
    let all = compile(serde_json::json!({
        "when": {"match": {"header": {
            "name": "x-tier", "value": {"exact": ["gold"]}, "multi_value": "all"
        }}}
    }));

    let mixed = Facts::http()
        .with_header("x-tier", "silver")
        .with_header("x-tier", "gold");
    assert!(
        any.evaluate(&mixed),
        "any: one matching occurrence suffices"
    );
    assert!(!all.evaluate(&mixed), "all: every occurrence must match");

    // The other order is the one an early-stop bug hides: a MATCHING first
    // occurrence must not settle `all` and let a later mismatch go unseen.
    let match_then_miss = Facts::http()
        .with_header("x-tier", "gold")
        .with_header("x-tier", "silver");
    assert!(
        any.evaluate(&match_then_miss),
        "any: the first matching occurrence still suffices"
    );
    assert!(
        !all.evaluate(&match_then_miss),
        "all: a mismatch AFTER a match must still make the predicate false"
    );

    // Three occurrences, mismatch last, so the scan cannot stop at either end.
    let trailing_miss = Facts::http()
        .with_header("x-tier", "gold")
        .with_header("x-tier", "gold")
        .with_header("x-tier", "bronze");
    assert!(any.evaluate(&trailing_miss));
    assert!(!all.evaluate(&trailing_miss));

    let uniform = Facts::http()
        .with_header("x-tier", "gold")
        .with_header("x-tier", "gold");
    assert!(any.evaluate(&uniform));
    assert!(all.evaluate(&uniform));

    // Same rule on the query and cookie surfaces, which use the same scan.
    let query_all = compile(serde_json::json!({
        "when": {"match": {"query": {
            "name": "tier", "value": {"exact": ["gold"]}, "multi_value": "all"
        }}}
    }));
    let query_uniform = Facts::http()
        .with_query("tier", "gold")
        .with_query("tier", "gold");
    let query_match_then_miss = Facts::http()
        .with_query("tier", "gold")
        .with_query("tier", "silver");
    assert!(query_all.evaluate(&query_uniform));
    assert!(!query_all.evaluate(&query_match_then_miss));

    let cookie_all = compile(serde_json::json!({
        "when": {"match": {"cookie": {
            "name": "tier", "value": {"exact": ["gold"]}, "multi_value": "all"
        }}}
    }));
    let cookie_uniform = Facts::http()
        .with_cookie("tier", "gold")
        .with_cookie("tier", "gold");
    let cookie_match_then_miss = Facts::http()
        .with_cookie("tier", "gold")
        .with_cookie("tier", "bronze");
    assert!(cookie_all.evaluate(&cookie_uniform));
    assert!(!cookie_all.evaluate(&cookie_match_then_miss));

    // `not` over `all` is where the early-stop bug was a security bypass: an
    // instance meant to run for anything that is NOT uniformly gold must run.
    let not_all = compile(serde_json::json!({
        "when": {"not": {"match": {"header": {
            "name": "x-tier", "value": {"exact": ["gold"]}, "multi_value": "all"
        }}}}
    }));
    assert!(
        not_all.evaluate(&match_then_miss),
        "not(all): a mismatch after a match must admit the instance"
    );
    assert!(!not_all.evaluate(&uniform));

    // `all` over zero occurrences is FALSE, not a vacuous truth.
    assert!(!all.evaluate(&Facts::http()));
    assert!(!any.evaluate(&Facts::http()));
}

#[test]
fn header_names_are_case_insensitive_and_values_are_not_unless_requested() {
    let sensitive = compile(serde_json::json!({
        "when": {"match": {"header": {"name": "X-Tier", "value": {"exact": ["Gold"]}}}}
    }));
    assert!(sensitive.evaluate(&Facts::http().with_header("x-tier", "Gold")));
    assert!(!sensitive.evaluate(&Facts::http().with_header("x-tier", "gold")));

    let insensitive = compile(serde_json::json!({
        "when": {"match": {"header": {
            "name": "X-Tier", "value": {"exact": ["Gold"], "case_insensitive": true}
        }}}
    }));
    assert!(insensitive.evaluate(&Facts::http().with_header("x-tier", "gold")));
}

#[test]
fn query_and_cookie_names_are_case_sensitive() {
    let query = compile(serde_json::json!({
        "when": {"match": {"query": {"name": "Debug"}}}
    }));
    assert!(query.evaluate(&Facts::http().with_query("Debug", "1")));
    assert!(!query.evaluate(&Facts::http().with_query("debug", "1")));

    let cookie = compile(serde_json::json!({
        "when": {"match": {"cookie": {"name": "SessionId"}}}
    }));
    assert!(cookie.evaluate(&Facts::http().with_cookie("SessionId", "abc")));
    assert!(!cookie.evaluate(&Facts::http().with_cookie("sessionid", "abc")));
}

#[test]
fn method_comparison_is_case_insensitive_in_both_directions() {
    let trigger = compile(serde_json::json!({"when": {"match": {"method": ["post"]}}}));
    let mut facts = Facts::http();
    facts.method = Some("POST".to_string());
    assert!(trigger.evaluate(&facts));
    facts.method = Some("PoSt".to_string());
    assert!(trigger.evaluate(&facts));
    facts.method = Some("GET".to_string());
    assert!(!trigger.evaluate(&facts));
}

// ---------------------------------------------------------------------------
// String matchers
// ---------------------------------------------------------------------------

#[test]
fn path_regex_is_anchored_so_it_cannot_partially_match() {
    let trigger = compile(serde_json::json!({
        "when": {"match": {"path": {"regex": "/v1/orders/[0-9]+"}}}
    }));
    let mut facts = Facts::http();
    facts.path = Some("/v1/orders/42".to_string());
    assert!(trigger.evaluate(&facts));
    facts.path = Some("/v1/orders/42/refunds".to_string());
    assert!(
        !trigger.evaluate(&facts),
        "anchored regex must not match a longer path"
    );
    facts.path = Some("/public/v1/orders/42".to_string());
    assert!(
        !trigger.evaluate(&facts),
        "anchored regex must not match a prefix-extended path"
    );
}

#[test]
fn path_matchers_require_canonical_spellings_at_admission() {
    for matcher in ["exact", "prefix"] {
        for path in [
            "/%61dmin",
            "/api%2Fadmin",
            "/api/../admin",
            "/api\\admin",
            "admin",
            "*",
        ] {
            let error = compile_error(serde_json::json!({
                "when": {"match": {"path": {matcher: [path]}}}
            }));
            assert!(error.contains("`path`"), "{matcher}: {error}");
        }
        for path in ["/admin", "/v1.0/x"] {
            let trigger = compile(serde_json::json!({
                "when": {"match": {"path": {matcher: [path]}}}
            }));
            let mut facts = Facts::http();
            facts.path = Some(path.to_string());
            assert!(trigger.evaluate(&facts));
        }
    }
    let error = compile_error(serde_json::json!({
        "when": {"match": {"path": {"regex": "^/%61dmin/.*"}}}
    }));
    assert!(error.contains("canonical"), "{error}");
    let trigger = compile(serde_json::json!({
        "when": {"match": {"path": {"regex": r"^/v1\.0/.*"}}}
    }));
    let mut facts = Facts::http();
    facts.path = Some("/v1.0/x".to_string());
    assert!(trigger.evaluate(&facts));
}

#[test]
fn host_uppercase_requires_explicit_case_insensitivity() {
    for matcher in ["exact", "prefix", "regex"] {
        for insensitive in [false, true] {
            let value = if matcher == "regex" {
                serde_json::json!("API.EXAMPLE.COM")
            } else {
                serde_json::json!(["API.EXAMPLE.COM"])
            };
            let config = serde_json::json!({
                "when": {"match": {"host": {
                    matcher: value, "case_insensitive": insensitive
                }}}
            });
            if insensitive {
                let trigger = compile(config);
                let mut facts = Facts::http();
                facts.host = Some("api.example.com".to_string());
                assert!(trigger.evaluate(&facts));
            } else {
                assert!(compile_error(config).contains("case_insensitive"));
            }
        }
    }
    let trigger = compile(serde_json::json!({
        "when": {"match": {"host": {"exact": ["api.example.com"]}}}
    }));
    let mut facts = Facts::http();
    facts.host = Some("api.example.com".to_string());
    assert!(trigger.evaluate(&facts));
}

#[test]
fn prefix_matching_is_byte_exact_and_case_insensitive_only_on_request() {
    let sensitive = compile(serde_json::json!({
        "when": {"match": {"path": {"prefix": ["/V1/"]}}}
    }));
    let insensitive = compile(serde_json::json!({
        "when": {"match": {"path": {"prefix": ["/V1/"], "case_insensitive": true}}}
    }));
    let mut facts = Facts::http();
    facts.path = Some("/v1/orders".to_string());
    assert!(!sensitive.evaluate(&facts));
    assert!(insensitive.evaluate(&facts));

    // A prefix longer than the value can never match, and must not panic.
    let long = compile(serde_json::json!({
        "when": {"match": {"path": {"prefix": ["/v1/orders/very/long"], "case_insensitive": true}}}
    }));
    assert!(!long.evaluate(&facts));
}

// ---------------------------------------------------------------------------
// Network, protocol, and identity predicates
// ---------------------------------------------------------------------------

#[test]
fn source_cidr_matches_v4_v6_and_ipv4_mapped_forms() {
    let trigger = compile(serde_json::json!({
        "when": {"match": {"source_cidr": ["10.0.0.0/8", "2001:db8::/32", "192.0.2.7"]}}
    }));
    let mut facts = Facts::http();

    facts.client_ip = Some("10.4.5.6".parse().unwrap());
    assert!(trigger.evaluate(&facts));
    facts.client_ip = Some("11.4.5.6".parse().unwrap());
    assert!(!trigger.evaluate(&facts));
    facts.client_ip = Some("2001:db8::1".parse().unwrap());
    assert!(trigger.evaluate(&facts));
    facts.client_ip = Some("2001:dba::1".parse().unwrap());
    assert!(!trigger.evaluate(&facts));
    facts.client_ip = Some("192.0.2.7".parse().unwrap());
    assert!(trigger.evaluate(&facts), "a bare address is a /32");
    // An IPv4-mapped peer must be compared in the v4 space, not as a v6 value.
    facts.client_ip = Some("::ffff:10.4.5.6".parse().unwrap());
    assert!(trigger.evaluate(&facts));

    // An unresolvable client IP never satisfies a positive predicate.
    facts.client_ip = None;
    assert!(!trigger.evaluate(&facts));
}

#[test]
fn protocol_identity_is_a_set_so_transport_and_flavor_both_match() {
    let http2 = compile(serde_json::json!({"when": {"match": {"protocol": ["http2"]}}}));
    let grpc = compile(serde_json::json!({"when": {"match": {"protocol": ["grpc"]}}}));
    let h3_or_ws =
        compile(serde_json::json!({"when": {"match": {"protocol": ["http3", "websocket"]}}}));

    let mut facts = Facts::http();
    facts.protocols = vec![PluginTriggerProtocol::Http2, PluginTriggerProtocol::Grpc];
    assert!(http2.evaluate(&facts));
    assert!(grpc.evaluate(&facts));
    assert!(!h3_or_ws.evaluate(&facts));

    facts.protocols = vec![
        PluginTriggerProtocol::Http1,
        PluginTriggerProtocol::Websocket,
    ];
    assert!(h3_or_ws.evaluate(&facts));
}

#[test]
fn identity_predicates_read_consumer_auth_method_and_spiffe_id() {
    let trigger = compile(serde_json::json!({
        "when": {"all": [
            {"match": {"consumer": {"value": {"exact": ["alice"]}}}},
            {"match": {"auth_method": ["JWT_AUTH"]}},
            {"match": {"spiffe_id": {"value": {"prefix": ["spiffe://prod/"]}}}}
        ]}
    }));
    let mut facts = Facts::http();
    facts.consumer = Some("alice".to_string());
    facts.auth_method = Some("jwt_auth".to_string());
    facts.spiffe_id = Some("spiffe://prod/ns/default/sa/orders".to_string());
    assert!(trigger.evaluate(&facts));

    facts.auth_method = Some("key_auth".to_string());
    assert!(!trigger.evaluate(&facts));
}

#[test]
fn identity_predicates_are_flagged_for_phase_safety() {
    for predicate in [
        serde_json::json!({"consumer": {}}),
        serde_json::json!({"auth_method": ["jwt_auth"]}),
        serde_json::json!({"spiffe_id": {}}),
    ] {
        let trigger = compile(serde_json::json!({"when": {"match": predicate}}));
        assert!(
            trigger.reads_authenticated_identity(),
            "identity predicate must be flagged"
        );
    }

    let trigger = compile(serde_json::json!({
        "when": {"all": [
            {"match": {"method": ["GET"]}},
            {"not": {"match": {"path": {"prefix": ["/x"]}}}}
        ]}
    }));
    assert!(!trigger.reads_authenticated_identity());

    // The flag propagates out of nested branches, not just the root leaf.
    let nested = compile(serde_json::json!({
        "when": {"any": [
            {"match": {"method": ["GET"]}},
            {"all": [{"not": {"match": {"auth_method": ["jwt_auth"]}}}]}
        ]}
    }));
    assert!(nested.reads_authenticated_identity());
}

// ---------------------------------------------------------------------------
// Non-HTTP contexts
// ---------------------------------------------------------------------------

#[test]
fn http_only_predicates_are_false_on_a_stream_connection() {
    for predicate in [
        serde_json::json!({"method": ["GET"]}),
        serde_json::json!({"path": {"prefix": ["/"]}}),
        serde_json::json!({"host": {"prefix": ["a"]}}),
        serde_json::json!({"header": {"name": "x-tier"}}),
        serde_json::json!({"header": {"name": "x-tier", "presence": "absent"}}),
        serde_json::json!({"query": {"name": "debug"}}),
        serde_json::json!({"cookie": {"name": "session"}}),
    ] {
        let trigger = compile(serde_json::json!({"when": {"match": predicate}}));
        assert!(
            !trigger.evaluate(&Facts::stream()),
            "HTTP-only predicate {predicate} must be false on a stream connection"
        );
    }
}

#[test]
fn network_predicates_still_apply_on_a_stream_connection() {
    let trigger = compile(serde_json::json!({
        "when": {"all": [
            {"match": {"protocol": ["tcp", "udp", "dtls"]}},
            {"match": {"source_cidr": ["10.0.0.0/8"]}},
            {"match": {"sni": {"exact": ["orders.internal"]}}}
        ]}
    }));
    let mut facts = Facts::stream();
    facts.client_ip = Some("10.1.2.3".parse().unwrap());
    facts.sni = Some("orders.internal".to_string());
    assert!(trigger.evaluate(&facts));

    facts.sni = Some("other.internal".to_string());
    assert!(!trigger.evaluate(&facts));
}

// ---------------------------------------------------------------------------
// Round-trip
// ---------------------------------------------------------------------------

#[test]
fn trigger_round_trips_through_json_without_emitting_absent_fields() {
    let trigger = parse(serde_json::json!({
        "when": {"all": [
            {"match": {"method": ["POST"]}},
            {"match": {"header": {"name": "x-tier", "value": {"exact": ["gold"]}}}}
        ]}
    }));
    let encoded = serde_json::to_string(&trigger).expect("trigger serializes");
    assert!(!encoded.contains("null"), "{encoded}");
    assert!(!encoded.contains("\"any\":"), "{encoded}");
    assert!(!encoded.contains("case_insensitive"), "{encoded}");
    let decoded: PluginTrigger = serde_json::from_str(&encoded).expect("round trip");
    assert_eq!(decoded, trigger);
}
