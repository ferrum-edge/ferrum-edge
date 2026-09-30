//! Mesh authorization on paths that carry `;` path parameters (issue #5948).
//!
//! A request path with a `;` has two spellings: the raw path the gateway
//! forwards (`/admin;x/users`) and the parameter-stripped path a Tomcat or
//! Spring backend executes (`/admin/users`). Only a proxy with
//! `allow_path_parameters` (a mesh service opted in with
//! `MeshService.allow_path_parameters` / the `ferrum.io/allow-path-parameters`
//! annotation) lets such a request reach authorization. Each rule is judged
//! once per spelling, with `paths:` / `notPaths:` and any
//! `when: request.headers[:path]` condition reading the same spelling, and the
//! two results are combined by action:
//!
//! | action | the rule matches when |
//! |--------|-----------------------|
//! | `DENY` / `CUSTOM` / `AUDIT` | it matches on the raw **or** the stripped spelling |
//! | `ALLOW` | it matches on the raw **and** the stripped spelling |
//!
//! So a `notPaths:` / `notValues:` exclusion lifts a DENY only when both
//! spellings are excluded, and removes an ALLOW grant when either one is. The
//! combination is per rule: two ALLOW rules that each match one spelling leave
//! the request implicitly denied.

use std::collections::BTreeMap;

use ferrum_edge::modes::mesh::config::{
    ConditionMatch, MeshPolicy, MeshRule, PolicyAction, PolicyScope, RequestMatch,
};
use ferrum_edge::modes::mesh::policy::{
    MeshAuthzAttribute, MeshAuthzDecision, MeshAuthzProtocol, MeshAuthzRequest,
    evaluate_mesh_authorization_full, evaluate_mesh_authorization_policies,
    mesh_authz_stripped_path,
};

const NS: &str = "default";
const PATH_KEY: &str = "request.headers[:path]";

/// An HTTP GET for `path` on `host`, built the way the `mesh_authz` plugin
/// builds it: the stripped spelling from the path, and the
/// `request.headers[:path]` attribute sourced from the same canonical path.
fn request_on(method: &str, host: &str, path: &str) -> MeshAuthzRequest {
    MeshAuthzRequest {
        method: Some(method.to_string()),
        path: Some(path.to_string()),
        stripped_path: mesh_authz_stripped_path(path),
        host: Some(host.to_string()),
        port: Some(8080),
        attributes: BTreeMap::from([(PATH_KEY.to_string(), MeshAuthzAttribute::from(path))]),
        protocol: MeshAuthzProtocol::Http,
        ..MeshAuthzRequest::default()
    }
}

fn request(path: &str) -> MeshAuthzRequest {
    request_on("GET", "web.default.svc.cluster.local", path)
}

fn paths(patterns: &[&str]) -> Vec<String> {
    patterns.iter().map(|pattern| pattern.to_string()).collect()
}

fn rule(action: PolicyAction, to: Vec<RequestMatch>, when: Vec<ConditionMatch>) -> MeshRule {
    MeshRule {
        to,
        when,
        action,
        ..MeshRule::default()
    }
}

fn policy_of(name: &str, rules: Vec<MeshRule>) -> MeshPolicy {
    MeshPolicy {
        name: name.to_string(),
        namespace: NS.to_string(),
        scope: PolicyScope::MeshWide,
        rules,
    }
}

/// A one-policy, one-rule set with a single `to:` entry.
fn policies(name: &str, action: PolicyAction, to: RequestMatch) -> Vec<MeshPolicy> {
    let only = rule(action, vec![to], Vec::new());
    vec![policy_of(name, vec![only])]
}

/// A one-policy, one-rule set gated only on `when: request.headers[:path]`.
fn path_condition(name: &str, action: PolicyAction, when: ConditionMatch) -> Vec<MeshPolicy> {
    let gated = rule(action, Vec::new(), vec![when]);
    vec![policy_of(name, vec![gated])]
}

fn on_paths(patterns: &[&str]) -> RequestMatch {
    RequestMatch {
        paths: paths(patterns),
        ..RequestMatch::default()
    }
}

fn path_values(values: &[&str]) -> ConditionMatch {
    ConditionMatch {
        key: PATH_KEY.to_string(),
        values: paths(values),
        not_values: Vec::new(),
    }
}

fn path_not_values(values: &[&str]) -> ConditionMatch {
    ConditionMatch {
        key: PATH_KEY.to_string(),
        values: Vec::new(),
        not_values: paths(values),
    }
}

fn evaluate(policies: &[MeshPolicy], path: &str) -> MeshAuthzDecision {
    evaluate_mesh_authorization_policies(policies, &request(path))
}

fn deny(policy: &str) -> MeshAuthzDecision {
    MeshAuthzDecision::Deny {
        policy: policy.to_string(),
    }
}

fn implicit_deny() -> MeshAuthzDecision {
    deny("implicit-deny")
}

// ── The second spelling ────────────────────────────────────────────────────

#[test]
fn only_a_path_with_a_parameter_has_a_stripped_spelling() {
    assert_eq!(
        mesh_authz_stripped_path("/admin;x/users").as_deref(),
        Some("/admin/users")
    );
    assert_eq!(
        mesh_authz_stripped_path("/app/page;jsessionid=abc").as_deref(),
        Some("/app/page")
    );
    assert_eq!(mesh_authz_stripped_path("/admin/users"), None);
}

#[test]
fn a_request_without_a_second_spelling_is_judged_on_the_raw_path() {
    // A caller that supplies no stripped spelling gets the single evaluation.
    let deny_admin = policies("deny-admin", PolicyAction::Deny, on_paths(&["/admin/*"]));
    let raw_only = MeshAuthzRequest {
        stripped_path: None,
        ..request("/admin;x/users")
    };
    assert_eq!(
        evaluate_mesh_authorization_policies(&deny_admin, &raw_only),
        MeshAuthzDecision::Allow
    );
    assert_eq!(evaluate(&deny_admin, "/admin/users"), deny("deny-admin"));
}

// ── DENY: either spelling ──────────────────────────────────────────────────

#[test]
fn a_deny_prefix_blocks_a_parameterised_segment() {
    let deny_admin = policies("deny-admin", PolicyAction::Deny, on_paths(&["/admin/*"]));

    for path in ["/admin;x/users", "/admin;/users", "/admin/users;x"] {
        assert_eq!(
            evaluate(&deny_admin, path),
            deny("deny-admin"),
            "{path} executes /admin/users on a parameter-stripping backend"
        );
    }
    assert_eq!(evaluate(&deny_admin, "/admin/users"), deny("deny-admin"));
    assert_eq!(
        evaluate(&deny_admin, "/app/;jsessionid=abc"),
        MeshAuthzDecision::Allow,
        "a path outside the DENY stays allowed"
    );
}

#[test]
fn a_nested_deny_blocks_a_parameter_on_an_earlier_segment() {
    let deny_nested = policies("deny-nest", PolicyAction::Deny, on_paths(&["/api/admin/*"]));

    assert_eq!(
        evaluate(&deny_nested, "/api;x/admin/users"),
        deny("deny-nest")
    );
    assert_eq!(
        evaluate(&deny_nested, "/api/admin;x/users"),
        deny("deny-nest")
    );
    assert_eq!(
        evaluate(&deny_nested, "/api;x/items"),
        MeshAuthzDecision::Allow
    );
}

#[test]
fn an_exact_deny_blocks_the_parameterised_spelling_of_its_path() {
    let deny_exact = policies("deny-exact", PolicyAction::Deny, on_paths(&["/admin"]));

    assert_eq!(evaluate(&deny_exact, "/admin;x"), deny("deny-exact"));
}

#[test]
fn a_deny_not_paths_exclusion_needs_both_spellings() {
    // DENY everything under /api/ except /api/public/*.
    let deny_api = policies(
        "deny-api",
        PolicyAction::Deny,
        RequestMatch {
            paths: paths(&["/api/*"]),
            not_paths: paths(&["/api/public/*"]),
            ..RequestMatch::default()
        },
    );

    // Raw `/api/public;v=1/doc` is not excluded (it does not start with
    // `/api/public/`), so the raw spelling still matches the DENY.
    assert_eq!(
        evaluate(&deny_api, "/api/public;v=1/docs"),
        deny("deny-api")
    );
    // Both spellings are excluded: the DENY does not apply.
    assert_eq!(
        evaluate(&deny_api, "/api/public/doc;v=1"),
        MeshAuthzDecision::Allow
    );
}

#[test]
fn a_not_paths_only_deny_needs_both_spellings_excluded() {
    // DENY every path except /public/*.
    let deny_private = policies(
        "deny-private",
        PolicyAction::Deny,
        RequestMatch {
            not_paths: paths(&["/public/*"]),
            ..RequestMatch::default()
        },
    );

    assert_eq!(
        evaluate(&deny_private, "/public;x/doc"),
        deny("deny-private")
    );
    assert_eq!(
        evaluate(&deny_private, "/public/doc;v=1"),
        MeshAuthzDecision::Allow
    );
}

// ── ALLOW: both spellings ──────────────────────────────────────────────────

#[test]
fn an_allow_suffix_must_hold_for_the_stripped_spelling() {
    let allow_png = policies("allow-png", PolicyAction::Allow, on_paths(&["*.png"]));

    assert_eq!(
        evaluate(&allow_png, "/admin/users;x.png"),
        implicit_deny(),
        "the backend executes /admin/users, which is not a .png"
    );
    assert_eq!(
        evaluate(&allow_png, "/img;v=2/logo.png"),
        MeshAuthzDecision::Allow,
        "both spellings end in .png"
    );
}

#[test]
fn an_allow_not_paths_exclusion_applies_to_either_spelling() {
    let allow_api = policies(
        "allow-api",
        PolicyAction::Allow,
        RequestMatch {
            paths: paths(&["/api/*"]),
            not_paths: paths(&["/api/admin/*"]),
            ..RequestMatch::default()
        },
    );

    assert_eq!(
        evaluate(&allow_api, "/api/admin;x/users"),
        implicit_deny(),
        "the stripped /api/admin/users is excluded from the grant"
    );
    assert_eq!(
        evaluate(&allow_api, "/api/items;jsessionid=abc"),
        MeshAuthzDecision::Allow
    );
}

#[test]
fn a_not_paths_only_allow_is_lost_when_either_spelling_is_excluded() {
    let allow_public = policies(
        "allow-public",
        PolicyAction::Allow,
        RequestMatch {
            not_paths: paths(&["/admin/*"]),
            ..RequestMatch::default()
        },
    );

    assert_eq!(evaluate(&allow_public, "/admin;x/users"), implicit_deny());
    assert_eq!(
        evaluate(&allow_public, "/app/page;jsessionid=abc"),
        MeshAuthzDecision::Allow
    );
}

#[test]
fn exact_and_prefix_allow_rules_are_unchanged() {
    let exact = policies("allow-page", PolicyAction::Allow, on_paths(&["/app/page"]));
    let prefix = policies("allow-app", PolicyAction::Allow, on_paths(&["/app/*"]));

    assert_eq!(evaluate(&exact, "/app/page"), MeshAuthzDecision::Allow);
    assert_eq!(evaluate(&prefix, "/app/page"), MeshAuthzDecision::Allow);
    for path in ["/app/;jsessionid=abc", "/app/page;jsessionid=abc"] {
        assert_eq!(evaluate(&prefix, path), MeshAuthzDecision::Allow, "{path}");
    }
    // An exact rule never matched the raw `;` spelling, and still does not.
    assert_eq!(
        evaluate(&exact, "/app/page;jsessionid=abc"),
        implicit_deny()
    );
}

#[test]
fn presence_patterns_match_both_spellings() {
    let allow_any = policies("allow-any", PolicyAction::Allow, on_paths(&["*"]));
    let deny_any = policies("deny-any", PolicyAction::Deny, on_paths(&["*"]));

    assert_eq!(
        evaluate(&allow_any, "/admin;x/users"),
        MeshAuthzDecision::Allow
    );
    assert_eq!(evaluate(&deny_any, "/admin;x/users"), deny("deny-any"));

    let allow_present = path_condition("allow-present", PolicyAction::Allow, path_values(&["*"]));
    assert_eq!(
        evaluate(&allow_present, "/admin;x/users"),
        MeshAuthzDecision::Allow
    );
}

#[test]
fn two_allow_rules_that_each_match_one_spelling_still_implicitly_deny() {
    // The combination is per rule: no single ALLOW rule holds for both
    // spellings, so the implicit-deny floor is not met.
    let raw_rule = rule(
        PolicyAction::Allow,
        vec![on_paths(&["/admin;x/*"])],
        Vec::new(),
    );
    let stripped_rule = rule(
        PolicyAction::Allow,
        vec![on_paths(&["/admin/users"])],
        Vec::new(),
    );
    let split = vec![policy_of("allow-split", vec![raw_rule, stripped_rule])];

    assert_eq!(evaluate(&split, "/admin;x/users"), implicit_deny());
}

#[test]
fn methods_and_hosts_stay_conjunctive_with_both_spellings() {
    let deny_post_admin = policies(
        "deny-post-admin",
        PolicyAction::Deny,
        RequestMatch {
            methods: vec!["POST".to_string()],
            hosts: vec!["web.*".to_string()],
            paths: paths(&["/admin/*"]),
            ..RequestMatch::default()
        },
    );
    let host = "web.default.svc.cluster.local";
    let decide = |method: &str, host: &str| {
        let request = request_on(method, host, "/admin;x/users");
        evaluate_mesh_authorization_policies(&deny_post_admin, &request)
    };

    assert_eq!(decide("POST", host), deny("deny-post-admin"));
    assert_eq!(decide("GET", host), MeshAuthzDecision::Allow);
    assert_eq!(decide("POST", "api.example.com"), MeshAuthzDecision::Allow);

    let allow_get_app = policies(
        "allow-get-app",
        PolicyAction::Allow,
        RequestMatch {
            methods: vec!["GET".to_string()],
            paths: paths(&["/app/*"]),
            ..RequestMatch::default()
        },
    );
    let get = request_on("GET", host, "/app;x/page");
    assert_eq!(
        evaluate_mesh_authorization_policies(&allow_get_app, &get),
        implicit_deny(),
        "the raw spelling does not start with /app/"
    );
    let get = request_on("GET", host, "/app/page;jsessionid=abc");
    assert_eq!(
        evaluate_mesh_authorization_policies(&allow_get_app, &get),
        MeshAuthzDecision::Allow
    );
}

// ── `when: request.headers[:path]`: the same spelling as `paths:` ──────────

#[test]
fn a_deny_path_condition_blocks_the_stripped_spelling() {
    let deny_admin = path_condition(
        "deny-admin-path",
        PolicyAction::Deny,
        path_values(&["/admin/*"]),
    );

    assert_eq!(
        evaluate(&deny_admin, "/admin;x/users"),
        deny("deny-admin-path")
    );
    assert_eq!(
        evaluate(&deny_admin, "/app;x/page"),
        MeshAuthzDecision::Allow
    );
}

#[test]
fn an_allow_path_condition_suffix_must_hold_for_the_stripped_spelling() {
    let allow_png = path_condition("allow-png", PolicyAction::Allow, path_values(&["*.png"]));

    assert_eq!(evaluate(&allow_png, "/admin/users;x.png"), implicit_deny());
    assert_eq!(
        evaluate(&allow_png, "/img;v=2/logo.png"),
        MeshAuthzDecision::Allow
    );
}

#[test]
fn an_allow_path_condition_not_values_applies_to_either_spelling() {
    let allow_api = path_condition(
        "allow-api",
        PolicyAction::Allow,
        path_not_values(&["/api/admin/*"]),
    );

    assert_eq!(evaluate(&allow_api, "/api/admin;x/users"), implicit_deny());
    assert_eq!(
        evaluate(&allow_api, "/api/items;v=1"),
        MeshAuthzDecision::Allow
    );
}

#[test]
fn paths_and_a_path_condition_read_the_same_spelling() {
    // `to.paths` admits only the raw spelling and the `:path` condition only
    // the stripped one. Judged on the same spelling each time, neither
    // evaluation satisfies both halves, so the DENY does not fire. Judging
    // them on different spellings would have matched.
    let to = on_paths(&["/admin;x/*"]);
    let when = path_values(&["/admin/users"]);
    let mixed_deny = vec![policy_of(
        "mixed-deny",
        vec![rule(PolicyAction::Deny, vec![to], vec![when])],
    )];
    assert_eq!(
        evaluate(&mixed_deny, "/admin;x/users"),
        MeshAuthzDecision::Allow
    );

    // Both halves hold on the stripped spelling: the DENY fires.
    let to = on_paths(&["/admin/*"]);
    let when = path_values(&["*/users"]);
    let deny_users = vec![policy_of(
        "deny-users",
        vec![rule(PolicyAction::Deny, vec![to], vec![when])],
    )];
    assert_eq!(evaluate(&deny_users, "/admin;x/users"), deny("deny-users"));

    // An ALLOW with both halves must hold on both spellings.
    let to = on_paths(&["/app/*"]);
    let when = path_values(&["*.png"]);
    let allow_png = vec![policy_of(
        "allow-app-png",
        vec![rule(PolicyAction::Allow, vec![to], vec![when])],
    )];
    assert_eq!(evaluate(&allow_png, "/app/a;x.png"), implicit_deny());
    assert_eq!(
        evaluate(&allow_png, "/app/x;v=1/a.png"),
        MeshAuthzDecision::Allow
    );
}

// ── CUSTOM / AUDIT: either spelling ────────────────────────────────────────

#[test]
fn a_custom_delegation_covers_the_stripped_spelling() {
    let custom = PolicyAction::Custom {
        provider: "authz".to_string(),
    };
    let ext_authz = policies("ext-authz", custom, on_paths(&["/admin/*"]));

    let admin = request("/admin;x/users");
    let evaluation = evaluate_mesh_authorization_full(&ext_authz, &admin);
    let delegation = evaluation
        .custom
        .expect("the stripped /admin/users must reach the external authorizer");
    assert_eq!(delegation.policy, "ext-authz");
    assert_eq!(delegation.provider, "authz");

    let page = request("/app;x/page");
    let evaluation = evaluate_mesh_authorization_full(&ext_authz, &page);
    assert!(evaluation.custom.is_none());
}

#[test]
fn an_audit_rule_records_the_stripped_spelling() {
    let audit_admin = policies("audit-admin", PolicyAction::Audit, on_paths(&["/admin/*"]));

    assert_eq!(
        evaluate(&audit_admin, "/admin;x/users"),
        MeshAuthzDecision::Audit {
            policy: "audit-admin".to_string()
        }
    );
}
