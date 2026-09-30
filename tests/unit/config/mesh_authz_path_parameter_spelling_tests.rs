//! Mesh authorization on services that allow `;` path parameters
//! (issue #5948).
//!
//! On a proxy with `allow_path_parameters` (a mesh service opted in with
//! `MeshService.allow_path_parameters` / the `ferrum.io/allow-path-parameters`
//! annotation), a request path has two spellings: the raw path the gateway
//! forwards (`/admin;x/users`) and the parameter-stripped path a Tomcat or
//! Spring backend executes (`/admin/users`). `paths:` / `notPaths:` are judged
//! on both, per rule:
//!
//! | action | `to:` matches when |
//! |--------|--------------------|
//! | `DENY` / `CUSTOM` / `AUDIT` | the raw **or** the stripped spelling matches |
//! | `ALLOW` | the raw **and** the stripped spelling match |
//!
//! A spelling "matches" when some `to:` entry's `paths:` contain it and its
//! `notPaths:` do not. So a `notPaths:` exclusion lifts a DENY only when both
//! spellings are excluded, and removes an ALLOW grant when either one is.
//!
//! Without the opt-in the request carries no second spelling and evaluation is
//! unchanged (the frontend refuses such a `;` with `400 path_parameter` before
//! authorization runs anyway).

use ferrum_edge::modes::mesh::config::{
    MeshPolicy, MeshRule, PolicyAction, PolicyScope, RequestMatch,
};
use ferrum_edge::modes::mesh::policy::{
    MeshAuthzDecision, MeshAuthzProtocol, MeshAuthzRequest, evaluate_mesh_authorization_full,
    evaluate_mesh_authorization_policies, mesh_authz_stripped_path,
};

const NS: &str = "default";

/// An HTTP GET for `path`, routed to a proxy whose path-parameter opt-in is
/// `opted_in`, built the way the `mesh_authz` plugin builds it.
fn request(path: &str, opted_in: bool) -> MeshAuthzRequest {
    MeshAuthzRequest {
        method: Some("GET".to_string()),
        path: Some(path.to_string()),
        stripped_path: mesh_authz_stripped_path(path, opted_in),
        port: Some(8080),
        protocol: MeshAuthzProtocol::Http,
        ..MeshAuthzRequest::default()
    }
}

fn paths(patterns: &[&str]) -> Vec<String> {
    patterns.iter().map(|pattern| pattern.to_string()).collect()
}

fn policies(name: &str, action: PolicyAction, to: RequestMatch) -> Vec<MeshPolicy> {
    vec![MeshPolicy {
        name: name.to_string(),
        namespace: NS.to_string(),
        scope: PolicyScope::MeshWide,
        rules: vec![MeshRule {
            to: vec![to],
            action,
            ..MeshRule::default()
        }],
    }]
}

fn on_paths(patterns: &[&str]) -> RequestMatch {
    RequestMatch {
        paths: paths(patterns),
        ..RequestMatch::default()
    }
}

fn evaluate(policies: &[MeshPolicy], path: &str, opted_in: bool) -> MeshAuthzDecision {
    evaluate_mesh_authorization_policies(policies, &request(path, opted_in))
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
fn only_an_opted_in_path_with_a_parameter_has_a_stripped_spelling() {
    assert_eq!(
        mesh_authz_stripped_path("/admin;x/users", true).as_deref(),
        Some("/admin/users")
    );
    assert_eq!(
        mesh_authz_stripped_path("/app/page;jsessionid=abc", true).as_deref(),
        Some("/app/page")
    );
    assert_eq!(mesh_authz_stripped_path("/admin;x/users", false), None);
    assert_eq!(mesh_authz_stripped_path("/admin/users", true), None);
}

// ── DENY: either spelling ──────────────────────────────────────────────────

#[test]
fn a_deny_prefix_blocks_a_parameterised_segment_on_an_opted_in_service() {
    let deny_admin = policies("deny-admin", PolicyAction::Deny, on_paths(&["/admin/*"]));

    for path in ["/admin;x/users", "/admin;/users", "/admin/users;x"] {
        assert_eq!(
            evaluate(&deny_admin, path, true),
            deny("deny-admin"),
            "{path} executes /admin/users on a parameter-stripping backend"
        );
    }
    assert_eq!(
        evaluate(&deny_admin, "/admin/users", true),
        deny("deny-admin")
    );
    assert_eq!(
        evaluate(&deny_admin, "/app/;jsessionid=abc", true),
        MeshAuthzDecision::Allow,
        "a path outside the DENY stays allowed"
    );
}

#[test]
fn a_nested_deny_blocks_a_parameter_on_an_earlier_segment() {
    let deny_nested = policies("deny-nest", PolicyAction::Deny, on_paths(&["/api/admin/*"]));

    assert_eq!(
        evaluate(&deny_nested, "/api;x/admin/users", true),
        deny("deny-nest")
    );
    assert_eq!(
        evaluate(&deny_nested, "/api/admin;x/users", true),
        deny("deny-nest")
    );
    assert_eq!(
        evaluate(&deny_nested, "/api;x/items", true),
        MeshAuthzDecision::Allow
    );
}

#[test]
fn an_exact_deny_blocks_the_parameterised_spelling_of_its_path() {
    let deny_exact = policies("deny-exact", PolicyAction::Deny, on_paths(&["/admin"]));

    assert_eq!(evaluate(&deny_exact, "/admin;x", true), deny("deny-exact"));
}

#[test]
fn a_deny_not_paths_exclusion_needs_both_spellings() {
    // DENY everything under /api/ except /api/public/*. The exclusion lifts
    // the DENY only when both spellings are excluded.
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
        evaluate(&deny_api, "/api/public;v=1/doc", true),
        deny("deny-api")
    );
    // Both spellings are excluded: the DENY does not apply.
    assert_eq!(
        evaluate(&deny_api, "/api/public/doc;v=1", true),
        MeshAuthzDecision::Allow
    );
    assert_eq!(
        evaluate(&deny_api, "/api/private;v=1/doc", true),
        deny("deny-api")
    );
}

// ── ALLOW: both spellings ──────────────────────────────────────────────────

#[test]
fn an_allow_suffix_must_hold_for_the_stripped_spelling() {
    let allow_png = policies("allow-png", PolicyAction::Allow, on_paths(&["*.png"]));

    assert_eq!(
        evaluate(&allow_png, "/admin/users;x.png", true),
        implicit_deny(),
        "the backend executes /admin/users, which is not a .png"
    );
    assert_eq!(
        evaluate(&allow_png, "/img;v=2/logo.png", true),
        MeshAuthzDecision::Allow,
        "both spellings end in .png"
    );
    assert_eq!(
        evaluate(&allow_png, "/img/logo.png", true),
        MeshAuthzDecision::Allow
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
        evaluate(&allow_api, "/api/admin;x/users", true),
        implicit_deny(),
        "the stripped /api/admin/users is excluded from the grant"
    );
    assert_eq!(
        evaluate(&allow_api, "/api;x/admin/users", true),
        implicit_deny()
    );
    assert_eq!(
        evaluate(&allow_api, "/api/items;jsessionid=abc", true),
        MeshAuthzDecision::Allow
    );
}

#[test]
fn exact_and_prefix_allow_rules_are_unchanged() {
    let exact = policies("allow-page", PolicyAction::Allow, on_paths(&["/app/page"]));
    let prefix = policies("allow-app", PolicyAction::Allow, on_paths(&["/app/*"]));

    // No `;`: one spelling, exactly as before.
    assert_eq!(
        evaluate(&exact, "/app/page", true),
        MeshAuthzDecision::Allow
    );
    assert_eq!(
        evaluate(&prefix, "/app/page", true),
        MeshAuthzDecision::Allow
    );
    // A prefix rule covers both spellings of a `;jsessionid=` path.
    for path in ["/app/;jsessionid=abc", "/app/page;jsessionid=abc"] {
        assert_eq!(
            evaluate(&prefix, path, true),
            MeshAuthzDecision::Allow,
            "{path}"
        );
    }
    // An exact rule never matched the raw `;` spelling, and still does not.
    for opted_in in [true, false] {
        assert_eq!(
            evaluate(&exact, "/app/page;jsessionid=abc", opted_in),
            implicit_deny()
        );
    }
}

// ── CUSTOM / AUDIT: either spelling ────────────────────────────────────────

#[test]
fn a_custom_delegation_covers_the_stripped_spelling() {
    let custom = PolicyAction::Custom {
        provider: "authz".to_string(),
    };
    let ext_authz = policies("ext-authz", custom, on_paths(&["/admin/*"]));

    let admin = request("/admin;x/users", true);
    let evaluation = evaluate_mesh_authorization_full(&ext_authz, &admin);
    let delegation = evaluation
        .custom
        .expect("the stripped /admin/users must reach the external authorizer");
    assert_eq!(delegation.policy, "ext-authz");
    assert_eq!(delegation.provider, "authz");

    let page = request("/app;x/page", true);
    let evaluation = evaluate_mesh_authorization_full(&ext_authz, &page);
    assert!(evaluation.custom.is_none());
}

#[test]
fn an_audit_rule_records_the_stripped_spelling() {
    let audit_admin = policies("audit-admin", PolicyAction::Audit, on_paths(&["/admin/*"]));

    assert_eq!(
        evaluate(&audit_admin, "/admin;x/users", true),
        MeshAuthzDecision::Audit {
            policy: "audit-admin".to_string()
        }
    );
}

// ── Services without the opt-in ────────────────────────────────────────────

#[test]
fn services_without_the_opt_in_judge_the_raw_path_only() {
    // No second spelling is built, so the raw path alone decides, exactly as
    // before issue #5948. The frontend refuses these `;` requests with
    // `400 path_parameter` before authorization ever sees them.
    let deny_admin = policies("deny-admin", PolicyAction::Deny, on_paths(&["/admin/*"]));
    let allow_png = policies("allow-png", PolicyAction::Allow, on_paths(&["*.png"]));

    assert_eq!(
        evaluate(&deny_admin, "/admin;x/users", false),
        MeshAuthzDecision::Allow
    );
    assert_eq!(
        evaluate(&allow_png, "/admin/users;x.png", false),
        MeshAuthzDecision::Allow
    );
    assert_eq!(
        evaluate(&deny_admin, "/admin/users", false),
        deny("deny-admin")
    );
}
