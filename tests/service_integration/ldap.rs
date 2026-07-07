//! LDAP authentication integration tests.
//!
//! These seed a live OpenLDAP server with a controlled directory and drive the
//! real `ldap_auth` plugin through the public `create_plugin` → `authenticate`
//! path — exercising the `ldap3` bind / search-then-bind / group-membership
//! code that the existing functional test (which only points the plugin at an
//! *unreachable* server) never reaches.
//!
//! Outcome contract (see `run_auth_impl` in `src/plugins/utils/auth_flow.rs`):
//!   - successful bind (+ group match)         → `Continue`
//!   - bad password / unknown user             → `Reject{401}`
//!   - authenticated but not in required group  → `Reject{403}`
//!
//! Related assertions are grouped per container to keep the number of
//! OpenLDAP boots (and thus wall-clock) low.

use std::sync::Arc;
use std::time::Duration;

use ferrum_edge::ConsumerIndex;
use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext, create_plugin};
use ldap3::{LdapConnAsync, Scope, SearchEntry};
use serde_json::json;
use serial_test::serial;

use crate::common::containers::{
    BoxError, LDAP_ADMIN_DN, LDAP_ADMIN_PASSWORD, LDAP_BASE_DN, OpenLdapContainer,
    fail_in_ci_else_skip, start_openldap_container,
};

/// Test directory: two people and a `groupOfNames` (`admins`) that contains
/// only `alice`. The base suffix (`dc=example,dc=org`) and the admin account
/// are created by the image; everything below is added by the test.
const SEED_LDIF: &str = "\
dn: ou=people,dc=example,dc=org
objectClass: organizationalUnit
ou: people

dn: uid=alice,ou=people,dc=example,dc=org
objectClass: inetOrgPerson
cn: Alice Anderson
sn: Anderson
uid: alice
userPassword: alice-secret

dn: uid=bob,ou=people,dc=example,dc=org
objectClass: inetOrgPerson
cn: Bob Brown
sn: Brown
uid: bob
userPassword: bob-secret

dn: ou=groups,dc=example,dc=org
objectClass: organizationalUnit
ou: groups

dn: cn=admins,ou=groups,dc=example,dc=org
objectClass: groupOfNames
cn: admins
member: uid=alice,ou=people,dc=example,dc=org
";

/// Start OpenLDAP and seed the test directory, or self-skip (locally) /
/// hard-fail (CI). A started-but-unseedable server is a real failure, not a
/// Docker-absence skip, so seeding panics.
async fn ldap_ready(test: &str) -> Option<OpenLdapContainer> {
    let container = match start_openldap_container().await {
        Ok(c) => c,
        Err(e) => {
            fail_in_ci_else_skip(test, "OpenLDAP", &e);
            return None;
        }
    };
    container
        .seed_ldif(SEED_LDIF)
        .await
        .expect("seed OpenLDAP directory");
    wait_for_seeded_directory(&container)
        .await
        .expect("seeded OpenLDAP directory should be visible through mapped port");
    Some(container)
}

async fn wait_for_seeded_directory(container: &OpenLdapContainer) -> Result<(), BoxError> {
    let mut last = String::new();
    for _ in 0..40 {
        match seeded_directory_visible(&container.url).await {
            Ok(()) => return Ok(()),
            Err(err) => {
                last = err.to_string();
                tokio::time::sleep(Duration::from_millis(750)).await;
            }
        }
    }
    Err(format!("OpenLDAP seed was not visible through mapped port: {last}").into())
}

async fn seeded_directory_visible(ldap_url: &str) -> Result<(), BoxError> {
    let (conn, mut ldap) = LdapConnAsync::new(ldap_url).await?;
    ldap3::drive!(conn);
    ldap.with_timeout(Duration::from_secs(5));

    ldap.simple_bind(LDAP_ADMIN_DN, LDAP_ADMIN_PASSWORD)
        .await?
        .success()?;

    let people_base = format!("ou=people,{LDAP_BASE_DN}");
    let (people, _result) = ldap
        .search(
            &people_base,
            Scope::Subtree,
            "(uid=alice)",
            Vec::<&str>::new(),
        )
        .await?
        .success()?;
    if people.len() != 1 {
        return Err(format!("expected one seeded alice entry, got {}", people.len()).into());
    }

    let alice = SearchEntry::construct(people.into_iter().next().ok_or("missing alice entry")?);
    if alice.dn != format!("uid=alice,{people_base}") {
        return Err(format!("unexpected alice DN {}", alice.dn).into());
    }

    let groups_base = format!("ou=groups,{LDAP_BASE_DN}");
    let (groups, _result) = ldap
        .search(
            &groups_base,
            Scope::Subtree,
            "(member=uid=alice,ou=people,dc=example,dc=org)",
            vec!["cn"],
        )
        .await?
        .success()?;
    let has_admins_group = groups.into_iter().any(|entry| {
        SearchEntry::construct(entry)
            .attrs
            .get("cn")
            .is_some_and(|values| values.iter().any(|value| value == "admins"))
    });
    if !has_admins_group {
        return Err("expected seeded admins group containing alice".into());
    }

    let _ = ldap.unbind().await;
    Ok(())
}

fn ldap_plugin(config: serde_json::Value) -> Arc<dyn Plugin> {
    create_plugin("ldap_auth", &config)
        .expect("ldap_auth config should be valid")
        .expect("ldap_auth should be a known plugin")
}

/// Build a request context carrying HTTP Basic credentials.
fn ctx_basic(user: &str, pass: &str) -> RequestContext {
    use base64::Engine;
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/secure".to_string(),
    );
    let creds = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
    ctx.headers
        .insert("authorization".to_string(), format!("Basic {creds}"));
    ctx
}

/// `None` => `Continue`; `Some(code)` => `Reject{code}` (HTTP or binary).
fn reject_status(r: &PluginResult) -> Option<u16> {
    match r {
        PluginResult::Continue => None,
        PluginResult::Reject { status_code, .. } => Some(*status_code),
        PluginResult::RejectBinary { status_code, .. } => Some(*status_code),
    }
}

async fn authenticate(plugin: &Arc<dyn Plugin>, user: &str, pass: &str) -> Option<u16> {
    let index = ConsumerIndex::new(&[]);
    let mut ctx = ctx_basic(user, pass);
    let result = plugin.authenticate(&mut ctx, &index).await;
    reject_status(&result)
}

#[tokio::test]
#[serial]
async fn ldap_direct_bind_validates_credentials() {
    let Some(ldap) = ldap_ready("ldap_direct_bind_validates_credentials").await else {
        return;
    };

    let plugin = ldap_plugin(json!({
        "ldap_url": ldap.url.clone(),
        "bind_dn_template": "uid={username},ou=people,dc=example,dc=org",
    }));

    // Correct password → authenticated (Continue, no rejection).
    assert_eq!(
        authenticate(&plugin, "alice", "alice-secret").await,
        None,
        "valid credentials should authenticate (Continue)"
    );

    // Wrong password → invalid credentials (401).
    assert_eq!(
        authenticate(&plugin, "alice", "wrong-password").await,
        Some(401),
        "wrong password should be rejected as 401"
    );

    // Unknown user → bind DN does not exist → invalid credentials (401).
    assert_eq!(
        authenticate(&plugin, "carol", "whatever").await,
        Some(401),
        "unknown user should be rejected as 401"
    );
}

#[tokio::test]
#[serial]
async fn ldap_search_then_bind_validates_credentials() {
    let Some(ldap) = ldap_ready("ldap_search_then_bind_validates_credentials").await else {
        return;
    };

    let plugin = ldap_plugin(json!({
        "ldap_url": ldap.url.clone(),
        "search_base_dn": "ou=people,dc=example,dc=org",
        "search_filter": "(uid={username})",
        "service_account_dn": LDAP_ADMIN_DN,
        "service_account_password": LDAP_ADMIN_PASSWORD,
    }));

    // Service account locates the user, then a bind as that user succeeds.
    assert_eq!(
        authenticate(&plugin, "alice", "alice-secret").await,
        None,
        "search-then-bind with valid credentials should authenticate"
    );

    // User is found by the search but the final user-bind password is wrong.
    assert_eq!(
        authenticate(&plugin, "alice", "wrong-password").await,
        Some(401),
        "search-then-bind with wrong password should be 401"
    );

    // No matching directory entry → 401 (not a 500 backend error).
    assert_eq!(
        authenticate(&plugin, "carol", "whatever").await,
        Some(401),
        "search-then-bind for a missing user should be 401"
    );
}

#[tokio::test]
#[serial]
async fn ldap_group_membership_is_enforced() {
    let Some(ldap) = ldap_ready("ldap_group_membership_is_enforced").await else {
        return;
    };

    // A service account makes the group search authenticated (independent of
    // anonymous-read ACLs); `required_groups` matches the group's `cn`.
    let plugin = ldap_plugin(json!({
        "ldap_url": ldap.url.clone(),
        "bind_dn_template": "uid={username},ou=people,dc=example,dc=org",
        "service_account_dn": LDAP_ADMIN_DN,
        "service_account_password": LDAP_ADMIN_PASSWORD,
        "group_base_dn": "ou=groups,dc=example,dc=org",
        "required_groups": ["admins"],
    }));

    // alice is a member of cn=admins → allowed.
    assert_eq!(
        authenticate(&plugin, "alice", "alice-secret").await,
        None,
        "member of a required group should be allowed"
    );

    // bob binds successfully but is not in cn=admins → forbidden (403),
    // distinct from a 401 credential failure.
    assert_eq!(
        authenticate(&plugin, "bob", "bob-secret").await,
        Some(403),
        "authenticated non-member should be forbidden (403)"
    );
}
