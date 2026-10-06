//! DP backend egress policy attestation: wire decoding, weakest-policy
//! aggregation, and the fail-closed public-only rule (issue #6020).

use ferrum_edge::config::{BackendAllowIps, BackendEgressPolicy};
use ferrum_edge::grpc::backend_egress_attestation::{
    ATTESTATION_REPORTED, ATTESTATION_UNKNOWN, DataPlaneEgressSummary, EgressMode,
    ReportedEgressPolicy, attestation_label, report_for_policy,
};
use ferrum_edge::grpc::proto::{BackendEgressMode, BackendEgressPolicyReport};
use serde_json::json;

fn policy(mode: EgressMode) -> ReportedEgressPolicy {
    ReportedEgressPolicy {
        mode,
        dangerous_ranges_blocked: true,
        allow_cidr_overrides_present: false,
        deny_cidr_overrides_present: false,
    }
}

#[test]
fn report_carries_presence_flags_and_never_cidrs() {
    let loaded = BackendEgressPolicy::from_env(
        BackendAllowIps::Public,
        "10.45.67.89/32",
        "8.8.8.8/32",
        false,
    )
    .unwrap();
    let report = report_for_policy(&loaded);
    assert_eq!(report.mode, BackendEgressMode::Public as i32);
    assert!(!report.dangerous_ranges_blocked);
    assert!(report.allow_cidr_overrides_present);
    assert!(report.deny_cidr_overrides_present);
    let rendered = format!("{report:?}");
    assert!(!rendered.contains("10.45.67.89"));
    assert!(!rendered.contains("8.8.8.8"));
    let decoded = ReportedEgressPolicy::from_report(Some(&report)).unwrap();
    assert_eq!(decoded, ReportedEgressPolicy::from_policy(&loaded));
    assert!(!decoded.public_only_guaranteed());
}

#[test]
fn every_mode_round_trips_through_the_wire_report() {
    for (allow_ips, mode) in [
        (BackendAllowIps::Both, EgressMode::Both),
        (BackendAllowIps::Public, EgressMode::Public),
        (BackendAllowIps::Private, EgressMode::Private),
    ] {
        let loaded = BackendEgressPolicy::from_allow_ips(allow_ips);
        let reported = ReportedEgressPolicy::from_policy(&loaded);
        assert_eq!(reported.mode, mode);
        assert_eq!(
            ReportedEgressPolicy::from_report(Some(&reported.to_report())),
            Some(reported)
        );
    }
}

#[test]
fn absent_unspecified_and_unrecognised_reports_are_unknown() {
    assert_eq!(ReportedEgressPolicy::from_report(None), None);
    for mode in [BackendEgressMode::Unspecified as i32, 4, 99, -1] {
        let report = BackendEgressPolicyReport {
            mode,
            dangerous_ranges_blocked: true,
            allow_cidr_overrides_present: false,
            deny_cidr_overrides_present: false,
        };
        assert_eq!(
            ReportedEgressPolicy::from_report(Some(&report)),
            None,
            "{mode}"
        );
    }
    assert_eq!(attestation_label(None), ATTESTATION_UNKNOWN);
    let public = policy(EgressMode::Public);
    assert_eq!(attestation_label(Some(&public)), ATTESTATION_REPORTED);
}

#[test]
fn public_only_requires_public_mode_without_allow_overrides() {
    assert!(policy(EgressMode::Public).public_only_guaranteed());
    assert!(!policy(EgressMode::Both).public_only_guaranteed());
    assert!(!policy(EgressMode::Private).public_only_guaranteed());
    let mut allow = policy(EgressMode::Public);
    allow.allow_cidr_overrides_present = true;
    assert!(!allow.public_only_guaranteed());
    // Deny overlays and a disabled baseline only restrict / do not widen
    // the mode stage, matching the local endpoint's guarantee rule.
    let mut restricted = policy(EgressMode::Public);
    restricted.deny_cidr_overrides_present = true;
    restricted.dangerous_ranges_blocked = false;
    assert!(restricted.public_only_guaranteed());
}

#[test]
fn weaken_takes_the_least_restrictive_value_of_every_field() {
    let public = policy(EgressMode::Public);
    let private = policy(EgressMode::Private);
    let both = policy(EgressMode::Both);
    assert_eq!(public.weaken(public).mode, EgressMode::Public);
    assert_eq!(private.weaken(private).mode, EgressMode::Private);
    assert_eq!(public.weaken(private).mode, EgressMode::Both);
    assert_eq!(private.weaken(public).mode, EgressMode::Both);
    assert_eq!(public.weaken(both).mode, EgressMode::Both);

    let mut open = public;
    open.dangerous_ranges_blocked = false;
    open.allow_cidr_overrides_present = true;
    open.deny_cidr_overrides_present = true;
    let weakest = public.weaken(open);
    assert!(!weakest.dangerous_ranges_blocked);
    assert!(weakest.allow_cidr_overrides_present);
    // One DP's deny list does not restrict another DP.
    assert!(!weakest.deny_cidr_overrides_present);
    assert_eq!(open.weaken(open), open);
    assert_eq!(public.weaken(open), open.weaken(public));
}

#[test]
fn summary_is_public_only_only_when_every_connected_dp_reports_public_only() {
    let public = policy(EgressMode::Public);
    let all_public = DataPlaneEgressSummary::from_reports([Some(public), Some(public)]);
    assert_eq!(all_public.connected_data_planes, 2);
    assert_eq!(all_public.reporting_data_planes, 2);
    assert_eq!(all_public.unknown_data_planes, 0);
    assert_eq!(all_public.weakest_policy, Some(public));
    assert!(all_public.weakest_policy_complete);
    assert!(all_public.all_connected_public_only_guaranteed);

    // One weaker DP decides the weakest policy.
    let mixed =
        DataPlaneEgressSummary::from_reports([Some(public), Some(policy(EgressMode::Both))]);
    assert!(mixed.weakest_policy_complete);
    assert_eq!(mixed.weakest_policy.unwrap().mode, EgressMode::Both);
    assert!(!mixed.all_connected_public_only_guaranteed);

    // An unknown DP keeps the computed policy but voids the guarantee.
    let with_unknown = DataPlaneEgressSummary::from_reports([Some(public), None]);
    assert_eq!(with_unknown.connected_data_planes, 2);
    assert_eq!(with_unknown.reporting_data_planes, 1);
    assert_eq!(with_unknown.unknown_data_planes, 1);
    assert_eq!(with_unknown.weakest_policy, Some(public));
    assert!(!with_unknown.weakest_policy_complete);
    assert!(!with_unknown.all_connected_public_only_guaranteed);

    let only_unknown = DataPlaneEgressSummary::from_reports([None]);
    assert_eq!(only_unknown.weakest_policy, None);
    assert!(!only_unknown.all_connected_public_only_guaranteed);

    // An empty set is never vacuously public-only.
    let empty = DataPlaneEgressSummary::from_reports(std::iter::empty());
    assert_eq!(empty.connected_data_planes, 0);
    assert_eq!(empty.weakest_policy, None);
    assert!(!empty.weakest_policy_complete);
    assert!(!empty.all_connected_public_only_guaranteed);
}

#[test]
fn serialized_shapes_match_the_admin_vocabulary() {
    let mut reported = policy(EgressMode::Public);
    reported.deny_cidr_overrides_present = true;
    assert_eq!(
        serde_json::to_value(reported).unwrap(),
        json!({
            "mode": "public",
            "mode_allowed_ip_classes": ["public"],
            "mode_blocked_ip_classes": ["private-reserved"],
            "dangerous_ranges_blocked": true,
            "allow_cidr_overrides_present": false,
            "deny_cidr_overrides_present": true,
            "public_only_guaranteed": true,
        })
    );
    for (mode, label, allowed, blocked) in [
        (
            EgressMode::Both,
            "both",
            json!(["public", "private-reserved"]),
            json!([]),
        ),
        (
            EgressMode::Private,
            "private",
            json!(["private-reserved"]),
            json!(["public"]),
        ),
    ] {
        let value = serde_json::to_value(policy(mode)).unwrap();
        assert_eq!(value["mode"], label);
        assert_eq!(value["mode_allowed_ip_classes"], allowed);
        assert_eq!(value["mode_blocked_ip_classes"], blocked);
        assert_eq!(value["public_only_guaranteed"], false);
    }
    let summary = DataPlaneEgressSummary::from_reports([None]);
    assert_eq!(
        serde_json::to_value(summary).unwrap(),
        json!({
            "connected_data_planes": 1,
            "reporting_data_planes": 0,
            "unknown_data_planes": 1,
            "weakest_policy": null,
            "weakest_policy_complete": false,
            "all_connected_public_only_guaranteed": false,
        })
    );
}
