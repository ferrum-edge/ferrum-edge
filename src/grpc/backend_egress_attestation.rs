//! Data-plane backend egress policy attestation over ConfigSync (#6020).
//!
//! A DP reports bounded metadata about its loaded backend address policy on
//! `SubscribeRequest.backend_egress_policy`: the mode plus three presence
//! flags, never CIDRs, addresses, counts, or raw settings. The CP records the
//! report against the live Subscribe stream in
//! [`DpNodeRegistry`](super::cp_server::DpNodeRegistry) and exposes it on
//! `GET /backend-egress-policy` and `GET /cluster`.
//!
//! The report is self-described by a JWT-authenticated DP running the same
//! build as the CP; it is not a cryptographic attestation of the DP host. A
//! missing report, or one whose mode is unspecified or unrecognised, is
//! recorded as unknown, and an unknown DP never counts as public-only.

use serde::{Serialize, Serializer};

use crate::config::{BackendAllowIps, BackendEgressPolicy};
use crate::grpc::proto::{BackendEgressMode, BackendEgressPolicyReport};

/// Per-DP attestation label for a DP that sent a recognised report.
pub const ATTESTATION_REPORTED: &str = "reported";
/// Per-DP attestation label for a DP whose policy is not known.
pub const ATTESTATION_UNKNOWN: &str = "unknown";

/// Backend address mode with its fixed `ferrum-private-reserved-v1` class lists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressMode {
    Both,
    Public,
    Private,
}

impl EgressMode {
    pub fn from_allow_ips(allow_ips: &BackendAllowIps) -> Self {
        match allow_ips {
            BackendAllowIps::Both => Self::Both,
            BackendAllowIps::Public => Self::Public,
            BackendAllowIps::Private => Self::Private,
        }
    }

    /// Stable `mode` label shared with `GET /backend-egress-policy`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Both => "both",
            Self::Public => "public",
            Self::Private => "private",
        }
    }

    /// Classes the mode stage admits.
    pub fn allowed_ip_classes(self) -> &'static [&'static str] {
        match self {
            Self::Both => &["public", "private-reserved"],
            Self::Public => &["public"],
            Self::Private => &["private-reserved"],
        }
    }

    /// Classes the mode stage blocks.
    pub fn blocked_ip_classes(self) -> &'static [&'static str] {
        match self {
            Self::Both => &[],
            Self::Public => &["private-reserved"],
            Self::Private => &["public"],
        }
    }

    fn allows_public(self) -> bool {
        !matches!(self, Self::Private)
    }

    fn allows_private(self) -> bool {
        !matches!(self, Self::Public)
    }

    /// The mode whose admitted classes are the union of both modes' classes.
    fn union(self, other: Self) -> Self {
        let public = self.allows_public() || other.allows_public();
        let private = self.allows_private() || other.allows_private();
        match (public, private) {
            (true, false) => Self::Public,
            (false, true) => Self::Private,
            _ => Self::Both,
        }
    }

    fn to_wire(self) -> BackendEgressMode {
        match self {
            Self::Both => BackendEgressMode::Both,
            Self::Public => BackendEgressMode::Public,
            Self::Private => BackendEgressMode::Private,
        }
    }
}

/// Presence-only backend egress policy metadata of one data plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReportedEgressPolicy {
    pub mode: EgressMode,
    pub dangerous_ranges_blocked: bool,
    pub allow_cidr_overrides_present: bool,
    pub deny_cidr_overrides_present: bool,
}

impl ReportedEgressPolicy {
    /// Metadata of a loaded policy, without its CIDRs.
    pub fn from_policy(policy: &BackendEgressPolicy) -> Self {
        let metadata = policy.metadata();
        Self {
            mode: EgressMode::from_allow_ips(&metadata.allow_ips),
            dangerous_ranges_blocked: metadata.dangerous_ranges_blocked,
            allow_cidr_overrides_present: metadata.allow_cidr_overrides_present,
            deny_cidr_overrides_present: metadata.deny_cidr_overrides_present,
        }
    }

    /// Wire form sent on `SubscribeRequest.backend_egress_policy`.
    pub fn to_report(self) -> BackendEgressPolicyReport {
        BackendEgressPolicyReport {
            mode: self.mode.to_wire() as i32,
            dangerous_ranges_blocked: self.dangerous_ranges_blocked,
            allow_cidr_overrides_present: self.allow_cidr_overrides_present,
            deny_cidr_overrides_present: self.deny_cidr_overrides_present,
        }
    }

    /// Decode a DP report. `None` (unknown) when the report is absent or its
    /// mode is unspecified or not in the closed vocabulary.
    pub fn from_report(report: Option<&BackendEgressPolicyReport>) -> Option<Self> {
        let report = report?;
        let mode = match BackendEgressMode::try_from(report.mode).ok()? {
            BackendEgressMode::Unspecified => return None,
            BackendEgressMode::Both => EgressMode::Both,
            BackendEgressMode::Public => EgressMode::Public,
            BackendEgressMode::Private => EgressMode::Private,
        };
        Some(Self {
            mode,
            dangerous_ranges_blocked: report.dangerous_ranges_blocked,
            allow_cidr_overrides_present: report.allow_cidr_overrides_present,
            deny_cidr_overrides_present: report.deny_cidr_overrides_present,
        })
    }

    /// The `GET /backend-egress-policy` guarantee rule for a serving data
    /// plane: public mode with no allow CIDR overrides.
    pub fn public_only_guaranteed(self) -> bool {
        matches!(self.mode, EgressMode::Public) && !self.allow_cidr_overrides_present
    }

    /// Least restrictive combination of two policies, field by field: the mode
    /// admitting the union of both class sets, the dangerous baseline only if
    /// both block it, allow overrides if either has them, and deny overrides
    /// only if both have them.
    pub fn weaken(self, other: Self) -> Self {
        Self {
            mode: self.mode.union(other.mode),
            dangerous_ranges_blocked: self.dangerous_ranges_blocked
                && other.dangerous_ranges_blocked,
            allow_cidr_overrides_present: self.allow_cidr_overrides_present
                || other.allow_cidr_overrides_present,
            deny_cidr_overrides_present: self.deny_cidr_overrides_present
                && other.deny_cidr_overrides_present,
        }
    }
}

#[derive(Serialize)]
struct EgressPolicyView {
    mode: &'static str,
    mode_allowed_ip_classes: &'static [&'static str],
    mode_blocked_ip_classes: &'static [&'static str],
    dangerous_ranges_blocked: bool,
    allow_cidr_overrides_present: bool,
    deny_cidr_overrides_present: bool,
    public_only_guaranteed: bool,
}

impl Serialize for ReportedEgressPolicy {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        EgressPolicyView {
            mode: self.mode.as_str(),
            mode_allowed_ip_classes: self.mode.allowed_ip_classes(),
            mode_blocked_ip_classes: self.mode.blocked_ip_classes(),
            dangerous_ranges_blocked: self.dangerous_ranges_blocked,
            allow_cidr_overrides_present: self.allow_cidr_overrides_present,
            deny_cidr_overrides_present: self.deny_cidr_overrides_present,
            public_only_guaranteed: self.public_only_guaranteed(),
        }
        .serialize(serializer)
    }
}

/// Wire report for this process's loaded policy, sent by the DP on Subscribe.
pub fn report_for_policy(policy: &BackendEgressPolicy) -> BackendEgressPolicyReport {
    ReportedEgressPolicy::from_policy(policy).to_report()
}

/// Per-DP attestation label.
pub fn attestation_label(policy: Option<&ReportedEgressPolicy>) -> &'static str {
    if policy.is_some() {
        ATTESTATION_REPORTED
    } else {
        ATTESTATION_UNKNOWN
    }
}

/// Aggregate over a set of connected data planes, one per live stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct DataPlaneEgressSummary {
    pub connected_data_planes: usize,
    pub reporting_data_planes: usize,
    pub unknown_data_planes: usize,
    /// Weakest policy over the reporting data planes; `None` when none report.
    pub weakest_policy: Option<ReportedEgressPolicy>,
    /// True only when at least one data plane is connected and every one of
    /// them reported, so `weakest_policy` covers the whole set.
    pub weakest_policy_complete: bool,
    /// True only when `weakest_policy_complete` and the weakest policy is
    /// public-only guaranteed. An empty set is never public-only.
    pub all_connected_public_only_guaranteed: bool,
}

impl DataPlaneEgressSummary {
    pub fn from_reports<I>(reports: I) -> Self
    where
        I: IntoIterator<Item = Option<ReportedEgressPolicy>>,
    {
        let mut connected = 0usize;
        let mut reporting = 0usize;
        let mut weakest: Option<ReportedEgressPolicy> = None;
        for report in reports {
            connected += 1;
            if let Some(policy) = report {
                reporting += 1;
                weakest = Some(weakest.map_or(policy, |current| current.weaken(policy)));
            }
        }
        let complete = connected > 0 && reporting == connected;
        Self {
            connected_data_planes: connected,
            reporting_data_planes: reporting,
            unknown_data_planes: connected - reporting,
            weakest_policy: weakest,
            weakest_policy_complete: complete,
            all_connected_public_only_guaranteed: complete
                && weakest.is_some_and(ReportedEgressPolicy::public_only_guaranteed),
        }
    }
}
