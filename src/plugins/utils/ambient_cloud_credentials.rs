//! Endpoint scope for ambient (process-environment) cloud credentials.
//!
//! `serverless_function` (`aws_lambda`) and `ai_federation` (`aws_bedrock`)
//! fall back to the process's standard AWS credential variables
//! (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`) when the
//! plugin config does not carry the credential itself. Those variables belong to
//! whoever owns the gateway process, not to the principal writing plugin config
//! through the admin API, a CP tenant, or a mesh policy author. Without a scope,
//! the same config that inherits the credential could also choose where it is
//! sent (`aws_endpoint_url`, `base_url`, or a hostile `aws_region` interpolated
//! into the derived host), turning a config write into use of the gateway's own
//! cloud identity against an arbitrary endpoint.
//!
//! The trust model is therefore:
//!
//! - A credential written into the plugin config is the config author's own
//!   credential, and may go to any endpoint that config validly names.
//! - A credential resolved from the process environment may only be sent to an
//!   official endpoint of the configured service in the configured region:
//!   `https://<service>[-fips].<region>.amazonaws.com[.cn]`, the dual-stack
//!   `https://<service>[-fips].<region>.api.aws`, or an interface VPC endpoint
//!   `https://vpce-<id>[-<az>].<service>.<region>.vpce.amazonaws.com[.cn]`, on
//!   the default HTTPS port.
//! - An explicit per-instance opt-in
//!   (`allow_custom_endpoint_with_ambient_credentials`) lifts the scope for a
//!   deliberately chosen private endpoint (LocalStack, an air-gapped ISO
//!   partition, a corporate egress proxy).
//!
//! Generic `*.amazonaws.com` is deliberately NOT accepted: customer-controlled
//! resources (EC2 public DNS names, load balancers, API Gateway, S3 websites)
//! live under that suffix too. Only the hostnames that are the service itself
//! for the configured region match.

use url::{Host, Url};

/// Config field that lifts the ambient-credential endpoint scope for one
/// plugin instance (`serverless_function`) or provider (`ai_federation`).
pub const ALLOW_CUSTOM_ENDPOINT_WITH_AMBIENT_CREDENTIALS: &str =
    "allow_custom_endpoint_with_ambient_credentials";

/// Longest AWS region identifier accepted for endpoint matching.
const MAX_AWS_REGION_BYTES: usize = 63;

/// Longest DNS label (the interface VPC endpoint id label).
const MAX_DNS_LABEL_BYTES: usize = 63;

/// AWS service whose official endpoints an ambient credential may reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AwsService {
    /// AWS Lambda Invoke API (`serverless_function` `aws_lambda`).
    Lambda,
    /// Amazon Bedrock Runtime (`ai_federation` `aws_bedrock`).
    BedrockRuntime,
}

impl AwsService {
    /// The service's endpoint prefix: the first DNS label of its regional host.
    pub fn endpoint_prefix(self) -> &'static str {
        match self {
            Self::Lambda => "lambda",
            Self::BedrockRuntime => "bedrock-runtime",
        }
    }
}

/// The official endpoints a process-environment AWS credential may be sent to.
///
/// Built once at plugin construction; [`Self::permits_url`] is the request-time
/// check and performs no allocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmbientAwsEndpointScope {
    service: AwsService,
    /// `None` accepts any well-formed region. Used only by shape-only
    /// admission, where the region may still come from a serving node's
    /// environment.
    region: Option<String>,
}

impl AmbientAwsEndpointScope {
    /// Scope pinned to `service` in `region`.
    pub fn new(service: AwsService, region: &str) -> Self {
        Self {
            service,
            region: Some(region.to_string()),
        }
    }

    /// Scope for `service` in any well-formed region.
    pub fn any_region(service: AwsService) -> Self {
        Self {
            service,
            region: None,
        }
    }

    /// The service this scope admits.
    pub fn service(&self) -> AwsService {
        self.service
    }

    /// True when `url` is an official endpoint of this scope's service and
    /// region: `https`, no userinfo, the default port, and a hostname (never an
    /// IP literal) that [`is_official_aws_service_host`] accepts.
    pub fn permits_url(&self, url: &Url) -> bool {
        if url.scheme() != "https" {
            return false;
        }
        if !url.username().is_empty() || url.password().is_some() {
            return false;
        }
        // `Url::port` is `None` for the scheme default (443 for https).
        if url.port().is_some() {
            return false;
        }
        match url.host() {
            Some(Host::Domain(host)) => {
                is_official_aws_service_host(host, self.service, self.region.as_deref())
            }
            _ => false,
        }
    }
}

/// True when `host` is an official endpoint hostname of `service`.
///
/// `region` pins the region label; `None` accepts any well-formed region. An
/// ill-formed pinned region matches nothing. Accepted shapes:
///
/// - `<service>.<region>.amazonaws.com` and `<service>-fips.<region>.amazonaws.com`
///   (commercial and GovCloud partitions),
/// - the same under `amazonaws.com.cn` (China partition),
/// - dual-stack `<service>[-fips].<region>.api.aws`,
/// - interface VPC endpoints
///   `vpce-<id>[-<az>].<service>[-fips].<region>.vpce.amazonaws.com[.cn]`.
///
/// Matching is exact on every label: no additional leading labels, no other
/// service, and no other region.
pub fn is_official_aws_service_host(host: &str, service: AwsService, region: Option<&str>) -> bool {
    if region.is_some_and(|region| !is_aws_region(region)) {
        return false;
    }
    for suffix in [".amazonaws.com", ".amazonaws.com.cn"] {
        let Some(rest) = host.strip_suffix(suffix) else {
            continue;
        };
        if service_and_region_match(rest, service, region) {
            return true;
        }
        if let Some(rest) = rest.strip_suffix(".vpce")
            && let Some((endpoint_id, service_and_region)) = rest.split_once('.')
            && is_vpc_endpoint_id_label(endpoint_id)
            && service_and_region_match(service_and_region, service, region)
        {
            return true;
        }
    }
    host.strip_suffix(".api.aws")
        .is_some_and(|rest| service_and_region_match(rest, service, region))
}

/// True when `value` is shaped like an AWS region identifier
/// (`us-east-1`, `us-gov-west-1`, `cn-north-1`, `eu-isoe-west-1`): lowercase
/// ASCII letters, digits, and hyphens, starting with a letter, ending with a
/// digit, and containing at least one hyphen.
pub fn is_aws_region(value: &str) -> bool {
    let bytes = value.as_bytes();
    let (Some(first), Some(last)) = (bytes.first(), bytes.last()) else {
        return false;
    };
    bytes.len() <= MAX_AWS_REGION_BYTES
        && first.is_ascii_lowercase()
        && last.is_ascii_digit()
        && bytes.contains(&b'-')
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

/// `labels` is exactly `<service>[-fips].<region>`.
fn service_and_region_match(labels: &str, service: AwsService, region: Option<&str>) -> bool {
    let Some((service_label, region_label)) = labels.split_once('.') else {
        return false;
    };
    let prefix = service.endpoint_prefix();
    let service_matches =
        service_label == prefix || service_label.strip_suffix("-fips") == Some(prefix);
    let region_matches = match region {
        Some(region) => region_label == region,
        None => is_aws_region(region_label),
    };
    service_matches && region_matches
}

/// `vpce-<id>` or `vpce-<id>-<az>`: one DNS label of lowercase alphanumerics
/// and hyphens.
fn is_vpc_endpoint_id_label(label: &str) -> bool {
    label.len() <= MAX_DNS_LABEL_BYTES
        && label
            .strip_prefix("vpce-")
            .is_some_and(|id| !id.is_empty() && !id.ends_with('-'))
        && label
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}
