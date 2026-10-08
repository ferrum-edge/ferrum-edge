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
//!   official endpoint of the configured service in the configured region, on
//!   the default HTTPS port:
//!   `https://<service>[-fips].<region>.amazonaws.com`, the dual-stack
//!   `https://<service>[-fips].<region>.api.aws`, or an interface VPC endpoint
//!   `https://vpce-<id>[-<az>].<service>[-fips].<region>.vpce.amazonaws.com`,
//!   where `<region>` is a commercial or GovCloud region. A China (`cn-*`)
//!   region uses `amazonaws.com.cn` and the dual-stack
//!   `api.amazonwebservices.com.cn` instead, and no other pairing of region
//!   and suffix matches.
//! - An explicit per-instance opt-in
//!   (`allow_custom_endpoint_with_ambient_credentials`) lifts the scope for a
//!   deliberately chosen private endpoint (LocalStack, an air-gapped ISO
//!   partition, the AWS European Sovereign Cloud, a corporate egress proxy).
//!
//! Generic `*.amazonaws.com` is deliberately NOT accepted: customer-controlled
//! resources (EC2 public DNS names, load balancers, API Gateway, S3 buckets and
//! websites) live under that suffix too. A region label is therefore matched
//! against the AWS partition grammar, not merely its shape: legacy dash-style
//! S3 hosts such as `<bucket>.s3-us-west-2.amazonaws.com` put a
//! region-shaped label (`s3-us-west-2`) where the region goes, and a bucket
//! named after the service would otherwise pass. Only the hostnames that are
//! the service itself for the configured region match.
//!
//! These plugins read only the three AWS credential variables (plus the region
//! and, for Lambda, the function name and endpoint override) from the
//! environment. They never consult the AWS SDK default credential chain
//! (instance metadata, ECS container credentials, web identity, SSO, or profile
//! files), so this scope covers every ambient credential source they use.

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
    /// `None` accepts any region of a modelled partition. Used only by
    /// shape-only admission, where the region may still come from a serving
    /// node's environment.
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

    /// Scope for `service` in any region of a modelled partition.
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

/// Where each AWS SigV4 credential of one plugin instance or provider was
/// resolved from (issue #6111).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AwsCredentialSources {
    /// `aws_access_key_id` resolved from `AWS_ACCESS_KEY_ID`.
    pub access_key_id_from_env: bool,
    /// `aws_secret_access_key` resolved from `AWS_SECRET_ACCESS_KEY`.
    pub secret_access_key_from_env: bool,
    /// `aws_session_token` resolved from `AWS_SESSION_TOKEN`.
    pub session_token_from_env: bool,
}

impl AwsCredentialSources {
    /// Whether `AWS_SESSION_TOKEN` may complete this credential set. An STS
    /// session token is bound to its access key, so the environment token is
    /// only paired with a key pair that also came from the environment, never
    /// with keys written into the config.
    pub fn may_use_environment_session_token(self) -> bool {
        self.access_key_id_from_env && self.secret_access_key_from_env
    }

    /// True when any credential came from the process environment.
    pub fn is_ambient(self) -> bool {
        self.access_key_id_from_env
            || self.secret_access_key_from_env
            || self.session_token_from_env
    }

    /// The environment-resolved schema fields, backticked and comma-separated,
    /// for diagnostics. Names fields only, never a value.
    pub fn ambient_field_list(self) -> String {
        [
            (self.access_key_id_from_env, "`aws_access_key_id`"),
            (self.secret_access_key_from_env, "`aws_secret_access_key`"),
            (self.session_token_from_env, "`aws_session_token`"),
        ]
        .into_iter()
        .filter_map(|(from_env, field)| from_env.then_some(field))
        .collect::<Vec<_>>()
        .join(", ")
    }
}

/// AWS partition an ambient credential's region belongs to. Only the
/// partitions with public endpoints these plugins can reach are modelled; the
/// air-gapped ISO partitions and the European Sovereign Cloud need the
/// explicit opt-in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AwsPartition {
    /// Commercial regions (`aws`): `us-east-1`, `eu-central-1`, ...
    Aws,
    /// China regions (`aws-cn`): `cn-north-1`, `cn-northwest-1`.
    AwsCn,
    /// GovCloud regions (`aws-us-gov`): `us-gov-west-1`, `us-gov-east-1`.
    AwsUsGov,
}

impl AwsPartition {
    /// DNS suffix of the partition's regional endpoints.
    pub fn dns_suffix(self) -> &'static str {
        match self {
            Self::Aws | Self::AwsUsGov => "amazonaws.com",
            Self::AwsCn => "amazonaws.com.cn",
        }
    }
}

/// Leading region labels of the commercial partition, from the published
/// `aws` partition grammar `^(us|eu|ap|sa|ca|me|af|il|mx)-\w+-\d+$`.
const AWS_COMMERCIAL_REGION_PREFIXES: &[&str] =
    &["us", "eu", "ap", "sa", "ca", "me", "af", "il", "mx"];

/// The partition `region` belongs to, or `None` when it is not a region of a
/// modelled partition.
///
/// Mirrors the AWS SDK partition grammars (`aws`:
/// `^(us|eu|ap|sa|ca|me|af|il|mx)-\w+-\d+$`, `aws-cn`: `^cn-\w+-\d+$`,
/// `aws-us-gov`: `^us-gov-\w+-\d+$`), with `\w+` narrowed to lowercase
/// ASCII letters. Region-shaped labels that are not regions (`s3-us-west-2`,
/// `s3-external-1`, `compute-1`, `us-iso-east-1`) match nothing.
pub fn aws_region_partition(region: &str) -> Option<AwsPartition> {
    if region.len() > MAX_AWS_REGION_BYTES {
        return None;
    }
    let (partition, rest) = if let Some(rest) = region.strip_prefix("us-gov-") {
        (AwsPartition::AwsUsGov, rest)
    } else if let Some(rest) = region.strip_prefix("cn-") {
        (AwsPartition::AwsCn, rest)
    } else {
        let (prefix, rest) = region.split_once('-')?;
        if !AWS_COMMERCIAL_REGION_PREFIXES.contains(&prefix) {
            return None;
        }
        (AwsPartition::Aws, rest)
    };
    let (area, number) = rest.split_once('-')?;
    let well_formed = !area.is_empty()
        && area.bytes().all(|byte| byte.is_ascii_lowercase())
        && !number.is_empty()
        && number.bytes().all(|byte| byte.is_ascii_digit());
    well_formed.then_some(partition)
}

/// True when `value` is a region of a modelled AWS partition
/// (see [`aws_region_partition`]).
pub fn is_aws_region(value: &str) -> bool {
    aws_region_partition(value).is_some()
}

/// DNS suffix of the regional endpoints for `region`, used to derive a
/// default endpoint.
///
/// Only the China partition uses a suffix other than `amazonaws.com`: Beijing
/// (`cn-north-1`) and Ningxia (`cn-northwest-1`) publish
/// `<service>.<region>.amazonaws.com.cn`, so deriving the commercial suffix
/// there targets a hostname that is not the service (issue #5180). GovCloud
/// (`us-gov-*`) regions are ordinary `amazonaws.com` hosts. The air-gapped ISO
/// partitions and the European Sovereign Cloud are NOT derived; those
/// deployments must configure the endpoint explicitly.
pub fn aws_partition_dns_suffix(region: &str) -> &'static str {
    if region.starts_with("cn-") {
        AwsPartition::AwsCn.dns_suffix()
    } else {
        AwsPartition::Aws.dns_suffix()
    }
}

/// An official endpoint suffix and the partition family it serves.
struct OfficialSuffix {
    suffix: &'static str,
    /// True for the China partition's suffixes.
    china: bool,
    /// True when interface VPC endpoints live under `.vpce.` + this suffix.
    vpc_endpoints: bool,
}

const OFFICIAL_SUFFIXES: [OfficialSuffix; 4] = [
    OfficialSuffix {
        suffix: ".amazonaws.com",
        china: false,
        vpc_endpoints: true,
    },
    OfficialSuffix {
        suffix: ".api.aws",
        china: false,
        vpc_endpoints: false,
    },
    OfficialSuffix {
        suffix: ".amazonaws.com.cn",
        china: true,
        vpc_endpoints: true,
    },
    OfficialSuffix {
        suffix: ".api.amazonwebservices.com.cn",
        china: true,
        vpc_endpoints: false,
    },
];

/// True when `host` is an official endpoint hostname of `service`.
///
/// `region` pins the region label; `None` accepts any region of a modelled
/// partition. An ill-formed pinned region matches nothing. Accepted shapes,
/// for a commercial or GovCloud region:
///
/// - `<service>[-fips].<region>.amazonaws.com`,
/// - dual-stack `<service>[-fips].<region>.api.aws`,
/// - interface VPC endpoints
///   `vpce-<id>[-<az>].<service>[-fips].<region>.vpce.amazonaws.com`;
///
/// and for a China (`cn-*`) region the same names under `amazonaws.com.cn`,
/// with dual-stack under `api.amazonwebservices.com.cn`.
///
/// Matching is exact on every label: no additional leading labels, no other
/// service, no other region, and no region paired with another partition's
/// suffix.
pub fn is_official_aws_service_host(host: &str, service: AwsService, region: Option<&str>) -> bool {
    for official in &OFFICIAL_SUFFIXES {
        let Some(rest) = host.strip_suffix(official.suffix) else {
            continue;
        };
        if service_and_region_match(rest, service, region, official.china) {
            return true;
        }
        if official.vpc_endpoints
            && let Some(rest) = rest.strip_suffix(".vpce")
            && let Some((endpoint_id, service_and_region)) = rest.split_once('.')
            && is_vpc_endpoint_id_label(endpoint_id)
            && service_and_region_match(service_and_region, service, region, official.china)
        {
            return true;
        }
    }
    false
}

/// `labels` is exactly `<service>[-fips].<region>`, where `<region>` belongs to
/// the China partition exactly when `china` is set, and equals the pinned
/// `region` when one is given.
fn service_and_region_match(
    labels: &str,
    service: AwsService,
    region: Option<&str>,
    china: bool,
) -> bool {
    let Some((service_label, region_label)) = labels.split_once('.') else {
        return false;
    };
    let prefix = service.endpoint_prefix();
    let service_matches =
        service_label == prefix || service_label.strip_suffix("-fips") == Some(prefix);
    let region_matches = region.is_none_or(|region| region_label == region)
        && aws_region_partition(region_label)
            .is_some_and(|partition| (partition == AwsPartition::AwsCn) == china);
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
