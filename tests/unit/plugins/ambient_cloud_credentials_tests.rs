//! Endpoint scope for process-environment AWS credentials (issue #6111).
//!
//! `serverless_function` and `ai_federation` both decide, at admission and
//! again before signing each request, whether an ambient credential may reach
//! an endpoint through `AmbientAwsEndpointScope::permits_url`. These tables pin
//! that single decision for both services.

use ferrum_edge::plugins::utils::ambient_cloud_credentials::{
    AmbientAwsEndpointScope, AwsCredentialSources, AwsPartition, AwsService,
    aws_partition_dns_suffix, aws_region_partition, is_aws_region, is_official_aws_service_host,
};
use url::Url;

fn permits(scope: &AmbientAwsEndpointScope, url: &str) -> bool {
    scope.permits_url(&Url::parse(url).expect("fixture URL parses"))
}

#[test]
fn lambda_scope_admits_only_official_endpoints_for_the_configured_region() {
    let scope = AmbientAwsEndpointScope::new(AwsService::Lambda, "us-east-1");
    for accepted in [
        "https://lambda.us-east-1.amazonaws.com",
        "https://lambda.us-east-1.amazonaws.com/",
        "https://lambda.us-east-1.amazonaws.com:443/2015-03-31/functions/f/invocations",
        "https://LAMBDA.US-EAST-1.AMAZONAWS.COM",
        "https://lambda-fips.us-east-1.amazonaws.com",
        "https://lambda.us-east-1.api.aws",
        "https://lambda-fips.us-east-1.api.aws",
        "https://vpce-0123456789abcdef0-abcdefgh.lambda.us-east-1.vpce.amazonaws.com",
        "https://vpce-0123456789abcdef0-abcdefgh-us-east-1a.lambda.us-east-1.vpce.amazonaws.com",
        "https://vpce-0123456789abcdef0.lambda-fips.us-east-1.vpce.amazonaws.com",
    ] {
        assert!(permits(&scope, accepted), "must admit {accepted}");
    }

    for refused in [
        // Not HTTPS, not the default port, or not a hostname.
        "http://lambda.us-east-1.amazonaws.com",
        "https://lambda.us-east-1.amazonaws.com:8443",
        "https://52.94.0.1",
        "https://[2001:db8::1]",
        // Another region or another service.
        "https://lambda.us-west-2.amazonaws.com",
        "https://bedrock-runtime.us-east-1.amazonaws.com",
        "https://vpce-0123.bedrock-runtime.us-east-1.vpce.amazonaws.com",
        // Customer-controlled names under the AWS suffix.
        "https://ec2-203-0-113-10.compute-1.amazonaws.com",
        "https://my-lb-123.us-east-1.elb.amazonaws.com",
        "https://abc123.execute-api.us-east-1.amazonaws.com",
        "https://bucket.s3-website-us-east-1.amazonaws.com",
        // Extra or forged labels.
        "https://evil.lambda.us-east-1.amazonaws.com",
        "https://lambda.us-east-1.amazonaws.com.evil.example",
        "https://lambda.us-east-1.evil.amazonaws.com",
        "https://lambda.us-east-1.amazonaws.com.",
        "https://lambdafips.us-east-1.amazonaws.com",
        "https://lambda.us-east-1.vpce.amazonaws.com",
        "https://vpce-.lambda.us-east-1.vpce.amazonaws.com",
        "https://endpoint-0123.lambda.us-east-1.vpce.amazonaws.com",
        // Private development endpoints need the explicit opt-in.
        "http://localhost:4566",
        "https://localhost.localstack.cloud:4566",
        "https://lambda.example.com",
    ] {
        assert!(!permits(&scope, refused), "must refuse {refused}");
    }
}

#[test]
fn bedrock_scope_admits_the_runtime_endpoints_only() {
    let scope = AmbientAwsEndpointScope::new(AwsService::BedrockRuntime, "eu-central-1");
    for accepted in [
        "https://bedrock-runtime.eu-central-1.amazonaws.com/model/m/converse",
        "https://bedrock-runtime-fips.eu-central-1.amazonaws.com/model/m/converse",
        "https://bedrock-runtime.eu-central-1.api.aws/model/m/converse",
        "https://vpce-0abc.bedrock-runtime.eu-central-1.vpce.amazonaws.com/model/m/converse",
    ] {
        assert!(permits(&scope, accepted), "must admit {accepted}");
    }
    for refused in [
        "https://bedrock.eu-central-1.amazonaws.com/model/m/converse",
        "https://bedrock-runtime.us-east-1.amazonaws.com/model/m/converse",
        "https://bedrock-runtime.amazonaws.com/model/m/converse",
        "https://lambda.eu-central-1.amazonaws.com",
        "https://bedrock-proxy.example.com/model/m/converse",
    ] {
        assert!(!permits(&scope, refused), "must refuse {refused}");
    }
}

#[test]
fn china_partition_endpoints_are_official() {
    let scope = AmbientAwsEndpointScope::new(AwsService::Lambda, "cn-north-1");
    for accepted in [
        "https://lambda.cn-north-1.amazonaws.com.cn",
        "https://lambda.cn-north-1.api.amazonwebservices.com.cn",
        "https://vpce-0abc.lambda.cn-north-1.vpce.amazonaws.com.cn",
    ] {
        assert!(permits(&scope, accepted), "must admit {accepted}");
    }
    for refused in [
        "https://lambda.cn-north-1.amazonaws.com.cn.evil.example",
        // A China region never pairs with another partition's suffix.
        "https://lambda.cn-north-1.amazonaws.com",
        "https://lambda.cn-north-1.api.aws",
        "https://vpce-0abc.lambda.cn-north-1.vpce.amazonaws.com",
        // No VPC endpoints under the dual-stack suffix.
        "https://vpce-0abc.lambda.cn-north-1.vpce.api.amazonwebservices.com.cn",
    ] {
        assert!(!permits(&scope, refused), "must refuse {refused}");
    }

    // ... and a non-China region never pairs with a China suffix.
    let scope = AmbientAwsEndpointScope::new(AwsService::BedrockRuntime, "us-east-1");
    for refused in [
        "https://bedrock-runtime.us-east-1.amazonaws.com.cn",
        "https://bedrock-runtime.us-east-1.api.amazonwebservices.com.cn",
        "https://vpce-0abc.bedrock-runtime.us-east-1.vpce.amazonaws.com.cn",
    ] {
        assert!(!permits(&scope, refused), "must refuse {refused}");
    }
    for refused in [
        "https://lambda.cn-north-1.amazonaws.com",
        "https://lambda.us-east-1.amazonaws.com.cn",
    ] {
        let scope = AmbientAwsEndpointScope::any_region(AwsService::Lambda);
        assert!(
            !permits(&scope, refused),
            "any region must refuse {refused}"
        );
    }
}

#[test]
fn govcloud_endpoints_are_official() {
    let scope = AmbientAwsEndpointScope::new(AwsService::Lambda, "us-gov-west-1");
    for accepted in [
        "https://lambda.us-gov-west-1.amazonaws.com",
        "https://lambda-fips.us-gov-west-1.amazonaws.com",
        "https://lambda.us-gov-west-1.api.aws",
        "https://vpce-0abc.lambda.us-gov-west-1.vpce.amazonaws.com",
    ] {
        assert!(permits(&scope, accepted), "must admit {accepted}");
    }
    assert!(!permits(
        &scope,
        "https://lambda.us-gov-west-1.amazonaws.com.cn"
    ));
}

#[test]
fn partitions_without_public_endpoints_need_the_opt_in() {
    // The European Sovereign Cloud and the air-gapped ISO partitions use their
    // own DNS suffixes and region grammars; neither is modelled.
    for (region, host) in [
        ("eusc-de-east-1", "lambda.eusc-de-east-1.amazonaws.eu"),
        ("eusc-de-east-1", "lambda.eusc-de-east-1.amazonaws.com"),
        ("us-iso-east-1", "lambda.us-iso-east-1.c2s.ic.gov"),
        ("us-iso-east-1", "lambda.us-iso-east-1.amazonaws.com"),
        ("us-isob-east-1", "lambda.us-isob-east-1.amazonaws.com"),
        ("eu-isoe-west-1", "lambda.eu-isoe-west-1.amazonaws.com"),
        ("us-isof-south-1", "lambda.us-isof-south-1.amazonaws.com"),
    ] {
        assert!(!is_aws_region(region), "region={region}");
        let url = &format!("https://{host}");
        let scope = AmbientAwsEndpointScope::new(AwsService::Lambda, region);
        assert!(!permits(&scope, url), "must refuse {url}");
        let scope = AmbientAwsEndpointScope::any_region(AwsService::Lambda);
        assert!(!permits(&scope, url), "any region must refuse {url}");
    }
}

/// Legacy dash-style S3 hosts put a region-shaped label where the region goes:
/// `<bucket>.s3-us-west-2.amazonaws.com` is the bucket named `<bucket>`, so a
/// bucket named after the service (or its FIPS variant) would otherwise pass.
const BUCKET_SHAPED_REGION_LABELS: [&str; 6] = [
    "s3-us-west-2",
    "s3-external-1",
    "s3-website-us-east-1",
    "s3-fips-us-gov-west-1",
    "s3-website.us-east-1",
    "compute-1",
];

#[test]
fn bucket_shaped_hosts_are_refused_for_every_service_and_scope() {
    for service in [AwsService::Lambda, AwsService::BedrockRuntime] {
        let prefix = service.endpoint_prefix();
        for label in BUCKET_SHAPED_REGION_LABELS {
            for host in [
                format!("{prefix}.{label}.amazonaws.com"),
                format!("{prefix}-fips.{label}.amazonaws.com"),
                format!("{prefix}.{label}.api.aws"),
                format!("vpce-0abc.{prefix}.{label}.vpce.amazonaws.com"),
            ] {
                let url = format!("https://{host}/");
                // The region label as a configured region ...
                let pinned = AmbientAwsEndpointScope::new(service, label);
                assert!(!permits(&pinned, &url), "pinned to {label}: {url}");
                // ... a real configured region ...
                let real = AmbientAwsEndpointScope::new(service, "us-west-2");
                assert!(!permits(&real, &url), "pinned to us-west-2: {url}");
                // ... and shape-only admission with no configured region.
                let any = AmbientAwsEndpointScope::any_region(service);
                assert!(!permits(&any, &url), "any region: {url}");
                assert!(!is_official_aws_service_host(&host, service, None));
            }
        }
    }
}

#[test]
fn region_grammar_follows_the_aws_partitions() {
    for (region, partition) in [
        ("us-east-1", AwsPartition::Aws),
        ("eu-central-2", AwsPartition::Aws),
        ("ap-southeast-5", AwsPartition::Aws),
        ("sa-east-1", AwsPartition::Aws),
        ("ca-west-1", AwsPartition::Aws),
        ("me-central-1", AwsPartition::Aws),
        ("af-south-1", AwsPartition::Aws),
        ("il-central-1", AwsPartition::Aws),
        ("mx-central-1", AwsPartition::Aws),
        ("us-gov-west-1", AwsPartition::AwsUsGov),
        ("us-gov-east-1", AwsPartition::AwsUsGov),
        ("cn-north-1", AwsPartition::AwsCn),
        ("cn-northwest-1", AwsPartition::AwsCn),
    ] {
        assert_eq!(
            aws_region_partition(region),
            Some(partition),
            "region={region}"
        );
        assert!(is_aws_region(region), "region={region}");
    }

    for region in [
        "",
        "US-EAST-1",
        "us-East-1",
        "us-east-1.evil.example",
        "us-east-1#",
        "us-east-1a",
        "us-east-",
        "us--1",
        "useast1",
        "us-east",
        "-us-east-1",
        "xx-east-1",
        "usx-east-1",
        "us-east2-1",
        "us-east-1-1",
        "us-gov-1",
        "cn-1",
        "s3-us-west-2",
        "s3-external-1",
        "s3-website-us-east-1",
        "compute-1",
        "us-iso-east-1",
        "eusc-de-east-1",
    ] {
        assert_eq!(aws_region_partition(region), None, "region={region:?}");
        assert!(!is_aws_region(region), "region={region:?}");
        let scope = AmbientAwsEndpointScope::new(AwsService::Lambda, region);
        assert!(
            !permits(&scope, "https://lambda.us-east-1.amazonaws.com"),
            "region={region:?}"
        );
    }
    assert!(!is_aws_region(&format!("us-{}-1", "a".repeat(64))));
}

#[test]
fn derived_endpoint_suffix_follows_the_partition() {
    assert_eq!(aws_partition_dns_suffix("cn-north-1"), "amazonaws.com.cn");
    assert_eq!(aws_partition_dns_suffix("us-gov-west-1"), "amazonaws.com");
    assert_eq!(aws_partition_dns_suffix("eu-west-1"), "amazonaws.com");
    assert_eq!(AwsPartition::AwsCn.dns_suffix(), "amazonaws.com.cn");
}

#[test]
fn credential_sources_name_only_environment_fields() {
    let config_only = AwsCredentialSources::default();
    assert!(!config_only.is_ambient());
    assert_eq!(config_only.ambient_field_list(), "");
    assert!(!config_only.may_use_environment_session_token());

    let mixed = AwsCredentialSources {
        access_key_id_from_env: false,
        secret_access_key_from_env: true,
        session_token_from_env: false,
    };
    assert!(mixed.is_ambient());
    assert!(!mixed.may_use_environment_session_token());
    assert_eq!(mixed.ambient_field_list(), "`aws_secret_access_key`");

    let environment = AwsCredentialSources {
        access_key_id_from_env: true,
        secret_access_key_from_env: true,
        session_token_from_env: true,
    };
    assert!(environment.may_use_environment_session_token());
    assert_eq!(
        environment.ambient_field_list(),
        "`aws_access_key_id`, `aws_secret_access_key`, `aws_session_token`"
    );
}

#[test]
fn any_region_scope_still_pins_the_service_and_region_grammar() {
    let scope = AmbientAwsEndpointScope::any_region(AwsService::Lambda);
    assert_eq!(scope.service(), AwsService::Lambda);
    assert!(permits(
        &scope,
        "https://lambda.ap-southeast-2.amazonaws.com"
    ));
    assert!(permits(
        &scope,
        "https://lambda-fips.us-gov-west-1.amazonaws.com"
    ));
    assert!(permits(
        &scope,
        "https://lambda.cn-northwest-1.amazonaws.com.cn"
    ));
    assert!(!permits(&scope, "https://lambda.evil.amazonaws.com"));
    assert!(!permits(
        &scope,
        "https://bedrock-runtime.us-east-1.amazonaws.com"
    ));
    assert!(!is_official_aws_service_host(
        "lambda.us-east-1.amazonaws.com",
        AwsService::BedrockRuntime,
        None
    ));
}
