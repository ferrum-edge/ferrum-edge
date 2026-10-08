//! Endpoint scope for process-environment AWS credentials (issue #6111).
//!
//! `serverless_function` and `ai_federation` both decide, at admission and
//! again before signing each request, whether an ambient credential may reach
//! an endpoint through `AmbientAwsEndpointScope::permits_url`. These tables pin
//! that single decision for both services.

use ferrum_edge::plugins::utils::ambient_cloud_credentials::{
    AmbientAwsEndpointScope, AwsService, is_aws_region, is_official_aws_service_host,
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
    assert!(permits(&scope, "https://lambda.cn-north-1.amazonaws.com.cn"));
    assert!(permits(
        &scope,
        "https://vpce-0abc.lambda.cn-north-1.vpce.amazonaws.com.cn"
    ));
    assert!(!permits(
        &scope,
        "https://lambda.cn-north-1.amazonaws.com.cn.evil.example"
    ));
}

#[test]
fn an_ill_formed_pinned_region_matches_nothing() {
    for region in [
        "",
        "US-EAST-1",
        "us-east-1.evil.example",
        "us-east-1#",
        "useast1",
        "-us-east-1",
        "us-east-",
    ] {
        assert!(!is_aws_region(region), "region={region:?}");
        let scope = AmbientAwsEndpointScope::new(AwsService::Lambda, region);
        assert!(
            !permits(&scope, "https://lambda.us-east-1.amazonaws.com"),
            "region={region:?}"
        );
    }
    for region in [
        "us-east-1",
        "us-gov-west-1",
        "cn-northwest-1",
        "eu-isoe-west-1",
    ] {
        assert!(is_aws_region(region), "region={region:?}");
    }
}

#[test]
fn any_region_scope_still_pins_the_service_and_region_shape() {
    let scope = AmbientAwsEndpointScope::any_region(AwsService::Lambda);
    assert_eq!(scope.service(), AwsService::Lambda);
    assert!(permits(&scope, "https://lambda.ap-southeast-2.amazonaws.com"));
    assert!(permits(&scope, "https://lambda-fips.us-gov-west-1.amazonaws.com"));
    assert!(!permits(&scope, "https://lambda.evil.amazonaws.com"));
    assert!(!permits(&scope, "https://bedrock-runtime.us-east-1.amazonaws.com"));
    assert!(!is_official_aws_service_host(
        "lambda.us-east-1.amazonaws.com",
        AwsService::BedrockRuntime,
        None
    ));
}
