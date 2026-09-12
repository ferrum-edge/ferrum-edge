//! Injector sidecar image default and pin contract (issue #5452).
//!
//! The compiled-in default must be the Helm chart repository plus the `v*`
//! release tag derived from `CARGO_PKG_VERSION`. An explicit `latest` tag or
//! an untagged name (Docker's implicit `latest`) fails closed at startup.
//! An explicit pinned image is accepted and copied into the JSONPatch
//! verbatim.

use base64::Engine as _;
use ferrum_edge::config::EnvConfig;
use ferrum_edge::modes::injector::{InjectorConfig, admission_response};
use serde_json::{Value, json};

use crate::unit::env_lock::EnvGuard;

const INJECTOR_IMAGE_ENV_KEYS: &[&str] = &[
    "FERRUM_INJECTOR_SIDECAR_IMAGE",
    "FERRUM_INJECTOR_ALLOW_PLAINTEXT",
    "FERRUM_INJECTOR_TLS_CERT_PATH",
    "FERRUM_INJECTOR_TLS_KEY_PATH",
    "FERRUM_INJECTOR_JWT_SECRET_REF_NAME",
    "FERRUM_INJECTOR_JWT_SECRET_REF_KEY",
    "FERRUM_MESH_CAPTURE_MODE",
];

fn expected_default_sidecar_image() -> String {
    format!("ferrumedge/ferrum-edge:v{}", ferrum_edge::FERRUM_VERSION)
}

fn parse_injector_config(image: Option<&str>) -> Result<InjectorConfig, String> {
    let guard = EnvGuard::new(INJECTOR_IMAGE_ENV_KEYS);
    for key in INJECTOR_IMAGE_ENV_KEYS {
        guard.unset(key);
    }
    guard.set("FERRUM_INJECTOR_ALLOW_PLAINTEXT", "true");
    if let Some(image) = image {
        guard.set("FERRUM_INJECTOR_SIDECAR_IMAGE", image);
    }
    InjectorConfig::from_env_config(&EnvConfig::default())
}

fn injected_container_images(config: &InjectorConfig) -> Vec<String> {
    let review = json!({
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "request": {
            "uid": "sidecar-image-pin",
            "namespace": "payments",
            "kind": {"group": "", "version": "v1", "kind": "Pod"},
            "resource": {"group": "", "version": "v1", "resource": "pods"},
            "object": {
                "metadata": {
                    "labels": {"ferrum.io/mesh": "enabled"}
                },
                "spec": {
                    "serviceAccountName": "api",
                    "containers": [{"name": "app", "image": "app:test"}]
                }
            }
        }
    });
    let response = admission_response(review.to_string().as_bytes(), config)
        .expect("admission response");
    assert_eq!(
        response.pointer("/response/allowed"),
        Some(&Value::Bool(true)),
        "admission must allow: {response}"
    );
    let patch = response
        .pointer("/response/patch")
        .and_then(Value::as_str)
        .expect("encoded patch");
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(patch)
        .expect("base64 patch");
    let ops: Vec<Value> = serde_json::from_slice(&decoded).expect("json patch");
    ops.iter()
        .filter_map(|op| {
            op.get("value")
                .and_then(|value| value.get("image"))
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .collect()
}

#[test]
fn unset_sidecar_image_uses_build_pinned_chart_repository_and_v_package_version() {
    let config = parse_injector_config(None).expect("injector config");
    let expected = expected_default_sidecar_image();
    assert_eq!(config.sidecar_image, expected);
    assert!(
        !config.sidecar_image.contains("latest"),
        "compiled-in default must not use a moving latest tag: {}",
        config.sidecar_image
    );
    assert!(
        config.sidecar_image.starts_with("ferrumedge/ferrum-edge:v"),
        "default must use the Helm chart repository and a v* tag: {}",
        config.sidecar_image
    );
    let images = injected_container_images(&config);
    assert!(
        !images.is_empty(),
        "unset default must still inject a sidecar image"
    );
    for image in images {
        assert_eq!(image, expected);
    }
}

#[test]
fn explicit_latest_and_untagged_sidecar_images_are_rejected_at_startup() {
    let digest = format!("sha256:{}", "a".repeat(64));
    let latest_digest = format!("ferrumedge/ferrum-edge:latest@{digest}");
    let images = [
        "ferrum-edge:latest",
        "ferrumedge/ferrum-edge:latest",
        "docker.io/ferrumedge/ferrum-edge:latest",
        "ferrumedge/ferrum-edge:LATEST",
        latest_digest.as_str(),
        "ferrum-edge",
        "ferrumedge/ferrum-edge",
        "ferrumedge/ferrum-edge:",
        "   ",
        "",
    ];
    for image in images {
        let err = parse_injector_config(Some(image)).expect_err(image);
        assert!(
            err.contains("FERRUM_INJECTOR_SIDECAR_IMAGE"),
            "{image}: {err}"
        );
        if image.trim().is_empty() {
            assert!(err.contains("empty"), "{image}: {err}");
        } else if image.to_ascii_lowercase().contains(":latest") {
            assert!(err.contains("latest"), "{image}: {err}");
        } else {
            assert!(
                err.contains("tag") || err.contains("latest"),
                "{image}: {err}"
            );
        }
    }
}

#[test]
fn explicit_pinned_sidecar_image_is_accepted_and_injected_verbatim() {
    let pinned = "registry.example/team/ferrum-edge:v9.9.9-pin";
    let config = parse_injector_config(Some(pinned)).expect("pinned image");
    assert_eq!(config.sidecar_image, pinned);
    let images = injected_container_images(&config);
    assert!(
        !images.is_empty(),
        "pinned image must appear in the JSONPatch"
    );
    for image in images {
        assert_eq!(image, pinned);
    }
}

#[test]
fn digest_only_sidecar_image_is_accepted_as_a_pin() {
    let digest = format!("sha256:{}", "b".repeat(64));
    let image = format!("ferrumedge/ferrum-edge@{digest}");
    let config = parse_injector_config(Some(&image)).expect("digest-only pin");
    assert_eq!(config.sidecar_image, image);
}

#[test]
fn compiled_in_default_sidecar_image_is_concat_of_repository_and_v_package_version() {
    let src = include_str!("../../../src/modes/injector.rs");
    assert!(
        src.contains("concat!(\"ferrumedge/ferrum-edge:v\", env!(\"CARGO_PKG_VERSION\"))"),
        "DEFAULT_SIDECAR_IMAGE must be derived from the Helm repository and CARGO_PKG_VERSION"
    );
    assert!(
        !src.contains("const DEFAULT_SIDECAR_IMAGE: &str = \"ferrum-edge:latest\""),
        "compiled-in default must not remain ferrum-edge:latest"
    );
}
