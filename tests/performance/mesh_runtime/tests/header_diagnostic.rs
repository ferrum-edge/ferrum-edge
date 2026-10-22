//! Opt-in header-ladder contracts. Run this target remotely with the tools.

use std::net::SocketAddr;
use std::process::Stdio;
use std::time::Duration;

use clap::Parser;
use http::{HeaderMap, HeaderValue};
use mesh_runtime_perf::header_diagnostic::{
    HeaderDiagnostic, HeaderDiagnosticArgs, RECEIPT_HEADER,
};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};

#[derive(Parser)]
struct DiagnosticCli {
    #[command(flatten)]
    diagnostic_headers: HeaderDiagnosticArgs,
}

fn headers(profile: &HeaderDiagnostic) -> HeaderMap {
    let mut result = HeaderMap::new();
    profile.append_request_headers(&mut result);
    result
}

#[test]
fn flags_are_paired_bounded_and_default_off() {
    assert!(
        HeaderDiagnostic::from_options(None, None)
            .unwrap()
            .is_none()
    );
    assert!(HeaderDiagnostic::from_options(Some(0), None).is_err());
    assert!(HeaderDiagnostic::from_options(None, Some(0)).is_err());
    assert!(HeaderDiagnostic::new(33, 0).is_err());
    assert!(HeaderDiagnostic::new(0, 257).is_err());
    assert!(
        DiagnosticCli::try_parse_from(["tool"])
            .unwrap()
            .diagnostic_headers
            .profile()
            .unwrap()
            .is_none()
    );
    for args in [
        vec!["tool", "--diagnostic-header-count", "0"],
        vec!["tool", "--diagnostic-header-value-bytes", "0"],
        vec![
            "tool",
            "--diagnostic-header-count",
            "33",
            "--diagnostic-header-value-bytes",
            "0",
        ],
        vec![
            "tool",
            "--diagnostic-header-count",
            "0",
            "--diagnostic-header-value-bytes",
            "257",
        ],
        vec![
            "tool",
            "--diagnostic-header-count",
            "-1",
            "--diagnostic-header-value-bytes",
            "0",
        ],
    ] {
        assert!(DiagnosticCli::try_parse_from(args).is_err());
    }
    let explicit = DiagnosticCli::try_parse_from([
        "tool",
        "--diagnostic-header-count",
        "0",
        "--diagnostic-header-value-bytes",
        "0",
    ])
    .unwrap();
    assert!(explicit.diagnostic_headers.profile().unwrap().is_some());
}

#[test]
fn names_values_wire_bytes_and_receipt_are_exact() {
    let profile = HeaderDiagnostic::new(32, 256).unwrap();
    let map = headers(&profile);
    assert_eq!(map.len(), 32);
    for index in 0..32 {
        let name = format!("x-mesh-bench-{index:03}");
        assert_eq!(map.get(&name).unwrap().as_bytes(), vec![b'h'; 256]);
    }
    assert!(map.contains_key("x-mesh-bench-000"));
    assert!(map.contains_key("x-mesh-bench-031"));
    assert!(!map.contains_key("x-mesh-bench-032"));
    assert!(profile.validate_request_headers(&map));
    assert_eq!(profile.receipt().as_bytes(), b"20-0100");
    let metadata = profile.metadata(7);
    assert_eq!(metadata.count, 32);
    assert_eq!(metadata.value_bytes, 256);
    assert_eq!(metadata.added_request_wire_bytes, 8832);
    assert_eq!(metadata.expected_receipt, "20-0100");
    assert_eq!(metadata.validated_receipt.as_deref(), Some("20-0100"));
    assert_eq!(metadata.validated_exchanges, 7);
    assert_eq!(profile.metadata(0).validated_receipt, None);
}

#[test]
fn explicit_zero_arm_rejects_every_synthetic_request_field() {
    let profile = HeaderDiagnostic::new(0, 0).unwrap();
    let mut map = headers(&profile);
    assert!(map.is_empty());
    assert!(profile.validate_request_headers(&map));
    assert_eq!(profile.receipt().as_bytes(), b"00-0000");
    assert_eq!(profile.metadata(0).added_request_wire_bytes, 0);
    map.insert("host", HeaderValue::from_static("test.local"));
    assert!(profile.validate_request_headers(&map));
    map.insert("x-mesh-bench-000", HeaderValue::from_static(""));
    assert!(!profile.validate_request_headers(&map));
}

#[test]
fn missing_duplicate_extra_and_wrong_value_fields_are_rejected() {
    let profile = HeaderDiagnostic::new(2, 3).unwrap();
    let exact = headers(&profile);
    let mut missing = exact.clone();
    missing.remove("x-mesh-bench-000");
    assert!(!profile.validate_request_headers(&missing));
    let mut duplicate = exact.clone();
    duplicate.append("x-mesh-bench-000", HeaderValue::from_static("hhh"));
    assert!(!profile.validate_request_headers(&duplicate));
    for name in [
        "x-mesh-bench-002",
        "x-mesh-bench-2",
        "x-mesh-bench-0000",
        "x-mesh-bench-abc",
        "x-mesh-bench-receipt",
    ] {
        let mut extra = exact.clone();
        extra.insert(name, HeaderValue::from_static("hhh"));
        assert!(!profile.validate_request_headers(&extra), "{name}");
    }
    for value in ["hh", "hhhh", "hhx", "hhh, hhh", ""] {
        let mut wrong = exact.clone();
        wrong.insert("x-mesh-bench-001", HeaderValue::from_str(value).unwrap());
        assert!(!profile.validate_request_headers(&wrong), "{value}");
    }
}

#[test]
fn empty_values_are_present_and_duplicates_still_fail() {
    let profile = HeaderDiagnostic::new(2, 0).unwrap();
    let mut map = headers(&profile);
    assert_eq!(map.len(), 2);
    assert!(profile.validate_request_headers(&map));
    assert_eq!(profile.metadata(1).added_request_wire_bytes, 40);
    map.append("x-mesh-bench-001", HeaderValue::from_static(""));
    assert!(!profile.validate_request_headers(&map));
}

#[test]
fn response_receipt_requires_exactly_one_exact_fixed_width_value() {
    let profile = HeaderDiagnostic::new(2, 3).unwrap();
    let mut map = HeaderMap::new();
    assert!(!profile.validate_response_headers(&map));
    for value in ["2-3", "02-0004", "00-0003", "02-0003 ", "02-0003, 02-0003"] {
        map.insert(RECEIPT_HEADER, HeaderValue::from_str(value).unwrap());
        assert!(!profile.validate_response_headers(&map));
    }
    map.insert(RECEIPT_HEADER, profile.receipt().clone());
    assert!(profile.validate_response_headers(&map));
    map.append(RECEIPT_HEADER, profile.receipt().clone());
    assert!(!profile.validate_response_headers(&map));
}

async fn backend(profile: Option<(u16, u16)>) -> (Child, SocketAddr) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_mesh_backend"));
    command
        .kill_on_drop(true)
        .args(["--listen", "127.0.0.1:0"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    if let Some((count, value_bytes)) = profile {
        command
            .arg("--diagnostic-header-count")
            .arg(count.to_string())
            .arg("--diagnostic-header-value-bytes")
            .arg(value_bytes.to_string());
    }
    let mut child = command.spawn().expect("spawn owned backend");
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let line = tokio::time::timeout(Duration::from_secs(5), lines.next_line())
        .await
        .expect("backend readiness deadline")
        .expect("backend readiness line")
        .expect("backend exited before readiness");
    let address = line
        .strip_prefix("listening on ")
        .expect("backend bound-address receipt")
        .parse()
        .expect("backend socket address");
    (child, address)
}

async fn loadgen(address: SocketAddr, profile: Option<(u16, u16)>) -> serde_json::Value {
    let mut command = Command::new(env!("CARGO_BIN_EXE_mesh_loadgen"));
    command.kill_on_drop(true).args([
        "--target",
        &format!("http://{address}/echo"),
        "--duration",
        "1",
        "--concurrency",
        "1",
        "--rate",
        "4",
        "--payload-size",
        "16",
        "--exchange-timeout-secs",
        "2",
        "--json",
    ]);
    if let Some((count, value_bytes)) = profile {
        command
            .arg("--diagnostic-header-count")
            .arg(count.to_string())
            .arg("--diagnostic-header-value-bytes")
            .arg(value_bytes.to_string());
    }
    let output = tokio::time::timeout(Duration::from_secs(10), command.output())
        .await
        .expect("bounded loadgen child")
        .expect("loadgen output");
    assert!(output.status.success(), "{output:?}");
    serde_json::from_slice(&output.stdout).expect("loadgen report")
}

#[tokio::test]
async fn real_tools_preserve_defaults_and_require_backend_and_response_validation() {
    for profile in [None, Some((0, 0)), Some((2, 0)), Some((32, 256))] {
        let (mut child, address) = backend(profile).await;
        let report = loadgen(address, profile).await;
        child.kill().await.expect("stop owned backend");
        assert_eq!(report["total_errors"], 0, "{report}");
        assert!(report["total_requests"].as_u64().unwrap() > 0);
        assert_eq!(
            report["admitted_requests"].as_u64().unwrap(),
            report["total_requests"].as_u64().unwrap()
                + report["drained_requests"].as_u64().unwrap()
                + report["admitted_errors"].as_u64().unwrap()
        );
        if let Some((count, value_bytes)) = profile {
            let metadata = &report["diagnostic_headers"];
            assert_eq!(metadata["count"], count);
            assert_eq!(metadata["value_bytes"], value_bytes);
            assert_eq!(
                metadata["validated_receipt"],
                format!("{count:02x}-{value_bytes:04x}")
            );
            assert_eq!(
                metadata["validated_exchanges"].as_u64().unwrap(),
                report["total_requests"].as_u64().unwrap()
                    + report["drained_requests"].as_u64().unwrap()
                    + report["warmup_requests"].as_u64().unwrap()
            );
        } else {
            assert!(report.get("diagnostic_headers").is_none());
        }
    }
    // A default backend echoes the right body but cannot attest the profile.
    // A differently configured backend must reject the request headers itself.
    for backend_profile in [None, Some((2, 3))] {
        let (mut child, address) = backend(backend_profile).await;
        let report = loadgen(address, Some((2, 4))).await;
        child.kill().await.expect("stop owned backend");
        assert_eq!(report["total_requests"], 0);
        assert!(report["total_errors"].as_u64().unwrap() > 0);
        assert!(report["diagnostic_headers"]["validated_receipt"].is_null());
        assert_eq!(report["diagnostic_headers"]["validated_exchanges"], 0);
    }
}
