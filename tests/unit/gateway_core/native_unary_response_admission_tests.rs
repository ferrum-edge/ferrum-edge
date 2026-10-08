use std::convert::Infallible;

use bytes::Bytes;
use ferrum_edge::grpc::admission::{CpGrpcAdmissionController, CpGrpcAdmissionLimits};
use ferrum_edge::grpc::response_admission::{FullConfigPermitHandle, FullConfigPermitLayer};
use http::{Request, Response};
use http_body_util::Full;
use tower::{Layer, ServiceExt, service_fn};

#[tokio::test]
async fn unary_admission_permit_lives_until_encoded_body_is_dropped() {
    let admission = CpGrpcAdmissionController::new(CpGrpcAdmissionLimits {
        max_streams_per_principal: 1,
        ..CpGrpcAdmissionLimits::default()
    });
    let permit = admission
        .reserve_native_stream("ferrum", "dp", "dp")
        .expect("admission succeeds");
    assert_eq!(admission.active_streams(), 1);

    let mut permit = Some(permit);
    let service = FullConfigPermitLayer.layer(service_fn(move |_| {
        let permit = permit.take().expect("one test request");
        async move {
            let mut response = Response::new(Full::new(Bytes::from_static(b"snapshot")));
            response
                .extensions_mut()
                .insert(FullConfigPermitHandle::new(permit));
            Ok::<_, Infallible>(response)
        }
    }));
    let response = service
        .oneshot(Request::new(()))
        .await
        .expect("service responds");

    assert_eq!(admission.active_streams(), 1);
    assert!(
        admission
            .reserve_native_stream("ferrum", "dp", "dp-2")
            .is_err()
    );
    drop(response);
    assert_eq!(admission.active_streams(), 0);
}

#[test]
fn unary_full_config_rate_is_scoped_to_authenticated_namespace_and_subject() {
    let admission = CpGrpcAdmissionController::new(CpGrpcAdmissionLimits::default());
    assert!(
        admission
            .reserve_full_config_rate("alpha", "shared")
            .is_ok()
    );
    assert!(
        admission
            .reserve_full_config_rate("alpha", "shared")
            .is_err()
    );
    assert!(admission.reserve_full_config_rate("beta", "shared").is_ok());
}

#[test]
fn unary_full_config_rate_capacity_is_partitioned_by_namespace() {
    let admission = CpGrpcAdmissionController::new(CpGrpcAdmissionLimits::default());
    for index in 0..4096 {
        assert!(
            admission
                .reserve_full_config_rate("alpha", &format!("subject-{index}"))
                .is_ok()
        );
    }
    assert!(
        admission
            .reserve_full_config_rate("alpha", "overflow")
            .is_err()
    );
    assert!(
        admission
            .reserve_full_config_rate("beta", "first-subject")
            .is_ok()
    );
}
