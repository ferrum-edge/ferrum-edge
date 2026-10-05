//! Hidden fixture access to the actual H1/H2 backend-admission finalizer. Kept
//! under src because release builds copy that tree without tests. External tests
//! still run the production retirement, hook, commit and log path.

use super::*;

pub(crate) struct Upload(RejectedUpload);

impl Upload {
    pub(crate) fn buffered(
        body: Vec<u8>,
        budget: response_buffer_budget::RequestBufferPermit,
    ) -> Self {
        Self(RejectedUpload::Client(ClientRequestBody::Buffered(Box::new(
            BufferedClientRequestBody {
                method: hyper::Method::POST,
                headers: hyper::HeaderMap::new(),
                body,
                trailers: None,
                budget: Some(budget),
            },
        ))))
    }

    pub(crate) fn retained(body: Bytes) -> Self {
        Self(RejectedUpload::Retained(body))
    }

    pub(crate) fn native_grpc(collected: Bytes, transformed: Bytes) -> Self {
        Self(RejectedUpload::NativeGrpc {
            collected,
            transformed,
        })
    }

    pub(crate) async fn finalize(
        self,
        plugins: &[Arc<dyn Plugin>],
        ctx: &mut RequestContext,
        state: &ProxyState,
        grpc: bool,
    ) -> Response<ProxyBody> {
        handle_backend_admission_rejection(
            backend_dispatch::BackendAdmissionRejection {
                plugin_name: "test_admission".into(),
                status_code: 503,
                body: Bytes::from_static(br#"{"error":"test admission refused"}"#),
                headers: HashMap::new(),
            },
            self.0,
            plugins,
            ctx,
            state,
            Instant::now(),
            0,
            None,
            grpc,
            None,
        )
        .await
    }
}
