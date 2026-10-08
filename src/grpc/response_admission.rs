use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use http::{Request, Response};
use http_body::Body;
use pin_project_lite::pin_project;
use tower::{Layer, Service};

use super::admission::CpGrpcStreamPermit;

/// Cloneable response-extension handle for one non-cloneable admission permit.
/// The permit is released once, when the final shared handle is dropped.
#[derive(Clone, Debug)]
pub struct FullConfigPermitHandle {
    _permit: Arc<CpGrpcStreamPermit>,
}

impl FullConfigPermitHandle {
    pub fn new(permit: CpGrpcStreamPermit) -> Self {
        Self {
            _permit: Arc::new(permit),
        }
    }
}

/// Holds a ConfigSync unary admission permit until its encoded HTTP body drops.
#[derive(Clone, Copy, Debug, Default)]
pub struct FullConfigPermitLayer;

impl<S> Layer<S> for FullConfigPermitLayer {
    type Service = FullConfigPermitService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        FullConfigPermitService { inner }
    }
}

#[derive(Clone, Debug)]
pub struct FullConfigPermitService<S> {
    inner: S,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for FullConfigPermitService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Send + Unpin + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    ReqBody: Send + 'static,
    ResBody: Body + Send + 'static,
    ResBody::Data: Send + 'static,
    ResBody::Error: Send + 'static,
{
    type Response = Response<FullConfigPermitBody<ResBody>>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<ReqBody>) -> Self::Future {
        let future = self.inner.call(request);
        Box::pin(async move {
            let mut response = future.await?;
            let permit = response.extensions_mut().remove::<FullConfigPermitHandle>();
            Ok(response.map(|inner| FullConfigPermitBody {
                inner,
                _permit: permit,
            }))
        })
    }
}

pin_project! {
    /// Body wrapper whose owned permit is released when the HTTP body is dropped.
    pub struct FullConfigPermitBody<B> {
        #[pin]
        inner: B,
        _permit: Option<FullConfigPermitHandle>,
    }
}

impl<B> Body for FullConfigPermitBody<B>
where
    B: Body,
{
    type Data = B::Data;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        self.project().inner.poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}
