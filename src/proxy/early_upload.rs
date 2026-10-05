//! Private collector witness and captured timeout attribution for early uploads.

use std::collections::HashMap;
use std::time::Duration;

use crate::plugin_cache::PluginCacheRequestView;
use crate::plugins::RequestContext;
use crate::plugins::early_route_total::EarlyRouteTotalSelection;
use crate::proxy::auth_lifetime::{StreamAuthDeadline, StreamAuthTermination};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UploadExpiry {
    Read,
    Rpc,
    Route,
    Authorization(StreamAuthTermination),
    Unresolved,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct EarlyCollectorWitness {
    selection: EarlyRouteTotalSelection,
    route_at: Option<tokio::time::Instant>,
}

impl EarlyCollectorWitness {
    pub(crate) fn select(
        view: &PluginCacheRequestView,
        ctx: &RequestContext,
        headers: &HashMap<String, String>,
        identity_ready: bool,
        authorization_ready: bool,
    ) -> Self {
        let selection =
            view.early_route_total_selection(ctx, headers, identity_ready, authorization_ready);
        let route_at = match selection {
            EarlyRouteTotalSelection::Timed(ms) => ctx.receipt_anchored_route_total(Some(ms)),
            _ => None,
        };
        Self {
            selection,
            route_at,
        }
    }

    pub(crate) fn capture(
        self,
        ctx: &RequestContext,
        read_ms: u64,
        authorization: Option<StreamAuthDeadline>,
        grpc: bool,
    ) -> Result<CapturedUploadBound, UploadExpiry> {
        let unrepresentable_route =
            matches!(self.selection, EarlyRouteTotalSelection::Timed(_)) && self.route_at.is_none();
        if self.selection == EarlyRouteTotalSelection::Unresolved || unrepresentable_route {
            return Err(UploadExpiry::Unresolved);
        }
        let route = self.route_at.map(|at| {
            (
                at,
                if grpc {
                    UploadExpiry::Rpc
                } else {
                    UploadExpiry::Route
                },
            )
        });
        let bound =
            CapturedUploadBound::compose(ctx.grpc_deadline_at(), route, authorization, read_ms);
        // A configured but unrepresentable read window is not an unbounded
        // policy. An existing finite absolute bound still safely caps it.
        if read_ms > 0 && bound.0.is_none() {
            return Err(UploadExpiry::Unresolved);
        }
        Ok(bound)
    }
}

/// The instant AND its owner are captured once, before the collector is polled.
/// RPC wins a route tie; an absolute bound wins a read tie; accepted
/// authorization wins every tie. No clock read at rejection can change this.
#[derive(Debug, Clone, Copy)]
pub(crate) struct CapturedUploadBound(pub(crate) Option<(tokio::time::Instant, UploadExpiry)>);

impl CapturedUploadBound {
    pub(crate) fn compose(
        rpc: Option<tokio::time::Instant>,
        route: Option<(tokio::time::Instant, UploadExpiry)>,
        authorization: Option<StreamAuthDeadline>,
        read_ms: u64,
    ) -> Self {
        let mut bound = rpc.map(|at| (at, UploadExpiry::Rpc));
        if let Some(route) = route
            && bound.is_none_or(|(at, _)| route.0 < at)
        {
            bound = Some(route);
        }
        if read_ms > 0 {
            let read_at = tokio::time::Instant::now().checked_add(Duration::from_millis(read_ms));
            if let Some(at) = read_at
                && bound.is_none_or(|(current, _)| at < current)
            {
                bound = Some((at, UploadExpiry::Read));
            }
        }
        if let Some(auth) = authorization
            && bound.is_none_or(|(at, _)| auth.at <= at)
        {
            bound = Some((auth.at, UploadExpiry::Authorization(auth.termination)));
        }
        Self(bound)
    }

    pub(crate) async fn collect<F, T>(self, collect: F) -> Result<T, UploadExpiry>
    where
        F: std::future::Future<Output = T>,
    {
        match self.0 {
            Some((at, owner)) => crate::plugins::await_deadline_first(Some(at), collect)
                .await
                .map_err(|()| owner),
            None => Ok(collect.await),
        }
    }
}

/// DRAFT supported-profile change. Fixed, redacted and before dispatch. This
/// is neither a timeout nor a failed authentication; no backend is charged.
pub(crate) fn unresolved_policy_result() -> crate::plugins::PluginResult {
    crate::plugins::PluginResult::Reject {
        status_code: 503,
        body: r#"{"error":"Request body policy cannot be resolved"}"#.to_string(),
        headers: HashMap::from([("content-type".to_string(), "application/json".to_string())]),
    }
}
