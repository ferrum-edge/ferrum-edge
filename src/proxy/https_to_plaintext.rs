//! Rate-limited operator diagnostics for HTTPS-to-plaintext backends.
//!
//! Omitting `backend_scheme` on HTTP-family proxies stores `https`. A
//! plaintext origin then fails the TLS handshake with an opaque client-facing
//! 502. This module keeps that body unchanged and emits a bounded WARN that
//! names the proxy, the backend target, and the `backend_scheme: http` hint
//! (issue #5460).
//!
//! Native HTTP/3/QUIC and stream-family `tcps`/`dtls` use different wire
//! failures and are not classified here. Mesh HBONE/mTLS transports are
//! skipped because they are not the omitted-`https` footgun.

use std::sync::OnceLock;

use dashmap::DashMap;
use tracing::warn;

use crate::config::types::{BackendScheme, Proxy};
use crate::retry::{ERROR_REASON_HTTPS_TO_PLAINTEXT, error_looks_like_https_to_plaintext};
use crate::util::atomic_log_rate_limiter::AtomicLogRateLimiter;

static PER_PROXY_WARN: OnceLock<DashMap<String, AtomicLogRateLimiter>> = OnceLock::new();
static GLOBAL_WARN: AtomicLogRateLimiter = AtomicLogRateLimiter::new();

fn per_proxy_warn() -> &'static DashMap<String, AtomicLogRateLimiter> {
    PER_PROXY_WARN
        .get_or_init(|| DashMap::with_shard_amount(crate::util::sharding::pool_shard_amount(0)))
}

/// Emit at most one WARN per proxy (and one process-wide) per limiter
/// window when a backend TLS handshake looks like plaintext HTTP behind
/// `https`. No-op for non-HTTPS schemes and for unrelated TLS failures.
pub(crate) fn maybe_warn_https_to_plaintext_backend(
    proxy: &Proxy,
    backend_target: &str,
    error: &(dyn std::error::Error + 'static),
) {
    if proxy.effective_scheme() != BackendScheme::Https {
        return;
    }
    if !error_looks_like_https_to_plaintext(error) {
        return;
    }

    let now_ms = crate::socket_opts::monotonic_now_ms();
    let emitted = {
        let instance = per_proxy_warn()
            .entry(proxy.id.clone())
            .or_insert_with(AtomicLogRateLimiter::new);
        AtomicLogRateLimiter::dual_gate_emit(&*instance, &GLOBAL_WARN, now_ms)
    };
    let Some((suppressed, globally_suppressed)) = emitted else {
        return;
    };

    warn!(
        proxy_id = %proxy.id,
        backend_target = %backend_target,
        error_reason = ERROR_REASON_HTTPS_TO_PLAINTEXT,
        suppressed,
        globally_suppressed,
        "backend_scheme is https (the default when omitted); set backend_scheme: http for plaintext backends"
    );
}
