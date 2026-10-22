//! FERRUM PATCH 007: fixed counters for an isolated diagnostic build.
//!
//! Only POST requests that reach ClientTask::poll_pipe are counted. No request
//! identifiers, field values, body bytes, clocks, or per-request allocations.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Cumulative process-wide HTTP/2 client POST upload branch counts.
///
/// Reads are individually atomic, not a transactional snapshot. Capture at
/// quiescent boundaries and reject any overflow. These counts cover every
/// client connection using this Hyper copy; they are not per route or peer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Http2UploadDiagnosticSnapshot {
    /// POST requests whose body already reported END_STREAM.
    pub post_eos: u64,
    /// POST uploads that completed successfully in the eager body-pipe poll.
    pub post_ready_ok: u64,
    /// POST uploads that failed in the eager body-pipe poll.
    pub post_ready_err: u64,
    /// POST uploads whose eager body-pipe poll suspended.
    pub post_pending: u64,
    /// At least one counter wrapped; discard this process's diagnostic data.
    pub overflow: bool,
}

pub(crate) enum H2UploadBranch {
    Eos,
    ReadyOk,
    ReadyErr,
    Pending,
}

struct Counters {
    eos: AtomicU64,
    ready_ok: AtomicU64,
    ready_err: AtomicU64,
    pending: AtomicU64,
    overflow: AtomicBool,
}

impl Counters {
    const fn new() -> Self {
        Self {
            eos: AtomicU64::new(0),
            ready_ok: AtomicU64::new(0),
            ready_err: AtomicU64::new(0),
            pending: AtomicU64::new(0),
            overflow: AtomicBool::new(false),
        }
    }

    fn record(&self, is_post: bool, branch: H2UploadBranch) {
        if !is_post {
            return;
        }
        let counter = match branch {
            H2UploadBranch::Eos => &self.eos,
            H2UploadBranch::ReadyOk => &self.ready_ok,
            H2UploadBranch::ReadyErr => &self.ready_err,
            H2UploadBranch::Pending => &self.pending,
        };
        if counter.fetch_add(1, Ordering::Relaxed) == u64::MAX {
            self.overflow.store(true, Ordering::Relaxed);
        }
    }

    fn snapshot(&self) -> Http2UploadDiagnosticSnapshot {
        Http2UploadDiagnosticSnapshot {
            post_eos: self.eos.load(Ordering::Relaxed),
            post_ready_ok: self.ready_ok.load(Ordering::Relaxed),
            post_ready_err: self.ready_err.load(Ordering::Relaxed),
            post_pending: self.pending.load(Ordering::Relaxed),
            overflow: self.overflow.load(Ordering::Relaxed),
        }
    }
}

static COUNTERS: Counters = Counters::new();

/// Read fixed branch counts from an explicitly instrumented Hyper build.
///
/// This API is diagnostic only and absent unless the non-default
/// `ferrum-h2-upload-diagnostic` feature is enabled. It does not reset counters.
/// It neither measures allocations nor reports CPU time or task scheduling.
pub fn http2_upload_diagnostic_snapshot() -> Http2UploadDiagnosticSnapshot {
    COUNTERS.snapshot()
}

pub(crate) fn record_h2_upload_branch(is_post: bool, branch: H2UploadBranch) {
    COUNTERS.record(is_post, branch);
}

#[cfg(test)]
#[path = "h2_upload_diagnostic_tests.rs"]
mod ferrum_h2_upload_diagnostic_tests;
