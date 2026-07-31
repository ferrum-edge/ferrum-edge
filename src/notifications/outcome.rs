//! Classify notification delivery outcomes as success, transient failure, or
//! permanent failure.
//!
//! Transient outcomes are eligible for the bounded, jittered retry policy in
//! [`super::dispatch`]. Permanent outcomes fail immediately so a bad webhook
//! URL or auth rejection cannot burn the retry budget.
//!
//! HTTP status semantics mirror the shared batch-log helper:
//! - 2xx → success
//! - 408 / 429 / 5xx → transient
//! - other 4xx → permanent
//! - transport / connect / timeout errors → transient

use std::fmt;

use reqwest::StatusCode;

/// Fixed channel-type label set. Never derived from operator-chosen channel
/// *names* — only from the compiled-in transport discriminant — so Prometheus
/// cardinality stays bounded at five series per metric family.
pub const CHANNEL_TYPES: &[&str] = &["slack", "teams", "discord", "webhook", "email"];

/// Why a delivery ended without a defined transport outcome.
///
/// The variants are compiled-in discriminants, never operator- or
/// attacker-influenced strings, so the `reason` label set is fixed at six
/// values and Prometheus cardinality stays bounded.
///
/// The taxonomy separates two operationally different things that the first
/// implementation of #2448 collapsed into one counter:
///
/// - **Pre-body rejections** ([`AbandonReason::Backpressure`],
///   [`AbandonReason::GenerationClosed`], [`AbandonReason::RegistryRejected`]):
///   the registry-owned delivery body never started. No `attempted` is recorded.
/// - **Post-body abandonment** ([`AbandonReason::GenerationRetired`],
///   [`AbandonReason::ShutdownDeadline`], [`AbandonReason::TaskDropped`]): the
///   delivery body started executing but produced no committed success/failure.
///   Channel transport may or may not have been polled — an admit-then-cancel
///   race can abandon after `attempted` advances and before the first channel
///   call.
///
/// Only [`AbandonReason::ShutdownDeadline`] increments
/// `ferrum_notification_delivery_abandoned_at_deadline_total`, so that signal
/// means exactly what the issue asked for: sends still outstanding when the
/// global shutdown drain deadline expired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbandonReason {
    /// The bounded dispatch semaphore was exhausted. No task, no attempt.
    Backpressure,
    /// The producer generation stopped admitting (reload / plugin `Drop`)
    /// before the dispatch task was created. No attempt.
    GenerationClosed,
    /// The process observability delivery registry refused admission
    /// (shutdown in progress, or the aggregate task budget is exhausted).
    /// The task body never ran, so no attempt.
    RegistryRejected,
    /// The generation was retired (reload / plugin `Drop`) after the delivery
    /// body started — including before the first channel transport call, during
    /// an in-flight send, or during bounded retry backoff.
    GenerationRetired,
    /// The task was hard-aborted because the global observability shutdown
    /// drain deadline expired.
    ShutdownDeadline,
    /// The task future was dropped without settling for any other reason
    /// (most plausibly a panic inside the transport future).
    TaskDropped,
}

/// Fixed `reason` label values for `ferrum_notification_delivery_rejected_total`.
pub const REJECT_REASONS: &[AbandonReason] = &[
    AbandonReason::GenerationClosed,
    AbandonReason::RegistryRejected,
];

/// Fixed `reason` label values for `ferrum_notification_delivery_abandoned_total`.
pub const ABANDON_REASONS: &[AbandonReason] = &[
    AbandonReason::GenerationRetired,
    AbandonReason::ShutdownDeadline,
    AbandonReason::TaskDropped,
];

impl AbandonReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Backpressure => "backpressure",
            Self::GenerationClosed => "generation_closed",
            Self::RegistryRejected => "registry_rejected",
            Self::GenerationRetired => "generation_retired",
            Self::ShutdownDeadline => "shutdown_deadline",
            Self::TaskDropped => "task_dropped",
        }
    }

    /// Index into [`REJECT_REASONS`], or `None` when this reason is not a
    /// pre-body rejection. `Backpressure` is deliberately `None`: it keeps
    /// its own dedicated `backpressure_dropped_total` family so no drop is
    /// counted twice.
    pub const fn reject_index(self) -> Option<usize> {
        match self {
            Self::GenerationClosed => Some(0),
            Self::RegistryRejected => Some(1),
            _ => None,
        }
    }

    /// Index into [`ABANDON_REASONS`], or `None` when this reason cannot
    /// describe a delivery body that actually started.
    pub const fn abandon_index(self) -> Option<usize> {
        match self {
            Self::GenerationRetired => Some(0),
            Self::ShutdownDeadline => Some(1),
            Self::TaskDropped => Some(2),
            _ => None,
        }
    }

    /// Whether this reason is the true hard shutdown-deadline abort.
    pub const fn is_shutdown_deadline(self) -> bool {
        matches!(self, Self::ShutdownDeadline)
    }
}

impl fmt::Display for AbandonReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Whether a failed delivery may be retried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureClass {
    /// Likely temporary (timeout, 429, 5xx, connect blip). Retry with backoff.
    Transient,
    /// Caller / config / auth fault. Do not retry.
    Permanent,
}

impl FailureClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Transient => "transient",
            Self::Permanent => "permanent",
        }
    }
}

/// Result of one channel send attempt (before retry policy).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryAttempt {
    Success,
    Failed {
        class: FailureClass,
        message: String,
    },
}

impl DeliveryAttempt {
    pub fn failed(class: FailureClass, message: impl Into<String>) -> Self {
        Self::Failed {
            class,
            message: message.into(),
        }
    }

    pub fn is_success(&self) -> bool {
        matches!(self, Self::Success)
    }

    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            Self::Failed {
                class: FailureClass::Transient,
                ..
            }
        )
    }
}

impl fmt::Display for DeliveryAttempt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Success => write!(f, "success"),
            Self::Failed { class, message } => {
                write!(f, "{class} failure: {message}", class = class.as_str())
            }
        }
    }
}

/// Classify an HTTP response status for notification delivery.
pub fn classify_http_status(status: StatusCode) -> FailureClass {
    if status.is_success() {
        // Callers should not invoke this for success; treat as permanent so a
        // misuse cannot enter the retry loop.
        return FailureClass::Permanent;
    }
    if status == StatusCode::REQUEST_TIMEOUT || status == StatusCode::TOO_MANY_REQUESTS {
        return FailureClass::Transient;
    }
    if status.is_server_error() {
        return FailureClass::Transient;
    }
    if status.is_client_error() {
        return FailureClass::Permanent;
    }
    // 1xx / 3xx and other unexpected statuses: treat as transient so a flaky
    // intermediary cannot permanently suppress alerts.
    FailureClass::Transient
}

/// Classify a reqwest transport error (no HTTP status obtained).
pub fn classify_transport_error(error: &reqwest::Error) -> FailureClass {
    if error.is_timeout() || error.is_connect() || error.is_request() || error.is_body() {
        return FailureClass::Transient;
    }
    // Status-bearing reqwest errors are unusual on our path (we read status
    // ourselves); fall through to transient so we do not permanently drop.
    FailureClass::Transient
}

/// Classify an SMTP channel failure.
pub fn classify_smtp_failure(failure: &super::channels::email::SmtpFailure) -> FailureClass {
    use super::channels::email::SmtpFailure;
    match failure {
        SmtpFailure::Resolve
        | SmtpFailure::Connect
        | SmtpFailure::Timeout(_)
        | SmtpFailure::Io(_)
        | SmtpFailure::ClosedEarly(_)
        | SmtpFailure::TlsHandshake => FailureClass::Transient,
        SmtpFailure::UnexpectedCode { code, .. } if (400..500).contains(code) => {
            FailureClass::Transient
        }
        SmtpFailure::EgressDenied(_)
        | SmtpFailure::TlsSetup
        | SmtpFailure::StartTlsUnsupported
        | SmtpFailure::StartTlsResidualData
        | SmtpFailure::MalformedReply(_)
        | SmtpFailure::ReplyTooLarge(_)
        | SmtpFailure::UnexpectedCode { .. }
        | SmtpFailure::CredentialReflected(_)
        | SmtpFailure::NoSupportedAuthMechanism => FailureClass::Permanent,
    }
}

/// Build a [`DeliveryAttempt::Failed`] from a non-success HTTP status.
pub fn http_status_failure(
    channel: &str,
    status: StatusCode,
    redacted_url: &str,
) -> DeliveryAttempt {
    let class = classify_http_status(status);
    DeliveryAttempt::failed(
        class,
        format!("{channel} dispatch returned non-success status {status} from {redacted_url}"),
    )
}
