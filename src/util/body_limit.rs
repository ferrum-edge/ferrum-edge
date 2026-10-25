//! Helpers for bounding request-body collection in size **and** time.
//!
//! `http_body_util::Limited` returns a boxed `dyn Error` whose root cause is a
//! `LengthLimitError` when the configured cap is hit. Callers used to detect
//! this by string-matching `e.to_string()` for `"length limit exceeded"`,
//! which is fragile (no stability guarantee from `http-body-util`) and
//! impossible to discriminate from a legitimate transport error that happens
//! to contain that phrase. [`is_length_limit_error`] walks the
//! [`std::error::Error::source`] chain and looks for a concrete
//! `LengthLimitError` via downcast, which is the API the crate intends.
//!
//! A size cap alone does not bound *time*. A client that trickles one byte per
//! interval never trips `Limited` yet pins the collecting task, its buffer, and
//! the underlying HTTP/1 connection or HTTP/2 stream for as long as it likes.
//! [`collect_body_with_limits`] pairs the size cap with an absolute deadline so
//! both failure modes are bounded at one place, and reports which one fired via
//! [`BodyCollectError`].

use http_body_util::{BodyExt, LengthLimitError, Limited};
use std::time::Duration;

/// The one JSON body every gateway-authored request-body-size `413` carries.
///
/// A route ceiling is enforced in several places: the `request_size_limiting`
/// plugin's hooks (declared `Content-Length`, buffered body, final body) and the
/// proxy core's collectors and streaming adapters for chunked or unknown-length
/// uploads, on H1/H2, H3, and the H3 bridge. Clients must see the same refusal
/// for the same policy whichever of those sites fires, so they all share this
/// body instead of each spelling its own.
pub const REQUEST_BODY_TOO_LARGE_BODY: &str = r#"{"error":"Request body exceeds maximum size"}"#;

/// Outcome of parsing a `Content-Length` field value that may be a
/// comma-folded list of repeated values.
///
/// Ferrum and Hyper both accept a *standards-valid* representation whose
/// `Content-Length` appears more than once with identical values, or once as a
/// single coalesced field line (`"2048, 2048"`) — RFC 9110 §8.6 permits the
/// list form so long as every member agrees. The plugin-facing header views are
/// `HashMap<String, String>`, so those repeats arrive already folded with
/// `", "`. A bare `str::parse::<u64>()` on that folded value fails, which used
/// to read as "no declared length" and silently skipped the size fast path
/// (`GHSA-xrfj-852f-645j`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentLength {
    /// Every member parsed and agreed on this single value.
    Exact(u64),
    /// The field is unusable as a bound: a member was empty, non-`1*DIGIT`,
    /// above `u64`, or the members disagreed. Callers must fail closed rather
    /// than treating it as an absent length.
    Ambiguous,
}

/// Parse a possibly comma-folded `Content-Length` field value into a single
/// authoritative length.
///
/// A present field that cannot be reduced to one agreed value is
/// [`ContentLength::Ambiguous`], never `None`, so an empty value or a fold like
/// `"2048, 4096"` can never be mistaken for "unknown length" and bypass a size
/// bound. Absence is represented by [`declared_content_length`] returning
/// `None` before this parser is called.
///
/// Digits are validated explicitly as `1*DIGIT`: `str::parse::<u64>()` accepts a
/// leading `+`, which is not a valid `Content-Length` and must not be honored as
/// a length.
pub fn parse_content_length(value: &str) -> ContentLength {
    let value = value.trim_matches(|c: char| c == ' ' || c == '\t');
    if value.is_empty() {
        return ContentLength::Ambiguous;
    }
    let mut canonical: Option<u64> = None;
    for token in value.split(',') {
        let token = token.trim_matches(|c: char| c == ' ' || c == '\t');
        // An empty member (`"2048,"`, `"2048,,2048"`) is malformed framing.
        if token.is_empty() {
            return ContentLength::Ambiguous;
        }
        // `1*DIGIT` only — no sign, decimal point, hex prefix, or whitespace
        // inside the token.
        if !token.bytes().all(|b| b.is_ascii_digit()) {
            return ContentLength::Ambiguous;
        }
        let Ok(parsed) = token.parse::<u64>() else {
            // All-digits but wider than u64.
            return ContentLength::Ambiguous;
        };
        match canonical {
            None => canonical = Some(parsed),
            Some(previous) if previous != parsed => return ContentLength::Ambiguous,
            _ => {}
        }
    }
    match canonical {
        Some(value) => ContentLength::Exact(value),
        None => ContentLength::Ambiguous,
    }
}

/// Canonical declared body length from a plugin-facing header map, or `None`
/// when the field is absent.
///
/// The key must already be the lowercase `content-length` these maps use.
pub fn declared_content_length(
    headers: &std::collections::HashMap<String, String>,
) -> Option<ContentLength> {
    Some(parse_content_length(headers.get("content-length")?))
}

/// Returns `true` when `error` (or any error in its source chain) is a
/// [`LengthLimitError`] produced by [`http_body_util::Limited`].
///
/// Used by every body-collection site that needs to distinguish "client sent
/// too many bytes" (→ HTTP `413 Payload Too Large` / gRPC `RESOURCE_EXHAUSTED`)
/// from generic transport failures (→ HTTP `400 Bad Request` / gRPC
/// `INTERNAL`).
pub fn is_length_limit_error(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut current = Some(error);
    while let Some(err) = current {
        if err.downcast_ref::<LengthLimitError>().is_some() {
            return true;
        }
        current = err.source();
    }
    false
}

/// Why a bounded body collection failed.
///
/// Callers map these onto protocol-appropriate responses: `413` for
/// [`BodyCollectError::TooLarge`], `408` for [`BodyCollectError::Timeout`], and
/// `400` for [`BodyCollectError::Transport`].
#[derive(Debug)]
pub enum BodyCollectError {
    /// The client sent more bytes than the configured cap allows.
    TooLarge,
    /// The body did not finish arriving inside the configured deadline.
    Timeout,
    /// The transport failed (reset, malformed framing, client disconnect).
    /// Carries the underlying error for logging; it never contains request
    /// headers, so it cannot leak credentials.
    Transport(Box<dyn std::error::Error + Send + Sync>),
}

/// Collect `body` into a `Vec<u8>`, bounded by `max_bytes` and — when
/// `timeout` is `Some` — by an absolute wall-clock deadline.
///
/// The deadline is absolute rather than idle by design: every caller already
/// caps the total size, so the worst-case legitimate transfer time is knowable
/// up front, while an idle-only bound still lets a client stretch a body across
/// an unbounded total duration by dripping a byte just inside every window.
///
/// On timeout the collect future is dropped, which drops the body and lets the
/// protocol layer release the HTTP/1 connection or reset the HTTP/2 stream.
pub async fn collect_body_with_limits<B>(
    body: B,
    max_bytes: usize,
    timeout: Option<Duration>,
) -> Result<Vec<u8>, BodyCollectError>
where
    B: http_body::Body,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let collect = async move {
        match Limited::new(body, max_bytes).collect().await {
            Ok(collected) => Ok(collected.to_bytes().to_vec()),
            Err(e) => {
                if is_length_limit_error(e.as_ref()) {
                    Err(BodyCollectError::TooLarge)
                } else {
                    Err(BodyCollectError::Transport(e))
                }
            }
        }
    };

    match timeout {
        Some(deadline) => match tokio::time::timeout(deadline, collect).await {
            Ok(result) => result,
            Err(_elapsed) => Err(BodyCollectError::Timeout),
        },
        None => collect.await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::Full;
    use std::error::Error;
    use std::fmt;

    #[derive(Debug)]
    struct Plain;

    impl fmt::Display for Plain {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("plain unrelated error")
        }
    }

    impl Error for Plain {}

    #[derive(Debug)]
    struct Misleading;

    impl fmt::Display for Misleading {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("length limit exceeded")
        }
    }

    impl Error for Misleading {}

    #[derive(Debug)]
    struct Wrapper(Box<dyn Error + Send + Sync + 'static>);

    impl fmt::Display for Wrapper {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("outer body collection error")
        }
    }

    impl Error for Wrapper {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            Some(self.0.as_ref())
        }
    }

    /// The real path the production code hits: a `Limited` body returns
    /// a boxed error whose inner cause is `LengthLimitError`. The helper must
    /// recognise it without relying on a brittle `to_string()` check. Also
    /// exercises the source-chain walk because `Limited` wraps the
    /// `LengthLimitError` inside a `Box<dyn Error>` that is itself returned
    /// as the outer error.
    #[tokio::test]
    async fn detects_real_limited_body_overflow() {
        let body = Full::new(bytes::Bytes::from_static(b"abcdefghij"));
        let err = Limited::new(body, 4)
            .collect()
            .await
            .expect_err("body should exceed limit");
        assert!(is_length_limit_error(err.as_ref()));
    }

    #[tokio::test]
    async fn detects_wrapped_limited_body_overflow() {
        let body = Full::new(bytes::Bytes::from_static(b"abcdefghij"));
        let err = Limited::new(body, 4)
            .collect()
            .await
            .expect_err("body should exceed limit");
        let wrapped = Wrapper(err);

        assert!(is_length_limit_error(&wrapped));
    }

    /// Unrelated transport errors must NOT be misclassified — that would
    /// silently turn a `400` into a `413` and confuse operators.
    #[test]
    fn rejects_unrelated_errors() {
        let err: Box<dyn Error + Send + Sync + 'static> = Box::new(Plain);
        assert!(!is_length_limit_error(err.as_ref()));
    }

    #[test]
    fn rejects_errors_that_only_match_length_limit_text() {
        let err: Box<dyn Error + Send + Sync + 'static> = Box::new(Misleading);
        assert!(!is_length_limit_error(err.as_ref()));
    }
}
