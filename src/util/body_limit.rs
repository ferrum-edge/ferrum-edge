//! Helpers for request-body size limit errors.
//!
//! `http_body_util::Limited` returns a boxed `dyn Error` whose root cause is a
//! `LengthLimitError` when the configured cap is hit. Callers used to detect
//! this by string-matching `e.to_string()` for `"length limit exceeded"`,
//! which is fragile (no stability guarantee from `http-body-util`) and
//! impossible to discriminate from a legitimate transport error that happens
//! to contain that phrase. [`is_length_limit_error`] walks the
//! [`std::error::Error::source`] chain and looks for a concrete
//! `LengthLimitError` via downcast, which is the API the crate intends.

use http_body_util::LengthLimitError;

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

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::{BodyExt, Full, Limited};
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
