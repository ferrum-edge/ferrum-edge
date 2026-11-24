//! The gRPC method a request belongs to, for plugins that select per-method
//! policy (`body_validator`, `ai_response_guard`, `ai_transcript_audit`).
//!
//! One resolution order governs every such selector so a method-scoped policy
//! cannot be steered by a value another plugin may write:
//!
//! 1. the backend-effective path the proxy bound at the backend-path boundary
//!    (`RequestContext::authorized_backend_path`, private and not
//!    plugin-writable), once it exists;
//! 2. before that boundary, the non-empty `grpc_full_method` metadata
//!    `grpc_method_router` publishes provisionally from the client path;
//! 3. otherwise the request path.
//!
//! Whatever the source, only the trailing `/Service/Method` is the method key.

use std::borrow::Cow;

use crate::plugins::RequestContext;

/// The canonical gRPC method key of a request path: its trailing
/// `/Service/Method` (query and fragment excluded). A gRPC method is always the
/// last two path segments, so a listen-path prefix, a stripped prefix, or a
/// backend base path cannot make the same method select a different entry.
pub fn canonical_grpc_method(path: &str) -> &str {
    let end = path.find(['?', '#']).unwrap_or(path.len());
    let path = &path[..end];
    let Some(last) = path.rfind('/') else {
        return path;
    };
    match path[..last].rfind('/') {
        Some(start) => &path[start..],
        None => path,
    }
}

/// Resolve the canonical gRPC method key for per-method policy selection, in
/// the order documented on this module.
///
/// `grpc_full_method` is plugin-writable metadata, so it never outranks the
/// bound backend path; it only stands in before that path exists (the
/// buffering vote and `before_proxy`). `grpc_method_router` publishes it as
/// `package.Service/Method` without a leading slash, so it is slash-prefixed
/// here. An empty value is not a method and falls through to the request path.
pub fn resolve_grpc_method_path(ctx: &RequestContext) -> Cow<'_, str> {
    if let Some(path) = ctx.authorized_backend_path() {
        return Cow::Borrowed(canonical_grpc_method(path));
    }
    match ctx.metadata.get("grpc_full_method") {
        Some(method) if method.starts_with('/') => {
            Cow::Borrowed(canonical_grpc_method(method.as_str()))
        }
        Some(method) if !method.is_empty() => {
            let mut path = String::with_capacity(method.len() + 1);
            path.push('/');
            path.push_str(method);
            if canonical_grpc_method(&path).len() == path.len() {
                Cow::Owned(path)
            } else {
                Cow::Owned(canonical_grpc_method(&path).to_string())
            }
        }
        _ => Cow::Borrowed(canonical_grpc_method(ctx.path.as_str())),
    }
}
