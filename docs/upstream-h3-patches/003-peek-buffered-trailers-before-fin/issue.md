# Expose already-buffered trailers before terminal FIN

## Summary

`RequestStream::poll_recv_trailers` buffers trailer HEADERS internally and then
returns `Pending` until it sees the terminal QUIC stream FIN. That is useful for
normal validation, but it gives applications no way to recover trailers that
were already received when their own trailer wait timeout fires before FIN.

## Why this matters

An HTTP/3 backend can send:

1. response HEADERS
2. DATA
3. trailer HEADERS
4. delayed FIN

If an application has fully received the body and applies a bounded timeout to
the optional trailer/FIN phase, h3 may have the trailer HEADERS buffered in
`RequestStream::trailers` while `poll_recv_trailers` still returns `Pending`.
The application must either wait beyond its timeout or finish the response
without trailers.

## Proposed API

Add a non-consuming method such as:

```rust
pub fn peek_recv_trailers(&self) -> Result<Option<HeaderMap>, StreamError>
```

The method should:

- return `Ok(None)` when no trailer HEADERS have been buffered,
- decode and return a clone of the buffered trailer HEADERS when present,
- leave `poll_recv_trailers` state untouched so callers that keep polling still
  get normal post-trailer frame validation once FIN or an invalid frame arrives.

## Notes

This is not a replacement for `poll_recv_trailers`; it is an escape hatch for
applications that intentionally collapse a delayed-FIN trailer wait after their
own deadline.
