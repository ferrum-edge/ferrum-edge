# h3-quinn: make `stop_sending` work while a read is in flight

Fixes #NNN

## Problem

`h3_quinn::RecvStream` moves its `quinn::RecvStream` into a `ReusableBoxFuture`
while a `read_chunk` is pending, leaving `RecvStream::stream` as `None`.
`stop_sending()` and `recv_id()` both `unwrap()` that `Option`, so they panic for
the entire duration of an in-flight read.

That is precisely when an HTTP/3 server wants `stop_sending`: it has finished the
response, no longer needs the request body, and should send
`STOP_SENDING(H3_NO_ERROR)`. Dropping the stream instead sends `STOP_SENDING(0)`,
which is not an HTTP/3 error code, and there is no way to reach the parked
`quinn::RecvStream` from outside.

## Change

Own the `quinn::RecvStream` inline and build the read future per poll:

```rust
pub struct RecvStream {
    stream: quinn::RecvStream,
}

fn poll_data(&mut self, cx: &mut task::Context<'_>) -> Poll<...> {
    let chunk = {
        let mut read_chunk_fut = pin!(self.stream.read_chunk(usize::MAX, true));
        ready!(read_chunk_fut.as_mut().poll(cx))
    };
    Poll::Ready(Ok(chunk.map_err(convert_read_error_to_stream_error)?.map(|c| c.bytes)))
}
```

`quinn::RecvStream::read_chunk` is documented cancel-safe: its `ReadChunk` future
is a thin wrapper that forwards `poll` to the stream's own `poll_read_chunk`, and
all state (read position, `all_data_read`, waker registration) lives on the
stream. Recreating the future per poll is therefore equivalent to reusing a boxed
one.

`stop_sending` and `recv_id` become total **with respect to in-flight-read
ownership**, with no `Option::unwrap` — under the protocol-valid invariants
they still rely on: `stop_sending` converts the `u64` code with
`VarInt::from_u64(error_code).expect("invalid error_code")` (as the README
example shows) and `recv_id` converts the typed stream id through an
invariant `expect`. Arbitrary `u64` stop codes outside the QUIC varint range
are not accepted without panic; Ferrum's caller passes typed `H3_NO_ERROR`.

## Notes

- No public API change; `RecvStream`'s fields are private.
- Removes the per-receive-stream `ReusableBoxFuture` allocation.
- `tokio-util` is left as a dependency in this change to keep the diff minimal;
  it can be dropped separately if nothing else needs it.
- `pin!` requires Rust 1.68; the vendored crate's `rust-version` is 1.75
  (raised for the return-position `impl Future` stopped-watch trait in
  patches h3 004 / h3-quinn 002, which needs Rust 1.75).
