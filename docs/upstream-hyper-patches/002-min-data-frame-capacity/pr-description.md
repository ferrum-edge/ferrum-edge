Closes #4211.

`PipeToSendStream` handed a polled chunk to h2 as soon as the stream held any capacity. That was usually just the 1-byte claim it reserves. h2 cuts DATA frames from whatever capacity a stream holds, so on a connection whose window was nearly used up, a 10 KB chunk went out as a 1-byte frame followed by more small frames. Since h2 0.4.16, servers charge non-final DATA frames under 256 bytes against a per-connection budget and send `GOAWAY(ENHANCE_YOUR_CALM, "too_many_data_frames")` when it runs out, which fails every stream on the connection.

### Change

- Reserve `min(len, MIN_DATA_FRAME_CAPACITY)` (1 KiB) for a polled chunk instead of 1 byte, and wait until that much is assigned before calling `send_data`.
- The claim stays small, so the reasoning from #4003 still holds: nothing is reserved speculatively, and no stream pins more than 1 KiB while it waits. h2 still raises the request to the buffered length inside `send_data`.
- 1 KiB is far below any stream window a real peer advertises, so this cannot hold a chunk back indefinitely.
- Chunks shorter than 1 KiB still wait only for their own length, so the one-byte case in `h2_idle_stream_does_not_pin_connection_window` is unchanged.

### Test

`h2_chunk_waits_for_useful_capacity_instead_of_sliver_frames`:

1. Stream A leaves exactly one byte of connection window.
2. Stream B polls a 10 KB chunk against that byte.
3. The server then releases stream A's capacity and records the size of stream B's first DATA frame.

Without the fix the first frame is 1 byte and the test fails deterministically. With it the first frame is at least 1024 bytes. `cargo test --features full` passes.

Found while running a reverse proxy (Ferrum Edge) against a hyper backend with `adaptive_window(true)`, where the pooled connection was being GOAWAY'd every few seconds.
