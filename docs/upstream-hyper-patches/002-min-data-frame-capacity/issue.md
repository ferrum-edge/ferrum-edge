**Version**
hyper 1.9.0 through `master` (c954d80), with h2 0.4.19.

**Platform**
Any. Seen on Linux and macOS.

**Description**

When a stream holds only a tiny amount of send capacity, the HTTP/2 client and server body pipe (`PipeToSendStream` in `src/proto/h2/mod.rs`) hands a body chunk to h2 anyway, and h2 splits it into DATA frames sized to that capacity. The body then goes out as a 1-byte DATA frame, followed by more small frames as capacity trickles in (silly-window syndrome).

On `master`, the pipe reserves a 1-byte claim once a chunk is in hand, then calls `send_data` as soon as `capacity() > 0`. hyper 1.9.0 reserved the byte before polling the body; the result is the same. On a connection whose window is nearly used up, that one byte is often all the stream has been assigned, so the first frame carries a single byte of a 10 KB chunk.

This used to cost only framing overhead. Since h2 0.4.16, it breaks connections. h2 servers (tonic, axum, hyper) now charge every non-final DATA frame under 256 bytes against a per-connection budget (`DEFAULT_DATA_FRAME_OVERHEAD_THRESHOLD`, a minimum of 25600). When that budget runs out they send `GOAWAY(ENHANCE_YOUR_CALM, "too_many_data_frames")`, and every in-flight stream on the connection fails.

We hit this in a reverse proxy that keeps pooled HTTP/2 connections to a hyper backend with `adaptive_window(true)`. Adaptive windows start at 65535, so a busy pooled connection often uses up its connection window. A frame trace showed about 2,900 frames of `sz=10240, available=1` in 4 seconds, and the backend GOAWAY'd the pooled connection every few seconds.

**Reproduction**

The regression test in the linked PR (`h2_chunk_waits_for_useful_capacity_instead_of_sliver_frames`) reproduces it deterministically:

1. Stream A sends 65534 bytes, which the server does not release, leaving one byte of connection window.
2. Stream B then sends a 10 KB body.
3. On `master`, stream B's first DATA frame is 1 byte.

**Proposed fix**

Keep the small claim that #4003 depends on, but make it big enough to cut a useful frame. Reserve `min(len, 1024)` and wait until that much is assigned before calling `send_data`. 1 KiB is well below any stream window a real peer advertises, so this cannot hold a chunk back indefinitely, and it rules out sub-256-byte frames.
