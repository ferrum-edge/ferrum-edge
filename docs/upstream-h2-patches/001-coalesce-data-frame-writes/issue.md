# Each DATA frame is written with its own write call

**Draft for hyperium/h2 — not yet filed.**

## Summary

`FramedWrite` can hold only one chained DATA payload (`Encoder::next`), and
`has_capacity()` is false while it is occupied. Any DATA frame at or above the
chain threshold (256 bytes with vectored I/O, 1 KiB without) therefore forces
a flush before the next frame can be staged, so a connection with data ready
on many streams still writes one DATA frame per `poll_write_vectored` call.

## Why it matters

- One write syscall per DATA frame, regardless of how many frames
  `Prioritize` could have staged in one pass.
- Over TLS (tokio-rustls, and any TLS layer that seals each write), a
  maximum-size 16 KiB DATA payload plus its 9-byte header is 16,393 bytes:
  one full record and one 9-byte record per frame, so the peer opens twice as
  many records as necessary.
- The peer is woken once per frame.

In a proxy relaying HTTP/2 between two TLS connections, this showed up as
the upstream server context-switching two to two and a half times as often
per request as it did behind an event-loop proxy (Envoy) that writes all
pending frames per loop pass. Copying DATA payloads into the write buffer up
to 64 KiB made the proxy 5–16% faster on HTTP/2 streams from 10 KiB to 5 MiB,
with no change in framing.

## Proposal

Copy a DATA payload into the write buffer while the buffer stays under a
bound (64 KiB in our patch), treating the copied frame as complete exactly
like a sub-threshold frame is today; chain only payloads that would exceed
the bound. Shrink the buffer back to its initial capacity once written, so
idle connections do not keep the larger allocation. A patch is attached in
the companion PR description.
