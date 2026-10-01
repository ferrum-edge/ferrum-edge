# codec: coalesce DATA frames into one write

**Draft for hyperium/h2 — not yet filed.**

Fixes: (issue to be filed from `issue.md`).

## What

`Encoder::buffer` copies a DATA payload into the write buffer, with its frame
header, while the buffer stays within `COALESCE_LIMIT` (64 KiB). A copied
frame is complete once buffered, so it goes to `last_data_frame` exactly as a
sub-threshold frame already does and `Prioritize::buffer_pending` reclaims it
before staging the next. A payload that would push the buffer past the limit
is chained as before.

`Encoder::has_capacity` treats room under the limit as capacity, so
`buffer_pending` stages frames from every ready stream until the limit and
the codec flushes them in one write. When coalescing needs room the buffer
grows once, to the limit; after a complete write, a buffer that grew past its
initial 16 KiB is replaced with a fresh 16 KiB one.

## Why

Today every DATA frame at or above the chain threshold is written by its own
`poll_write_vectored` call: a syscall per frame, a peer wakeup per frame, and
over TLS a 9-byte record per maximum-size frame (16 KiB + 9-byte header does
not fit one record). See the issue for measurements.

## Trade-off

Each coalesced payload is copied once. Over TLS the encryption layer copies
it again anyway; over cleartext the copy replaces a zero-copy `writev`
segment. Payloads larger than the limit keep the zero-copy path.

## Tests

`codec::framed_write::ferrum_coalesce_data_frame_writes_tests` (to be renamed
for upstream): frames within the limit share one write with byte-exact
framing, vectored and not; a frame past the limit is chained behind the
copied ones; a frame larger than the limit is chained whole; the buffer
shrinks back after a coalesced write; a copied frame is handed back fully
consumed.
