The original version of this PR waited for at least 1 KiB of HTTP/2 send
capacity before handing a body chunk to h2. Review correctly identified that
this can hang when a peer advertises a smaller stream window.

I reproduced that failure through Ferrum Edge 0.9.10 with a standards-compliant
h2 backend using a 512-byte stream window: request headers reached the backend,
but the backend received zero body bytes before timeout. A fixed positive
threshold cannot distinguish a transient connection-window sliver from all of
the capacity a peer has made available, so Hyper must allow body progress
whenever capacity is nonzero.

This revision removes the 1 KiB gate and adds two deterministic regression
tests:

- a 2 KiB request body makes progress through a peer's 512-byte stream window;
- a request uses the final available byte of connection capacity without
  waiting for a `WINDOW_UPDATE`.

The receiver-side protection against excessive small DATA frames belongs in
h2. [hyperium/h2#965](https://github.com/hyperium/h2/pull/965) updates h2's
automatic DATA-frame budget whenever adaptive flow control changes the target
connection window, preserving explicit budgets and outstanding charges.

Validation:

- `cargo test --features full --test client` (70 passed)
- `cargo fmt --all -- --check`

Related: #4211
