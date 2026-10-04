# h2: update the automatic DATA-frame budget at runtime

> Governance: tracked in [docs/dependency-policy.md](../../dependency-policy.md).
> Any change to `vendor/h2-0.4.19-ferrum-patched/` must regenerate the drift
> manifest (`scripts/update_vendor_integrity.sh`).

## Status

Filed upstream on 2026-10-04 as
[hyperium/h2#965](https://github.com/hyperium/h2/pull/965), following the
maintainer diagnosis in
[hyperium/hyper#4211](https://github.com/hyperium/hyper/issues/4211#issuecomment-5961792097).
Owner: Ferrum Edge maintainers.

## Problem

h2 limits the aggregate overhead from non-final DATA frames smaller than 256
bytes. Its automatic budget is half of the target connection window, with a
25,600-byte floor. The budget prevents a peer from consuming unbounded CPU and
memory with tiny frames; exhaustion closes the connection with
`ENHANCE_YOUR_CALM`.

Before this patch, the automatic budget was converted to a fixed byte count
during handshake. Later calls to `Connection::set_target_window_size`,
including calls made by adaptive flow control, changed the advertised receive
window without changing the budget. If the target grew, a peer could fill the
legal window with small DATA frames and exhaust a budget still sized for the
old window.

The attempted sender-side workaround in Hyper was to wait for at least 1 KiB
before sending a body chunk. That is not valid: a peer can advertise a smaller
stream window. The released Ferrum Edge 0.9.10 binary was reproduced sending
zero body bytes to a backend with a legal 512-byte stream window. Hyper must
make progress on every positive window; h2 must scale its receiver-side guard
with the window it advertises.

## Patch

[`h2-runtime-data-frame-budget.patch`](h2-runtime-data-frame-budget.patch)
applies after Ferrum's h2 patch 001 and changes the budget accounting as
follows:

- `DataFrameBudget::Auto` remains distinct from an explicitly configured
  budget until stream state is constructed.
- Every target connection-window update recomputes an automatic budget from
  the new target. Explicit budgets remain fixed.
- Accounting stores bytes charged (`spent`) rather than bytes remaining. This
  lets a limit grow or shrink without forgiving outstanding charges. After a
  shrink below current spend, subsequent small frames remain rejected until
  larger frames or released buffered frames repay the debt.
- The public builder and runtime-target documentation describes the dynamic
  behavior.

The empty non-final DATA-frame lifetime limit is unchanged.

## Regression coverage

The counts tests prove that:

- an automatic budget follows a 1 MiB target and accepts traffic that would
  exceed the default 25,600-byte budget;
- an explicitly configured budget does not change;
- growing and shrinking a budget preserves existing charges.

Run them with:

```bash
cargo test --manifest-path vendor/h2-0.4.19-ferrum-patched/Cargo.toml --lib budget
```

The Hyper and Ferrum gateway regressions under patch 002 separately prove that
the sender continues to make progress through small legal peer windows.

## Retirement

Retire this patch when an h2 release containing hyperium/h2#965, or an
equivalent runtime automatic-budget update, is adopted. Remove this lifecycle
entry and patch document, preserve behavior-level regressions that apply to the
released dependency, and regenerate `vendor/VENDOR_INTEGRITY.sha256`. The
coalescing and stream-lifetime patches must also retire before removing the
vendored crate.
