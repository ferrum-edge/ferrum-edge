# hyper-util: forward the HTTP/2 response write-stall bound from the auto builder

> Governance: tracked in [docs/dependency-policy.md](../../dependency-policy.md).
> Any change to `vendor/hyper-util-0.1.21-ferrum-patched/` must regenerate the
> drift manifest (`scripts/update_vendor_integrity.sh`).

## Status

Deliberate fork with no upstream filing, governed by the
[deliberate fork policy](../../dependency-policy.md#deliberate-fork-policy-and-sla).
Owner: Ferrum Edge maintainers. It exists only to reach
[hyper patch 008](../../upstream-hyper-patches/008-h2-response-write-timeout/README.md)
and retires with it.

## The problem

Ferrum's HTTP frontends (`handle_connection` and `handle_tls_connection` in
`src/proxy/mod.rs`) serve HTTP/1.1 and HTTP/2 through
`hyper_util::server::conn::auto::Builder`. That builder owns its
`hyper::server::conn::http2::Builder` privately and exposes only the HTTP/2
settings it forwards one by one. It cannot reach a setting it does not know
about, such as hyper patch 008's `response_write_timeout`.

## Patch

[`hyper-util-forward-h2-response-write-timeout.patch`](hyper-util-forward-h2-response-write-timeout.patch)
applies after hyper-util patch 001, against hyper-util 0.1.21.

- `Http2Builder::response_write_timeout(impl Into<Option<Duration>>)`
  (`src/server/conn/auto/mod.rs`) forwards to the hyper builder, like the
  existing `timer` and `keep_alive_interval` forwards.
- The method is behind a new crate feature, `ferrum-h2-response-write-timeout`,
  which enables `server-auto`. It is not part of `full`. The
  `test-vendor-patches` job tests this crate standalone against stock hyper
  from crates.io, which has no such method. Ferrum's root `Cargo.toml` enables
  the feature, so the gateway build uses the forward. If the vendored copy
  ever stops providing the feature, that build fails instead of silently
  dropping the bound.

## Regression coverage

The forward has no behavior of its own. Removing it fails the gateway build.
The behavior it carries is covered by hyper patch 008's vendored tests and the
gateway's `tests/unit/gateway_core/frontend_h2_response_write_stall_tests.rs`.
That file drives both frontends through this builder and asserts the stalled
stream is reset.

## Retirement

Retire with hyper patch 008. Remove the feature from the root `Cargo.toml`,
this entry from `docs/dependency-policy.md` and the lifecycle inventory, and
regenerate `vendor/VENDOR_INTEGRITY.sha256`. An upstream hyper-util release
that forwards an equivalent setting would let this patch go first.
