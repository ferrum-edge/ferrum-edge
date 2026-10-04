# Vendored reqwest patch: selectable rustls provider fallback

> Governance: tracked in [docs/dependency-policy.md](../../dependency-policy.md).
> Any change to `vendor/reqwest-0.13.4-ferrum-patched/` must refresh the drift
> manifest recorded in `vendor/VENDOR_INTEGRITY.sha256`.

## What this patches

Adds an internal `__rustls-ring` feature alongside reqwest's existing
`__rustls-aws-lc-rs` arm. When no process-default rustls provider has been
installed yet, reqwest selects the provider named by that mutually exclusive
Ferrum feature pair. Cargo unifies features across reqwest consumers, so an
ordinary Ring build can also inherit reqwest's upstream AWS-LC default through
a transitive consumer; in that combined reqwest graph Ring deliberately takes
precedence. Hosted policy rejects `__rustls-ring` from the FIPS graph, while
selecting neither retains the upstream `No provider set` failure for the public
`rustls-no-provider` mode.

## Why Ferrum Edge needs it

Ferrum's normal and FIPS builds must select Ring and AWS-LC-FIPS respectively
through one auditable cargo-feature pair. The binary installs that provider
before startup, but library and test clients can construct reqwest before the
binary entry point runs. Upstream reqwest 0.13.4 only has an AWS-LC fallback,
so using `rustls-no-provider` made those clients panic and using `rustls` would
silently route the ordinary profile through AWS-LC. The paired internal arm
preserves the selected backend in both contexts.

## Upstream tracking and retirement

This is a deliberate, currently unfiled fork. Retire it when reqwest ships a
public provider-neutral integration that accepts or selects the application's
rustls provider without hard-wiring AWS-LC, or when Ferrum no longer vendors
reqwest. Keep the `crypto-ring` / `fips` feature-policy checks and the ordinary
integration/service test coverage after retirement.

## Regression evidence

- `.github/scripts/check_fips_feature_policy.py` requires the paired declared
  and resolved reqwest provider arms.
- The admin/API, protocols-data-plane, and service-integration hosted shards
  construct reqwest clients before Ferrum's binary bootstrap and fail if the
  selected fallback is unavailable.
