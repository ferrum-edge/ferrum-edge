# SQLx Any typed floating-point NULL bindings

## Status

**Retired** on the move to SQLx 0.9.1. Upstream corrected the same two arms in
[launchbadge/sqlx#4359](https://github.com/launchbadge/sqlx/pull/4359)
(merge `80f44db8073e9a6a61ef6488eb15341554716d35`, 2026-08-19), and
`sqlx-core` 0.9.1 (published 2026-11-18) is the first release that carries it:
its `src/any/arguments.rs` binds `Null(Real)` through `Option<f32>::None` and
`Null(Double)` through `Option<f64>::None`. No 0.8.x release carries the fix,
so retiring this correction meant migrating Ferrum to SQLx 0.9.1. The vendor
copy (`vendor/sqlx-core-0.9.1-ferrum-patched/`) remains for
[patch 001](../001-verify-ca-name-context/README.md) only and leaves
`src/any/arguments.rs` byte-identical to the crate. The lifecycle entry
`sqlx-core-002-typed-float-null-bindings`, its `merged_release_hold`, and its
inventory row were removed. This record is kept as the audit trail; the
sections below describe the patch as it was carried on the 0.8.6 base.

## Patch

The base is the crates.io `sqlx-core` 0.8.6 source (package checksum
`ee6798b1838b6a0f69c007c133b8df5866302197e404e8b6ee8ed3e3a5e68dc6`).
The existing [TLS patch](../001-verify-ca-name-context/README.md) remains in the
same vendor copy.

This patch changes only two arms of `AnyArguments::convert_to` in
`src/any/arguments.rs`: `Null(Real)` uses `Option<f32>::None`, and
`Null(Double)` uses `Option<f64>::None`. The upstream 0.8.6 arms are reversed.
Non-NULL argument conversion and other scalar bindings are unchanged.

SQLx Any converts these arguments into native driver arguments before execution.
For PostgreSQL, the [Any adapter](https://github.com/launchbadge/sqlx/blob/v0.8.6/sqlx-postgres/src/any.rs)
calls `convert_to`, and [native argument construction](https://github.com/launchbadge/sqlx/blob/v0.8.6/sqlx-postgres/src/arguments.rs)
records the supplied parameter types. A cast on the parameter or an assignment
into a typed column could hide the reversal, so the regression observes the
parameter's native type directly.

This is a pre-existing conversion defect. The review did not establish stored
value loss, and the correction does not explain the earlier PostgreSQL initial
import 500, which occurred before the preservation operations. That error's
underlying cause remains unknown.

## Release hold history

From 2026-11-08 the lifecycle inventory carried a dated `merged_release_hold`
for this patch (latest stable 0.9.0, expiring 2026-12-08), because the merged
fix was not yet in a release. SQLx 0.9.1 ended the hold by shipping it.

## Regression coverage

The behavioral regression is kept after retirement and now guards the
upstream behavior. `tests/integration/admin_conditional_write_tests.rs` calls
`assert_postgres_any_float_null_parameter_types` from
`postgres_conditional_restore_checks_state_and_lease_in_transaction`. The
existing hosted **Integration Tests (conditional-live-stores)** gate runs this
caller with a real PostgreSQL database and ignored tests enabled.

The query binds `Option<f32>::None` and `Option<f64>::None` through `AnyPool`.
It checks `pg_typeof($1)::text` is exactly `real`, `pg_typeof($2)::text` is exactly
`double precision`, and both parameters satisfy `IS NULL`. Only the `pg_typeof`
results are cast to text; neither parameter is cast. With the old arms the
reported types reverse, so an explicit type assertion fails.

The probe runs after all raw-fixture ALTERs and one reconnect of the shared
store to its original durable database, before the strict initial POST 201.
These fixtures target a stable extended schema; they do not qualify SQLx
online DDL. The preceding policy-graph probe reports only a fixed operation,
an error category, and a validated SQLSTATE if the read fails.

## Retirement

Done. Retired by the SQLx 0.9.1 migration: the vendored 0.9.1 copy carries no
change to `src/any/arguments.rs`, and the hosted PostgreSQL regression above
stays in the **Integration Tests (conditional-live-stores)** gate.
