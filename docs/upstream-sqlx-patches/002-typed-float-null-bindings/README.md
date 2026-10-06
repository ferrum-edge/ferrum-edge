# SQLx Any typed floating-point NULL bindings

## Status

Deliberate fork, unfiled upstream. Owner: Ferrum Edge maintainers. This correction
was accepted during issue #6010 review and follows the weekly review and
stable-release checkpoint in [dependency policy](../../dependency-policy.md).
Hosted qualification of the new head remains required before merge.

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

## Regression coverage

`tests/integration/admin_conditional_write_tests.rs` calls
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

Retire this correction when a compatible SQLx release preserves native
REAL/DOUBLE typed-NULL parameter types and passes the same hosted PostgreSQL
regression. Keep that behavioral regression after retirement. Retain the vendor
copy and its root/mesh `[patch.crates-io]` entries while patch 001 still needs
them. Once both patches can retire, update both lockfiles, remove the vendor
copy and patch entries, and update the integrity manifest, policy inventory,
and lifecycle inventory together. No SQLx version or dependency graph changes
are part of this correction.
