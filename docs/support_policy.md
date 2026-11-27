# Support, Versioning, and Deprecation Policy

What a Ferrum Edge version number promises, how long a release is supported, how
deprecations are announced, how security fixes reach released versions, and how
compatible each interface is across versions.

**Status: adopted.** Every commitment in
[From 1.0.0 onward](#from-100-onward) applies to Ferrum Edge 1.0.0 and every
later release. Releases before 1.0.0 (`0.x`) are build-out releases and carry
none of these commitments; see [Before 1.0.0](#before-100-build-out-0x-releases).

> **Current release status.** Main CI validates changes and does not publish
> production artifacts. The version-tag release workflow publishes after
> exact-commit validation. Tag existence does not establish successful artifact
> publication; verify the version's workflow and
> [Releases page](https://github.com/ferrum-edge/ferrum-edge/releases).
> The `latest` container tag follows `main` (the newest built commit that
> passed CI and was signed; intermediate commits may be skipped); it is a
> development channel, not a release. The historical `latest` GitHub prerelease
> is not refreshed.

## Commitments at a glance

From 1.0.0 onward:

| Topic | Commitment | Section |
|---|---|---|
| Versioning | [SemVer 2.0.0](https://semver.org/) over the declared public surface | [Semantic versioning](#semantic-versioning) |
| Current minor | Supported: every fix ships as a patch release of it | [Supported versions](#supported-versions-and-support-windows) |
| Previous minor | Supported for **6 months** after the next minor is published | [Supported versions](#supported-versions-and-support-windows) |
| Older minors, and `0.x` once 1.0.0 is published | Unsupported | [Supported versions](#supported-versions-and-support-windows) |
| Deprecation period | At least **one full minor release and 90 days**, whichever is longer; removal only in a major release | [Deprecation](#deprecation-notice-period) |
| Security backports | Critical and High: always backported to the supported previous minor; Medium: at maintainer discretion; Low: not backported | [Security fixes](#security-fix-backport-policy) |
| CP / DP versions | Control plane and every data plane run the **identical build**; no version skew is supported | [CP/DP version skew](#control-plane--data-plane-version-skew) |
| Custom-plugin Rust API | **Unstable**: not covered by SemVer; changes only in minor or major releases (not patch, except for a security fix), each with an upgrade-guide entry | [Custom plugins](#custom-plugin-rust-api) |
| gRPC / proto | Internal between Ferrum components; not a public API | [gRPC and protobuf](#grpc-and-protobuf-surfaces) |
| ClickHouse charge schema | Native row contract changes only in minor (additive) or major (incompatible) releases, with the DDL to apply | [ClickHouse](#clickhouse-chargeback-schema) |
| Backup and config documents | A document written by a 1.x release loads on every later 1.x release | [Backup and config format](#backup-export-and-file-config-format) |
| Database schema | Forward-only migrations from 1.0.0 | [Database schema](#database-schema) |
| Feature maturity | GA, Beta, Experimental, Dev-only, Out-of-scope, each with its own promise | [Feature maturity](#feature-maturity-levels) |

## Before 1.0.0: build-out (`0.x` releases)

Releases before 1.0.0 are built during active build-out. The repository's own
engineering policy ([CLAUDE.md](../CLAUDE.md) "Build-Out Policy" and the
path-scoped rules under `.claude/rules/`) states this directly:

- **Breaking changes are expected between `0.x` builds.** Configuration shapes,
  environment variable names, database values, admin API responses, and plugin
  schemas may change between builds.
- **No compatibility shims.** Old fields, environment variables, config shapes,
  and database values are removed rather than aliased. Custom plugin migrations
  under `custom_plugins/` are the exception.
- **No incremental schema migrations.** Schema changes are folded into the
  current baseline. A core schema change therefore requires a **fresh database**
  populated from a namespace-complete logical export, keeping the old database
  intact as the rollback target.

No `0.x` release has a support window or backport commitment: a fix ships in the
next published release. The upgrade procedure for `0.x` releases, including the
upgrade from the last `0.x` release to 1.0.0, is
[upgrade_guide.md](upgrade_guide.md); a database created by a `0.x` release is
rebuilt from a logical export rather than upgraded in place. Breaking changes
that have already landed are listed per release in the upgrade guide (for
example, [Breaking changes in 0.9.0](upgrade_guide.md#breaking-changes-in-090)).

During build-out, the surfaces that change least are the ones with parity gates
in CI: the admin API against [openapi.yaml](../openapi.yaml), the environment
variable inventory against [configuration.md](configuration.md) and
`ferrum.conf`, and the Prometheus metric contract against
[prometheus_metrics.md](prometheus_metrics.md). A gate makes a change
*visible*, not *forbidden*. Pin an exact build and read the upgrade guide before
every `0.x` upgrade.

### Artifacts

| Artifact | What it is | Use in production? |
|---|---|---|
| Published `vX.Y.Z` release and container image | version-tag workflow output after validation | Pin the published version or digest; its support window is in [Supported versions](#supported-versions-and-support-windows) |
| `latest` / `main-<sha>` container tags | development build of the newest built `main` commit that passed CI; `latest` may skip intermediate commits and `main-<sha>` exists only for built commits | No — a moving development channel, not a release or update channel |
| Historical `latest` GitHub prerelease | retained old binaries; not refreshed | No |
| Source at a commit | source identity, not proof of a published artifact | Pin the commit and validate your own build |

The Helm charts default to `Chart.appVersion`, which may name a version still in
release preparation. Confirm that the image exists before installation or set
an explicit published tag; see the
[ferrum-gateway chart](../charts/ferrum-gateway/README.md#security-defaults-you-should-know).

## From 1.0.0 onward

### Semantic versioning

Releases follow [SemVer 2.0.0](https://semver.org/) over the following declared
public surface:

- The `FERRUM_*` environment variable names, accepted values, and defaults
  documented in [configuration.md](configuration.md), and the matching
  `ferrum.conf` keys.
- The file-mode configuration schema and the backup/restore document format
  ([below](#backup-export-and-file-config-format)).
- The admin REST API as published in [openapi.yaml](../openapi.yaml), whose
  `info.version` equals the release version.
- The built-in plugin set and plugin configuration schemas in
  [plugins.md](plugins.md).
- The transaction log schema in [log_schema.md](log_schema.md).
- The Prometheus metric contract in [prometheus_metrics.md](prometheus_metrics.md).
- The CLI surface in [cli.md](cli.md).
- The `ferrum-gateway` and `ferrum-mesh` Helm chart values. The charts are
  versioned with Ferrum Edge through `appVersion`; they are not published to a
  Helm repository, and the chart `version` field is not a compatibility signal.
- The Edge-owned vocabularies published in
  [ferrum-contracts](https://github.com/ferrum-edge/ferrum-contracts) (gateway
  errors, gateway headers, `provisioned-by`, the plugin catalog, and the
  diagnostic reference), released as `contracts-edge-<edge version>` tags.

Explicitly **not** part of the SemVer surface: internal Rust APIs, including the
custom-plugin API ([below](#custom-plugin-rust-api)); the gRPC protocols between
Ferrum components ([below](#grpc-and-protobuf-surfaces)); log line wording
outside the declared schema; human-readable error and status messages; database
table layout ([below](#database-schema)); performance characteristics; and
anything whose maturity is not GA ([below](#feature-maturity-levels)), for
example the node-waypoint mesh topology.

| Change | Version bump |
|---|---|
| Removing or renaming a documented `FERRUM_*` variable, config field, or API field | major |
| Changing a documented default to a different behaviour | major |
| Removing an endpoint, metric, or built-in plugin | major |
| Tightening validation so a previously accepted configuration is refused | major |
| Adding a variable, field, endpoint, metric, or plugin | minor |
| Adding an optional field with a backward-compatible default | minor |
| Deprecating a documented surface ([below](#deprecation-notice-period)) | minor |
| Bug fix with no documented-surface change | patch |
| Security fix with no documented-surface change | patch |

A security fix that **must** break a documented surface to close the issue may
ship in a minor or patch release. When that happens it is called out in the
release notes, the upgrade guide, and the advisory, and the reason is stated.

### Supported versions and support windows

| Line | Window | What it receives |
|---|---|---|
| Current minor (newest `1.Y`) | supported | Bug, regression, and security fixes, as patch releases |
| Previous minor | supported for **6 months** after the next minor is published | Critical and High security fixes, and fixes for severe regressions introduced in that minor, as patch releases |
| Older minors | unsupported | Nothing; upgrade to a supported minor |
| `0.x` releases | unsupported once 1.0.0 is published | Nothing; upgrade to 1.x |

- Within a supported minor, only the newest patch release is supported: a fix
  ships as a new patch release, never as a change to an existing one.
- Feature work lands in the current minor only.
- The table applies across a major release: after 2.0.0 is published, the last
  1.x minor is the previous minor for 6 months.
- There is no long-term-support line.
- Until 1.0.0 is published, the newest `0.9.x` release is the only maintained
  release, and fixes ship in the next published release (no backports).

### Deprecation notice period

A documented surface is removed only after it has been announced as deprecated:

1. It is marked deprecated in its own documentation and in the release notes of
   the release that deprecates it. Deprecation happens in a minor or major
   release, never in a patch.
2. Where the runtime can detect its use, a startup or first-use warning names the
   replacement.
3. It keeps working for at least **one full minor release and 90 days**,
   whichever is longer, after the release that deprecates it is published.
4. It is removed in a major release, with an upgrade-guide entry that names the
   replacement.

The surface-specific rules below apply the same period.

| Surface | How a deprecation is marked | Breaking changes |
|---|---|---|
| `FERRUM_*` environment variables and `ferrum.conf` keys | Marked deprecated in [configuration.md](configuration.md) and in `ferrum.conf`; a startup warning names the replacement. The deprecating release states what happens when both the old and the new name are set. | Removed in a major release. `ferrum.conf` refuses unknown keys, so a removed key left in that file stops startup until it is deleted; the upgrade guide says so. |
| Config schema (file mode, Admin API resources, database rows, backups, plugin configs) | Marked `deprecated: true` in [openapi.yaml](../openapi.yaml) and in the field's documentation. A renamed field keeps the old spelling as a write-only input alias, never returned in responses, as `cooldown_seconds` is today. | Removing a field or alias, renaming without an alias, changing a field's type or meaning, or making an optional field required: major. |
| Admin API endpoints and responses | Marked `deprecated: true` in [openapi.yaml](../openapi.yaml) and in [admin_api.md](admin_api.md). | Adding endpoints, optional request fields, or response fields is a minor change, so clients must ignore response fields they do not know. Removing an endpoint or response field, changing a field's type, or changing the status code of an existing success path: major. |
| Prometheus metrics and log schema fields | Marked deprecated in [prometheus_metrics.md](prometheus_metrics.md) or [log_schema.md](log_schema.md). | Removing or renaming a metric, label, or log field: major. |
| Built-in plugins | Marked deprecated in [plugins.md](plugins.md) and in the plugin's own page. | Removing a plugin or a plugin config key: major. |

A Beta or Experimental surface follows the rules of its
[maturity level](#feature-maturity-levels) instead.

### Security-fix backport policy

| Severity | Fixed in current minor | Backported to the supported previous minor |
|---|---|---|
| Critical | yes | yes |
| High | yes | yes |
| Medium | yes | at maintainer discretion |
| Low | yes | no — rolls into the next minor |

Severity targets and the private disclosure process are in
[SECURITY.md](../SECURITY.md). Fixed vulnerabilities are published as GitHub
security advisories.

Advisories in the dependency tree are handled separately and continuously: a
blocking `cargo deny` gate runs when CI selects the full dependency-audit lane
for dependency or supply-chain governance changes, and a weekly re-check runs
against the current advisory database, including the vendored, patched upstream
crates. See [dependency-policy.md](dependency-policy.md#1-blocking-dependency-gate-denytoml--ci).

### Control plane / data plane version skew

**Covered:** none. The control plane (CP) and every data plane (DP) must run the
identical Ferrum Edge build. This is the rule in every release, including `0.x`.

Each side enforces it with the ConfigSync build identity,
`<crate version>+configsync.r<revision>`, where the revision is
`CONFIG_SYNC_PROTOCOL_REVISION` in `src/grpc/configsync_lifecycle.rs`. The DP
sends its identity on every ConfigSync request; the CP refuses any other
identity (another crate version, patch releases included, another revision, or
none) with `FAILED_PRECONDITION` before streaming any config. The CP stamps its
identity on every frame, heartbeats included, and the DP drops the stream on a
frame from another build. See
[Build Identity Gate](upgrade_guide.md#build-identity-gate).

**Supported upgrade procedure:** upgrade every CP first, then every DP, in one
maintenance window ([Upgrade Order](upgrade_guide.md#upgrade-order)). In a
multi-CP deployment, every CP must be upgraded before the DPs; failover never
bridges builds. Rollback is the same operation in reverse, with every CP and
every DP returned to the old build.

**What a DP does while it cannot sync:** a DP that a CP refuses, or that cannot
reach any CP, keeps serving the last configuration it validated and applied.
That configuration is bounded by `FERRUM_DP_CONFIG_MAX_STALE_SECONDS` (default
`3600`): once its age passes the bound while no CP is authoritative, the DP
degrades readiness and, under the default
`FERRUM_DP_CONFIG_STALE_ACTION=fail_closed`, refuses new traffic while existing
connections drain. A DP keeps no on-disk configuration cache, so a DP restarted
during the window starts empty and stays not-ready until it applies a snapshot
from a CP on the same build. Finish the upgrade inside the stale bound; see
[cp_dp_mode.md](cp_dp_mode.md#bounded-last-known-good-configuration-age).

**Mesh data planes** subscribe with `MeshSubscribe` (or Ferrum xDS). The CP
checks major/minor version compatibility, but the mesh slice root and its policy
members are closed schemas, so a patch release that adds a member is refused by
an older data plane, which keeps serving its last accepted slice. Run mesh
control planes and data planes on the same build and upgrade them in the same
order.

**Breaking changes:** any change to the ConfigSync messages, frame semantics, or
snapshot/delta JSON contract bumps the revision, and can happen in any release.
The build identity gate turns every such change into a refusal at subscribe
instead of a misread configuration, and the upgrade guide names the new
revision. A future release that adds a supported skew window will state it here.

### Custom-plugin Rust API

Custom plugins are Rust source files under `custom_plugins/` compiled into the
gateway binary ([CUSTOM_PLUGINS.md](../CUSTOM_PLUGINS.md)). They implement the
`Plugin` trait and use the crate's internal types (`RequestContext`,
`PluginConfigContract`, the stream contexts, and the helpers they reach). There
is no separately published plugin crate, ABI, or API version number: the API is
whatever the gateway crate contains in that release, and it has changed in many
`0.x` releases.

**Stability level: unstable.** The custom-plugin Rust API is not part of the
SemVer surface.

- **Covered:** from 1.0.0 onward, a breaking change to the `Plugin` trait or the
  types it exposes ships only in a minor or major release, not in a patch
  release unless a security fix requires it. Each one has an upgrade-guide entry
  titled "Custom plugins: …" that states the change and the migration.
- **Not covered:** source compatibility across minor releases; any binary or
  dynamic-loading interface (none exists); internal modules a plugin reaches
  that are not part of the `Plugin` trait's signatures.
- **Operator data is separate:** plugin configuration rows, and the tables a
  plugin creates through its own migrations (tracked in
  `_ferrum_plugin_migrations`), belong to the plugin author. Ferrum Edge does not
  rewrite them.

Rebuild and test custom plugins against every minor release before upgrading.

### gRPC and protobuf surfaces

The `.proto` files under [`proto/`](../proto) are build inputs, not a published
API package. Third-party clients and servers for the Ferrum-defined services are
not supported.

| Surface | Between | Compatibility |
|---|---|---|
| `ferrum.ConfigSync` (`Subscribe`, `GetFullConfig`) | Ferrum CP and Ferrum DP | Identical build only ([above](#control-plane--data-plane-version-skew)). Changes bump the ConfigSync revision and can happen in any release. |
| `ferrum.MeshConfigSync` (`MeshSubscribe`, `ReportMeshSliceStatus`) and Ferrum xDS (`FERRUM_MESH_CONFIG_PROTOCOL=xds`, Envoy ADS framing with Ferrum resources and ECDS carriers) | Ferrum CP and Ferrum mesh data planes, including cross-cluster discovery | Same build required in practice ([above](#control-plane--data-plane-version-skew)); changes can happen in any release. |
| Standard protocols Ferrum speaks: Envoy xDS v3 discovery (`stock_xds`), Envoy RTDS, the SPIFFE Workload API, and `grpc.health.v1` health checks | Ferrum and third-party components | Follow the upstream specification. Support for each is a feature with its own maturity level (for example, `stock_xds` is Beta). |

### ClickHouse chargeback schema

[`schemas/clickhouse/charges.sql`](../schemas/clickhouse/charges.sql) is the
reference DDL for the external ClickHouse database that the
`api_chargeback_sink` plugin writes to. The operator applies it; Ferrum Edge never
alters an existing ClickHouse table.

- **Covered:** the native `JSONEachRow` row contract for `ferrum.charges_raw`
  (the key set and types in
  [api_chargeback_sink.md](plugins/api_chargeback_sink.md#jsoneachrow-wire-contract)).
  Removing, renaming, or retyping a native key is a major change. Adding a native
  key is a minor change, never a patch, and it requires operator action:
  ClickHouse rejects JSON keys that are not table columns, so the upgrade guide
  gives the `ALTER TABLE` statement to apply before the upgrade.
- **Not covered:** the reference rollup views (re-apply the file to refresh them;
  they are `CREATE OR REPLACE VIEW`), the retention `TTL` (operator-owned), and
  tables shaped by an operator `schema` / `schema_ref` projection.

### Backup, export, and file-config format

`GET /backup` documents and file-mode configuration files carry a top-level
`version` field, currently `"1"` (`CURRENT_CONFIG_VERSION` in
`src/config/types.rs`). File-mode loading and backup bootstrap run a
version-migration chain in memory when a document carries an older `version`,
and `FERRUM_MODE=migrate` with `FERRUM_MIGRATE_ACTION=config` rewrites a
configuration file on disk. No migration step exists yet, because `"1"` is the
only version. `POST /restore` reads the document shape directly and does not
check `version`.

- **Covered:** from 1.0.0 onward, a backup or file-mode configuration written by
  a 1.x release is accepted by every later 1.x release, through every loader
  (file mode, backup bootstrap, and `POST /restore`). A change that would make
  such a document unreadable either keeps the old shape accepted (a minor change)
  or increments `version` and ships the migration step for it.
- **Not covered:** loading a document written by a newer release on an older
  release; documents written by `0.x` releases (take a fresh `GET /backup` from
  the last `0.x` release before upgrading to 1.0.0); partial `?resources=`
  exports as a complete rebuild source.

### Database schema

From 1.0.0 onward, the core database schema (PostgreSQL, MySQL, SQLite, and the
MongoDB index plan) changes only through forward-only migrations shipped with the
release that needs them; a database created by a `0.x` release is rebuilt from a
logical export, not migrated in place to 1.0.0. Rolling back a release that
migrated the schema means restoring the database taken before the upgrade, not
starting the older binary against the migrated schema. The migration mechanism,
the integrity checks, and custom-plugin migrations are documented in
[migrations.md](migrations.md); the upgrade procedure is in
[upgrade_guide.md](upgrade_guide.md). Table layout is not part of the SemVer
surface: integrate through the Admin API and backups, not by reading tables.

### Feature maturity levels

Each feature has one maturity level. A feature that no document labels is
**GA**. Labels are used today mainly in the service mesh documentation
([mesh_supported_matrix.md](mesh_supported_matrix.md) and the maturity tables in
[mesh.md](mesh.md#maturity-and-support-status), where "Stable" means GA).

| Level | What it promises across releases |
|---|---|
| **GA** | Covered by SemVer and the deprecation notice period. A regression is a release blocker. A mesh GA feature is also enrolled in `tests/conformance/ga_contract.yaml`, so a semantic regression fails CI. GA is never downgraded except in a major release. |
| **Beta** | Feature-complete and tested, with a documented sharp edge or an owed verification step. Receives bug and security fixes within the support windows. Its configuration is not removed or renamed without a deprecation notice, but the notice may end in a minor release rather than a major one, and documented behaviour may change in a minor release with an upgrade-guide entry. |
| **Experimental** | Opt-in and off by default, with a safety-relevant caveat or no live data-path verification. No compatibility promise: it may change or be removed in any minor release, with a release-notes and upgrade-guide entry. Security reports about it are handled like any other. |
| **Dev-only** | Requires a non-default build feature or development opt-in and is absent from the default published artifacts. No support promise. |
| **Out-of-scope** | An explicit non-goal, documented so it is not mistaken for a gap (for example `EnvoyFilter`). |

Patch releases contain only bug and security fixes at every level. A feature is
promoted (Experimental to Beta to GA) in a minor release; the mesh graduation
criteria are in
[mesh_supported_matrix.md](mesh_supported_matrix.md#how-a-feature-graduates).
Support for upstream Kubernetes Gateway API experimental-channel resources and
fields follows upstream: when upstream changes an experimental field, Ferrum Edge
follows it in a minor release with an upgrade-guide entry. Ferrum-defined
Kubernetes custom resources follow Kubernetes API versioning: a `v1alpha1`
resource such as `UDPResponseAmplificationPolicy` may change incompatibly in a
minor release, with an upgrade-guide entry.

Current gaps and unsupported shapes are listed in
[known_limitations.md](known_limitations.md).

## Upgrading

- Procedure, rollback, and per-release breaking changes:
  [upgrade_guide.md](upgrade_guide.md).
- Database schema handling: [migrations.md](migrations.md).
- Rolling deploys and draining: [graceful_shutdown.md](graceful_shutdown.md).
- Hardening the result: [hardening.md](hardening.md).

## Changes to this policy

A change that reduces a commitment (a shorter support window, a shorter
deprecation period, a narrower SemVer surface, a weaker compatibility rule) is
announced in the release notes one minor release before it takes effect. A change
that extends a commitment takes effect when it is published.
