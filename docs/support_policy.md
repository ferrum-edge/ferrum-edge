# Support, Versioning, and Deprecation Policy

What a Ferrum Edge version number promises, how long a release is supported, how
deprecations are announced, and how security fixes reach released versions.

> **Release-preparation snapshot (2026-09-06).** `Cargo.toml` declares
> `version = "0.9.3"`; source tags `v0.9.0`, `v0.9.1`, and `v0.9.2` already
> exist. Main CI validates and does not publish production artifacts. The
> version-tag release workflow publishes after exact-commit validation.
> Tag existence does not establish successful artifact publication; verify the
> version's workflow and [Releases page](https://github.com/ferrum-edge/ferrum-edge/releases).
> Historical `latest` artifacts may remain but are not refreshed by main.
> The "After 1.0" commitments below remain **proposed**; pre-1.0 tags do not
> activate them.

## Today: build-out (pre-1.0)

Ferrum Edge is in active build-out. The repository's own engineering policy —
[CLAUDE.md](../CLAUDE.md) "Build-Out Policy" and the path-scoped rules under
`.claude/rules/` — states this directly:

- **Breaking changes are expected on `main`.** Configuration shapes, environment
  variable names, database values, admin API responses, and plugin schemas may
  change between builds.
- **No compatibility shims.** Old fields, environment variables, config shapes,
  and database values are removed rather than aliased. Custom plugin migrations
  under `custom_plugins/` are the exception.
- **No incremental schema migrations.** Schema changes are folded into the
  current baseline. A core schema change therefore requires a **fresh database**
  populated from a namespace-complete logical export, keeping the old database
  intact as the rollback target.

The upgrade procedure for this phase is
[docs/upgrade_guide.md](upgrade_guide.md), which records the schema-freeze
dependency explicitly:

> "Tagged releases after the declared schema freeze will document additive
> forward migrations; until then, follow the rebuild procedure below."
> — [upgrade_guide.md](upgrade_guide.md)

**The schema freeze has not been declared.** It begins with the first tagged
release designated stable: `v1.0.0`, or an earlier release whose notes explicitly
declare the stable baseline, as defined in
[migrations.md](migrations.md#when-v002-migrations-start-the-schema-freeze).
A pre-1.0 source tag by itself does not freeze the schema.

Breaking changes that have already landed are listed per release in
[Breaking changes in 0.9.0](upgrade_guide.md#breaking-changes-in-090).

### What is stable enough to build on today

Nothing in this phase carries a compatibility guarantee. In practice the surfaces
that change least are the ones with parity gates in CI — the admin API against
[openapi.yaml](../openapi.yaml), the environment variable inventory against
[docs/configuration.md](configuration.md) and `ferrum.conf`, and the Prometheus
metric contract against
[docs/prometheus_metrics.md](prometheus_metrics.md). A gate makes a change
*visible*, not *forbidden*. Pin an exact build and read
[upgrade_guide.md](upgrade_guide.md) before every upgrade.

### Artifacts

| Artifact | What it is | Use in production? |
|---|---|---|
| Published `vX.Y.Z` release and container image | version-tag workflow output after validation | Pin the published version or digest and review its build-out limitations |
| Historical `latest` release/container tag | retained old artifact; main no longer refreshes it | No — not a current release or update channel |
| Source at a commit | source identity, not proof of a published artifact | Pin the commit and validate your own build |

The Helm chart defaults to `Chart.appVersion`, which may name a version still in
release preparation. Confirm that the image exists before installation or set
an explicit published tag; see the
[ferrum-gateway chart](../charts/ferrum-gateway/README.md#security-defaults-you-should-know).

## After 1.0 (proposed)

Every commitment in this section is **proposed** for the declared 1.0 support
policy. Until it is adopted, it describes intent, not an obligation; existing
pre-1.0 tags do not activate it.

### Semantic versioning

From 1.0, releases follow [SemVer 2.0.0](https://semver.org/) over the following
declared public surface:

- The `FERRUM_*` environment variable names, accepted values, and defaults
  documented in [configuration.md](configuration.md).
- The file-mode configuration schema.
- The admin REST API as published in [openapi.yaml](../openapi.yaml).
- The plugin configuration schemas in [plugins.md](plugins.md).
- The transaction log schema in [log_schema.md](log_schema.md).
- The Prometheus metric contract in [prometheus_metrics.md](prometheus_metrics.md).
- The CLI surface in [cli.md](cli.md).
- The `ferrum-gateway` and `ferrum-mesh` Helm chart values.

Explicitly **not** part of the SemVer surface: internal Rust APIs (the crate is
not published as a library contract), log line wording outside the declared
schema, database table layout (governed by [migrations.md](migrations.md)),
performance characteristics, and anything a document marks experimental — for
example the node-waypoint mesh topology.

| Change | Version bump |
|---|---|
| Removing or renaming a documented `FERRUM_*` variable, config field, or API field | major |
| Changing a documented default to a different behaviour | major |
| Removing an endpoint, metric, or plugin | major |
| Tightening validation so a previously accepted configuration is refused | major |
| Adding a variable, field, endpoint, metric, or plugin | minor |
| Adding an optional field with a backward-compatible default | minor |
| Bug fix with no documented-surface change | patch |
| Security fix with no documented-surface change | patch |

A security fix that **must** break a documented surface to close the issue may
ship in a minor or patch release. When that happens it is called out in the
release notes and the advisory, and the reason is stated.

### Support window (proposed)

| Line | Proposed window |
|---|---|
| Current minor | supported |
| Previous minor | supported for **6 months** after the next minor is released |
| Older minors | unsupported |

"Supported" means security fixes and regression fixes. Feature work lands on the
current minor only.

The six-month figure is a **proposed conservative value**. It is not derived from
anything in the code, and it will be reconfirmed — and may be shortened or
lengthened — when the 1.0 support policy is adopted.

### Deprecation notice period (proposed)

A documented surface is removed only after it has been announced as deprecated:

1. It is marked deprecated in its own documentation and in the release notes of
   the release that deprecates it.
2. Where the runtime can detect its use, a startup or first-use warning names the
   replacement.
3. It keeps working for at least **one full minor release and 90 days**,
   whichever is longer.
4. It is removed in a major release.

The "one minor and 90 days" figure is likewise a **proposed** value pending the
declared 1.0 support policy.

### Security-fix backport policy (proposed)

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
blocking `cargo deny` gate runs on every pull request and a weekly re-check runs
against the current advisory database, including the vendored, patched upstream
crates. See [dependency-policy.md](dependency-policy.md).

## Upgrading

- Procedure, rollback, and per-release breaking changes:
  [upgrade_guide.md](upgrade_guide.md).
- Database schema handling: [migrations.md](migrations.md).
- Rolling deploys and draining: [graceful_shutdown.md](graceful_shutdown.md).
- Hardening the result: [hardening.md](hardening.md).

## Changes to this policy

While the 1.0 commitments remain proposed, they may change without notice — that is what
"proposed" means. After 1.0, a change that reduces a commitment (a shorter
support window, a shorter deprecation period, a narrower SemVer surface) is
itself announced one minor release ahead.
