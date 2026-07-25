# Changelog

All notable changes to Ferrum Edge will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Authenticated `/metrics` now renders TLS certificate gauges from a cached,
  non-secret TLS inventory snapshot and performs no certificate, private-key,
  Kubernetes, HSM, or cloud-secret I/O on the scrape path. The snapshot is
  refreshed by a bounded single-flight background task governed by the new
  `FERRUM_TLS_INVENTORY_SNAPSHOT_TTL_SECONDS` (default 300, `0` disables it), its
  freshness is exported as `ferrum_tls_inventory_snapshot_timestamp_seconds` /
  `ferrum_tls_inventory_snapshot_max_age_seconds`, and certificate gauges are
  absent until the first snapshot is published. `GET /admin/tls/inventory` still
  collects live.
- Added release governance requiring version tags to match the package version and
  requiring build-out breaking changes to be recorded here.
- Hardened `tcp_connection_throttle` config loading to fail closed for
  unsupported-only global targets, non-TCP scoped attachments, unknown config
  fields, and cleanup intervals above 86400 seconds. Existing deployments must
  remediate these rows before upgrade; see the
  [Safe Upgrade Guide](docs/upgrade_guide.md#tcp-connection-throttle-validation-hardening).

## [0.9.0]

Ferrum Edge 0.9.0 represents the current build-out baseline: a multi-protocol
edge proxy with file, database, control-plane, data-plane, mesh, injector, and
node-agent modes plus its plugin and operational tooling. This entry is
intentionally coarse-grained rather than a reconstruction of unreleased history;
see [GitHub Releases](https://github.com/ferrum-edge/ferrum-edge/releases) for
published release notes.

[Unreleased]: https://github.com/ferrum-edge/ferrum-edge/compare/v0.9.0...HEAD
[0.9.0]: https://github.com/ferrum-edge/ferrum-edge/releases/tag/v0.9.0
