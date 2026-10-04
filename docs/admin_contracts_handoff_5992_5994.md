# Admin contract handoff: #5992 and #5994

This is the pre-release handoff for
[Edge PR #5999](https://github.com/ferrum-edge/ferrum-edge/pull/5999),
[issue #5992](https://github.com/ferrum-edge/ferrum-edge/issues/5992), and
[issue #5994](https://github.com/ferrum-edge/ferrum-edge/issues/5994).
The APIs are Unreleased. This file records publication work still required;
it is not evidence that a ferrum-contracts update has shipped.

## Edge sources to synchronize

| Surface | Exact Edge paths | Contract to carry forward |
| --- | --- | --- |
| Credential-complete consumer verification | `src/admin/conditional_snapshots.rs`, `src/admin/crud.rs`, `src/admin/preconditions.rs`, `src/admin/mod.rs`, `docs/admin_api.md`, `openapi.yaml` | `GET /consumers/{id}/verification`, admin-role and namespace authorization, complete stored credentials, keyed strong state ETag shared with ordinary CRUD, audit-before-response, no-store and no cached fallback. |
| Coherent conditional backup | `src/admin/backup.rs`, `src/admin/conditional_snapshots.rs`, `src/config/db_backend.rs`, `src/config/db_loader.rs`, `src/config/mongo_store.rs`, `docs/admin_backup_restore.md`, `openapi.yaml` | Full unfiltered `GET /backup?conditional=true`, `conditional.namespace_etag`, all four `conditional.row_etags` maps, exact stored consumer fields, complete ownership/trust state and durable namespace revision. |
| Atomic conditional replacement and lease fencing | `src/admin/conditional_snapshots.rs`, `src/admin/crud.rs`, `src/config/batch_atomicity.rs`, `src/config/db_backend.rs`, `src/config/db_loader.rs`, `src/config/mongo_store.rs`, `docs/admin_backup_restore.md`, `openapi.yaml` | `POST /restore?confirm=true` with namespace `If-Match`; comparison and replacement in one transaction, including empty replacement and lease entry/commit gates; stale state `412`, invalid header or wildcard `400`, unsupported topology `501`, unavailable state/lease `503`. Body metadata alone is not a precondition. |
| Inherited backend egress discovery | `src/admin/backend_egress_policy.rs`, `src/admin/mod.rs`, `src/config/env_config.rs`, `docs/admin_api.md`, `openapi.yaml` | `GET /backend-egress-policy`, namespace-authorized JWT reads, `schema_version=1`, `ip_classification=ferrum-private-reserved-v1`, process scope, four enforcement scopes, three modes, evaluation order, dangerous-range and overlay-presence flags, conservative `public_only_guaranteed`. No raw CIDRs, credentials, DNS probe, or DP attestation by CP. |
| Adoption and release notes | `CHANGELOG.md`, `docs/upgrade_guide.md`, `README.md` | Mark availability against the actual Edge release; update the published contracts tag only after the contract artifacts are released. |

Before release, reconcile the older conditional-write paragraph in
`docs/admin_api.md` under `Conditional writes (ETag / If-Match)`: it still says
any other mutating route including `POST` is refused, without the new
`POST /restore` exception. Cross-check it with
`openapi.yaml#/components/parameters/IfMatch` and `NamespaceIfMatch`.
Describe the tags as validators of complete stored state, since ordinary
consumer responses are redacted; they are not hashes of those response bytes.

The OpenAPI handoff must verify these exact locations in `openapi.yaml`:

- Paths `/consumers/{id}/verification`, `/backup`, `/restore`, and
  `/backend-egress-policy`, including authorization, refusal statuses, `ETag`,
  and `Cache-Control: no-store` where emitted.
- `components.parameters.IfMatch` and `components.parameters.NamespaceIfMatch`.
- `components.headers.ResourceETag`.
- `components.schemas.ConsumerVerification`, `ConditionalBackupMetadata`,
  `ResourceETagMap`, `BackupResponse`, `RestoreRequest`, and
  `BackendEgressPolicyResponse`.

## ferrum-contracts publication work

The existing published contract set does not contain dedicated conditional
snapshot or backend egress policy artifacts. Root must arrange the corresponding
ferrum-contracts PR before the Edge release, with real release-tag and full-SHA
provenance. Do not edit an already published `contracts-edge-*` tag.

Existing exact paths requiring review/update in ferrum-contracts:

- `vocabularies/gateway-headers.json` and
  `schemas/vocabulary-gateway-headers/v1.schema.json`: add or document admin
  `ETag`/`If-Match` semantics and the namespace restore exception without
  presenting HTTP-standard headers as newly invented Edge header names.
  Update `fixtures/vocabulary-gateway-headers/valid/` and
  `fixtures/vocabulary-gateway-headers/invalid/` when the vocabulary schema changes.
- `docs/ownership.md`, `docs/adoption.md`, `docs/versioning.md`,
  `docs/release-process.md`, `README.md`, and `CHANGELOG.md`: register ownership,
  availability and adoption, then publish the immutable
  `contracts-edge-<edge-version>` tag for the actual release.
- `ci/validate.py`, `.github/workflows/validate.yml`, and
  `fixtures/invalid-expectations.json`: register and validate any new schemas,
  vocabularies, and valid/invalid fixture sets through hosted CI.

Proposed exact paths for the new contract surfaces (not yet published; names
must be agreed in that PR):

- `schemas/admin-conditional-snapshot/v1.schema.json` with sanitized examples
  in `fixtures/admin-conditional-snapshot/valid/` and
  `fixtures/admin-conditional-snapshot/invalid/`. Capture the metadata shape,
  opaque quoted tokens, resource kinds, and the separation between row and
  namespace preconditions; never commit real credential-bearing backups.
- `schemas/backend-egress-policy/v1.schema.json`,
  `schemas/vocabulary-backend-egress-policy/v1.schema.json`, and
  `vocabularies/backend-egress-policy.json`, with example responses in
  `fixtures/backend-egress-policy/valid/` and
  `fixtures/backend-egress-policy/invalid/`. Publish classification and scope
  identifiers, evaluation order, and the conservative guarantee rule. A
  classifier meaning change requires versioned contract coordination.

GitForgeOps (#5992) must adopt the credential-complete verification and coherent
snapshot tokens. Nexus (#5994, Nexus #506 / GHSA-93rq-89vr-38pc part B) must
check the serving process's versioned policy and scope before publishing;
Foundry and other control planes should use the same contract. CP metadata
cannot substitute for checking the relevant serving DPs. Existing process
policy, default mode, and documented enforcement-path limitations are inherited.

## Hosted CI and root review

Root must obtain a fresh independent review of the new CI policy logic and
confirm that `conditional-live-stores` executes all three PostgreSQL, MySQL,
and replica-set MongoDB tests with `--run-ignored=all -j 1` at the final SHA.
Local execution was prohibited for this handoff. The new fixture pins were
verified on 2026-10-04 against Docker Hub tag metadata and registry OCI index
`Docker-Content-Digest` headers for `postgres:16-alpine`, `mysql:8`, and `mongo:7`.
The corresponding Docker Hub tag metadata is available at
[`postgres:16-alpine`](https://hub.docker.com/v2/repositories/library/postgres/tags/16-alpine),
[`mysql:8`](https://hub.docker.com/v2/repositories/library/mysql/tags/8), and
[`mongo:7`](https://hub.docker.com/v2/repositories/library/mongo/tags/7);
the immutable index pins live in `.github/workflows/ci.yml`.

At inspected head `302266a85a2b747669e2f29a2def128cdea0efa2`, CI run
[37190337612](https://github.com/ferrum-edge/ferrum-edge/actions/runs/37190337612)
passed CI Policy but did not reach the live shard. These deterministic Rust
failures require the respective source owners; they are outside this CI/docs fix:

- Lint: unused `debug_persistence_failure_redacted` in `src/admin/mod.rs:12412`
  and `clippy::collapsible_if` in `src/admin/conditional_snapshots.rs:353`.
- Build Test Artifacts: ambiguous `parse()` in
  `tests/integration/admin_backend_egress_policy_tests.rs:126` and unavailable
  `pool()` on `Arc<dyn DatabaseBackend>` in
  `tests/integration/admin_conditional_write_tests.rs:1391`.
