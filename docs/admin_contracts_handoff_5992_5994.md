# Admin contract handoff: #5992 and #5994

This records the published v0.9.11 baseline for
[Edge PR #5999](https://github.com/ferrum-edge/ferrum-edge/pull/5999),
[issue #5992](https://github.com/ferrum-edge/ferrum-edge/issues/5992), and
[issue #5994](https://github.com/ferrum-edge/ferrum-edge/issues/5994), plus the
next candidate handoff. Edge v0.9.11 was published at 2026-10-04T21:26:11Z at
`c764084b3b51c3f7ffde268c039688d35e49c553`; its verified distribution and
limits are in the [release record](releases/v0.9.11.md).
Canonical [`contracts-edge-0.9.11`](https://github.com/ferrum-edge/ferrum-contracts/tree/390edbd5b2485af0988e02f7827fde778d76ae0a)
targets `390edbd5b2485af0988e02f7827fde778d76ae0a`, not later main
`96228e1cc3341c6bd2dff3c47eea9efa45e0545e`. New `deployment-v1` source from
merged #6012 is in the [0.9.12 candidate](releases/v0.9.12.md); its release,
canonical contracts and downstream adoption are pending.

## Edge sources to synchronize

| Surface | Exact Edge paths | Contract to carry forward |
| --- | --- | --- |
| Credential-complete consumer verification | `src/admin/conditional_snapshots.rs`, `src/admin/crud.rs`, `src/admin/preconditions.rs`, `src/admin/mod.rs`, `docs/admin_api.md`, `openapi.yaml` | `GET /consumers/{id}/verification`, admin-role and namespace authorization, complete stored credentials, keyed strong state ETag shared with ordinary CRUD, audit-before-response, no-store and no cached fallback. |
| Coherent conditional backup | `src/admin/backup.rs`, `src/admin/conditional_snapshots.rs`, `src/config/db_backend.rs`, `src/config/db_loader.rs`, `src/config/mongo_store.rs`, `docs/admin_backup_restore.md`, `openapi.yaml` | Full unfiltered `GET /backup?conditional=true`, `conditional.namespace_etag`, all four `conditional.row_etags` maps, exact stored consumer fields, complete ownership/trust state and durable namespace revision. |
| Atomic conditional replacement and lease fencing | `src/admin/conditional_snapshots.rs`, `src/admin/crud.rs`, `src/config/batch_atomicity.rs`, `src/config/db_backend.rs`, `src/config/db_loader.rs`, `src/config/mongo_store.rs`, `docs/admin_backup_restore.md`, `openapi.yaml` | `POST /restore?confirm=true` with namespace `If-Match`; comparison and replacement in one transaction, including empty replacement and lease entry/commit gates; stale state `412`, invalid header or wildcard `400`, unsupported topology `501`, unavailable state/lease `503`. Body metadata alone is not a precondition. |
| Inherited backend egress discovery | `src/admin/backend_egress_policy.rs`, `src/admin/mod.rs`, `src/config/env_config.rs`, `docs/admin_api.md`, `openapi.yaml` | `GET /backend-egress-policy`, namespace-authorized JWT reads, `schema_version=1`, `ip_classification=ferrum-private-reserved-v1`, process scope, four enforcement scopes, three modes, evaluation order, dangerous-range and overlay-presence flags, conservative `public_only_guaranteed`. No raw CIDRs, credentials, DNS probe, or DP attestation by CP. |
| Adoption and release notes | `CHANGELOG.md`, `docs/upgrade_guide.md`, `README.md` | Mark availability against the actual Edge release; update the published contracts tag only after the contract artifacts are released. |

`docs/admin_api.md` under `Conditional writes (ETag / If-Match)` now separates
the four row `PUT`/`DELETE` routes from the `POST /restore` namespace exception.
Carry those semantics into the published contract: `IfMatch` and
`ResourceETag` validate complete stored row state, including privately verified
credentials, rather than redacted wire bytes. Ordinary consumer reads and
admin-only verification share the same row tag. `NamespaceIfMatch` instead
validates the complete coherent namespace snapshot, including its durable
change watermark; a row tag or body metadata cannot authorize that replacement.

The new route contracts to publish are:

| Route | Successful contract | Refusal semantics to preserve |
| --- | --- | --- |
| `GET /consumers/{id}/verification` | `200`, complete stored consumer and matching strong row `ETag`, `Cache-Control: no-store`, mandatory security audit admission before response. | `400` invalid input, `401` missing/invalid JWT, `403` role or namespace denial, `404` absent consumer, `503` unavailable authoritative state, tag key or security audit admission. |
| `GET /backup?conditional=true` | `200`, unfiltered primary transaction snapshot, namespace `ETag` equal to `conditional.namespace_etag`, all four row-tag maps, `Cache-Control: no-store`. | `400` invalid opt-in/filter/namespace, `401` authentication, `403` authorization, `501` unsupported MongoDB topology, `503` unavailable authoritative snapshot, tag key or security audit admission. No cached fallback. |
| `POST /restore?confirm=true` with namespace `If-Match` | Atomic compare and complete replacement under transaction lease fencing; response retains the existing restore/live-apply contract and carries no new `ETag`. | `412` stale or weak-only tag, `400` malformed/empty header or wildcard, `501` unsupported topology, `503` unavailable authoritative state/lease. Existing authentication, admission, body-size, confirmation, conflict and live-apply statuses still apply. Omission of the header preserves unconditional restore. |
| `GET /backend-egress-policy` | `200`, JWT-authorized versioned metadata for the immutable process policy, `Cache-Control: no-store`; available on read-only listeners. | `400` invalid namespace, `401` missing/invalid JWT, `403` namespace claim/ceiling denial. Metrics credentials do not authorize this route. |

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

The immutable published v0.9.11 tag above contains
`schemas/admin-conditional-snapshot/v1.schema.json`,
`schemas/backend-egress-policy/v1.schema.json`, the backend egress vocabulary
and fixtures, and standard admin ETag/If-Match semantics. Its actual
[canonical release record](https://github.com/ferrum-edge/ferrum-contracts/blob/390edbd5b2485af0988e02f7827fde778d76ae0a/docs/releases/contracts-edge-0.9.11.md)
and artifact provenance bind owner source to released Edge
`c764084b3b51c3f7ffde268c039688d35e49c553`. The plugin catalog references
OpenAPI SHA-256 `687db80271512a367814ded6002ecce546eb190a347a57e32eca36af7d665020`
through pointers into that exact owner document. Schema syntax validation does
not establish cryptographic authority, authorization or downstream live apply.
Some retained canonical preparation text still says publication pending; the
actual published ref supplies the target, and later main cannot replace it.

The earlier inspection on 2026-10-04 at canonical main
`c35f4c9d254820ad96e7e308583135127c2003de` and historical
`contracts-edge-0.9.9-r2`/`591c73a3f965fdab440c3a76b2707accdf491ba5` predates
publication. Its missing-artifact observations are historical, not the current
baseline. Preserve all published tags. Next root must synchronize the additive
`deployment-v1` snapshot/mutation contract from the actual verified 0.9.12
release, then qualify consumers; neither step is complete here.

Canonical paths to retain and review for the next ferrum-contracts publication:

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

Exact paths published in the v0.9.11 baseline (retain their semantics):

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

Review 11 accepted the live fixture behavior and identified a P2 gap in its
substring guards: a skipped runner, nonfatal cleanup, or MySQL password argv
could retain every required substring. The guards in
`tests/unit/config/conditional_live_stores_ci_tests.rs` now parse the active
YAML job/matrix/steps and pin the complete reviewed shell programs, conditions,
timeouts and environment wiring. Their negative mutations cover those three
findings plus exact filter selection, serial ignored tests, TCP authentication,
query readiness, network bindings, credentials and bounded failure handling.
The existing `Unit Tests (core)` target includes these unignored tests; hosted
execution of them is required, not established by this source inspection.
No global scanner or workflow condition was changed by the guard repair.

The final v0.9.11 release subsequently qualified at the exact #6005 head
and merge target: all 14 main-push workflows and all 20 release jobs succeeded.
The source snapshots below preserve the earlier guard-repair history, not an
outstanding v0.9.11 publication gate. For the new #6012 head, actual hosted logs
confirmed all three live PostgreSQL/MySQL/replica-Mongo conditional tests plus
SQLite's admin control; its exact qualification boundary is recorded in the
[0.9.12 candidate](releases/v0.9.12.md). Fresh preparation-head and main-push
qualification remain root-owned and pending. No local project execution occurs.

The new fixture pins were verified on 2026-10-04 against Docker Hub tag metadata and registry OCI index
`Docker-Content-Digest` headers for `postgres:16-alpine`, `mysql:8`, and `mongo:7`.
The corresponding Docker Hub tag metadata is available at
[`postgres:16-alpine`](https://hub.docker.com/v2/repositories/library/postgres/tags/16-alpine),
[`mysql:8`](https://hub.docker.com/v2/repositories/library/mysql/tags/8), and
[`mongo:7`](https://hub.docker.com/v2/repositories/library/mongo/tags/7);
the immutable index pins live in `.github/workflows/ci.yml`.

At inspected head `302266a85a2b747669e2f29a2def128cdea0efa2`, CI run
[37190337612](https://github.com/ferrum-edge/ferrum-edge/actions/runs/37190337612)
passed CI Policy but did not reach the live shard. It reported these historical
Rust failures:

- Lint: unused `debug_persistence_failure_redacted` in `src/admin/mod.rs:12412`
  and `clippy::collapsible_if` in `src/admin/conditional_snapshots.rs:353`.
- Build Test Artifacts: ambiguous `parse()` in
  `tests/integration/admin_backend_egress_policy_tests.rs:126` and unavailable
  `pool()` on `Arc<dyn DatabaseBackend>` in
  `tests/integration/admin_conditional_write_tests.rs:1391`.

The separate source/schema follow-up
`4405f5e649c0267a5cfecb7e02cc44c7dd89f90e` contains fixes for those findings.
Its source delta is outside this guard/docs repair; the earlier failed run is
neither proof of a remaining failure nor evidence that the fixes pass. The later
final v0.9.11 qualification superseded this historical pending status. It does not qualify a new 0.9.12 preparation or release head.

## Next deployment-v1 publication (#6010 / #6012)

Carry the new owner surfaces from `openapi.yaml`, `docs/deployment_mutations.md`,
`src/admin/deployment_mutations.rs` and the SQL/Mongo deployment mutation stores:
admin-only coherent raw snapshots; original `deployment-v1` namespace authority;
strict opt-in proxy cascade removal and API-spec replacement; all four stores'
entry/commit fences and topology requirements; supported unknown-state preservation
and fail-closed unrepresentable evidence. Publish the exact durable/live/cleanup
envelopes, typed external-reference `409/not_committed/unconfirmed/false` refusal,
and uncertain driver/commit/lease handling. Backup tags and row ETags cannot
substitute. No refreshed token, retry or full restore-minus-target is recovery
cleanup authority. CP durable-only acknowledgement is not serving-DP application.

Publish from the actual verified 0.9.12 release/full SHA after fresh root review
and hosted qualification. Preserve the v0.9.11 baseline and its schema/catalog
provenance. Consumers must retain original encrypted evidence/journals through
refusal, committed-not-live and uncertainty and qualify their adoption separately.
No 0.9.12 canonical publication, packaged adoption or advisory closure is claimed.
