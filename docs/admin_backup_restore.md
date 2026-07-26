# Admin API: Backup & Restore

The Ferrum Edge Admin API provides dedicated endpoints for full configuration backup and restore, enabling disaster recovery, environment migration, and configuration snapshots.

## Overview

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/backup` | GET | Export complete gateway config as JSON |
| `/restore?confirm=true` | POST | Replace all config from a backup payload |

Both endpoints require JWT authentication. The restore endpoint is blocked in read-only mode.

## Backup — `GET /backup`

Returns the entire gateway configuration as a single JSON document. The output format is directly compatible with both `POST /restore` (full replacement) and `POST /batch` (additive import).

### Key Behaviors

- **Unredacted credentials**: Unlike `GET /consumers` (whose closed ordinary-response projection omits `basicauth` and unknown/custom credential types, drops legacy extra fields, and redacts `hmac_auth.secret`, `jwt.secret`, and `keyauth.key`), the backup endpoint returns raw stored credential values, including custom credential maps. This is necessary for faithful restoration and means backup payloads must be protected as secrets. In the OpenAPI document, backup consumer items use the `ConsumerBackup` schema (`basicauth` entries carry the canonical stored `password_hash`; plaintext passwords are never exported) and restore consumer items use `ConsumerRestore` (which additionally accepts a plaintext `password` per entry, hashed on import). Real `keyauth` backup/restore entries use `KeyAuthCredentialBackup`, which excludes the reserved `[REDACTED]` marker the same way `KeyAuthCredential` does on create/update, because runtime `Consumer::validate_fields()` rejects that placeholder on restore.
- **Canonical JWT credentials**: Consumer `jwt` entries in input, backup, and restore contain exactly one `secret` string (32-4096 characters) for HS256. Algorithm selectors, public keys, and JWKS fields are not Consumer credential forms and are rejected; RSA/EC/JWKS verification belongs to the separate `jwks_auth` plugin configuration. So that a backup taken from a database written before this contract stays restorable, `GET /backup` canonicalizes each exactly-one-field credential entry to that field — `jwt` and `hmac_auth` to `secret`, `mtls_auth` to `identity` — dropping ignored extras such as a `jwt` `algorithm`, and wraps any credential value still stored in the legacy single-object form in a one-element array, because restore requires every credential value to be a non-empty array of objects. This is an export-boundary rewrite only: it never mutates stored values, preserves every rotation entry and its order, leaves an entry without a string value at the canonical field untouched so genuinely unrepresentable data surfaces as a restore error rather than being silently dropped, and copies credential types without a single-field rule — `basicauth`, `keyauth`, and unknown/custom maps — through with their fields verbatim. A resource-filtered export (`GET /backup?resources=...`) that omits `consumers` skips this canonicalization entirely, so filtering by resource type does not pay for credential-heavy consumers it will not serialize.
- **Credential bounds**: Credential string maxima use Unicode character counts. Basic passwords, API keys, HMAC secrets, JWT secrets, and mTLS identities are limited to 4096 characters and reject disallowed ASCII control bytes; HMAC secrets must contain at least 32 non-whitespace characters on input and restore.
- **Database-first with cached fallback**: Reads from the database when available. If the database is unreachable, falls back to the in-memory cached config and sets the `X-Data-Source: cached` response header.
- **Content-Disposition header**: Includes `attachment; filename="ferrum-backup.json"` for browser-friendly downloads.
- **Resource filtering**: Use `?resources=proxies,consumers` to export only specific resource types. Valid values: `proxies`, `consumers`, `plugin_configs`, `upstreams`. Omit the parameter to export everything.

### Example

```bash
# Full backup
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:9000/backup | jq . > ferrum-backup.json

# Partial backup (proxies and upstreams only)
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://localhost:9000/backup?resources=proxies,upstreams" | jq . > proxies-backup.json

# Check what's in the backup
cat ferrum-backup.json | jq '.counts'
# {
#   "proxies": 42,
#   "consumers": 150,
#   "plugin_configs": 85,
#   "upstreams": 12
# }
```

### Response Format

```json
{
  "version": "1",
  "exported_at": "2025-03-26T10:30:00Z",
  "source": "database",
  "counts": {
    "proxies": 42,
    "consumers": 150,
    "plugin_configs": 85,
    "upstreams": 12
  },
  "proxies": [ ... ],
  "consumers": [ ... ],
  "plugin_configs": [ ... ],
  "upstreams": [ ... ]
}
```

## Restore — `POST /restore?confirm=true`

Replaces the entire gateway configuration with the provided backup payload. This is a **destructive operation**, but the payload is normalized and validated before any data is deleted:

1. **Normalizes** the restore payload once with the same `normalize_fields()` admission used by CRUD, batch, file mode, and database loaders (lowercase hosts/backend hosts/upstream targets, backend TLS SNI and DNS SAN allow-list entries, blank `custom_id` / plugin `proxy_id` → omitted). That exact canonical instance is what later preparation and persistence use — credential hashing and restore timestamps do not reintroduce the discarded wire-form original.
2. **Validates** the normalized payload for internal consistency (config version compatibility, resource ID uniqueness, consumer identity/credential uniqueness, regex listen_path compilation and length limits, listen_path+hosts uniqueness, stream proxy configuration including response_body_mode, upstream references). If validation fails, the request returns `400` with detailed errors and **existing config is NOT deleted**.
3. **Snapshots** the current namespace configuration for recovery (fail-safe — see below)
4. **Deletes** all existing proxies, consumers, plugin configs, upstreams, and junction table entries
5. **Imports** the provided resources in dependency order
6. **Rolls back** to the snapshot if the delete or any import persistence step fails

Build-out compatibility note: legacy backups whose `basicauth` entries contain fields other than exactly one `password` or `password_hash` no longer pass restore validation. Remove obsolete fields (for example an entry-local `username`) before restore. Ferrum intentionally does not add a legacy restore shim during active build-out.

### Recovery snapshot is authoritative and fail-safe

The recovery snapshot in step 3 is captured with a **non-validating raw load from the primary** (`load_namespace_snapshot`), *not* the validating `load_full_config`. That distinction matters two ways:

- **Invalid-but-present config still snapshots.** An already-invalid namespace (dangling references, conflicting listen_paths, invalid regex) — precisely what an operator runs restore to *repair* — loads its raw rows without the fatal validation pipeline, so the snapshot succeeds and rollback stays available throughout the repair. A restore that imports cleanly succeeds and repairs the namespace; if a later step fails, rollback reapplies the (still invalid) prior config.
- **One guard normally spans the entire restore.** Ferrum acquires a persistent namespace-scoped datastore guard before reading the rollback snapshot and keeps the same owner through the destructive clear, every successful-import batch, and any compensating replay. Other admin processes therefore cannot insert resources absent from the payload between phases or have a concurrent write erased by rollback. Cancellation before the first protected mutation starts bounded owner-qualified cleanup. Once clear/import/replay is dispatched, cancellation retains the fence until the outcome is definitively verified or replay settles; cancellation between a completed clear and import also retains it because the multi-phase restore is incomplete. On MongoDB, the owner pins the exact connection generation for these uncertain phases, so reconnect/failover cannot move a later phase to a different bundle. The guarded rollback replay bypasses normal mTLS DNS admission only for the captured snapshot; the guarded successful import still runs full admission. If the renewable namespace lease expires while a successful clear is still settling and another writer commits under the next lease generation, recovery releases and reacquires the guards in their normal order. It then treats the intervening writer's resources as authoritative for matching IDs, validates the combined transaction-log schema graph, and inserts only missing snapshot resources. Recovery never runs a second clear over the intervening write. An invalid combined graph fails closed without replaying any snapshot resources.
- **An unavailable guard or unreadable snapshot aborts the restore.** A connectivity/timeout failure while acquiring the pre-snapshot guard or reading the snapshot returns `503` with `failure_class: "connectivity"`; the guard-acquisition response redacts backend details. Guard contention returns the stable retryable namespace-admission `503` with `Retry-After: 1` and is not mislabeled as a database outage. Corrupt or undecodable stored rows/documents return `500` with `failure_class: "data_integrity"` and a safe resource type/id when available. All paths abort before deleting anything. Semantic config invalidity alone is still tolerated by this raw snapshot path.

Both the config resources and the `api_specs` count are read from the **primary**, never a lagging read replica, so the recovery report is authoritative.

### API specs are not restored by rollback

`api_specs` are admin-only metadata that live **outside** `GatewayConfig` and the backup/restore payload. The delete phase removes them, and neither a successful restore nor config rollback recreates them. When a failed restore rolls back a namespace that carried specs, the `500` response reports `api_specs_not_restored` (the **authoritative total**) and `api_specs_note` (guidance).

After any restore, re-submit the original spec documents via `POST /api-specs`; use `GET /api-specs` to list specs currently stored in the namespace. On rollback, spec-owned proxy/upstream/plugins are reapplied as **hand-managed** resources (`api_spec_id` is cleared), so operators may first need to remove conflicting restored resources before re-submitting a spec.

### Safety Guard

The `?confirm=true` query parameter is required. Without it, the endpoint returns `400 Bad Request` with a descriptive error message. This prevents accidental invocation.

### Request Format

Accepts the same JSON format produced by `GET /backup`. All resource arrays are optional — omitted types are treated as empty (meaning existing resources of that type will be deleted but not replaced).

```json
{
  "proxies": [ ... ],
  "consumers": [ ... ],
  "plugin_configs": [ ... ],
  "upstreams": [ ... ]
}
```

The `exported_at`, `source`, and `counts` metadata fields from a backup are silently ignored if present, so you can pass a backup response directly as the restore payload. The `version` field, if present, is validated against the current config version — a mismatch returns `400 Bad Request`.

### Body Size Limit

The restore endpoint accepts up to **100 MiB** request bodies by default (vs. 1 MiB for other endpoints), which comfortably covers 30K proxies + 30K consumers + 90K plugins (~80 MB). Configurable via the `FERRUM_ADMIN_RESTORE_MAX_BODY_SIZE_MIB` environment variable:

```bash
# Reduce to 50 MiB for constrained environments
FERRUM_ADMIN_RESTORE_MAX_BODY_SIZE_MIB=50

# Increase to 200 MiB for extremely large deployments
FERRUM_ADMIN_RESTORE_MAX_BODY_SIZE_MIB=200
```

### Size Guidance

| Deployment | Resources | Approx backup size |
|---|---|---|
| Small | ~100 proxies, ~50 consumers | 100-200 KB |
| Medium | ~1,000 proxies, ~500 consumers | 1-2 MB |
| Large | ~5,000 proxies, ~3,000 consumers | 5-10 MB |
| Very large | 10,000+ proxies, 5,000+ consumers | 15+ MB |
| Enterprise | 30,000 proxies, 30,000 consumers, 90,000 plugins | ~80 MB |

For deployments exceeding the body limit, use partial backups via `?resources=` and restore with `POST /batch` (additive).

### Memory and Performance

**Backup** serializes directly from in-memory config structs to the output buffer — no intermediate `serde_json::Value` copy. Peak memory overhead is roughly equal to the output JSON size.

**Restore** deserializes the request body directly into typed structs — again skipping the `Value` intermediate. Peak memory is body bytes + parsed structs.

**Database inserts** are chunked into 1,000-record transactions to keep WAL/redo log size bounded and avoid prolonged lock holds. A 90,000-plugin restore runs as 90 separate transactions rather than one massive transaction.

### Example: Backup & Restore Workflow

```bash
TOKEN="your-jwt-token"
SOURCE="http://source-gateway:9000"
TARGET="http://target-gateway:9000"

# 1. Backup the source gateway
curl -s -H "Authorization: Bearer $TOKEN" \
  "$SOURCE/backup" > backup.json

echo "Backed up $(cat backup.json | jq '.counts')"

# 2. Restore to the target gateway
curl -s -X POST "$TARGET/restore?confirm=true" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d @backup.json | jq .

# Response:
# {
#   "restored": {
#     "proxies": 42,
#     "consumers": 150,
#     "plugin_configs": 85,
#     "upstreams": 12
#   }
# }
```

### Error Handling

If the delete or any resource type fails during import, the endpoint removes the partial state, reapplies the pre-restore snapshot, and returns `500 Internal Server Error`:

```json
{
  "error": "Restore failed; restore rolled back and prior config retained",
  "restore_errors": [
    "consumers: unique constraint violation on username"
  ],
  "rollback": "completed",
  "api_specs_not_restored": 2,
  "api_specs_note": "2 API spec(s) were removed and are not part of config restore or rollback. Re-submit the original documents via POST /api-specs; list specs currently stored in the namespace with GET /api-specs."
}
```

The `rollback` field reports the outcome:

- `completed` — the prior config was reapplied and retained. After a clear that committed beyond its expired lease, this can instead mean the valid union of intervening resources and missing prior resources was retained.
- `incomplete` — reapplying the prior config failed; the response includes `rollback_errors` and instructs the operator to perform manual recovery. This also covers a late-clear additive recovery whose combined transaction-log schema graph is invalid: Ferrum preserves the intervening configuration and rejects the replay before writing any snapshot resources. The rollback is best-effort because it uses the same database backend that reported the failure.
- `not_needed` — the **clear definitively aborted atomically** (SQL runs it in one transaction; replica-set MongoDB in a multi-document transaction). Nothing was deleted, so the prior config — including its `api_specs` — is fully intact and no compensating re-import runs. An unknown MongoDB transaction commit result is not a definitive abort, even when an immediate read still sees the prior counts. Only standalone (non-replica-set) MongoDB, whose clear deletes collections one-by-one, can leave a known partial state and take the `completed`/`incomplete` path on an ordinary delete failure.
- `unknown_outcome` — MongoDB reported an unknown transaction commit result. Ferrum retains the namespace admission guard even when an immediate count suggests the prior config is intact, because a timed-out write may still settle later. Inspect the namespace, stop or restart the owning admin process, and remove only the verified owner-qualified guard during manual recovery.

For an unknown MongoDB commit result, Ferrum verifies authoritative namespace
counts before classifying the failure. An empty namespace is treated as a
committed clear and rolled back from the held in-memory snapshot, but the outer
guard remains fail-closed because the original commit result was uncertain.
Counts matching the snapshot likewise report `unknown_outcome` and retain the
guard. Only a definitive atomic abort takes the `not_needed` short-circuit and
releases the guard, preserving `api_specs`.

When the pre-snapshot guard cannot be acquired or the prior config cannot be
snapshotted for rollback, restore **aborts before any delete**. Connectivity
failures in either phase return `503` with
`failure_class: "connectivity"`. Stored row/document integrity failures return
`500` with `failure_class: "data_integrity"` and identify the offending resource
type/id when safely available. Both are fail-safe paths: the destructive delete
never runs when an exact rollback point cannot be captured. Data-integrity
failures use `500` because the database is reachable but its stored configuration
cannot be decoded; this lets operators distinguish persistent corruption from a
retryable availability problem.

`api_specs_not_restored` / `api_specs_note` appear only when the namespace carried API specs, which config restore and rollback cannot recreate (see above). The payload is still validated before the snapshot and delete phases; validation failures return `400` and leave existing config untouched.

#### Restore aborted — `503`

```json
{
  "error": "Restore aborted: the prior configuration could not be snapshotted for rollback (database unavailable). Existing config was NOT deleted; retry once the database is reachable.",
  "failure_class": "connectivity",
  "restore_errors": [
    "failed to snapshot prior config for rollback: pool timed out while waiting for an open connection"
  ]
}
```

#### Restore aborted — `500` data integrity

```json
{
  "error": "Restore aborted: the prior configuration contains a data-integrity error and could not be snapshotted for rollback. Existing config was NOT deleted; repair the identified stored resource before retrying.",
  "failure_class": "data_integrity",
  "restore_errors": [
    "data-integrity failure decoding proxy resource 'proxy-123'"
  ]
}
```

## Restore vs. Batch

| Feature | `POST /restore` | `POST /batch` |
|---------|-----------------|---------------|
| Deletes existing data | Yes (full wipe) | No (additive) |
| Safety guard | Requires `?confirm=true` | None |
| Use case | Disaster recovery, environment migration | Incremental provisioning |
| Body size limit | 100 MiB (configurable) | 1 MiB |
| Response key | `restored` | `created` |

## Backup in File Mode and Data Plane Mode

In **file mode** and **data plane mode**, there is no database. The backup endpoint falls back to the in-memory cached config:

```bash
# Works in file/DP mode — returns cached config
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:9000/backup

# Response includes: "source": "cached"
```

Restore requires a database and will return `503 Service Unavailable` in file/DP mode.

## Recommended Practices

1. **Keep external backups**: Restore takes an automatic recovery snapshot, but periodic external backups remain necessary for database-wide outages and disaster recovery.
2. **Validate backup integrity**: Check the `counts` field matches expectations before restoring.
3. **Use batch for incremental changes**: If you only need to add resources without wiping existing ones, use `POST /batch` instead.
4. **Automate periodic backups**: Schedule `GET /backup` via cron for disaster recovery snapshots.
5. **Cross-environment migration**: Use backup/restore to promote configuration from staging to production.
