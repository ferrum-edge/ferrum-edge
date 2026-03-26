# Admin API: Backup & Restore

The Ferrum Gateway Admin API provides dedicated endpoints for full configuration backup and restore, enabling disaster recovery, environment migration, and configuration snapshots.

## Overview

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/backup` | GET | Export complete gateway config as JSON |
| `/restore?confirm=true` | POST | Replace all config from a backup payload |

Both endpoints require JWT authentication. The restore endpoint is blocked in read-only mode.

## Backup — `GET /backup`

Returns the entire gateway configuration as a single JSON document. The output format is directly compatible with both `POST /restore` (full replacement) and `POST /batch` (additive import).

### Key Behaviors

- **Unredacted credentials**: Unlike `GET /consumers`, the backup endpoint returns raw credential hashes (e.g., bcrypt `$2b$` or `hmac_sha256:` values). This is necessary for faithful restoration.
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

Replaces the entire gateway configuration with the provided backup payload. This is a **destructive operation**:

1. **Deletes** all existing proxies, consumers, plugin configs, upstreams, and junction table entries
2. **Imports** the provided resources in dependency order

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

The `version`, `exported_at`, `source`, and `counts` metadata fields from a backup are silently ignored if present, so you can pass a backup response directly as the restore payload.

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

If some resource types fail during import while others succeed, the endpoint returns `207 Multi-Status`:

```json
{
  "restored": {
    "proxies": 42,
    "consumers": 0,
    "plugin_configs": 85,
    "upstreams": 12
  },
  "errors": [
    "consumers: unique constraint violation on username"
  ]
}
```

**Important**: The delete phase happens before import. If import partially fails, you may end up with fewer resources than before. Use `GET /backup` first to create a safety snapshot.

## Restore vs. Batch

| Feature | `POST /restore` | `POST /batch` |
|---------|-----------------|---------------|
| Deletes existing data | Yes (full wipe) | No (additive) |
| Safety guard | Requires `?confirm=true` | None |
| Use case | Disaster recovery, environment migration | Incremental provisioning |
| Body size limit | 10 MiB | 1 MiB |
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

1. **Always backup before restore**: Run `GET /backup` and save the output before running `POST /restore`.
2. **Validate backup integrity**: Check the `counts` field matches expectations before restoring.
3. **Use batch for incremental changes**: If you only need to add resources without wiping existing ones, use `POST /batch` instead.
4. **Automate periodic backups**: Schedule `GET /backup` via cron for disaster recovery snapshots.
5. **Cross-environment migration**: Use backup/restore to promote configuration from staging to production.
