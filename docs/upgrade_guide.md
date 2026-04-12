# Safe Upgrade Guide

This document describes how to safely upgrade Ferrum Edge between versions with zero data loss and a clear rollback path. The approach varies by operating mode, but the core principle is the same: **validate the new version against a copy of your data before cutting over production traffic.**

## Database Mode (`FERRUM_MODE=database`)

This is the most involved upgrade because schema migrations may alter your database. The strategy is: clone the database, migrate the clone, validate with the new binary, then cut over.

### Step-by-Step

#### 1. Backup Your Current Database

Create a full copy of the production database. This copy serves two purposes: it's the migration target for the new version, and it's your rollback safety net.

```bash
# PostgreSQL
pg_dump -Fc -h db-host -U ferrum ferrum_db > ferrum_backup_v1.dump
createdb -h db-host -U ferrum ferrum_db_upgrade
pg_restore -h db-host -U ferrum -d ferrum_db_upgrade ferrum_backup_v1.dump

# MySQL
mysqldump -h db-host -u ferrum -p ferrum_db > ferrum_backup_v1.sql
mysql -h db-host -u ferrum -p -e "CREATE DATABASE ferrum_db_upgrade"
mysql -h db-host -u ferrum -p ferrum_db_upgrade < ferrum_backup_v1.sql

# SQLite
cp ferrum.db ferrum_upgrade.db
```

Alternatively, use the Admin API backup endpoint to capture the logical config:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:9000/backup > ferrum-config-backup.json
```

#### 2. Run Migrations Against the Cloned Database

Use the new Ferrum Edge binary in `migrate` mode to apply pending schema migrations to the clone. The original database is untouched.

```bash
# Dry run first — see what would change
FERRUM_MODE=migrate \
  FERRUM_MIGRATE_ACTION=up \
  FERRUM_MIGRATE_DRY_RUN=true \
  FERRUM_DB_TYPE=postgres \
  FERRUM_DB_URL=postgres://ferrum:pass@db-host/ferrum_db_upgrade \
  ./ferrum-edge-new

# Apply migrations
FERRUM_MODE=migrate \
  FERRUM_MIGRATE_ACTION=up \
  FERRUM_DB_TYPE=postgres \
  FERRUM_DB_URL=postgres://ferrum:pass@db-host/ferrum_db_upgrade \
  ./ferrum-edge-new
```

Check migration status to confirm everything applied cleanly:

```bash
FERRUM_MODE=migrate \
  FERRUM_MIGRATE_ACTION=status \
  FERRUM_DB_TYPE=postgres \
  FERRUM_DB_URL=postgres://ferrum:pass@db-host/ferrum_db_upgrade \
  ./ferrum-edge-new
```

#### 3. Validate the New Version Against the Upgraded Database

Start the new binary in `database` mode pointing at the cloned database. This lets you exercise the full proxy and admin API without touching production.

```bash
# Run new version against cloned DB on non-production ports
FERRUM_MODE=database \
  FERRUM_DB_TYPE=postgres \
  FERRUM_DB_URL=postgres://ferrum:pass@db-host/ferrum_db_upgrade \
  FERRUM_PROXY_HTTP_PORT=8100 \
  FERRUM_PROXY_HTTPS_PORT=8543 \
  FERRUM_ADMIN_HTTP_PORT=9100 \
  FERRUM_ADMIN_JWT_SECRET=your-secret \
  ./ferrum-edge-new
```

Validate:

- **Health check**: `curl http://localhost:9100/health` — confirm `status: ok`
- **Config loaded**: `curl -H "Authorization: Bearer $TOKEN" http://localhost:9100/proxies` — verify all proxies are present and correctly configured
- **Proxy traffic**: send test requests through port 8100 to verify routing, plugin execution, and backend connectivity
- **Admin API**: test CRUD operations against the staging instance
- **Logs**: check for warnings or errors at `FERRUM_LOG_LEVEL=info`

#### 4. Cut Over Production

Once validation passes, stop the old binary and start the new one against the production database. The new binary will run any pending migrations automatically on startup (or you can run them explicitly first with `FERRUM_MODE=migrate`).

```bash
# Option A: Let the new binary auto-migrate on startup
# Stop old binary, then:
FERRUM_MODE=database \
  FERRUM_DB_TYPE=postgres \
  FERRUM_DB_URL=postgres://ferrum:pass@db-host/ferrum_db \
  ./ferrum-edge-new

# Option B: Explicit migration then start
FERRUM_MODE=migrate \
  FERRUM_MIGRATE_ACTION=up \
  FERRUM_DB_TYPE=postgres \
  FERRUM_DB_URL=postgres://ferrum:pass@db-host/ferrum_db \
  ./ferrum-edge-new

FERRUM_MODE=database \
  FERRUM_DB_TYPE=postgres \
  FERRUM_DB_URL=postgres://ferrum:pass@db-host/ferrum_db \
  ./ferrum-edge-new
```

#### 5. Rollback Path

If issues arise after cutting over:

1. **Stop** the new binary
2. **Restore** the original database from the backup taken in step 1:
   ```bash
   # PostgreSQL
   dropdb -h db-host -U ferrum ferrum_db
   createdb -h db-host -U ferrum ferrum_db
   pg_restore -h db-host -U ferrum -d ferrum_db ferrum_backup_v1.dump

   # MySQL
   mysql -h db-host -u ferrum -p -e "DROP DATABASE ferrum_db; CREATE DATABASE ferrum_db"
   mysql -h db-host -u ferrum -p ferrum_db < ferrum_backup_v1.sql

   # SQLite
   cp ferrum_original.db ferrum.db
   ```
3. **Restart** the old binary against the restored database

The old binary + old database is a fully consistent state. No data is lost.

> **Important**: Schema migrations are forward-only. You cannot run the old binary against a database that has been migrated to a newer schema. Always restore from the pre-migration backup when rolling back.

---

## Control Plane / Data Plane Mode (`FERRUM_MODE=cp` / `dp`)

CP/DP upgrades follow the same database strategy for the CP, with the added consideration of rolling out DP nodes. The key property that makes this safe: **DPs cache their config in memory and continue serving traffic even if the CP is temporarily unavailable.**

### Version Negotiation (Built-In Safety Net)

Starting in v0.9.0, CP and DP nodes exchange their Ferrum Edge binary version during gRPC handshake. The **major and minor** version components must match — patch-level differences (e.g., `0.9.0` vs `0.9.1`) are allowed.

| CP Version | DP Version | Result |
|------------|------------|--------|
| `0.9.0` | `0.9.0` | Allowed |
| `0.9.0` | `0.9.3` | Allowed (patch difference) |
| `0.9.0` | `0.10.0` | **Rejected** — DP Subscribe/GetFullConfig fails with `FAILED_PRECONDITION` |
| `1.0.0` | `0.9.0` | **Rejected** — major version mismatch |

What happens on rejection:
- The **CP** returns a gRPC `FAILED_PRECONDITION` status with a message identifying both versions and the required DP version.
- The **DP** logs the error, disconnects, and retries in 5 seconds (standard reconnect loop). It will keep failing until upgraded to a compatible version.
- **No config is exchanged** — the DP continues serving traffic with whatever config it had cached before the connection attempt.

This prevents a scenario where a newer CP pushes config containing fields or structures that an older DP cannot deserialize, which could cause silent data loss or deserialization failures.

You can verify versions via the authenticated `GET /admin/metrics` endpoint on any node — the `gateway.ferrum_version` field reports the running binary version.

### Upgrade Order

Always upgrade in this order: **CP first, then DPs.** The CP manages the database and schema migrations. DPs are stateless proxies that receive config via gRPC. Version negotiation ensures that if you forget to upgrade a DP, it will refuse the incompatible config rather than silently applying a partial parse.

### Step-by-Step

#### 1. Backup the CP Database

Same as database mode step 1 — clone the CP's database.

#### 2. Validate New CP Against Cloned Database

Run the new CP binary against the cloned database on staging ports:

```bash
FERRUM_MODE=cp \
  FERRUM_DB_TYPE=postgres \
  FERRUM_DB_URL=postgres://ferrum:pass@db-host/ferrum_db_upgrade \
  FERRUM_CP_GRPC_LISTEN_ADDR=0.0.0.0:50052 \
  FERRUM_ADMIN_HTTP_PORT=9100 \
  FERRUM_ADMIN_JWT_SECRET=your-secret \
  FERRUM_CP_DP_GRPC_JWT_SECRET=grpc-secret \
  ./ferrum-edge-new
```

Optionally connect a test DP to the staging CP to verify the full gRPC config sync pipeline:

```bash
FERRUM_MODE=dp \
  FERRUM_DP_CP_GRPC_URL=http://cp-host:50052 \
  FERRUM_CP_DP_GRPC_JWT_SECRET=grpc-secret \
  FERRUM_PROXY_HTTP_PORT=8100 \
  FERRUM_ADMIN_HTTP_PORT=9200 \
  FERRUM_ADMIN_JWT_SECRET=your-secret \
  ./ferrum-edge-new
```

Verify the test DP receives the full config snapshot and proxies traffic correctly.

#### 3. Upgrade the Production CP

Stop the old CP, run migrations against the production database, and start the new CP.

During the CP restart window, existing DPs continue serving traffic with their cached config. No downtime for API consumers.

```bash
# Stop old CP, then:
FERRUM_MODE=migrate \
  FERRUM_MIGRATE_ACTION=up \
  FERRUM_DB_TYPE=postgres \
  FERRUM_DB_URL=postgres://ferrum:pass@db-host/ferrum_db \
  ./ferrum-edge-new

FERRUM_MODE=cp \
  FERRUM_DB_TYPE=postgres \
  FERRUM_DB_URL=postgres://ferrum:pass@db-host/ferrum_db \
  FERRUM_CP_GRPC_LISTEN_ADDR=0.0.0.0:50051 \
  FERRUM_ADMIN_JWT_SECRET=your-secret \
  FERRUM_CP_DP_GRPC_JWT_SECRET=grpc-secret \
  ./ferrum-edge-new
```

#### 4. Rolling Upgrade of DPs

Upgrade DP nodes one at a time (or in batches). Each DP reconnects to the CP on startup and receives a fresh config snapshot.

```bash
# On each DP node, stop old binary and start new:
FERRUM_MODE=dp \
  FERRUM_DP_CP_GRPC_URL=http://cp-host:50051 \
  FERRUM_CP_DP_GRPC_JWT_SECRET=grpc-secret \
  FERRUM_ADMIN_JWT_SECRET=your-secret \
  ./ferrum-edge-new
```

If a load balancer sits in front of the DP fleet, drain each node before restarting to avoid dropping in-flight requests.

#### Multi-CP Failover Deployments

When DPs are configured with `FERRUM_DP_CP_GRPC_URLS` (multiple CPs), upgrades are smoother:

1. Upgrade CP₁ first (DPs automatically fail over to CP₂ during the restart window)
2. Upgrade CP₂ (DPs fail back to CP₁ which is already running the new version)
3. Rolling upgrade DPs as above

This eliminates the read-only window during CP upgrades — DPs always have at least one CP available for config updates.

```bash
# DP configured for multi-CP failover:
FERRUM_MODE=dp \
  FERRUM_DP_CP_GRPC_URLS=https://cp1:50051,https://cp2:50051 \
  FERRUM_CP_DP_GRPC_JWT_SECRET=grpc-secret \
  FERRUM_ADMIN_JWT_SECRET=your-secret \
  ./ferrum-edge-new
```

#### 5. Rollback Path

- **DP rollback**: Stop the new DP binary, restart the old one. It reconnects to the CP and gets the current config via gRPC. DPs are stateless — rollback is instant.
- **CP rollback**: Stop the new CP, restore the database from backup (step 1), restart the old CP. All DPs will reconnect and receive the old config. During the CP restart, DPs serve cached config.

> **Note**: If the new CP has already broadcast a migrated config to DPs, rolling back the CP means DPs will receive the old-schema config on reconnect. Since DPs are always overwritten by the CP's config on connect, this is safe — the old config format replaces whatever the DP had cached.

---

## File Mode (`FERRUM_MODE=file`)

File mode is the simplest to upgrade because there's no database. The config file is read at startup and on SIGHUP reload (Unix). The risk is that a new Ferrum version might interpret existing config fields differently or require new fields.

### Step-by-Step

#### 1. Backup Your Config File

```bash
cp config.yaml config.yaml.backup-v1
```

#### 2. Run Config Migration (If Needed)

New Ferrum versions may introduce a new config file version. Use migrate mode to update your file:

```bash
# Dry run — see what would change
FERRUM_MODE=migrate \
  FERRUM_MIGRATE_ACTION=config \
  FERRUM_MIGRATE_DRY_RUN=true \
  FERRUM_FILE_CONFIG_PATH=./config.yaml \
  ./ferrum-edge-new

# Apply migration (creates a timestamped .backup automatically)
FERRUM_MODE=migrate \
  FERRUM_MIGRATE_ACTION=config \
  FERRUM_FILE_CONFIG_PATH=./config.yaml \
  ./ferrum-edge-new
```

Even if no version bump is required, the new binary will auto-migrate the config in memory on startup and log a warning if the on-disk version is behind.

#### 3. Validate the New Version

Start the new binary on non-production ports pointing at the (possibly migrated) config file:

```bash
FERRUM_MODE=file \
  FERRUM_FILE_CONFIG_PATH=./config.yaml \
  FERRUM_PROXY_HTTP_PORT=8100 \
  FERRUM_PROXY_HTTPS_PORT=8543 \
  FERRUM_ADMIN_HTTP_PORT=9100 \
  FERRUM_LOG_LEVEL=info \
  ./ferrum-edge-new
```

Validate:

- **Health check**: `curl http://localhost:9100/health`
- **Config loaded**: `curl http://localhost:9100/proxies` — verify all routes are present
- **Proxy traffic**: send test requests through port 8100
- **Logs**: look for deprecation warnings or config parsing errors

#### 4. Cut Over

Stop the old binary, start the new one on production ports:

```bash
FERRUM_MODE=file \
  FERRUM_FILE_CONFIG_PATH=./config.yaml \
  ./ferrum-edge-new
```

#### 5. Rollback Path

1. Stop the new binary
2. Restore the config backup: `cp config.yaml.backup-v1 config.yaml`
3. Restart the old binary

---

## General Recommendations

### Pre-Upgrade Checklist

- [ ] Read the release notes for breaking changes, deprecated fields, and new required fields
- [ ] Back up your database (database/CP modes) or config file (file mode)
- [ ] Back up your `ferrum.conf` if you use one — new versions may add env vars with different defaults
- [ ] Use `GET /backup` to capture a logical config snapshot (database/CP modes)
- [ ] Run migrations in dry-run mode before applying
- [ ] Validate the new version on non-production ports before cutting over

### Version Compatibility

| Component | Forward Compatible? | Backward Compatible? |
|-----------|-------------------|---------------------|
| Database schema | Yes (auto-migrates forward) | No (old binary cannot read new schema) |
| Config file format | Yes (auto-migrates in memory) | Depends on version gap |
| gRPC protocol (CP↔DP) | Same major.minor required (enforced at connect time) | Same major.minor required |
| Admin API | Generally stable | Check release notes |

### Downtime Expectations

| Mode | Upgrade Downtime | With Load Balancer |
|------|-----------------|-------------------|
| Database (single instance) | Brief (binary restart) | Near-zero (drain + restart) |
| CP/DP | Zero for API consumers | Zero (rolling DP restart) |
| File (single instance) | Brief (binary restart) | Near-zero (drain + restart) |

### Environment Variable Changes

New Ferrum versions may introduce new `FERRUM_*` environment variables. Review `ferrum.conf` in the release for new defaults. Existing variables that are removed will be silently ignored — check release notes for any behavioral changes.
