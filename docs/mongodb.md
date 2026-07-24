# MongoDB Deployment Guide

This guide covers deploying Ferrum Edge with MongoDB as the configuration database. MongoDB is a NoSQL alternative to the SQL backends (PostgreSQL, MySQL, SQLite), offering document-based storage with native replica set support.

## When to Use MongoDB

| Choose MongoDB when... | Choose SQL when... |
|---|---|
| Your team already operates MongoDB | You want the simplest setup (SQLite) |
| You want built-in replica set failover | You need multi-document ACID transactions without a replica set |
| You prefer document-based config storage | You want mature schema migration tooling |
| You're deploying on MongoDB Atlas | You're using managed RDS/Cloud SQL |
| You want driver-managed topology discovery | You need SQL read-replica admin-read offload |

## Quick Start

```bash
# Start MongoDB (Docker)
docker run -d --name mongo -p 27017:27017 mongo:7

# Start Ferrum Edge
FERRUM_MODE=database \
FERRUM_DB_TYPE=mongodb \
FERRUM_DB_URL="mongodb://localhost:27017" \
FERRUM_MONGO_DATABASE=ferrum \
FERRUM_ADMIN_JWT_SECRET="change-me-to-a-32-character-admin-secret" \
FERRUM_LOG_LEVEL=info \
cargo run --release -- run
```

## URL Path vs FERRUM_MONGO_DATABASE

The database name in the MongoDB URL path (e.g., `mongodb://host:27017/mydb`) is the **auth database** — where MongoDB looks up user credentials. `FERRUM_MONGO_DATABASE` controls which database the gateway stores its config collections in. These are independent:

```bash
# Authenticate against "admin" DB, store config in "ferrum" DB
FERRUM_DB_URL="mongodb://user:pass@host:27017/?authSource=admin"
FERRUM_MONGO_DATABASE=ferrum

# No authentication (dev) — URL path is ignored, config goes to "ferrum"
FERRUM_DB_URL="mongodb://localhost:27017"
FERRUM_MONGO_DATABASE=ferrum
```

For production with authentication, always use `?authSource=admin` (or your auth DB) explicitly rather than putting the database name in the URL path.

## Configuration Reference

### MongoDB-Specific Settings

| Variable | Default | Description |
|---|---|---|
| `FERRUM_MONGO_DATABASE` | `ferrum` | Database name for gateway config storage |
| `FERRUM_MONGO_APP_NAME` | (none) | App name visible in `db.currentOp()` and server logs |
| `FERRUM_MONGO_REPLICA_SET` | (none) | Replica set name. Required for transactions and change streams |
| `FERRUM_MONGO_AUTH_MECHANISM` | (auto) | Auth override: `SCRAM-SHA-256`, `MONGODB-X509`, etc. |
| `FERRUM_MONGO_SERVER_SELECTION_TIMEOUT_SECONDS` | `30` | How long the driver waits to find a suitable server |
| `FERRUM_MONGO_CONNECT_TIMEOUT_SECONDS` | `10` | TCP connection timeout per server |

### MongoDB Driver Runtime Options

MongoDB connection pooling and topology behavior mostly lives in the MongoDB URI. `FERRUM_DB_POOL_*` is not read on the MongoDB code path.

| Concern | Configure with | Notes |
|---|---|---|
| Max pool size | `maxPoolSize` URI option | MongoDB equivalent of pool capacity. Example: `?maxPoolSize=100` |
| Minimum idle pool size | `minPoolSize` URI option | Keeps warm driver connections open. Example: `?minPoolSize=5` |
| Idle connection age | `maxIdleTimeMS` URI option | Driver-side idle eviction. Example: `?maxIdleTimeMS=600000` |
| Pool checkout wait | `waitQueueTimeoutMS` URI option | Driver-side wait for an available connection. |
| Server selection timeout | `FERRUM_MONGO_SERVER_SELECTION_TIMEOUT_SECONDS` or `serverSelectionTimeoutMS` URI option | The env var is applied programmatically by Ferrum and overrides the URI value when set. |
| TCP connect timeout | `FERRUM_MONGO_CONNECT_TIMEOUT_SECONDS` or `connectTimeoutMS` URI option | The env var is applied programmatically by Ferrum and overrides the URI value when set. |
| Read preference | Ignored by Ferrum's config store | Runtime config reads are forced to primary for authoritative polling consistency. |
| TLS | `FERRUM_DB_TLS_MODE` plus certificate path env vars, or URI options such as `tls=true`, `tlsCAFile`, `tlsCertificateKeyFile` | Env mode values supported for MongoDB are `disable`, `require`, and `verify-full`. |
| App name | `FERRUM_MONGO_APP_NAME` or `appName` URI option | Helps identify Ferrum connections in MongoDB server diagnostics. The env var overrides the URI value when set. |

### Shared Settings (SQL + MongoDB)

These `FERRUM_DB_*` settings apply to both SQL and MongoDB backends:

| Variable | MongoDB Behavior |
|---|---|
| `FERRUM_DB_TYPE` | Set to `mongodb` |
| `FERRUM_DB_URL` | MongoDB connection string (`mongodb://` or `mongodb+srv://`) |
| `FERRUM_DB_POLL_INTERVAL` | Polling interval in seconds (same as SQL) |
| `FERRUM_DB_CONFIG_BACKUP_PATH` | On-disk JSON backup served if the initial config load fails transiently after connect. Unlike SQL backends, MongoDB has no lazy-pool connect-time bootstrap: if every configured Mongo URL is unreachable at startup the process exits rather than serving the backup |
| `FERRUM_DB_FAILOVER_URLS` | Comma-separated fallback MongoDB URLs (same pattern as SQL, but see [Failover](#failover) below) |
| `FERRUM_DB_SLOW_QUERY_THRESHOLD_MS` | Slow query warning threshold (same as SQL) |
| `FERRUM_DB_TLS_MODE` | MongoDB TLS policy: `disable`, `require`, or `verify-full` (see [TLS](#tls)) |
| `FERRUM_DB_TLS_CA_CERT_PATH` | CA certificate for server verification |
| `FERRUM_DB_TLS_CLIENT_CERT_PATH` | Client certificate for mTLS; may be an already-combined cert+key PEM when `FERRUM_DB_TLS_CLIENT_KEY_PATH` is omitted |
| `FERRUM_DB_TLS_CLIENT_KEY_PATH` | Client private key for mTLS when cert and key are supplied as separate files |

### SQL-Only Settings (Ignored for MongoDB)

These settings have no effect when `FERRUM_DB_TYPE=mongodb`:

| Variable | Why N/A for MongoDB |
|---|---|
| `FERRUM_DB_READ_REPLICA_URL` | SQL-only. MongoDB uses one authoritative client and Ferrum forces primary reads. |
| `FERRUM_DB_POOL_MAX_CONNECTIONS` | MongoDB driver manages its own connection pool internally |
| `FERRUM_DB_POOL_MIN_CONNECTIONS` | MongoDB driver manages its own connection pool internally |
| `FERRUM_DB_POOL_ACQUIRE_TIMEOUT_SECONDS` | MongoDB uses `FERRUM_MONGO_SERVER_SELECTION_TIMEOUT_SECONDS` instead |
| `FERRUM_DB_POOL_IDLE_TIMEOUT_SECONDS` | MongoDB driver manages idle connection eviction internally |
| `FERRUM_DB_POOL_MAX_LIFETIME_SECONDS` | MongoDB driver manages connection cycling internally |
| `FERRUM_DB_POOL_CONNECT_TIMEOUT_SECONDS` | Use `FERRUM_MONGO_CONNECT_TIMEOUT_SECONDS` instead |
| `FERRUM_DB_POOL_STATEMENT_TIMEOUT_SECONDS` | MongoDB has no per-statement timeout (use `maxTimeMS` in queries if needed) |

## Read Consistency

Ferrum's MongoDB config store uses primary reads for startup full loads,
incremental change-log polling, relationship reads, and admin reads.
If `FERRUM_DB_URL` includes a `readPreference` option, Ferrum logs a warning and
overrides it to primary when building the MongoDB client. This prevents replica
lag from hiding runtime config changes or advancing polling cursors against a
stale secondary.

When `FERRUM_MONGO_REPLICA_SET` is configured, startup and fallback full loads
run inside a snapshot transaction so proxies, consumers, plugin configs, and
upstreams come from one multi-collection view. A full-load query, decode, or
validation failure rejects the complete candidate and the gateway keeps serving
the last known-good runtime configuration. Standalone MongoDB deployments cannot
provide multi-collection snapshots; Ferrum uses sequential primary reads there
and rejects candidates only for errors and validation checks enforced by the
runtime load path, so concurrent writes can require a later poll to converge.

`FERRUM_DB_READ_REPLICA_URL` is SQL-only. MongoDB replica sets are still useful
for primary failover, transactions, and majority write concern; they are not a
Ferrum config-polling read-offload mechanism.

## Failover

### Native Replica Set Failover (Preferred)

When using a MongoDB replica set, the driver handles failover automatically. List all members in the connection string:

```bash
FERRUM_DB_URL="mongodb://mongo1:27017,mongo2:27017,mongo3:27017/ferrum?replicaSet=rs0"
FERRUM_MONGO_REPLICA_SET=rs0
```

If the primary goes down, the driver automatically discovers and connects to the new primary after election. **No `FERRUM_DB_FAILOVER_URLS` needed** — this is the key difference from SQL backends.

### SRV Record Failover (Atlas / DNS-based)

MongoDB Atlas and DNS-based deployments use SRV records for automatic topology discovery:

```bash
FERRUM_DB_URL="mongodb+srv://user:pass@cluster0.abc123.mongodb.net/ferrum"
```

The driver resolves SRV records to discover all replica set members. No additional failover configuration needed.

### FERRUM_DB_FAILOVER_URLS (Standalone Fallback)

`FERRUM_DB_FAILOVER_URLS` still works with MongoDB for standalone (non-replica-set) endpoints that expose the same authoritative dataset:

```bash
FERRUM_DB_URL="mongodb://primary-mongo:27017"
FERRUM_DB_FAILOVER_URLS="mongodb://backup-mongo:27017"
```

Do not point these URLs at independent, unreplicated datasets: no datastore lock or
write can serialize two divergent databases. For replica sets, list all members
in the primary URL instead of using `FERRUM_DB_FAILOVER_URLS`.

## TLS

MongoDB TLS can be configured two ways. See [docs/database_tls.md](database_tls.md#mongodb) for full details.

### Approach 1: FERRUM_DB_TLS_* Environment Variables (Recommended)

Uses the canonical database TLS env vars. MongoDB supports `disable`, `require`, and `verify-full` here; use URI options for more specialized driver TLS settings.

```bash
FERRUM_DB_TLS_MODE=verify-full
FERRUM_DB_TLS_CA_CERT_PATH=/certs/ca.pem
FERRUM_DB_TLS_CLIENT_CERT_PATH=/certs/client.crt    # mTLS
FERRUM_DB_TLS_CLIENT_KEY_PATH=/certs/client.key      # mTLS
```

`FERRUM_DB_TLS_MODE=require` enables encrypted MongoDB connections but allows invalid server certificates. `FERRUM_DB_TLS_MODE=verify-full` enables TLS and validates the server certificate chain, using `FERRUM_DB_TLS_CA_CERT_PATH` when provided.

**Note:** MongoDB requires client cert + key in a single PEM file. Set only `FERRUM_DB_TLS_CLIENT_CERT_PATH` when it already points to a combined PEM, or provide separate cert/key files and the gateway automatically combines them into an owner-scoped temporary PEM. Generated PEMs use restrictive permissions, remain available while the active MongoDB driver client may need them, and are removed automatically after the owning connection bundle is dropped.

### Approach 2: Connection String Options

```bash
FERRUM_DB_URL="mongodb://host:27017/ferrum?tls=true&tlsCAFile=/certs/ca.pem&tlsCertificateKeyFile=/certs/client-combined.pem"
```

Configure MongoDB TLS in exactly one source: either the `FERRUM_DB_TLS_*` environment variables **or** connection-string TLS options — not both. If `FERRUM_DB_TLS_MODE` is set and any configured MongoDB URI (`FERRUM_DB_URL` or a `FERRUM_DB_FAILOVER_URLS` entry) also carries TLS options (a `tls`/`ssl` query parameter or the implicit-TLS `mongodb+srv://` scheme), the gateway fails startup with a conflict error rather than silently letting one source win. Unset `FERRUM_DB_TLS_MODE` when you want the connection string to be authoritative.

### X.509 Certificate Authentication

For passwordless authentication using client certificates:

```bash
FERRUM_MONGO_AUTH_MECHANISM=MONGODB-X509
FERRUM_DB_TLS_MODE=verify-full
FERRUM_DB_TLS_CA_CERT_PATH=/certs/ca.pem
FERRUM_DB_TLS_CLIENT_CERT_PATH=/certs/client.crt
FERRUM_DB_TLS_CLIENT_KEY_PATH=/certs/client.key
```

## Replica Sets and Transactions

### When You Need a Replica Set

| Feature | Standalone | Replica Set |
|---|---|---|
| Single-document CRUD | Atomic | Atomic |
| Multi-document operations (e.g., delete proxy + plugins) | Fail-safe sequential ordering (partial failures leave recoverable orphans) | Transactional (ACID) via `ClientSession::start_transaction` |
| Change streams (future) | Not available | Available |
| Read preference routing | Not available | Available |
| Automatic failover | Not available | Automatic |

For production, a **replica set is strongly recommended**. Setting `FERRUM_MONGO_REPLICA_SET` (or `?replicaSet=...` in the connection string) enables true multi-document ACID transactions for `delete_proxy` / `update_proxy` — the proxy document, its proxy-scoped plugin configs, and the orphaned-proxy_group cleanup all commit atomically.

Without a replica set, the gateway falls back to a fail-safe sequential ordering: the proxy document is deleted **before** its plugin configs, so a partial failure can only leave orphaned plugin configs (no proxy references them). Orphans are recoverable; the previous order — plugin configs first — could leave a proxy in the DB referencing now-deleted plugin_config IDs, which validation rejects on every subsequent polling cycle until manually cleaned up.

### Minimum Replica Set (Development)

```bash
# Start a single-node replica set for development
docker run -d --name mongo-rs -p 27017:27017 mongo:7 --replSet rs0
docker exec mongo-rs mongosh --eval "rs.initiate()"

# Configure Ferrum Edge
FERRUM_DB_URL="mongodb://localhost:27017/ferrum?replicaSet=rs0"
FERRUM_MONGO_REPLICA_SET=rs0
```

### Production Replica Set

A production MongoDB replica set typically has 3+ members:

```bash
FERRUM_DB_URL="mongodb://mongo1:27017,mongo2:27017,mongo3:27017/ferrum?replicaSet=rs0&w=majority"
FERRUM_MONGO_REPLICA_SET=rs0
FERRUM_MONGO_DATABASE=ferrum
```

The `w=majority` write concern ensures writes are acknowledged by a majority of members before returning, providing durability guarantees.

### Concurrent-Write Admission Hardening (issue #2122)

Admission checks that cannot be expressed as unique indexes (host-overlap route uniqueness, upstream reference integrity) are check-then-write and therefore raceable. The gateway hardens them differently per topology:

**Replica set (full serialization):**

- **Route uniqueness (DB-H1)** — `create_proxy`/`update_proxy` transactions first upsert a nonce document in the `proxy_route_locks` collection (`_id = "{namespace}:{route_key_hash}"`), then re-run the host/listen-path uniqueness check *inside* the transaction. Two concurrent transactions touching the same route bucket write-conflict on the lock document; the driver aborts and retries one, serializing them — the Mongo analogue of SQL's `SELECT ... FOR UPDATE` lock row.
- **Upstream references (DB-H4)** — proxy writes that reference an upstream upsert a nonce document in `upstream_ref_guards` (`_id = "{namespace}:{upstream_id}"`) and verify the upstream exists in-session; `delete_upstream` writes the same guard document and runs its referencing-proxy checks inside its transaction. A concurrent create-referencing-proxy and delete-upstream pair write-conflict on the guard and serialize. The upstream document itself is never modified.

**Standalone (convergent post-write reconciliation):** without transactions the gateway performs the check again *after* the write. Route conflicts resolve by deterministic loser-yield on `(created_at, _id)` — the losing document removes/restores itself and the request gets a 409; upstream delete-vs-reference races re-check after the delete and restore the upstream if a reference appeared. Every interleaving of one concurrent pair converges, but a narrow residual window remains — **replica sets are required for full concurrent-write safety**, consistent with the incremental-polling and multi-document-atomicity requirements above.

Consumer identity uniqueness (issue #2121 — `id`/`username`/`custom_id` share one keyspace per namespace) needs no lock documents: it is enforced atomically by the `consumer_identity_index` collection's `_id = "{namespace}:{identity_value}"` uniqueness, reserved *before* the consumer write on standalone deployments and written in the same transaction on replica sets. Consumer documents themselves use `_id = "{namespace}:{id}"`, making consumer ids per-namespace.

mTLS `san_dns` identity admission uses a separate majority-durable,
non-expiring namespace mutex in `mtls_dns_admission_locks`. The connection
bundle that acquires the mutex is pinned through the authoritative candidate
read, protected mutation, and owner-qualified release; reconnect/failover is
deferred while that generation is pinned. A cancelled, timed-out, or failed
future before any protected mutation is dispatched starts bounded,
owner-qualified mutex cleanup and releases the generation pin when cleanup
settles. A cancellation after a mutation was dispatched has an uncertain write
outcome, so Ferrum retains both the MongoDB mutex document and the process-local
connection pin instead of deleting the fence from `Drop`. Verify the durable
write outcome, stop or restart that admin process, and only then remove the exact
owner-qualified mutex document. Definitive server rejections (including a
duplicate-key loser) and definitively aborted transactions explicitly settle
and release the mutex; they do not create a permanent operator-recovery fence.
A settled operation also releases its process-local connection-generation pin
when owner-qualified mutex cleanup fails or loses its acknowledgement. The
durable document remains fail-closed when it still exists, cleanup status is
logged for operator recovery, and reconnect/failover can recover the process;
only an uncertain protected mutation retains both the fence and local pin.
A restore keeps one pin and owner from its pre-clear rollback snapshot through
the clear, all import batches, and any compensating replay. Credential endpoints
likewise acquire that owner before reading the Consumer and borrow it for the
write, so an unrelated credential update cannot resurrect a concurrently
rotated mTLS identity from a stale full-Consumer snapshot.
If a replica-set clear returns `UnknownTransactionCommitResult`, an immediate
read that still sees the pre-restore resource counts does not prove abort: the
delayed commit can become visible later on another pooled connection. Ferrum
therefore retains the owner-qualified fence and generation pin for manual
recovery instead of admitting writes that the delayed clear could erase.

Both lock/guard collections hold tiny nonce documents (one per route bucket / referenced upstream) and are created explicitly at migration time because MongoDB < 4.4 cannot implicitly create collections inside transactions.

## Managed Services

### MongoDB Atlas

```bash
FERRUM_DB_TYPE=mongodb
FERRUM_DB_URL="mongodb+srv://ferrum-user:password@cluster0.abc123.mongodb.net/ferrum?retryWrites=true&w=majority"
FERRUM_MONGO_DATABASE=ferrum
# No FERRUM_MONGO_REPLICA_SET needed — Atlas handles this via SRV
# No FERRUM_DB_TLS_* needed — Atlas enables TLS by default via mongodb+srv://
```

Atlas automatically provides:
- TLS encryption (via `mongodb+srv://`)
- Replica set topology discovery (via DNS SRV records)
- Read preference routing
- Automatic failover

### AWS DocumentDB

AWS DocumentDB is MongoDB-compatible but has some differences:

```bash
FERRUM_DB_TYPE=mongodb
FERRUM_DB_URL="mongodb://ferrum-user:password@docdb-cluster.cluster-xxxx.us-east-1.docdb.amazonaws.com:27017/ferrum?retryWrites=false"
FERRUM_MONGO_DATABASE=ferrum
FERRUM_DB_TLS_MODE=verify-full
FERRUM_DB_TLS_CA_CERT_PATH=/certs/rds-combined-ca-bundle.pem
```

**DocumentDB differences:**
- `retryWrites=false` required (DocumentDB doesn't support retryable writes)
- Download the [Amazon RDS CA bundle](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.SSL.html) for TLS verification
- When using `FERRUM_DB_TLS_MODE` and `FERRUM_DB_TLS_CA_CERT_PATH`, leave URI TLS options such as `tls=true` out of `FERRUM_DB_URL` so Ferrum builds the MongoDB driver's TLS options from the env settings.
  If you configure TLS in the URI instead, include `tlsCAFile` in the URI and omit the env CA path.
- Change streams require enabling them on the cluster parameter group
- **Migration lease uses the client clock on DocumentDB.** On real MongoDB the
  migration lease evaluates expiry and stamps timestamps from MongoDB *server*
  time (an aggregation-pipeline `$$NOW` update), so replica clock skew can never
  stomp an active lease. DocumentDB does not support aggregation-pipeline-form
  updates, so Ferrum detects that rejection on the first lease acquire and
  transparently falls back to a classic operator update stamped from the
  *client* clock for that migration run. Ownership fencing, the 120s lease
  window, and safe release are unchanged, but the lease is only skew-safe to the
  extent your DocumentDB replicas keep their clocks in sync (use NTP). This
  affects concurrent startups running index migrations, not steady-state
  proxying.

### Azure Cosmos DB (MongoDB API)

```bash
FERRUM_DB_TYPE=mongodb
FERRUM_DB_URL="mongodb://ferrum-user:password@ferrum-cosmos.mongo.cosmos.azure.com:10255/ferrum?ssl=true&replicaSet=globaldb&retryWrites=false"
FERRUM_MONGO_DATABASE=ferrum
```

## Kubernetes Deployment

### MongoDB with Ferrum Edge on Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ferrum-edge
spec:
  replicas: 1
  template:
    spec:
      containers:
        - name: ferrum-edge
          image: ghcr.io/ferrum-edge/ferrum-edge:latest
          ports:
            - containerPort: 8000  # Proxy
            - containerPort: 9000  # Admin API
          env:
            - name: FERRUM_MODE
              value: database
            - name: FERRUM_DB_TYPE
              value: mongodb
            - name: FERRUM_DB_URL
              valueFrom:
                secretKeyRef:
                  name: ferrum-secrets
                  key: mongodb-url
            - name: FERRUM_MONGO_DATABASE
              value: ferrum
            - name: FERRUM_MONGO_REPLICA_SET
              value: rs0
            - name: FERRUM_ADMIN_JWT_SECRET
              valueFrom:
                secretKeyRef:
                  name: ferrum-secrets
                  key: admin-jwt-secret
            - name: FERRUM_LOG_LEVEL
              value: info
```

For MongoDB itself, consider using the [MongoDB Community Kubernetes Operator](https://github.com/mongodb/mongodb-kubernetes-operator) to manage replica sets.

## Schema and Migrations

MongoDB uses **indexes** instead of SQL table migrations. Indexes are created automatically at startup or via `FERRUM_MODE=migrate`:

```bash
FERRUM_MODE=migrate FERRUM_MIGRATE_ACTION=up \
  FERRUM_DB_TYPE=mongodb \
  FERRUM_DB_URL="mongodb://localhost:27017" \
  FERRUM_MONGO_DATABASE=ferrum \
  ferrum-edge
```

Index creation is idempotent (`createIndex` is a no-op if the index already exists). See [docs/migrations.md](migrations.md#mongodb-migrations) for the full index reference.

### Adding New Fields

New fields added to the Rust domain types (`Proxy`, `Consumer`, `Upstream`, `PluginConfig`) are automatically persisted to MongoDB via serde BSON serialization — no ALTER TABLE equivalent needed. This is a key advantage over SQL backends where new fields require explicit schema migrations.

## Incremental Polling

MongoDB replica sets use the same durable incremental polling strategy as SQL backends:

1. **Startup:** A full load reads all runtime collections and seeds the latest accepted `config_changes.sequence`. Replica sets use a snapshot transaction; standalone deployments use sequential primary reads and only reject inconsistencies caught by the runtime load validation path.
2. **Subsequent polls:** Pollers read ordered `config_changes` documents after the accepted sequence cursor, collapse each resource to its final operation in the batch, and point-load changed IDs only.
3. **Deletion detection:** Deletes are delivered by durable `config_changes` delete records; normal incremental polling does not scan every runtime collection ID.
4. **Retention:** Old change records are compacted after the retained per-namespace window. If a poller's cursor is older than retained history, it falls back to the same full-load path and reseeds the sequence cursor.
5. **Fallback:** If incremental poll fails, Ferrum falls back to the same full-load path and rejects the candidate on any query, decode, or runtime load validation error.

The `config_changes` collection has `{namespace, sequence}` and `{sequence}` indexes so polling cost is proportional to the number of retained changes read, not total runtime resource count.

Standalone MongoDB does not provide multi-document transactions, so resource writes and their `config_changes` records cannot be made crash-atomic. Ferrum therefore forces standalone MongoDB pollers through the full-load fallback path instead of accepting an incremental cursor that could miss a resource mutation whose change record was not committed.
