# MongoDB Deployment Guide

This guide covers deploying Ferrum Edge with MongoDB as the configuration database. MongoDB is a NoSQL alternative to the SQL backends (PostgreSQL, MySQL, SQLite), offering document-based storage with native replica set support.

## When to Use MongoDB

| Choose MongoDB when... | Choose SQL when... |
|---|---|
| Your team already operates MongoDB | You want the simplest setup (SQLite) |
| You want built-in replica set failover | You need multi-document ACID transactions without a replica set |
| You prefer document-based config storage | You want mature schema migration tooling |
| You're deploying on MongoDB Atlas | You're using managed RDS/Cloud SQL |
| You need read/write splitting via read preference | You need a separate read replica URL |

## Quick Start

```bash
# Start MongoDB (Docker)
docker run -d --name mongo -p 27017:27017 mongo:7

# Start Ferrum Edge
FERRUM_MODE=database \
FERRUM_DB_TYPE=mongodb \
FERRUM_DB_URL="mongodb://localhost:27017" \
FERRUM_MONGO_DATABASE=ferrum \
FERRUM_ADMIN_JWT_SECRET="change-me-in-production" \
FERRUM_LOG_LEVEL=info \
cargo run --release
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

### Shared Settings (SQL + MongoDB)

These `FERRUM_DB_*` settings apply to both SQL and MongoDB backends:

| Variable | MongoDB Behavior |
|---|---|
| `FERRUM_DB_TYPE` | Set to `mongodb` |
| `FERRUM_DB_URL` | MongoDB connection string (`mongodb://` or `mongodb+srv://`) |
| `FERRUM_DB_POLL_INTERVAL` | Polling interval in seconds (same as SQL) |
| `FERRUM_DB_CONFIG_BACKUP_PATH` | On-disk JSON backup for startup failover (same as SQL) |
| `FERRUM_DB_FAILOVER_URLS` | Comma-separated fallback MongoDB URLs (same pattern as SQL, but see [Failover](#failover) below) |
| `FERRUM_DB_SLOW_QUERY_THRESHOLD_MS` | Slow query warning threshold (same as SQL) |
| `FERRUM_DB_TLS_ENABLED` | Enable TLS via programmatic `TlsOptions` (see [TLS](#tls)) |
| `FERRUM_DB_TLS_CA_CERT_PATH` | CA certificate for server verification |
| `FERRUM_DB_TLS_CLIENT_CERT_PATH` | Client certificate for mTLS |
| `FERRUM_DB_TLS_CLIENT_KEY_PATH` | Client private key for mTLS |
| `FERRUM_DB_TLS_INSECURE` | Skip server certificate validation (testing only) |

### SQL-Only Settings (Ignored for MongoDB)

These settings have no effect when `FERRUM_DB_TYPE=mongodb`:

| Variable | Why N/A for MongoDB |
|---|---|
| `FERRUM_DB_READ_REPLICA_URL` | MongoDB handles read routing via `readPreference` in the connection string (see [Read Preference](#read-preference)) |
| `FERRUM_DB_POOL_MAX_CONNECTIONS` | MongoDB driver manages its own connection pool internally |
| `FERRUM_DB_POOL_MIN_CONNECTIONS` | MongoDB driver manages its own connection pool internally |
| `FERRUM_DB_POOL_ACQUIRE_TIMEOUT_SECONDS` | MongoDB uses `FERRUM_MONGO_SERVER_SELECTION_TIMEOUT_SECONDS` instead |
| `FERRUM_DB_POOL_IDLE_TIMEOUT_SECONDS` | MongoDB driver manages idle connection eviction internally |
| `FERRUM_DB_POOL_MAX_LIFETIME_SECONDS` | MongoDB driver manages connection cycling internally |
| `FERRUM_DB_POOL_CONNECT_TIMEOUT_SECONDS` | Use `FERRUM_MONGO_CONNECT_TIMEOUT_SECONDS` instead |
| `FERRUM_DB_POOL_STATEMENT_TIMEOUT_SECONDS` | MongoDB has no per-statement timeout (use `maxTimeMS` in queries if needed) |
| `FERRUM_DB_SSL_MODE` | MongoDB uses `tls=true` in connection string or `FERRUM_DB_TLS_ENABLED=true` |
| `FERRUM_DB_SSL_ROOT_CERT` | Use `FERRUM_DB_TLS_CA_CERT_PATH` or `tlsCAFile` in connection string |
| `FERRUM_DB_SSL_CLIENT_CERT` | Use `FERRUM_DB_TLS_CLIENT_CERT_PATH` or `tlsCertificateKeyFile` in connection string |
| `FERRUM_DB_SSL_CLIENT_KEY` | Use `FERRUM_DB_TLS_CLIENT_KEY_PATH` (auto-combined with cert into single PEM) |

## Read Preference

MongoDB handles read/write splitting natively through **read preference** in the connection string — no separate replica URL needed. The driver routes reads and writes to the appropriate replica set members automatically.

```bash
# All reads go to secondaries when available, primary as fallback
FERRUM_DB_URL="mongodb://user:pass@mongo1:27017,mongo2:27017,mongo3:27017/ferrum?replicaSet=rs0&readPreference=secondaryPreferred"
```

This is why `FERRUM_DB_READ_REPLICA_URL` is SQL-only. MongoDB's `readPreference` replaces it with better behavior:

| Read Preference | Behavior | Use Case |
|---|---|---|
| `primary` (default) | All reads go to primary | Strongest consistency |
| `primaryPreferred` | Primary if available, else secondary | Consistency with HA fallback |
| `secondary` | Reads only from secondaries | Offload primary completely |
| `secondaryPreferred` | Secondary if available, else primary | **Recommended for Ferrum Edge** — offloads config polling reads from primary |
| `nearest` | Lowest latency member regardless of role | Multi-region deployments |

### Example: Production Config Polling on Secondary

```bash
FERRUM_DB_TYPE=mongodb
FERRUM_DB_URL="mongodb://mongo-primary:27017,mongo-secondary1:27017,mongo-secondary2:27017/ferrum?replicaSet=rs0&readPreference=secondaryPreferred"
FERRUM_MONGO_DATABASE=ferrum
FERRUM_MONGO_REPLICA_SET=rs0
```

The gateway writes new proxy/consumer/plugin configs to the primary via the Admin API, and the polling loop reads config changes from a secondary — same read/write split as `FERRUM_DB_READ_REPLICA_URL` for SQL, but built into the driver.

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

`FERRUM_DB_FAILOVER_URLS` still works with MongoDB for standalone (non-replica-set) deployments where you have independent MongoDB instances:

```bash
FERRUM_DB_URL="mongodb://primary-mongo:27017"
FERRUM_DB_FAILOVER_URLS="mongodb://backup-mongo:27017"
```

For replica sets, prefer listing all members in the primary URL instead of using `FERRUM_DB_FAILOVER_URLS`.

## TLS

MongoDB TLS can be configured two ways. See [docs/database_tls.md](database_tls.md#mongodb) for full details.

### Approach 1: FERRUM_DB_TLS_* Environment Variables (Recommended)

Uses the same env vars as SQL backends. The gateway handles MongoDB-specific requirements (cert+key combination) automatically.

```bash
FERRUM_DB_TLS_ENABLED=true
FERRUM_DB_TLS_CA_CERT_PATH=/certs/ca.pem
FERRUM_DB_TLS_CLIENT_CERT_PATH=/certs/client.crt    # mTLS
FERRUM_DB_TLS_CLIENT_KEY_PATH=/certs/client.key      # mTLS
```

**Note:** MongoDB requires client cert + key in a single PEM file. When separate files are provided, the gateway automatically combines them into a PID-scoped temp file (`/tmp/ferrum-mongo-client-{pid}.pem`).

### Approach 2: Connection String Options

```bash
FERRUM_DB_URL="mongodb://host:27017/ferrum?tls=true&tlsCAFile=/certs/ca.pem&tlsCertificateKeyFile=/certs/client-combined.pem"
```

Connection string TLS options take precedence over `FERRUM_DB_TLS_*` env vars when both are set.

### X.509 Certificate Authentication

For passwordless authentication using client certificates:

```bash
FERRUM_MONGO_AUTH_MECHANISM=MONGODB-X509
FERRUM_DB_TLS_ENABLED=true
FERRUM_DB_TLS_CA_CERT_PATH=/certs/ca.pem
FERRUM_DB_TLS_CLIENT_CERT_PATH=/certs/client.crt
FERRUM_DB_TLS_CLIENT_KEY_PATH=/certs/client.key
```

## Replica Sets and Transactions

### When You Need a Replica Set

| Feature | Standalone | Replica Set |
|---|---|---|
| Single-document CRUD | Atomic | Atomic |
| Multi-document operations (e.g., delete proxy + plugins) | Idempotent (partial failure safe) | Transactional (ACID) |
| Change streams (future) | Not available | Available |
| Read preference routing | Not available | Available |
| Automatic failover | Not available | Automatic |

For production, a **replica set is strongly recommended**. Without one, multi-document operations (like deleting a proxy and its associated plugin configs) are not transactional — partial failures are handled via idempotent cleanup on the next poll cycle.

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
FERRUM_DB_URL="mongodb://mongo1:27017,mongo2:27017,mongo3:27017/ferrum?replicaSet=rs0&readPreference=secondaryPreferred&w=majority"
FERRUM_MONGO_REPLICA_SET=rs0
FERRUM_MONGO_DATABASE=ferrum
```

The `w=majority` write concern ensures writes are acknowledged by a majority of members before returning, providing durability guarantees.

## Managed Services

### MongoDB Atlas

```bash
FERRUM_DB_TYPE=mongodb
FERRUM_DB_URL="mongodb+srv://ferrum-user:password@cluster0.abc123.mongodb.net/ferrum?retryWrites=true&w=majority&readPreference=secondaryPreferred"
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
FERRUM_DB_URL="mongodb://ferrum-user:password@docdb-cluster.cluster-xxxx.us-east-1.docdb.amazonaws.com:27017/ferrum?tls=true&retryWrites=false"
FERRUM_MONGO_DATABASE=ferrum
FERRUM_DB_TLS_ENABLED=true
FERRUM_DB_TLS_CA_CERT_PATH=/certs/rds-combined-ca-bundle.pem
```

**DocumentDB differences:**
- `retryWrites=false` required (DocumentDB doesn't support retryable writes)
- Download the [Amazon RDS CA bundle](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.SSL.html) for TLS verification
- Change streams require enabling them on the cluster parameter group

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

MongoDB uses the same incremental polling strategy as SQL backends:

1. **Startup:** Full collection scan loads all documents
2. **Subsequent polls:** `updated_at > last_poll_timestamp` queries fetch only changed documents (indexed)
3. **Deletion detection:** Lightweight `_id` projection queries detect removed documents
4. **Fallback:** If incremental poll fails, falls back to full collection scan

The `updated_at` indexes on all four collections ensure polling queries use index scans, not full collection scans.
