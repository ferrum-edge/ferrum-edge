# Multi-Region High Availability

This guide covers deploying Ferrum Edge across multiple regions for high availability using DP multi-CP failover and a shared database cluster. No custom CP-to-CP mesh protocol is needed — the database layer handles cross-region replication.

## Architecture Overview

```
                    ┌─────────────────────────────────────┐
                    │      Shared Database Cluster         │
                    │  (cross-region replication)          │
                    │                                     │
                    │  ┌─────────┐ ┌─────────┐ ┌───────┐ │
                    │  │ US East │ │ US West │ │US Cent│ │
                    │  │ (R/W)   │ │ (R/W)   │ │ (R/W) │ │
                    │  └────┬────┘ └────┬────┘ └───┬───┘ │
                    └───────┼───────────┼──────────┼─────┘
                            │           │          │
              ┌─────────────▼─┐  ┌──────▼──────┐ ┌▼────────────┐
              │  US East      │  │  US West    │ │ US Central   │
              │               │  │             │ │              │
              │  CP₁ ←── DB   │  │  CP₂ ←── DB│ │ CP₃ ←── DB  │
              │  │  (polls)   │  │  │  (polls) │ │ │  (polls)   │
              │  ▼            │  │  ▼          │ │ ▼            │
              │  DP₁  DP₂    │  │  DP₃  DP₄   │ │ DP₅  DP₆    │
              │               │  │             │ │              │
              │  ns: us-east  │  │  ns: us-west│ │ ns: us-cent  │
              └───────────────┘  └─────────────┘ └──────────────┘
```

Each region runs:
- A **Control Plane** instance polling the shared database
- Multiple **Data Plane** instances receiving config from CPs via gRPC
- An optional local **read replica** for reduced polling latency

Each CP is stateless — it simply polls the database and broadcasts config. The database cluster handles replication, conflict resolution, and consistency.

## How It Works

1. **All CPs share one database cluster** — writes to any CP's admin API go to the shared DB
2. **Each CP polls independently** — config changes replicate through the DB and each CP picks them up on its next poll cycle
3. **DPs have fallback CPs** — using `FERRUM_DP_CP_GRPC_URLS`, DPs can fail over to CPs in other regions
4. **Namespace isolation** — each region can manage its own namespace while all CPs can write to any namespace via the admin API

### Failure Scenarios

| Failure | Impact | Recovery |
|---------|--------|----------|
| Single CP goes down | DPs failover to next CP in list | Automatic via `FERRUM_DP_CP_GRPC_URLS` |
| CP + its DPs go down (full region) | Other regions unaffected. Region's namespace still manageable via other CPs | DPs retry primary CP periodically |
| Database node goes down | DB cluster handles failover internally. CPs continue with cached config during brief failover | Automatic via DB cluster replication |
| Network partition between regions | Each region continues operating independently with local DB node. Writes converge when partition heals | Automatic via DB cluster replication |

### What This Gives You vs. Single CP

| Capability | Single CP | Multi-Region HA |
|-----------|-----------|-----------------|
| DP continues serving during CP outage | Yes (cached config) | Yes (cached config) |
| Config writes during CP outage | No (read-only) | **Yes** (via another region's CP) |
| Config writes during DB outage | No | **Yes** (via other DB nodes in cluster) |
| Region-level fault isolation | No | **Yes** (each region operates independently) |
| Cross-region namespace management | N/A | **Yes** (any CP can manage any namespace) |

## Database Cluster Support

The multi-region pattern requires a database that supports cross-region replication. Here is how each supported database backend works:

### PostgreSQL — Recommended for Multi-Region

PostgreSQL supports several multi-region strategies:

**Option A: Patroni + Streaming Replication (Active-Passive)**

- One primary accepts writes; standbys in other regions replicate via streaming
- On primary failure, Patroni promotes a standby automatically
- Use `FERRUM_DB_FAILOVER_URLS` to list standby connection URLs
- Use `FERRUM_DB_READ_REPLICA_URL` per-region to offload polling reads to local standby

```bash
# US East CP (primary DB in US East)
FERRUM_DB_URL=postgres://user:pass@pg-east:5432/ferrum
FERRUM_DB_FAILOVER_URLS=postgres://user:pass@pg-west:5432/ferrum,postgres://user:pass@pg-central:5432/ferrum
FERRUM_DB_READ_REPLICA_URL=postgres://user:pass@pg-east-replica:5432/ferrum

# US West CP (primary in East, local read replica)
FERRUM_DB_URL=postgres://user:pass@pg-east:5432/ferrum
FERRUM_DB_FAILOVER_URLS=postgres://user:pass@pg-west:5432/ferrum,postgres://user:pass@pg-central:5432/ferrum
FERRUM_DB_READ_REPLICA_URL=postgres://user:pass@pg-west-replica:5432/ferrum
```

- **Pro**: Mature, well-understood, strong consistency
- **Con**: Single write primary; write failover takes seconds during promotion

**Option B: CockroachDB or YugabyteDB (Active-Active)**

- All nodes accept reads and writes with distributed consensus
- Data automatically replicates and survives node/region failures
- Each CP points to its local node; no failover URLs needed

```bash
# US East CP
FERRUM_DB_TYPE=postgres
FERRUM_DB_URL=postgres://user:pass@crdb-east:26257/ferrum

# US West CP
FERRUM_DB_TYPE=postgres
FERRUM_DB_URL=postgres://user:pass@crdb-west:26257/ferrum

# US Central CP
FERRUM_DB_TYPE=postgres
FERRUM_DB_URL=postgres://user:pass@crdb-central:26257/ferrum
```

- **Pro**: True multi-region active-active writes, automatic rebalancing, no single point of failure
- **Con**: Higher write latency (cross-region consensus), more operational complexity

**Option C: PostgreSQL Logical Replication (Multi-Primary)**

- Multiple primaries, each owning a set of tables or publication/subscription pairs
- Requires careful partitioning to avoid conflicts
- Not recommended for Ferrum Edge — the config tables are small and all CPs need full read/write access

### MySQL — Supported

**Option A: MySQL InnoDB Cluster / Group Replication**

- Single-primary or multi-primary mode with automatic failover
- Use `FERRUM_DB_FAILOVER_URLS` for standby nodes

```bash
FERRUM_DB_TYPE=mysql
FERRUM_DB_URL=mysql://user:pass@mysql-east:3306/ferrum
FERRUM_DB_FAILOVER_URLS=mysql://user:pass@mysql-west:3306/ferrum,mysql://user:pass@mysql-central:3306/ferrum
```

- In **single-primary mode**: one node accepts writes, others are read-only. Failover is automatic within the group
- In **multi-primary mode**: all nodes accept writes with optimistic conflict detection. Conflicts on the same row are resolved by aborting the later transaction

**Option B: MySQL with ProxySQL or MySQL Router**

- A SQL-aware proxy routes writes to primary, reads to replicas
- The gateway connects to the proxy address; failover is transparent

**Option C: PlanetScale or Vitess**

- Horizontally sharded MySQL with automatic replication
- Works with `FERRUM_DB_TYPE=mysql` — Vitess is MySQL wire-protocol compatible
- PlanetScale provides managed Vitess with automatic failover

### SQLite — Not Suitable for Multi-Region

SQLite is a single-file embedded database with no built-in replication. It is ideal for single-instance or development deployments but **cannot be used for multi-region HA**.

- No network protocol — all access is via local filesystem
- No replication — a single file on one machine
- `FERRUM_DB_FAILOVER_URLS` has no effect (all URLs would point to the same file)

**Use SQLite for**: development, testing, single-instance file-mode deployments.

**Use PostgreSQL or MySQL for**: production multi-region deployments.

### MongoDB — Native Multi-Region Support

MongoDB replica sets provide native cross-region replication:

```bash
# All regions use the same replica set connection string
FERRUM_DB_TYPE=mongodb
FERRUM_DB_URL=mongodb://mongo-east:27017,mongo-west:27017,mongo-central:27017/ferrum?replicaSet=rs0
```

- **Writes** go to the primary (elected automatically)
- **Reads** can go to local secondaries via `readPreference=secondaryPreferred` in the connection string
- **Failover** is automatic — the driver routes to the new primary within seconds
- `FERRUM_DB_FAILOVER_URLS` is not needed — list all members in `FERRUM_DB_URL`
- `FERRUM_DB_READ_REPLICA_URL` is not needed — use `readPreference` in the connection string

```bash
# CP reads locally with secondaryPreferred, writes auto-route to primary
FERRUM_DB_URL=mongodb://mongo-east:27017,mongo-west:27017,mongo-central:27017/ferrum?replicaSet=rs0&readPreference=secondaryPreferred
```

- **Pro**: Native multi-region with automatic primary election, no external tooling needed
- **Con**: Single write primary (like PG streaming replication). Writes during network partition require majority quorum

### Database Comparison for Multi-Region

| Feature | PostgreSQL (Patroni) | CockroachDB/Yugabyte | MySQL (InnoDB Cluster) | MongoDB (Replica Set) | SQLite |
|---------|---------------------|---------------------|----------------------|---------------------|--------|
| Multi-region writes | Single primary | All nodes | Single or multi-primary | Single primary | N/A |
| Automatic failover | Via Patroni | Built-in | Built-in | Built-in | N/A |
| Ferrum config needed | `FERRUM_DB_FAILOVER_URLS` | None (local node) | `FERRUM_DB_FAILOVER_URLS` | None (replica set URL) | N/A |
| Write consistency | Strong (single primary) | Strong (consensus) | Strong (single) or eventual (multi) | Strong (single primary) | N/A |
| Operational complexity | Medium | High | Medium | Low-Medium | N/A |
| Ferrum DB type | `postgres` | `postgres` | `mysql` | `mongodb` | N/A |

## Complete Multi-Region Example

### Three-Region Deployment with PostgreSQL (Patroni)

**Shared JWT secrets** — all CPs and DPs share the same secrets:

```bash
# Generate once, distribute to all nodes
export GRPC_JWT_SECRET=$(openssl rand -base64 32)
export ADMIN_JWT_SECRET=$(openssl rand -base64 32)
```

**US East — Control Plane:**

```bash
FERRUM_MODE=cp
FERRUM_NAMESPACE=us-east
FERRUM_DB_TYPE=postgres
FERRUM_DB_URL=postgres://user:pass@pg-east:5432/ferrum
FERRUM_DB_FAILOVER_URLS=postgres://user:pass@pg-west:5432/ferrum,postgres://user:pass@pg-central:5432/ferrum
FERRUM_DB_READ_REPLICA_URL=postgres://user:pass@pg-east-replica:5432/ferrum
FERRUM_CP_GRPC_LISTEN_ADDR=0.0.0.0:50051
FERRUM_CP_DP_GRPC_JWT_SECRET=$GRPC_JWT_SECRET
FERRUM_ADMIN_JWT_SECRET=$ADMIN_JWT_SECRET
FERRUM_CP_GRPC_TLS_CERT_PATH=/certs/server.pem
FERRUM_CP_GRPC_TLS_KEY_PATH=/certs/server-key.pem
```

**US East — Data Planes:**

```bash
FERRUM_MODE=dp
FERRUM_NAMESPACE=us-east
FERRUM_DP_CP_GRPC_URLS=https://cp-east:50051,https://cp-west:50051,https://cp-central:50051
FERRUM_DP_CP_FAILOVER_PRIMARY_RETRY_SECS=300
FERRUM_CP_DP_GRPC_JWT_SECRET=$GRPC_JWT_SECRET
FERRUM_ADMIN_JWT_SECRET=$ADMIN_JWT_SECRET
FERRUM_DP_GRPC_TLS_CA_CERT_PATH=/certs/ca.pem
```

**US West — Control Plane:**

```bash
FERRUM_MODE=cp
FERRUM_NAMESPACE=us-west
FERRUM_DB_TYPE=postgres
FERRUM_DB_URL=postgres://user:pass@pg-east:5432/ferrum
FERRUM_DB_FAILOVER_URLS=postgres://user:pass@pg-west:5432/ferrum,postgres://user:pass@pg-central:5432/ferrum
FERRUM_DB_READ_REPLICA_URL=postgres://user:pass@pg-west-replica:5432/ferrum
FERRUM_CP_GRPC_LISTEN_ADDR=0.0.0.0:50051
FERRUM_CP_DP_GRPC_JWT_SECRET=$GRPC_JWT_SECRET
FERRUM_ADMIN_JWT_SECRET=$ADMIN_JWT_SECRET
FERRUM_CP_GRPC_TLS_CERT_PATH=/certs/server.pem
FERRUM_CP_GRPC_TLS_KEY_PATH=/certs/server-key.pem
```

**US West — Data Planes:**

```bash
FERRUM_MODE=dp
FERRUM_NAMESPACE=us-west
FERRUM_DP_CP_GRPC_URLS=https://cp-west:50051,https://cp-east:50051,https://cp-central:50051
FERRUM_DP_CP_FAILOVER_PRIMARY_RETRY_SECS=300
FERRUM_CP_DP_GRPC_JWT_SECRET=$GRPC_JWT_SECRET
FERRUM_ADMIN_JWT_SECRET=$ADMIN_JWT_SECRET
FERRUM_DP_GRPC_TLS_CA_CERT_PATH=/certs/ca.pem
```

### Cross-Region Namespace Management

Any CP can manage any namespace through its admin API using the `X-Ferrum-Namespace` header:

```bash
# US West CP creating a proxy in the us-east namespace
curl -X POST https://cp-west:9443/proxies \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Ferrum-Namespace: us-east" \
  -H "Content-Type: application/json" \
  -d '{"name": "api", "listen_path": "/api", "backend_host": "api.us-east.internal", "backend_port": 8080}'
```

The write goes to the shared database. US East's CP picks up the change on its next poll cycle and pushes it to US East DPs.

### Three-Region Deployment with MongoDB

MongoDB simplifies the deployment significantly — no failover URLs or read replica configuration needed:

**All CPs (same connection string, different namespace):**

```bash
FERRUM_MODE=cp
FERRUM_NAMESPACE=us-east   # or us-west, us-central per region
FERRUM_DB_TYPE=mongodb
FERRUM_DB_URL=mongodb://mongo-east:27017,mongo-west:27017,mongo-central:27017/ferrum?replicaSet=rs0&readPreference=secondaryPreferred
FERRUM_CP_GRPC_LISTEN_ADDR=0.0.0.0:50051
FERRUM_CP_DP_GRPC_JWT_SECRET=$GRPC_JWT_SECRET
FERRUM_ADMIN_JWT_SECRET=$ADMIN_JWT_SECRET
```

**All DPs (same pattern, local CP first in failover list):**

```bash
FERRUM_MODE=dp
FERRUM_NAMESPACE=us-east
FERRUM_DP_CP_GRPC_URLS=https://cp-east:50051,https://cp-west:50051,https://cp-central:50051
FERRUM_CP_DP_GRPC_JWT_SECRET=$GRPC_JWT_SECRET
FERRUM_ADMIN_JWT_SECRET=$ADMIN_JWT_SECRET
```

## Operational Notes

### Monitoring

- Each CP's `/health` endpoint shows `db_available` status — monitor this to detect DB connectivity issues
- Each DP's `/health` endpoint shows `cached_config` status with `loaded_at` timestamp — stale timestamps indicate CP disconnection
- Each CP's `/overload` endpoint shows resource pressure — useful for capacity planning

### Scaling CPs

CPs are stateless (they poll the DB and broadcast). You can run multiple CPs per region behind a load balancer. Each CP independently polls the DB and maintains its own broadcast channel for subscribed DPs.

### Namespace Design

- Use one namespace per region for regional resource isolation
- Use a shared namespace (e.g., `global`) for cross-region resources that all DPs should serve
- A DP only loads resources from its configured `FERRUM_NAMESPACE` — it ignores resources from other namespaces even if the CP manages multiple

### Config Propagation Latency

With a shared database cluster, config changes propagate as:

1. Admin API write → database (immediate, latency depends on DB write path)
2. Database replication → other regions (milliseconds for same-region, 50-200ms cross-region typical)
3. CP poll → picks up change (`FERRUM_DB_POLL_INTERVAL`, default 30s)
4. CP broadcast → DPs receive update (immediate via gRPC streaming)

**Total worst-case latency**: DB replication time + poll interval. To reduce this, lower `FERRUM_DB_POLL_INTERVAL` (e.g., to 5-10s for latency-sensitive deployments).
