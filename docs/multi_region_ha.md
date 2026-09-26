# Multi-Region High Availability

This guide covers deploying Ferrum Edge across multiple regions for high
availability using a shared database cluster, regional control planes (CPs),
and optional DP multi-CP failover. No custom CP-to-CP mesh protocol is needed —
the database layer handles cross-region replication.

**Read this together with** [cp_namespace_tenancy.md](cp_namespace_tenancy.md).
CP scope (`FERRUM_CP_NAMESPACES`) and DP failover (`FERRUM_DP_CP_GRPC_URLS`)
must agree: a DP only subscribes to CPs whose scope includes the DP's
`FERRUM_NAMESPACE`. Cross-region CP URLs with mismatched namespaces are
rejected with `FAILED_PRECONDITION`, not treated as a usable fallback.

## Architecture Overview

```
                    ┌─────────────────────────────────────┐
                    │      Shared Database Cluster         │
                    │  (cross-region replication)          │
                    │                                     │
                    │  ┌─────────┐ ┌─────────┐ ┌───────┐ │
                    │  │ US East │ │ US West │ │US Cent│ │
                    │  │  node   │ │  node   │ │ node  │ │
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

The database boxes represent members, not three independent writers. Writer,
replica, and quorum roles follow the selected database topology; do not turn an
asynchronous standby into a writable Ferrum failover target.

Each region runs:

- A **Control Plane** instance polling the shared database for the namespace(s)
  it serves
- Multiple **Data Plane** instances receiving config from CPs via gRPC
- An optional local SQL **read replica** for eligible admin-read offload

Each CP is stateless — it polls the primary-consistent database view and
broadcasts config for the namespaces in its scope. The database cluster handles
replication, conflict resolution, and consistency.

## CP scope and DP failover (required reading)

`FERRUM_DP_CP_GRPC_URLS` is a priority-ordered list. The DP tries the next URL
when a connection attempt fails (transport error, subscribe rejection, or other
pre-stream failure). **Reachability is not enough:** every CP in the list must
**serve the DP's namespace** under its CP scope.

| CP configuration | Serves `us-east` DPs? |
|------------------|----------------------|
| `FERRUM_NAMESPACE=us-east` (default single-namespace scope) | Yes |
| `FERRUM_NAMESPACE=us-west` | **No** — `FAILED_PRECONDITION` |
| `FERRUM_CP_NAMESPACES=us-east,us-west` + trust bundle | Yes (with per-tenant credentials) |

A `us-east` DP listing `cp-east,cp-west,cp-central` when each CP runs only its
regional namespace does **not** get cross-region failover. After `cp-east` fails,
`cp-west` rejects the subscribe (`CP scope (...) does not include DP namespace
'us-east'`), the DP advances to the next URL, and the cycle repeats with
backoff — the same availability posture as a single CP.

### Recommended pattern: one namespace per region

Keep each CP on a **single-namespace** scope (`FERRUM_NAMESPACE` only; leave
`FERRUM_CP_NAMESPACES` unset). For CP redundancy within a region:

- Run multiple CP replicas behind a load balancer (each replica serves the same
  namespace), **or**
- List only same-namespace CP URLs in `FERRUM_DP_CP_GRPC_URLS` (for example
  primary and standby CPs in the same region, or hot-standby CPs in another
  region that also run `FERRUM_NAMESPACE=us-east`).

DP failover does **not** substitute for a CP that serves another region's
namespace.

### Advanced pattern: multi-namespace CPs

To let one physical CP process serve multiple regional namespaces (so a
`us-east` DP can fail over to a `us-west` host that also serves `us-east`),
configure explicit multi-namespace scope and namespace-bound verification
credentials:

1. Set `FERRUM_CP_NAMESPACES` to the full served set (or `*` for cluster-wide).
2. Configure `FERRUM_CP_DP_GRPC_TRUST_BUNDLE_PATH` with per-tenant verification
   credentials. A multi-namespace CP **refuses to start** with only the
   fleet-wide `FERRUM_CP_DP_GRPC_JWT_SECRET` (advisory GHSA-3f2j-wwqw-grmg).
3. Issue DP tokens (or trust-bundle credentials) whose `ns` claim authorises
   the namespaces each DP may subscribe to.

See [cp_namespace_tenancy.md](cp_namespace_tenancy.md) for scope resolution,
trust-bundle format, and migration steps.

## How It Works

1. **All CPs share one database cluster** — admin API writes on any reachable CP
   go to the shared DB (subject to the database write fence below).
2. **Each CP polls independently** — config changes replicate through the DB;
   each CP picks up namespaces in its scope on its next poll cycle.
3. **DPs have fallback CPs** — using `FERRUM_DP_CP_GRPC_URLS`, DPs fail over only
   to CPs that **serve the same namespace**. Restrict the list to same-scope CPs.
4. **Namespace isolation** — each region typically owns one namespace. Any CP can
   **admin-write** to any namespace via `X-Ferrum-Namespace`, but only CPs
   whose scope includes that namespace poll and broadcast it to DPs.

### Failure Scenarios

| Failure | Impact | Recovery |
|---------|--------|----------|
| Single CP goes down | DPs in that region use cached config (bounded by `FERRUM_DP_CONFIG_MAX_STALE_SECONDS`, default 1 hour); failover works only if another listed CP serves the same namespace | Automatic via `FERRUM_DP_CP_GRPC_URLS` when scopes match |
| CP + its DPs go down (full region) | Other regions continue serving their own namespaces. Admin writes to the down region's namespace persist in the DB but DPs there do not receive updates until a CP serving that namespace is back | Restore regional CP or hot-standby CP with matching scope |
| Database node goes down | DB cluster handles failover internally. CPs continue with cached config during brief failover. **Admin mutations fail closed** while Ferrum is on a `FERRUM_DB_FAILOVER_URLS` entry unless `FERRUM_DB_FAILOVER_ALLOW_WRITES=true` | Prefer a writer/virtual-IP endpoint for `FERRUM_DB_URL` so promotion stays transparent; see below |
| Network partition between regions | DPs keep serving cached config. CP reads/writes depend on database writer and quorum reachability; a single-primary or minority partition is not independently writable, and Ferrum must not manufacture multi-primary behavior with failover-write opt-in | Restore writer/quorum connectivity. Do not enable failover writes on asynchronous standbys |

### What This Gives You vs. Single CP

| Capability | Single CP | Multi-Region HA |
|-----------|-----------|-----------------|
| DP continues serving during CP outage | Yes (cached config, up to `FERRUM_DP_CONFIG_MAX_STALE_SECONDS`) | Yes (cached config, same bound) |
| Config writes during CP outage | No (CP unreachable) | **Partial** — another region's CP can admin-write via `X-Ferrum-Namespace`, but DPs in the down region do not receive updates until a CP serving their namespace recovers |
| Config writes during DB outage | No | **No** by default — failover URLs are read-only for admin mutations (503). Point `FERRUM_DB_URL` at the cluster writer/leader endpoint instead |
| Region-level fault isolation | No | **Yes** (each region operates independently) |
| Cross-region namespace management (admin API) | N/A | **Yes** (any reachable CP can write any namespace to the shared DB) |
| Cross-region DP→CP failover | N/A | **Only** when fallback CPs serve the DP's namespace (same-namespace standbys or multi-namespace CP + trust bundle) |

## Database Cluster Support

The multi-region pattern requires a database that supports cross-region
replication. Here is how each supported database backend works.

### Admin writes and `FERRUM_DB_FAILOVER_URLS`

Ferrum tracks whether the active config-database pool points at the configured
primary (`FERRUM_DB_URL`) or a sticky failover URL (`FERRUM_DB_FAILOVER_URLS`).
While on failover, **admin mutations fail closed with HTTP 503** unless
`FERRUM_DB_FAILOVER_ALLOW_WRITES=true`. The default protects async standbys from
split-brain config writes. After an admitted failover write, Ferrum fences
automatic primary failback until the process is restarted (process-local; see
[admin_api.md](admin_api.md) and [configuration.md](configuration.md)).

**Operational guidance:**

- Point `FERRUM_DB_URL` at the **writer** endpoint (Patroni leader, HAProxy
  primary, MongoDB replica-set primary via driver election, and so on) so DB
  promotion does not flip Ferrum into the failover write fence.
- Use `FERRUM_DB_FAILOVER_URLS` for **read availability** and transient primary
  loss, not as a writable admin target in active/passive topologies.
- Set `FERRUM_DB_FAILOVER_ALLOW_WRITES=true` only when the operator asserts
  **synchronously replicated multi-primary** replication. Do not enable it on
  async streaming standbys.

Polling and admin reads stay available on failover URLs either way.

### PostgreSQL — Recommended for Multi-Region

PostgreSQL supports several multi-region strategies:

**Option A: Patroni + Streaming Replication (Active-Passive)**

- One primary accepts writes; standbys in other regions replicate via streaming
- On primary failure, Patroni promotes a standby automatically
- Point `FERRUM_DB_URL` at the Patroni/HAProxy **writer** endpoint so promotion
  does not trip the admin write fence
- Optionally list standby URLs in `FERRUM_DB_FAILOVER_URLS` for read failover
  during primary loss (admin writes remain 503 unless opt-in; see above)
- Use `FERRUM_DB_READ_REPLICA_URL` per-region only for eligible admin-read
  offload; runtime config polling still reads the primary-consistent writer
  endpoint

```bash
# US East CP — writer VIP tracks Patroni leader
FERRUM_DB_URL=postgres://user:pass@pg-writer-vip:5432/ferrum
# Optional: standbys for read failover only (not for admin writes)
FERRUM_DB_FAILOVER_URLS=postgres://user:pass@pg-west:5432/ferrum,postgres://user:pass@pg-central:5432/ferrum
FERRUM_DB_READ_REPLICA_URL=postgres://user:pass@pg-east-replica:5432/ferrum

# US West CP — same writer VIP; local admin-read replica
FERRUM_DB_URL=postgres://user:pass@pg-writer-vip:5432/ferrum
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
- Point `FERRUM_DB_URL` at the router/proxy **writer** endpoint; use
  `FERRUM_DB_FAILOVER_URLS` only for read failover unless you operate true
  multi-primary with `FERRUM_DB_FAILOVER_ALLOW_WRITES=true`

```bash
FERRUM_DB_TYPE=mysql
FERRUM_DB_URL=mysql://user:pass@mysql-router-writer:3306/ferrum
FERRUM_DB_FAILOVER_URLS=mysql://user:pass@mysql-west:3306/ferrum,mysql://user:pass@mysql-central:3306/ferrum
```

- In **single-primary mode**: one node accepts writes, others are read-only. Failover is automatic within the group
- In **multi-primary mode**: all nodes accept writes with optimistic conflict detection. Conflicts on the same row are resolved by aborting the later transaction

**Option B: MySQL with ProxySQL or MySQL Router**

- A SQL-aware proxy routes writes to primary, reads to replicas
- The gateway connects to the proxy writer address; failover is transparent

**Option C: PlanetScale or Vitess**

- Horizontally sharded MySQL with automatic replication
- Works with `FERRUM_DB_TYPE=mysql` — Vitess is MySQL wire-protocol compatible
- PlanetScale provides managed Vitess with automatic failover

### SQLite — Not Suitable for Multi-Region

SQLite is a single-file embedded database with no built-in replication. It is ideal for single-instance or development deployments but **cannot be used for multi-region HA**.

- No network protocol — all access is via local filesystem
- No replication — a single file on one machine
- `FERRUM_DB_FAILOVER_URLS` has no effect (all URLs would point to the same file)

**Use SQLite for**: development, testing, and single-instance database-mode deployments.

**Use PostgreSQL or MySQL for**: production multi-region deployments.

### MongoDB — Native Multi-Region Support

MongoDB replica sets provide native cross-region replication:

```bash
# All regions use the same replica set connection string
FERRUM_DB_TYPE=mongodb
FERRUM_DB_URL=mongodb://mongo-east:27017,mongo-west:27017,mongo-central:27017/ferrum?replicaSet=rs0
```

- **Writes** go to the primary (elected automatically)
- **Reads** used for Ferrum config polling go to the primary-consistent client view; URI `readPreference` is ignored by Ferrum's config store
- **Failover** is automatic — the driver routes to the new primary within seconds
- `FERRUM_DB_FAILOVER_URLS` is not needed — list all members in `FERRUM_DB_URL`
- `FERRUM_DB_READ_REPLICA_URL` is SQL-only and is not used by MongoDB

- **Pro**: Native multi-region with automatic primary election, no external tooling needed
- **Con**: Single write primary (like PG streaming replication). Writes during network partition require majority quorum

### Database Comparison for Multi-Region

| Feature | PostgreSQL (Patroni) | CockroachDB/Yugabyte | MySQL (InnoDB Cluster) | MongoDB (Replica Set) | SQLite |
|---------|---------------------|---------------------|----------------------|---------------------|--------|
| Multi-region writes | Single primary | All nodes | Single or multi-primary | Single primary | N/A |
| Automatic failover | Via Patroni | Built-in | Built-in | Built-in | N/A |
| Ferrum `FERRUM_DB_URL` target | Writer VIP/leader | Local node | Router writer | Replica set URL | N/A |
| Ferrum `FERRUM_DB_FAILOVER_URLS` | Optional read failover | None (local node) | Optional read failover | None (replica set URL) | N/A |
| Admin writes on Ferrum failover URL | 503 unless opt-in | N/A | 503 unless opt-in | N/A | N/A |
| Write consistency | Strong (single primary) | Strong (consensus) | Strong (single) or eventual (multi) | Strong (single primary) | N/A |
| Operational complexity | Medium | High | Medium | Low-Medium | N/A |
| Ferrum DB type | `postgres` | `postgres` | `mysql` | `mongodb` | N/A |

## Complete Multi-Region Example

### Three-Region Deployment with PostgreSQL (Patroni)

This example uses **one namespace per region** and **same-namespace CP failover
only** — the recommended starting point.

**Namespace-specific DP signing secrets** — CPs and DPs serving the same
namespace share one legacy secret. Use a different value for each namespace: a
DP holding a legacy HS256 secret is a signing authority, so distributing one
value across regional namespaces defeats their credential isolation.
Multi-namespace CPs require a trust bundle instead. The admin secret below is
shown shared only because this example intentionally permits cross-region admin
management:

```bash
# Generate one DP signing secret per namespace; distribute each only to that
# namespace's CPs/DPs (including same-namespace hot standbys).
export GRPC_JWT_SECRET_US_EAST=$(openssl rand -base64 32)
export GRPC_JWT_SECRET_US_WEST=$(openssl rand -base64 32)
export GRPC_JWT_SECRET_US_CENTRAL=$(openssl rand -base64 32)
export ADMIN_JWT_SECRET=$(openssl rand -base64 32)
```

**US East — Control Plane (primary and hot-standby in the same region):**

```bash
FERRUM_MODE=cp
FERRUM_NAMESPACE=us-east
FERRUM_DB_TYPE=postgres
FERRUM_DB_URL=postgres://user:pass@pg-writer-vip:5432/ferrum
FERRUM_DB_FAILOVER_URLS=postgres://user:pass@pg-west:5432/ferrum,postgres://user:pass@pg-central:5432/ferrum
FERRUM_DB_READ_REPLICA_URL=postgres://user:pass@pg-east-replica:5432/ferrum
FERRUM_CP_GRPC_LISTEN_ADDR=0.0.0.0:50051
FERRUM_CP_DP_GRPC_JWT_SECRET=$GRPC_JWT_SECRET_US_EAST
FERRUM_ADMIN_JWT_SECRET=$ADMIN_JWT_SECRET
FERRUM_CP_GRPC_TLS_CERT_PATH=/certs/server.pem
FERRUM_CP_GRPC_TLS_KEY_PATH=/certs/server-key.pem
```

Run a second `us-east` CP the same way (for example `cp-east-standby`) if you
want explicit URL failover instead of a load balancer.

**US East — Data Planes:**

```bash
FERRUM_MODE=dp
FERRUM_NAMESPACE=us-east
# Only CPs that serve us-east — NOT cp-west/cp-central unless they also scope us-east
FERRUM_DP_CP_GRPC_URLS=https://cp-east:50051,https://cp-east-standby:50051
FERRUM_DP_CP_FAILOVER_PRIMARY_RETRY_SECS=300
FERRUM_CP_DP_GRPC_JWT_SECRET=$GRPC_JWT_SECRET_US_EAST
FERRUM_ADMIN_JWT_SECRET=$ADMIN_JWT_SECRET
FERRUM_DP_GRPC_TLS_CA_CERT_PATH=/certs/ca.pem
```

**US West — Control Plane:**

```bash
FERRUM_MODE=cp
FERRUM_NAMESPACE=us-west
FERRUM_DB_TYPE=postgres
FERRUM_DB_URL=postgres://user:pass@pg-writer-vip:5432/ferrum
FERRUM_DB_FAILOVER_URLS=postgres://user:pass@pg-west:5432/ferrum,postgres://user:pass@pg-central:5432/ferrum
FERRUM_DB_READ_REPLICA_URL=postgres://user:pass@pg-west-replica:5432/ferrum
FERRUM_CP_GRPC_LISTEN_ADDR=0.0.0.0:50051
FERRUM_CP_DP_GRPC_JWT_SECRET=$GRPC_JWT_SECRET_US_WEST
FERRUM_ADMIN_JWT_SECRET=$ADMIN_JWT_SECRET
FERRUM_CP_GRPC_TLS_CERT_PATH=/certs/server.pem
FERRUM_CP_GRPC_TLS_KEY_PATH=/certs/server-key.pem
```

**US West — Data Planes:**

```bash
FERRUM_MODE=dp
FERRUM_NAMESPACE=us-west
FERRUM_DP_CP_GRPC_URLS=https://cp-west:50051,https://cp-west-standby:50051
FERRUM_DP_CP_FAILOVER_PRIMARY_RETRY_SECS=300
FERRUM_CP_DP_GRPC_JWT_SECRET=$GRPC_JWT_SECRET_US_WEST
FERRUM_ADMIN_JWT_SECRET=$ADMIN_JWT_SECRET
FERRUM_DP_GRPC_TLS_CA_CERT_PATH=/certs/ca.pem
```

Repeat for `us-central` with `FERRUM_NAMESPACE=us-central` and
same-namespace CP URLs only, using `$GRPC_JWT_SECRET_US_CENTRAL`.

### Cross-Region Namespace Management

Any reachable CP can persist changes to any namespace through its admin API
using the `X-Ferrum-Namespace` header. The write goes to the shared database.
Only CPs whose scope **includes** that namespace poll it and push updates to
DPs:

```bash
# US West CP creating a proxy in the us-east namespace (DB write only)
curl -X POST https://cp-west:9443/proxies \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Ferrum-Namespace: us-east" \
  -H "Content-Type: application/json" \
  -d '{"name": "api", "listen_path": "/api", "backend_host": "api.us-east.internal", "backend_port": 8080}'
```

`cp-west` (single-namespace `us-west`) does **not** broadcast this change.
`cp-east` picks it up on its next poll cycle and pushes it to US East DPs. If
`cp-east` is down, the config is stored but US East DPs keep serving cached
config until a `us-east`-scoped CP recovers.

### Three-Region Deployment with MongoDB

MongoDB simplifies the deployment significantly — no failover URLs or read replica configuration needed:

**All CPs (same connection string, different namespace):**

```bash
FERRUM_MODE=cp
FERRUM_NAMESPACE=us-east   # or us-west, us-central per region
FERRUM_DB_TYPE=mongodb
FERRUM_DB_URL=mongodb://mongo-east:27017,mongo-west:27017,mongo-central:27017/ferrum?replicaSet=rs0
FERRUM_CP_GRPC_LISTEN_ADDR=0.0.0.0:50051
FERRUM_CP_DP_GRPC_JWT_SECRET=$GRPC_JWT_SECRET_US_EAST   # the region's own secret
FERRUM_ADMIN_JWT_SECRET=$ADMIN_JWT_SECRET
FERRUM_CP_GRPC_TLS_CERT_PATH=/certs/server.pem
FERRUM_CP_GRPC_TLS_KEY_PATH=/certs/server-key.pem
```

**All DPs (same-namespace CP URLs only):**

```bash
FERRUM_MODE=dp
FERRUM_NAMESPACE=us-east
FERRUM_DP_CP_GRPC_URLS=https://cp-east:50051,https://cp-east-standby:50051
FERRUM_CP_DP_GRPC_JWT_SECRET=$GRPC_JWT_SECRET_US_EAST
FERRUM_ADMIN_JWT_SECRET=$ADMIN_JWT_SECRET
FERRUM_DP_GRPC_TLS_CA_CERT_PATH=/certs/ca.pem
```

## Operational Notes

### Failover writes and admin audit

`FERRUM_DB_FAILOVER_ALLOW_WRITES=true` is an explicit opt-in for config-database mutations while the active pool is on a failover URL. Use it only when you assert synchronously replicated multi-primary replication, and treat it as **single-replica-only**: each gateway process arms its own process-local primary-failback fence that is not coordinated across replicas. Shipped default is `false` (fail closed on failover writes).

For regulated deployments, Ferrum recommends (but does not ship by default) `FERRUM_ADMIN_AUDIT_ENABLED=true`, `FERRUM_ADMIN_AUDIT_UNAVAILABLE_POLICY=fail_closed`, and a persistent non-empty `FERRUM_ADMIN_AUDIT_SPOOL_DIR`. Shipped defaults are audit disabled with `fail_open` unavailable policy. See [configuration.md](configuration.md).

### Monitoring

Observability endpoints are tiered. Unauthenticated `/health` and `/status` return only `status` and `ready`; unauthenticated `/overload` returns only `{"level": ...}`. Detailed fields require observability auth (admin JWT, `FERRUM_METRICS_BEARER_TOKEN`, or `FERRUM_METRICS_ALLOWED_CIDRS`).

- Each CP's authenticated `/health` detail shows database connectivity and pool stats — monitor these to detect DB issues
- Authenticated `/health` also reports `database.failover_topology` and
  `admin_writes_enabled` while on a failover URL (see [admin_api.md](admin_api.md))
- Each DP's authenticated `/health` detail shows `cached_config` with `loaded_at` and a `dp_config` object (`cp_authority`, `snapshot_age_seconds`, `stale`) — see [cp_dp_mode.md](cp_dp_mode.md#bounded-last-known-good-configuration-age)
- Authenticated `/overload` detail shows resource pressure — useful for capacity planning

### Scaling CPs

CPs are stateless (they poll the DB and broadcast). You can run multiple CPs per region behind a load balancer when every replica serves the same namespace scope. Each CP independently polls the DB and maintains its own broadcast channel for subscribed DPs.

When listing multiple CP URLs in `FERRUM_DP_CP_GRPC_URLS` instead of a load balancer, every URL must serve the DP's namespace.

### Namespace Design

- Use one namespace per region for regional resource isolation
- Cross-region resources require **dedicated DPs** with `FERRUM_NAMESPACE` set to
  that shared namespace (for example `global`). A `us-east` DP loads only
  `us-east` resources — it never serves proxies from another namespace even if
  the CP could admin-write them
- To serve multiple namespaces from one DP fleet, split into separate DP
  deployments per namespace (or adopt multi-namespace CP scope + trust bundle
  per [cp_namespace_tenancy.md](cp_namespace_tenancy.md))

### Config Propagation Latency

With a shared database cluster, config changes propagate as:

1. Admin API write → database (immediate, latency depends on DB write path)
2. Database replication → other regions (milliseconds for same-region, 50-200ms cross-region typical)
3. CP poll → picks up change (`FERRUM_DB_POLL_INTERVAL`, default 30s) **for namespaces in CP scope**
4. CP broadcast → DPs receive update (immediate via gRPC streaming)

**Total worst-case latency**: DB replication time + poll interval. To reduce this, lower `FERRUM_DB_POLL_INTERVAL` (e.g., to 5-10s for latency-sensitive deployments).
