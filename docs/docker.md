# Docker Deployment Guide

This guide covers building and running Ferrum Edge using Docker and Docker Compose.

## Table of Contents

- [Building the Docker Image](#building-the-docker-image)
- [Running with Docker](#running-with-docker)
- [Running with Docker Compose](#running-with-docker-compose)
- [Configuration via Environment Variables](#configuration-via-environment-variables)
- [Production Deployment Tips](#production-deployment-tips)

## Building the Docker Image

### Prerequisites

- Docker 20.10+ or compatible container runtime
- Docker Compose 1.29+ (for docker-compose examples)

### Building Locally

```bash
# Build the image
docker build -t ferrum-edge:latest .

# Build with specific tag
docker build -t ferrum-edge:v0.1.0 .

# Build with custom name and registry
docker build -t myregistry.azurecr.io/ferrum-edge:latest .
```

### Image Details

The Dockerfile uses a **multi-stage build** for optimal size:

1. **Builder Stage**: Compiles the Rust binary with all build dependencies (rust:latest)
2. **Runtime Stage**: Google distroless image (`gcr.io/distroless/cc-debian13:nonroot`) — no shell, no package manager, no OS-level CVEs

**Image Features**:
- **Distroless**: Zero OS packages beyond glibc, libgcc, and ca-certificates. No shell, no curl, no apt — dramatically reduced attack surface
- Non-root user execution (UID 65532, distroless `nonroot`)
- Built-in health check via `ferrum-edge health` CLI subcommand
- Multi-platform support (x86_64, ARM64)
- OpenSSL is vendored (statically linked) — no runtime `libssl` dependency
- Comprehensive labels for container metadata

**Approximate Image Size**: ~30MB (varies by platform)

## Running with Docker

### Basic Usage

Single-node database mode with SQLite:

```bash
docker run -d \
  --name ferrum-edge \
  -p 8000:8000 \
  -p 8443:8443 \
  -p 9000:9000 \
  -p 9443:9443 \
  -e FERRUM_MODE=database \
  -e FERRUM_DB_TYPE=sqlite \
  -e FERRUM_DB_URL="sqlite:////data/ferrum.db?mode=rwc" \
  -e FERRUM_ADMIN_JWT_SECRET="your-secret-key" \
  -v ferrum_data:/data \
  ferrum-edge:latest
```

### Port Mappings

| Container Port | Purpose | Protocol |
|---|---|---|
| 8000 | HTTP proxy traffic | HTTP |
| 8443 | HTTPS proxy traffic | HTTPS |
| 9000 | Admin API (HTTP) | HTTP |
| 9443 | Admin API (HTTPS) | HTTPS |
| 50051 | gRPC (CP/DP communication) | gRPC |

### Volume Mounts

For persistent data, mount a volume:

```bash
# Create a named volume
docker volume create ferrum_data

# Mount volume in container
docker run -v ferrum_data:/data ferrum-edge:latest
```

### Health Check

The container includes a built-in health check using the `ferrum-edge health` CLI subcommand (no curl needed in distroless):

```bash
# Check container health
docker ps
# Shows health status (healthy/starting/unhealthy)

# Test from the host
curl -f http://localhost:9000/health
```

> **Note**: The distroless image has no shell or curl. Use `curl` from the host or configure orchestrator-level health checks (e.g., Kubernetes `httpGet` probes).

## Running with Docker Compose

Ferrum Edge includes a comprehensive `docker-compose.yml` with multiple deployment configurations.

### 1. SQLite Single-Node (Development/Testing)

Simplest setup - no external dependencies:

```bash
docker-compose up ferrum-sqlite
```

**Environment**:
- HTTP: http://localhost:8000
- Admin API: http://localhost:9000

**Data**:
- SQLite database stored in `ferrum_data` volume
- Persists between container restarts

### 2. PostgreSQL Single-Node (Production-Ready)

Production-grade setup with managed PostgreSQL:

```bash
# Set environment variables (optional)
export POSTGRES_PASSWORD="secure-password"
export FERRUM_ADMIN_JWT_SECRET="jwt-secret-key"

# Start PostgreSQL + Ferrum Edge
docker-compose --profile postgres up ferrum-postgres
```

**Services Started**:
- `postgres` - PostgreSQL 16 database
- `ferrum-postgres` - Ferrum Edge instance

**Environment**:
- HTTP: http://localhost:8001
- Admin API: http://localhost:9001
- PostgreSQL: localhost:5432

**Database Initialization**:
- Tables auto-created on first startup
- Automatic schema migrations

### 3. MongoDB Single-Node (NoSQL Alternative)

```bash
# Start services
docker compose --profile mongodb up -d

# Verify
curl http://localhost:9002/health
```

Uses the `mongodb` and `ferrum-mongodb` services defined in `docker-compose.yml`. See [docs/mongodb.md](mongodb.md) for the full MongoDB deployment guide including replica sets, read preference, and managed service configuration.

**Key differences from SQL**:
- Indexes created automatically instead of SQL migrations
- Read/write splitting via `readPreference` in connection string (not `FERRUM_DB_READ_REPLICA_URL`)
- `FERRUM_DB_POOL_*` settings are ignored — MongoDB driver manages its own pool

### 4. CP/DP Distributed Mode (Horizontal Scaling)

Multi-node architecture with separate Control Plane and Data Planes:

```bash
# Set environment variables
export POSTGRES_PASSWORD="secure-password"
export FERRUM_ADMIN_JWT_SECRET="jwt-secret-key"
export FERRUM_CP_DP_GRPC_JWT_SECRET="grpc-shared-secret"

# Start all services
docker-compose --profile cp-dp up
```

**Services Started**:
- `postgres` - Shared PostgreSQL database
- `ferrum-cp` - Control Plane (configuration authority)
- `ferrum-dp-1` - Data Plane node 1 (traffic handling)
- `ferrum-dp-2` - Data Plane node 2 (traffic handling)

**Port Mappings**:
- **Control Plane**:
  - Admin API: http://localhost:9002
  - gRPC: localhost:50051

- **Data Plane 1**:
  - HTTP: http://localhost:8002
  - Admin API (read-only): http://localhost:9003

- **Data Plane 2**:
  - HTTP: http://localhost:8003
  - Admin API (read-only): http://localhost:9004

**Architecture**:
```
┌─────────────────────────────────────┐
│         PostgreSQL Database         │
└──────────────┬──────────────────────┘
               │
        ┌──────▼──────┐
        │Control Plane│
        │ (CP gRPC)   │
        └──────┬──────┘
      ┌────────┴────────┐
      │                 │
  ┌───▼────┐       ┌───▼────┐
  │DP Node1│       │DP Node2│
  │(proxy) │       │(proxy) │
  └────────┘       └────────┘
```

**Traffic Flow**:
1. Client connects to DP node (load balanced)
2. DP requests config from CP
3. CP manages all proxies/consumers in PostgreSQL
4. Config changes pushed to all DPs in real-time
5. If CP unavailable, DPs continue with cached config

## Configuration via Environment Variables

All Ferrum Edge configuration uses environment variables. See the main [README.md](../README.md) for the complete environment variable reference.

### Essential Variables

```bash
# Operating mode (required)
FERRUM_MODE=database              # database, file, cp, dp

# Logging
FERRUM_LOG_LEVEL=info            # error, warn, info, debug, trace

# Proxy listeners
FERRUM_PROXY_HTTP_PORT=8000
FERRUM_PROXY_HTTPS_PORT=8443
FERRUM_FRONTEND_TLS_CERT_PATH=/path/to/cert.pem
FERRUM_FRONTEND_TLS_KEY_PATH=/path/to/key.pem

# Admin API
FERRUM_ADMIN_HTTP_PORT=9000
FERRUM_ADMIN_HTTPS_PORT=9443
FERRUM_ADMIN_JWT_SECRET=your-secret-key

# Database (for database/cp modes)
FERRUM_DB_TYPE=postgres           # postgres, mysql, sqlite, mongodb
FERRUM_DB_URL=postgres://user:pass@host/db
# For MongoDB: FERRUM_DB_URL=mongodb://user:pass@host:27017/ferrum
FERRUM_DB_POLL_INTERVAL=30

# Control Plane (for cp mode)
FERRUM_CP_GRPC_LISTEN_ADDR=0.0.0.0:50051
FERRUM_CP_DP_GRPC_JWT_SECRET=grpc-secret

# Data Plane (for dp mode)
FERRUM_DP_CP_GRPC_URL=http://cp:50051
FERRUM_CP_DP_GRPC_JWT_SECRET=grpc-secret
```

### Setting Variables in Docker

**Via `-e` flag**:
```bash
docker run -e FERRUM_LOG_LEVEL=debug ferrum-edge:latest
```

**Via `.env` file** (docker-compose):
```bash
# Create .env file
cat > .env << EOF
FERRUM_ADMIN_JWT_SECRET=my-secret
POSTGRES_PASSWORD=pg-secret
EOF

docker-compose up
```

**Via environment substitution**:
```bash
export FERRUM_ADMIN_JWT_SECRET="secret-key"
docker-compose up
```

## Production Deployment Tips

### 1. Security

**Use Strong Secrets**:
```bash
# Generate secure random secrets
openssl rand -base64 32  # JWT secret
openssl rand -base64 32  # gRPC secret
```

**Use Docker Secrets** (Swarm/Kubernetes):
```yaml
services:
  ferrum-edge:
    secrets:
      - admin_jwt_secret
secrets:
  admin_jwt_secret:
    external: true
```

**Enable TLS**:
```bash
docker run \
  -e FERRUM_FRONTEND_TLS_CERT_PATH=/etc/ferrum/cert.pem \
  -e FERRUM_FRONTEND_TLS_KEY_PATH=/etc/ferrum/key.pem \
  -v /etc/ferrum:/etc/ferrum:ro \
  ferrum-edge:latest
```

### 2. Persistent Data

**Backup Volumes**:
```bash
# Backup database volume
docker run --rm -v ferrum_data:/data -v $(pwd):/backup \
  alpine tar czf /backup/ferrum_backup.tar.gz /data

# Restore from backup
docker run --rm -v ferrum_data:/data -v $(pwd):/backup \
  alpine tar xzf /backup/ferrum_backup.tar.gz -C /
```

**External Database**:
```bash
# Use managed database (AWS RDS, Azure Database, etc.)
FERRUM_DB_URL=postgres://user:pass@rds-endpoint.amazonaws.com/ferrum
```

### 3. Logging and Monitoring

**Structured JSON Logs**:
```bash
# Enable JSON logging
docker run -e FERRUM_LOG_LEVEL=info ferrum-edge:latest

# Ship logs to aggregator
docker run \
  --log-driver json-file \
  --log-opt max-size=10m \
  --log-opt max-file=10 \
  ferrum-edge:latest
```

**Prometheus Metrics**:
```bash
# Metrics available at Admin API
curl -H "Authorization: Bearer $TOKEN" http://localhost:9000/admin/metrics
```

**Health Monitoring**:
```bash
# Container health check (automatic via ferrum-edge health subcommand)
docker ps
# HEALTHCHECK shows status

# Manual health endpoint (from host)
curl http://localhost:9000/health
# {"status": "ok"}
```

### 4. Resource Limits

**CPU and Memory**:
```bash
docker run \
  --cpus="2" \
  --memory="2g" \
  --memory-swap="2g" \
  ferrum-edge:latest
```

**In docker-compose.yml**:
```yaml
services:
  ferrum-edge:
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 2G
        reservations:
          cpus: '1'
          memory: 1G
```

### 5. Scaling

**Horizontal Scaling** (CP/DP Mode):
```bash
# Start multiple DP nodes
docker-compose --profile cp-dp up --scale ferrum-dp=5
```

**Load Balancing**:
```bash
# Using nginx as load balancer
docker run -d \
  -p 80:80 \
  -v /path/to/nginx.conf:/etc/nginx/nginx.conf \
  nginx:latest
```

**nginx.conf Example**:
```nginx
upstream ferrum {
    server ferrum-dp-1:8000;
    server ferrum-dp-2:8000;
}

server {
    listen 80;
    location / {
        proxy_pass http://ferrum;
    }
}
```

### 6. Graceful Shutdown

Docker sends SIGTERM to graceful shutdown:

```bash
# Container will drain active requests before stopping
docker stop --time=30 ferrum-edge
```

**In orchestration** (Kubernetes):

> **Note**: The distroless image has no shell. Use a `httpGet` preStop hook or configure `terminationGracePeriodSeconds` instead of a shell-based sleep.

```yaml
terminationGracePeriodSeconds: 30
```

### 7. Upgrade Strategy

**Rolling Updates** (docker-compose):
```bash
# Update image
docker-compose pull

# Restart with new image (one at a time)
docker-compose up -d --no-deps --build ferrum-edge
```

**Blue-Green Deployment**:
```bash
# Keep old and new versions running
docker-compose up -d ferrum-edge-v1
docker-compose up -d ferrum-edge-v2

# Switch load balancer when ready
# Remove old version
docker-compose rm ferrum-edge-v1
```

### 8. Backup and Recovery

**Automated Backups**:
```bash
#!/bin/bash
# backup.sh
docker exec ferrum-postgres pg_dump -U ferrum ferrum > backup.sql
gzip backup.sql
aws s3 cp backup.sql.gz s3://my-backups/$(date +%Y%m%d).sql.gz
```

**Point-in-Time Recovery**:
```bash
# Restore PostgreSQL from backup
docker-compose down
docker volume rm ferrum_postgres_data
docker-compose up -d postgres
docker exec -i postgres psql -U ferrum < backup.sql
docker-compose up -d ferrum-postgres
```

## Docker Compose Commands

```bash
# Start services
docker-compose up -d

# View logs
docker-compose logs -f ferrum-edge

# Stop services
docker-compose down

# Remove volumes
docker-compose down -v

# Restart a service
docker-compose restart ferrum-edge

# Scale service (for DP mode)
docker-compose up -d --scale ferrum-dp=5

# Check health from host
curl http://localhost:9000/health

# View resource usage
docker stats
```

## Troubleshooting

### Container Won't Start

**Check logs**:
```bash
docker logs ferrum-edge
```

**Common Issues**:
- Port already in use: Change `FERRUM_PROXY_HTTP_PORT` or stop conflicting service
- Database connection failed: Verify `FERRUM_DB_URL` and database accessibility
- Missing environment variables: Ensure required vars are set

### Permission Denied

The container runs as the distroless `nonroot` user (UID 65532). Ensure volume permissions:

```bash
# Fix volume permissions on the host before starting the container
sudo chown -R 65532:65532 /path/to/volume
```

> **Note**: `docker exec` with shell commands is not available in distroless images (no shell). Fix permissions from the host or use an init container.

### Health Check Failing

```bash
# Debug health endpoint (from host — no curl available inside distroless)
curl -v http://localhost:9000/health

# Check Admin API JWT (from host)
curl -H "Authorization: Bearer $TOKEN" http://localhost:9000/health

# Check Docker health status
docker inspect --format='{{.State.Health.Status}}' ferrum-edge
```

## See Also

- [Main README](../README.md) - Configuration and usage
- [CI/CD Documentation](ci_cd.md) - Automated releases
- [CP/DP Mode](cp_dp_mode.md) - Distributed architecture
