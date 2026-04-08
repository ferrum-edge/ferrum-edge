# Database TLS Configuration

Ferrum Edge supports TLS-encrypted connections to PostgreSQL, MySQL, and MongoDB databases. SQLite is an embedded database with no network layer, so TLS does not apply.

## Quick Reference

| Database   | TLS Support | SSL Mode Values                                         | mTLS (Client Certs) |
|------------|-------------|---------------------------------------------------------|----------------------|
| PostgreSQL | Yes         | `disable`, `prefer`, `require`, `verify-ca`, `verify-full` | Yes                  |
| MySQL      | Yes         | `disable`, `prefer`, `require`, `verify-ca`, `verify-full` | Yes                  |
| MongoDB    | Yes         | Via `FERRUM_DB_TLS_*` env vars or connection string options | Yes                  |
| SQLite     | N/A         | All SSL settings silently ignored                       | N/A                  |

## Configuration Approaches

Ferrum Edge provides two approaches for configuring database TLS. **The native SQL parameter approach is recommended.**

### Approach 1: Native SQL Parameters (Recommended)

Uses `FERRUM_DB_SSL_*` environment variables that map directly to database driver parameters.

| Environment Variable       | Description                                                      | Example                     |
|---------------------------|------------------------------------------------------------------|-----------------------------|
| `FERRUM_DB_SSL_MODE`       | SSL connection mode                                              | `verify-full`               |
| `FERRUM_DB_SSL_ROOT_CERT`  | Path to CA certificate for server verification                   | `/etc/ferrum/certs/ca.crt`  |
| `FERRUM_DB_SSL_CLIENT_CERT`| Path to client certificate for mutual TLS                        | `/etc/ferrum/certs/client.crt` |
| `FERRUM_DB_SSL_CLIENT_KEY` | Path to client private key for mutual TLS                        | `/etc/ferrum/certs/client.key` |

These variables are appended to the `FERRUM_DB_URL` connection string as query parameters. The gateway automatically translates them into the correct format for each database:

**PostgreSQL** — appended as `sslmode=X&sslrootcert=Y&sslcert=Z&sslkey=W`

**MySQL** — values are mapped to MySQL conventions:
- `disable` → `DISABLED`
- `prefer` → `PREFERRED`
- `require` → `REQUIRED`
- `verify-ca` → `VERIFY_CA`
- `verify-full` → `VERIFY_IDENTITY`

### Approach 2: Legacy TLS Configuration

Uses `FERRUM_DB_TLS_*` environment variables that configure TLS at the connection builder level.

| Environment Variable          | Description                                         | Default |
|-------------------------------|-----------------------------------------------------|---------|
| `FERRUM_DB_TLS_ENABLED`       | Enable TLS for the database connection              | `false` |
| `FERRUM_DB_TLS_CA_CERT_PATH`  | Path to CA certificate for server verification      | (none)  |
| `FERRUM_DB_TLS_CLIENT_CERT_PATH` | Path to client certificate for mTLS              | (none)  |
| `FERRUM_DB_TLS_CLIENT_KEY_PATH`  | Path to client private key for mTLS              | (none)  |
| `FERRUM_DB_TLS_INSECURE`      | Skip server certificate verification (testing only) | `false` |

When `FERRUM_DB_TLS_ENABLED=true`:
- **`FERRUM_DB_TLS_INSECURE=false`** (default): Uses `sslmode=verify-full` (PostgreSQL) or `ssl-mode=VERIFY_IDENTITY` (MySQL) — encrypted and verified.
- **`FERRUM_DB_TLS_INSECURE=true`**: Uses `sslmode=require` (PostgreSQL) or `ssl-mode=REQUIRED` (MySQL) — encrypted but **no certificate verification**.

## PostgreSQL TLS Setup

### Server-Side Setup

Enable SSL in PostgreSQL by configuring `postgresql.conf`:

```conf
ssl = on
ssl_cert_file = '/path/to/server.crt'
ssl_key_file = '/path/to/server.key'
ssl_ca_file = '/path/to/ca.crt'
```

The server key must have restrictive permissions (`chmod 600`) and be owned by the postgres user.

### Gateway Configuration

#### Encrypted + Full Verification (Production)

```bash
export FERRUM_MODE=database
export FERRUM_DB_TYPE=postgres
export FERRUM_DB_URL="postgres://ferrum:password@db-host:5432/ferrum"
export FERRUM_DB_SSL_MODE=verify-full
export FERRUM_DB_SSL_ROOT_CERT=/etc/ferrum/certs/ca.crt
```

This verifies:
1. The connection is encrypted (TLS)
2. The server certificate is signed by a trusted CA
3. The server hostname matches the certificate's CN or SAN

#### Encrypted + CA Verification (No Hostname Check)

```bash
export FERRUM_DB_SSL_MODE=verify-ca
export FERRUM_DB_SSL_ROOT_CERT=/etc/ferrum/certs/ca.crt
```

#### Encrypted Only (No Verification)

```bash
export FERRUM_DB_SSL_MODE=require
```

Encrypts the connection but does not verify the server certificate. Suitable for development or when using private networks.

#### Mutual TLS (Client Certificate Authentication)

```bash
export FERRUM_DB_SSL_MODE=verify-full
export FERRUM_DB_SSL_ROOT_CERT=/etc/ferrum/certs/ca.crt
export FERRUM_DB_SSL_CLIENT_CERT=/etc/ferrum/certs/client.crt
export FERRUM_DB_SSL_CLIENT_KEY=/etc/ferrum/certs/client.key
```

Requires PostgreSQL to be configured with `ssl_ca_file` pointing to a CA that signed the client certificate, and `pg_hba.conf` entries using `hostssl ... cert` authentication.

### Docker Example

```bash
# Generate test certificates
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 365 -key ca.key -out ca.crt -subj "/CN=Test CA"
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -subj "/CN=postgres"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days 365 -out server.crt

# Start PostgreSQL with TLS
docker run -d \
  --name pg-tls \
  -p 5432:5432 \
  -e POSTGRES_DB=ferrum \
  -e POSTGRES_USER=ferrum \
  -e POSTGRES_PASSWORD=secret \
  -v $(pwd)/certs:/certs-src:ro \
  --entrypoint sh \
  postgres:16 \
  -c 'cp /certs-src/server.crt /var/lib/postgresql/ &&
      cp /certs-src/server.key /var/lib/postgresql/ &&
      cp /certs-src/ca.crt /var/lib/postgresql/ &&
      chown postgres:postgres /var/lib/postgresql/server.* /var/lib/postgresql/ca.crt &&
      chmod 600 /var/lib/postgresql/server.key &&
      exec docker-entrypoint.sh postgres \
        -c ssl=on \
        -c ssl_cert_file=/var/lib/postgresql/server.crt \
        -c ssl_key_file=/var/lib/postgresql/server.key \
        -c ssl_ca_file=/var/lib/postgresql/ca.crt'

# Start gateway with TLS verification
docker run -d \
  -e FERRUM_MODE=database \
  -e FERRUM_DB_TYPE=postgres \
  -e FERRUM_DB_URL="postgres://ferrum:secret@host.docker.internal:5432/ferrum" \
  -e FERRUM_DB_SSL_MODE=verify-full \
  -e FERRUM_DB_SSL_ROOT_CERT=/certs/ca.crt \
  -e FERRUM_ADMIN_JWT_SECRET=your-secret \
  -v $(pwd)/certs:/certs:ro \
  ferrum-edge
```

## MySQL TLS Setup

### Server-Side Setup

Enable SSL in MySQL by setting system variables:

```sql
-- my.cnf or command-line flags
[mysqld]
require_secure_transport = ON
ssl-cert = /path/to/server-cert.pem
ssl-key = /path/to/server-key.pem
ssl-ca = /path/to/ca.pem
```

### Gateway Configuration

#### Encrypted + Identity Verification (Production)

```bash
export FERRUM_MODE=database
export FERRUM_DB_TYPE=mysql
export FERRUM_DB_URL="mysql://ferrum:password@db-host:3306/ferrum"
export FERRUM_DB_SSL_MODE=verify-full
export FERRUM_DB_SSL_ROOT_CERT=/etc/ferrum/certs/ca.crt
```

`verify-full` is automatically translated to MySQL's `VERIFY_IDENTITY`, which verifies the server certificate and checks that the hostname matches.

#### Encrypted + CA Verification Only

```bash
export FERRUM_DB_SSL_MODE=verify-ca
export FERRUM_DB_SSL_ROOT_CERT=/etc/ferrum/certs/ca.crt
```

Translated to MySQL's `VERIFY_CA`.

#### Encrypted Only

```bash
export FERRUM_DB_SSL_MODE=require
```

Translated to MySQL's `REQUIRED`.

#### Mutual TLS

```bash
export FERRUM_DB_SSL_MODE=verify-full
export FERRUM_DB_SSL_ROOT_CERT=/etc/ferrum/certs/ca.crt
export FERRUM_DB_SSL_CLIENT_CERT=/etc/ferrum/certs/client.crt
export FERRUM_DB_SSL_CLIENT_KEY=/etc/ferrum/certs/client.key
```

### Docker Example

```bash
# Start MySQL with TLS
docker run -d \
  --name mysql-tls \
  -p 3306:3306 \
  -e MYSQL_DATABASE=ferrum \
  -e MYSQL_USER=ferrum \
  -e MYSQL_PASSWORD=secret \
  -e MYSQL_ROOT_PASSWORD=root-secret \
  -v $(pwd)/certs/server-cert.pem:/etc/mysql/ssl/server-cert.pem:ro \
  -v $(pwd)/certs/server-key.pem:/etc/mysql/ssl/server-key.pem:ro \
  -v $(pwd)/certs/ca.pem:/etc/mysql/ssl/ca.pem:ro \
  mysql:8 \
  --require-secure-transport=ON \
  --ssl-cert=/etc/mysql/ssl/server-cert.pem \
  --ssl-key=/etc/mysql/ssl/server-key.pem \
  --ssl-ca=/etc/mysql/ssl/ca.pem

# Start gateway
docker run -d \
  -e FERRUM_MODE=database \
  -e FERRUM_DB_TYPE=mysql \
  -e FERRUM_DB_URL="mysql://ferrum:secret@host.docker.internal:3306/ferrum" \
  -e FERRUM_DB_SSL_MODE=verify-full \
  -e FERRUM_DB_SSL_ROOT_CERT=/certs/ca.crt \
  -e FERRUM_ADMIN_JWT_SECRET=your-secret \
  -v $(pwd)/certs:/certs:ro \
  ferrum-edge
```

## MongoDB

MongoDB TLS is configured through the `FERRUM_DB_TLS_*` environment variables (same as PostgreSQL/MySQL) or directly via connection string options. The `FERRUM_DB_TLS_*` approach is recommended for consistency with SQL backends.

### Using FERRUM_DB_TLS_* Environment Variables (Recommended)

```bash
export FERRUM_MODE=database
export FERRUM_DB_TYPE=mongodb
export FERRUM_DB_URL="mongodb://user:pass@mongo.example.com:27017/ferrum?authSource=admin"
export FERRUM_MONGO_DATABASE=ferrum

# Enable TLS with CA verification
export FERRUM_DB_TLS_ENABLED=true
export FERRUM_DB_TLS_CA_CERT_PATH=/path/to/ca.pem

# Client certificate authentication (mTLS)
export FERRUM_DB_TLS_CLIENT_CERT_PATH=/path/to/client.crt
export FERRUM_DB_TLS_CLIENT_KEY_PATH=/path/to/client.key

# Skip server cert verification (testing only)
# export FERRUM_DB_TLS_INSECURE=true
```

**Note:** MongoDB requires client cert + key in a single PEM file. When separate `FERRUM_DB_TLS_CLIENT_CERT_PATH` and `FERRUM_DB_TLS_CLIENT_KEY_PATH` are provided, the gateway automatically combines them into a temporary PEM file at startup.

### Using Connection String Options

TLS can also be configured directly in the MongoDB connection string. Connection string options take precedence over `FERRUM_DB_TLS_*` environment variables.

```bash
# TLS with CA verification
export FERRUM_DB_URL="mongodb://user:pass@mongo.example.com:27017/ferrum?tls=true&tlsCAFile=/path/to/ca.pem"

# mTLS (client cert auth) — cert+key must be in a single combined PEM file
export FERRUM_DB_URL="mongodb://user:pass@mongo.example.com:27017/ferrum?tls=true&tlsCAFile=/path/to/ca.pem&tlsCertificateKeyFile=/path/to/client-combined.pem"

# Skip cert validation (testing only)
export FERRUM_DB_URL="mongodb://user:pass@mongo.example.com:27017/ferrum?tlsAllowInvalidCertificates=true"

# MongoDB Atlas (SRV DNS with automatic TLS)
export FERRUM_DB_URL="mongodb+srv://user:pass@cluster0.abc123.mongodb.net/ferrum"
```

### MONGODB-X509 Authentication

For X.509 certificate-based authentication (no password), use the `FERRUM_MONGO_AUTH_MECHANISM` env var:

```bash
export FERRUM_DB_TYPE=mongodb
export FERRUM_DB_URL="mongodb://mongo.example.com:27017/ferrum"
export FERRUM_MONGO_AUTH_MECHANISM=MONGODB-X509
export FERRUM_DB_TLS_ENABLED=true
export FERRUM_DB_TLS_CA_CERT_PATH=/path/to/ca.pem
export FERRUM_DB_TLS_CLIENT_CERT_PATH=/path/to/client.crt
export FERRUM_DB_TLS_CLIENT_KEY_PATH=/path/to/client.key
```

### Docker Example

```bash
docker run -d --name ferrum-edge \
  -p 8000:8000 -p 9000:9000 \
  -e FERRUM_MODE=database \
  -e FERRUM_DB_TYPE=mongodb \
  -e FERRUM_DB_URL="mongodb://user:pass@mongo:27017/?authSource=admin" \
  -e FERRUM_MONGO_DATABASE=ferrum \
  -e FERRUM_DB_TLS_ENABLED=true \
  -e FERRUM_DB_TLS_CA_CERT_PATH=/certs/ca.pem \
  -e FERRUM_DB_TLS_CLIENT_CERT_PATH=/certs/client.crt \
  -e FERRUM_DB_TLS_CLIENT_KEY_PATH=/certs/client.key \
  -e FERRUM_ADMIN_JWT_SECRET="dev-secret" \
  -v /path/to/certs:/certs:ro \
  ghcr.io/ferrum-edge/ferrum-edge:latest
```

**Note on MongoDB URL path vs `FERRUM_MONGO_DATABASE`:** The database name in the URL path (e.g., `mongodb://host/mydb`) is the **auth database** — where MongoDB looks up credentials. `FERRUM_MONGO_DATABASE` controls which database the gateway stores config in. For authenticated connections, use `?authSource=admin` (or your auth DB) and set `FERRUM_MONGO_DATABASE` separately. For no-auth dev setups, the URL path is ignored.

## SQLite

SQLite is an embedded, file-based database. It does not use network connections, so TLS is not applicable. Any `FERRUM_DB_SSL_*` or `FERRUM_DB_TLS_*` environment variables are silently ignored when `FERRUM_DB_TYPE=sqlite`.

```bash
export FERRUM_MODE=database
export FERRUM_DB_TYPE=sqlite
export FERRUM_DB_URL="sqlite:///data/ferrum.db?mode=rwc"
# FERRUM_DB_SSL_* variables are ignored — no warning, no error
```

## SSL Mode Reference

| Mode          | Encrypted | Server Cert Verified | Hostname Verified | Use Case                         |
|---------------|-----------|----------------------|-------------------|----------------------------------|
| `disable`     | No        | No                   | No                | Development only                 |
| `prefer`      | Maybe     | No                   | No                | Development (uses TLS if server supports it) |
| `require`     | Yes       | No                   | No                | Private networks, testing        |
| `verify-ca`   | Yes       | Yes                  | No                | Trusted CA, dynamic hostnames    |
| `verify-full` | Yes       | Yes                  | Yes               | **Production (recommended)**     |

## Managed Database Services

Most managed database services (AWS RDS, Azure Database, Google Cloud SQL) provide TLS by default. Use the CA certificate bundle provided by the cloud provider.

### AWS RDS PostgreSQL

```bash
export FERRUM_DB_TYPE=postgres
export FERRUM_DB_URL="postgres://ferrum:password@mydb.xxxx.us-east-1.rds.amazonaws.com:5432/ferrum"
export FERRUM_DB_SSL_MODE=verify-full
export FERRUM_DB_SSL_ROOT_CERT=/etc/ferrum/rds-combined-ca-bundle.pem
```

### AWS RDS MySQL

```bash
export FERRUM_DB_TYPE=mysql
export FERRUM_DB_URL="mysql://ferrum:password@mydb.xxxx.us-east-1.rds.amazonaws.com:3306/ferrum"
export FERRUM_DB_SSL_MODE=verify-full
export FERRUM_DB_SSL_ROOT_CERT=/etc/ferrum/rds-combined-ca-bundle.pem
```

### Azure Database for PostgreSQL

```bash
export FERRUM_DB_TYPE=postgres
export FERRUM_DB_URL="postgres://ferrum:password@mydb.postgres.database.azure.com:5432/ferrum"
export FERRUM_DB_SSL_MODE=verify-full
export FERRUM_DB_SSL_ROOT_CERT=/etc/ferrum/DigiCertGlobalRootCA.crt.pem
```

### MongoDB Atlas

TLS is enabled by default when using `mongodb+srv://` URLs:

```bash
export FERRUM_DB_TYPE=mongodb
export FERRUM_DB_URL="mongodb+srv://ferrum:password@cluster0.abc123.mongodb.net/ferrum?retryWrites=true&w=majority&readPreference=secondaryPreferred"
export FERRUM_MONGO_DATABASE=ferrum
# No FERRUM_DB_TLS_* needed — Atlas enables TLS by default via mongodb+srv://
```

### AWS DocumentDB

```bash
export FERRUM_DB_TYPE=mongodb
export FERRUM_DB_URL="mongodb://ferrum:password@docdb-cluster.xxxx.us-east-1.docdb.amazonaws.com:27017/ferrum?retryWrites=false"
export FERRUM_MONGO_DATABASE=ferrum
export FERRUM_DB_TLS_ENABLED=true
export FERRUM_DB_TLS_CA_CERT_PATH=/etc/ferrum/rds-combined-ca-bundle.pem
```

**Note:** DocumentDB requires `retryWrites=false` (retryable writes not supported).

## Functional Testing

The project includes functional tests that verify TLS database connectivity end-to-end.

### Setup

```bash
# Generate certificates and start TLS-enabled database containers
./tests/scripts/setup_db_tls.sh

# Build the gateway
cargo build
```

### Run Tests

```bash
# Run all database TLS tests
cargo test --test functional_tests functional_db_tls -- --ignored --nocapture

# Run individual tests
cargo test --test functional_tests test_postgresql_tls_verify_full -- --ignored --nocapture
cargo test --test functional_tests test_mysql_tls_verify_identity -- --ignored --nocapture
cargo test --test functional_tests test_sqlite_ignores_tls_settings -- --ignored --nocapture
```

### Test Coverage

| Test                                   | Database   | TLS Mode        | What It Verifies                                |
|----------------------------------------|------------|-----------------|------------------------------------------------|
| `test_postgresql_tls_verify_full`      | PostgreSQL | verify-full     | Full cert verification + CRUD + proxy routing   |
| `test_postgresql_tls_require`          | PostgreSQL | require         | Encrypted connection + CRUD + proxy routing     |
| `test_postgresql_tls_legacy_insecure`  | PostgreSQL | legacy insecure | Legacy `FERRUM_DB_TLS_*` env vars work          |
| `test_mysql_tls_verify_identity`       | MySQL      | verify-full     | Full cert verification + CRUD + proxy routing   |
| `test_mysql_tls_required`              | MySQL      | require         | Encrypted connection + CRUD + proxy routing     |
| `test_mysql_tls_legacy_insecure`       | MySQL      | legacy insecure | Legacy `FERRUM_DB_TLS_*` env vars work          |
| `test_sqlite_ignores_tls_settings`     | SQLite     | N/A             | SSL env vars are silently ignored               |
| `test_health_endpoint_shows_db_status` | PostgreSQL | require         | Health endpoint works with TLS database         |

Each test performs a complete CRUD cycle:
1. Creates an upstream, proxy, consumer, and plugin config via the Admin API
2. Reads each resource back and verifies correctness
3. Waits for database polling to load the proxy into the routing table
4. Sends an HTTP request through the proxy to verify end-to-end routing
5. Updates and verifies a proxy modification
6. Lists all resources
7. Deletes all resources

### Cleanup

```bash
# Stop and remove the test database containers
./tests/scripts/setup_db_tls.sh --cleanup
```

## Troubleshooting

### "certificate verify failed" / "ssl_ca_file not found"

- Verify the CA cert path exists and is readable by the gateway process
- Ensure the CA cert was used to sign the server's certificate
- For `verify-full`: ensure the server hostname matches the certificate's CN or SAN

### "SSL required" from MySQL

MySQL's `require_secure_transport=ON` rejects non-TLS connections. Set at least `FERRUM_DB_SSL_MODE=require`.

### PostgreSQL key permission errors

PostgreSQL requires the server key file to have `chmod 600` and be owned by the postgres user. The setup script handles this via a copy-and-chown step.

### Connection works without TLS env vars

If the database URL already contains SSL parameters (e.g., `?sslmode=require`), those take precedence. The `FERRUM_DB_SSL_*` variables are appended and may conflict. Use one approach or the other.

## Failover and Read Replica URLs

### SQL Databases (PostgreSQL, MySQL)

When using `FERRUM_DB_FAILOVER_URLS` or `FERRUM_DB_READ_REPLICA_URL`, the same TLS
settings (`FERRUM_DB_TLS_*` and `FERRUM_DB_SSL_*`) apply to all database connections.
If your failover or replica databases require different TLS parameters, embed them
directly in the URL query string:

```
FERRUM_DB_FAILOVER_URLS=postgres://standby1:5432/ferrum?sslmode=verify-full&sslrootcert=/certs/ca.pem,postgres://standby2:5432/ferrum?sslmode=require
```

### MongoDB

MongoDB handles failover and read routing differently from SQL backends:

- **`FERRUM_DB_READ_REPLICA_URL` does not apply to MongoDB.** Use `readPreference` in the connection string instead (e.g., `?readPreference=secondaryPreferred`). The MongoDB driver routes reads to secondaries and writes to the primary automatically.

- **`FERRUM_DB_FAILOVER_URLS` is typically unnecessary for MongoDB replica sets.** List all members directly in `FERRUM_DB_URL` and the driver handles failover natively:

```
FERRUM_DB_URL=mongodb://mongo1:27017,mongo2:27017,mongo3:27017/ferrum?replicaSet=rs0&readPreference=secondaryPreferred&tls=true&tlsCAFile=/certs/ca.pem
```

See [docs/mongodb.md](mongodb.md) for the full MongoDB deployment guide including Atlas, DocumentDB, and Kubernetes examples.
