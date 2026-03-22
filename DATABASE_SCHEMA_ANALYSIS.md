# 🗄️ **Database Schema Architecture & Multi-DB Support**

## **🏗️ How Database Schema Creation Works**

### **📋 Universal Schema Design**

The Ferrum Gateway uses a **database-agnostic schema** that works across all supported databases (PostgreSQL, MySQL, SQLite) through `sqlx::Any`. The schema is defined in `/src/config/db_loader.rs` in the `run_migrations()` method.

### **🔧 Database Driver Installation**

```rust
// In connect() method
sqlx::any::install_default_drivers();
```

This single call installs drivers for:
- ✅ **PostgreSQL** via `sqlx-postgres`
- ✅ **MySQL** via `sqlx-mysql` 
- ✅ **SQLite** via `sqlx-sqlite`

### **📊 Schema Tables Created**

The system automatically creates **5 core tables** on first startup:

#### **1. `proxies` Table - Main Route Definitions**
```sql
CREATE TABLE IF NOT EXISTS proxies (
    id TEXT PRIMARY KEY,                           -- "proxy-httpbin"
    name TEXT,                                     -- "HTTPBin Proxy"  
    listen_path TEXT NOT NULL UNIQUE,             -- "/httpbin" (UNIQUE enforced!)
    backend_protocol TEXT NOT NULL DEFAULT 'http', -- "https", "ws", "wss", "grpc"
    backend_host TEXT NOT NULL,                   -- "httpbin.org"
    backend_port INTEGER NOT NULL DEFAULT 80,     -- 443
    backend_path TEXT,                            -- Optional backend path prefix
    strip_listen_path INTEGER NOT NULL DEFAULT 1, -- Boolean (1=true, 0=false)
    preserve_host_header INTEGER NOT NULL DEFAULT 0, -- Boolean
    backend_connect_timeout_ms INTEGER NOT NULL DEFAULT 5000,
    backend_read_timeout_ms INTEGER NOT NULL DEFAULT 30000,
    backend_write_timeout_ms INTEGER NOT NULL DEFAULT 30000,
    backend_tls_client_cert_path TEXT,             -- mTLS support (future)
    backend_tls_client_key_path TEXT,              -- mTLS support (future)
    backend_tls_verify_server_cert INTEGER NOT NULL DEFAULT 1,
    backend_tls_server_ca_cert_path TEXT,          -- Custom CA support (future)
    dns_override TEXT,                             -- Static IP override
    dns_cache_ttl_seconds INTEGER,                 -- Custom DNS TTL
    auth_mode TEXT NOT NULL DEFAULT 'single',     -- "single" or "multi"
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
)
```

#### **2. `consumers` Table - API Users**
```sql
CREATE TABLE IF NOT EXISTS consumers (
    id TEXT PRIMARY KEY,                           -- Unique consumer ID
    username TEXT NOT NULL UNIQUE,                 -- "alice", "bob" (UNIQUE!)
    custom_id TEXT,                                -- Optional custom identifier
    credentials TEXT NOT NULL DEFAULT '{}',        -- JSON credential store
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
)
```

#### **3. `plugin_configs` Table - Plugin Configuration**
```sql
CREATE TABLE IF NOT EXISTS plugin_configs (
    id TEXT PRIMARY KEY,                           -- "plugin-stdout"
    plugin_name TEXT NOT NULL,                     -- "stdout_logging"
    config TEXT NOT NULL DEFAULT '{}',             -- JSON plugin config
    scope TEXT NOT NULL DEFAULT 'global',          -- "global" or "proxy"
    proxy_id TEXT,                                 -- NULL for global, proxy_id for scoped
    enabled INTEGER NOT NULL DEFAULT 1,            -- Boolean
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
)
```

#### **4. `proxy_plugins` Table - Many-to-Many Relationship**
```sql
CREATE TABLE IF NOT EXISTS proxy_plugins (
    proxy_id TEXT NOT NULL,
    plugin_config_id TEXT NOT NULL,
    PRIMARY KEY (proxy_id, plugin_config_id)       -- Composite key
)
```

#### **5. `upstreams` Table - Load-Balanced Backend Groups**
```sql
CREATE TABLE IF NOT EXISTS upstreams (
    id TEXT PRIMARY KEY,                            -- "upstream-backend-pool"
    name TEXT,                                      -- "My Backend Pool"
    targets TEXT NOT NULL DEFAULT '[]',             -- JSON array of {host, port, weight, tags}
    algorithm TEXT NOT NULL DEFAULT 'round_robin',  -- Load balancing algorithm
    hash_on TEXT,                                   -- Field for consistent hashing (e.g. "header:x-user-id")
    health_checks TEXT,                             -- JSON health check config (active/passive)
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
)
```

Upstreams store their `targets` and `health_checks` as JSON text columns, supporting variable-length arrays of backend targets and nested health check configuration without additional join tables.

---

## **🔄 File Config ↔ Database Schema Mapping**

### **📋 YAML Configuration Maps Directly to Database**

Your `tests/config.yaml` file structure maps **1:1** to the database schema:

#### **Example YAML → Database Mapping**

**YAML Configuration:**
```yaml
proxies:
  - id: "proxy-httpbin"
    name: "HTTPBin Proxy"
    listen_path: "/httpbin"
    backend_protocol: https
    backend_host: "httpbin.org"
    backend_port: 443
    strip_listen_path: true
    preserve_host_header: false
    backend_connect_timeout_ms: 5000
    backend_read_timeout_ms: 30000
    backend_write_timeout_ms: 30000
    backend_tls_verify_server_cert: true
    auth_mode: single
    plugins:
      - plugin_config_id: "plugin-stdout"
```

**Database Storage:**
```sql
INSERT INTO proxies (
    id, name, listen_path, backend_protocol, backend_host, backend_port,
    strip_listen_path, preserve_host_header, backend_connect_timeout_ms,
    backend_read_timeout_ms, backend_write_timeout_ms, backend_tls_verify_server_cert,
    auth_mode, created_at, updated_at
) VALUES (
    'proxy-httpbin', 'HTTPBin Proxy', '/httpbin', 'https', 'httpbin.org', 443,
    1, 0, 5000, 30000, 30000, 1, 'single', '2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z'
);

INSERT INTO proxy_plugins (proxy_id, plugin_config_id) 
VALUES ('proxy-httpbin', 'plugin-stdout');
```

---

## **🔧 Multi-Database Compatibility**

### **✅ How It Works Across All Databases**

#### **1. Universal SQL Types**
The schema uses **portable SQL types** that work everywhere:

| YAML/Config Type | Database Storage | SQLite | PostgreSQL | MySQL |
|------------------|------------------|---------|------------|-------|
| `String` | `TEXT` | `TEXT` | `TEXT` | `TEXT` |
| `u16` (port) | `INTEGER` | `INTEGER` | `INTEGER` | `INTEGER` |
| `u64` (timeouts) | `INTEGER` | `INTEGER` | `INTEGER` | `INTEGER` |
| `bool` | `INTEGER` (0/1) | `INTEGER` | `INTEGER` | `INTEGER` |
| `DateTime` | `TEXT` (ISO8601) | `TEXT` | `TEXT` | `TEXT` |
| `JSON` | `TEXT` | `TEXT` | `TEXT` | `TEXT` |

#### **2. Database-Specific Handling**

**SQLite:**
```bash
FERRUM_DB_TYPE=sqlite \
FERRUM_DB_URL="sqlite://ferrum.db?mode=rwc"
```
- Creates single file `ferrum.db`
- Auto-creates tables on first run
- Perfect for development and small deployments

**PostgreSQL:**
```bash
FERRUM_DB_TYPE=postgres \
FERRUM_DB_URL="postgres://user:pass@localhost/ferrum"
```
- Requires PostgreSQL server
- Better for production workloads
- Supports concurrent connections

**MySQL:**
```bash
FERRUM_DB_TYPE=mysql \
FERRUM_DB_URL="mysql://user:pass@localhost/ferrum"
```
- Requires MySQL server
- Alternative production option
- Widely supported hosting

---

## **🔄 Configuration Loading Flow**

### **📋 File Mode vs Database Mode**

#### **File Mode (`FERRUM_MODE=file`)**
```rust
// file_loader.rs
let config: GatewayConfig = match ext.as_str() {
    "yaml" => serde_yaml::from_str(&content)?,
    "json" => serde_json::from_str(&content)?
};
```
- Direct deserialization from YAML/JSON to Rust structs
- No database involved
- Configuration lives entirely in memory

#### **Database Mode (`FERRUM_MODE=database`)**
```rust
// db_loader.rs
let proxies = self.load_proxies().await?;
let consumers = self.load_consumers().await?;
let plugin_configs = self.load_plugin_configs().await?;
```
- SQL queries load data from database
- Rows mapped to same Rust structs as file mode
- **Identical configuration structures**!

---

## **🛡️ Data Type Conversions**

### **🔄 Boolean Handling**
```rust
// Database stores as INTEGER (0/1)
strip_listen_path INTEGER NOT NULL DEFAULT 1

// Rust converts to bool
strip_listen_path: row.try_get::<i32, _>("strip_listen_path").unwrap_or(1) != 0
```

### **🔄 Enum Handling**
```rust
// Database stores as TEXT
backend_protocol TEXT NOT NULL DEFAULT 'http'
auth_mode TEXT NOT NULL DEFAULT 'single'

// Rust parses to enums
backend_protocol: parse_protocol(&proto_str)
auth_mode: parse_auth_mode(&auth_mode_str)
```

### **🔄 JSON Storage**
```rust
// Credentials stored as JSON TEXT
credentials TEXT NOT NULL DEFAULT '{}'

// Rust deserializes JSON
let credentials = serde_json::from_str(&creds_str).unwrap_or_default();
```

---

## **🚀 Admin API Integration**

### **📊 CRUD Operations Map to Same Schema**

The Admin API uses the **same database schema**:

```bash
# Create proxy via Admin API
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"listen_path": "/new-api", "backend_protocol": "http", ...}' \
  http://localhost:9000/proxies

# This calls db_loader.rs:
pub async fn create_proxy(&self, proxy: &Proxy) -> Result<(), anyhow::Error> {
    sqlx::query("INSERT INTO proxies (...) VALUES (...)").execute(&self.pool).await?;
}
```

---

## **🔧 Migration Strategy**

### **✅ Auto-Migration on Startup**

```rust
// In DatabaseStore::connect()
store.run_migrations().await?;
```

**Migration Process:**
1. **Connect** to database using `sqlx::AnyPool`
2. **Run `CREATE TABLE IF NOT EXISTS`** for each table
3. **Skip existing tables** - no data loss
4. **Apply schema automatically** - no manual setup needed

### **🔄 Future Schema Evolution**

The system is designed for **zero-downtime schema evolution**:
- `IF NOT EXISTS` prevents conflicts
- New columns can be added with defaults
- Backward compatible with existing data

---

## **📈 Benefits of This Design**

### **✅ Unified Configuration Model**
- **Same Rust structs** for file and database modes
- **Identical validation** across all modes
- **Seamless migration** from file to database

### **✅ Database Agnostic**
- **Single codebase** supports PostgreSQL, MySQL, SQLite
- **Portable SQL** uses standard types
- **No database-specific code** needed

### **✅ Production Ready**
- **Auto-migration** on startup
- **Connection pooling** for performance
- **Resilient caching** for outages

### **✅ Admin API Integration**
- **Full CRUD** operations via REST API
- **Real-time updates** in database mode
- **Consistent data model** across all interfaces

---

## **🎯 Summary**

The Ferrum Gateway's database schema is **elegantly designed** to:

1. **Map 1:1** with YAML configuration structure
2. **Work universally** across PostgreSQL, MySQL, SQLite
3. **Auto-migrate** on first startup
4. **Support all features** from the requirements
5. **Integrate seamlessly** with Admin API
6. **Maintain data consistency** with proper constraints

**The same configuration that works in `tests/config.yaml` will work identically when stored in any supported database!** 🎉
