# Ferrum Gateway Architecture

This document provides a comprehensive overview of the Ferrum Gateway codebase architecture to help new developers understand the project structure and contribute effectively.

## 🏗️ High-Level Architecture

Ferrum Gateway is a high-performance API Gateway built in Rust that follows a modular, plugin-based architecture. It supports multiple operating modes and provides dynamic routing, authentication, authorization, and protocol translation capabilities.

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Client Apps   │───▶│  Ferrum Gateway │───▶│  Backend Services│
└─────────────────┘    └─────────────────┘    └─────────────────┘
                       │
                       ▼
              ┌─────────────────┐
              │   Admin API     │
              │   (Management)  │
              └─────────────────┘
```

## 📁 Project Structure

### **Core Application (`src/`)**

```
src/
├── main.rs                 # Application entry point and CLI argument parsing
├── lib.rs                  # Library root with public API exports
├── config/                 # Configuration management
│   ├── mod.rs             # Configuration module exports
│   ├── env_config.rs      # Environment variable configuration
│   ├── pool_config.rs     # Connection pool configuration
│   └── types.rs           # Core data structures (Proxy, Consumer, Plugin)
├── proxy/                 # Proxy request handling
│   ├── mod.rs             # ProxyState and main proxy logic
│   └── handler.rs         # HTTP request/response processing
├── connection_pool.rs     # HTTP client connection pooling with mTLS support
├── dns/                   # DNS resolution and caching
│   ├── mod.rs             # DNS module exports
│   └── resolver.rs        # Async DNS resolver with caching
├── admin/                 # Admin API for configuration management
│   ├── mod.rs             # Admin API routes and handlers
│   ├── jwt_auth.rs        # JWT authentication for Admin API
│   └── handlers/          # Individual Admin API endpoints
│       ├── proxies.rs     # Proxy CRUD operations
│       ├── consumers.rs   # Consumer CRUD operations
│       └── plugins.rs     # Plugin configuration management
├── plugins/               # Plugin system for extensibility
│   ├── mod.rs             # Plugin framework and registry
│   ├── key_auth.rs        # API key authentication plugin
│   ├── access_control.rs  # IP-based access control plugin
│   ├── rate_limiting.rs   # Rate limiting plugin
│   └── stdout_logging.rs  # Request/response logging plugin
├── modes/                 # Operating modes (DB, File, CP, DP)
│   ├── database.rs        # Database mode configuration
│   ├── file.rs            # File mode configuration
│   ├── data_plane.rs      # Data Plane mode configuration
│   └── control_plane.rs   # Control Plane mode configuration
└── utils/                 # Shared utilities
    ├── grpc/              # gRPC protocol buffer definitions
    └── logging.rs         # Structured logging configuration
```

### **Tests (`tests/`)**

```
tests/
├── README.md              # Test suite documentation and guidelines
├── admin_tests.rs         # Admin API integration tests
├── backend_mtls_tests.rs  # Backend mTLS functionality tests
├── access_control_tests.rs # Access control plugin tests
├── key_auth_tests.rs      # Key authentication plugin tests
├── rate_limiting_tests.rs # Rate limiting plugin tests
├── plugin_integration_tests.rs # Plugin system integration tests
├── plugin_utils.rs        # Shared test utilities for plugins
├── config_file_loader_tests.rs # Configuration file loading tests
├── config_types_tests.rs  # Configuration type validation tests
├── proxy_tests.rs         # Proxy functionality tests
└── stdout_logging_tests.rs # Logging plugin tests
```

### **Examples (`examples/`)**

```
examples/
├── config.yaml            # Example configuration file
├── websocket_echo_server.rs  # WebSocket echo server for testing
├── websocket_gateway_test.rs  # WebSocket gateway integration test
└── secure_echo_server_simple.rs # Simple HTTPS echo server
```

### **Documentation (`docs/`)**

```
docs/
└── backend_mtls.md        # Backend mTLS configuration guide
```

### **Performance Testing (`perftest/`)**

```
perftest/
├── README.md              # Performance testing documentation
├── performance_report.html # Generated performance report
└── scripts/               # Performance test scripts
```

## 🧩 Core Components

### **1. Configuration System (`src/config/`)**

The configuration system provides flexible configuration management through multiple sources:

- **`env_config.rs`**: Environment variable parsing and validation
- **`pool_config.rs`**: Connection pool settings with global defaults and proxy overrides
- **`types.rs`**: Core data structures including `Proxy`, `Consumer`, and `Plugin` definitions

**Key Features**:
- Environment variable configuration for all settings
- YAML/JSON file configuration support
- Per-proxy configuration overrides
- Configuration validation and defaults

### **2. Proxy Engine (`src/proxy/`)**

The proxy engine handles all request routing and processing:

- **`mod.rs`**: Contains `ProxyState` - the main state management structure
- **`handler.rs`**: HTTP request/response processing logic

**Key Features**:
- Longest prefix match routing
- Protocol translation (HTTP ↔ WebSocket)
- Request/response transformation
- Plugin pipeline execution

### **3. Connection Pool (`src/connection_pool.rs`)**

High-performance HTTP client connection pooling with backend mTLS support:

**Key Features**:
- Connection reuse and keep-alive
- Backend mTLS authentication with client certificates
- Custom CA bundle support for server certificate verification
- Per-proxy connection configuration
- DNS resolution integration
- Connection statistics and monitoring

### **4. Plugin System (`src/plugins/`)**

Extensible plugin architecture for authentication, authorization, and transformations:

**Plugin Types**:
- **Authentication**: `key_auth.rs` - API key validation
- **Authorization**: `access_control.rs` - IP-based access control
- **Rate Limiting**: `rate_limiting.rs` - Request rate limiting
- **Logging**: `stdout_logging.rs` - Request/response logging

**Plugin Lifecycle**:
1. **Request Phase**: Authentication → Authorization → Rate Limiting
2. **Response Phase**: Logging → Metrics
3. **Error Phase**: Error handling and logging

### **5. Admin API (`src/admin/`)**

RESTful API for dynamic configuration management:

**Endpoints**:
- `/proxies` - Proxy CRUD operations
- `/consumers` - Consumer management
- `/plugins` - Plugin configuration
- JWT-based authentication and authorization

### **6. Operating Modes (`src/modes/`)**

Four distinct operating modes for different deployment scenarios:

#### **Database Mode (`database.rs`)**
- Single gateway instance with database storage
- Periodic configuration polling
- Admin API included
- **Use Case**: Small to medium deployments

#### **File Mode (`file.rs`)**
- Configuration from local files
- SIGHUP-based reloading
- No Admin API
- **Use Case**: Development, immutable infrastructure

#### **Control Plane Mode (`control_plane.rs`)**
- Centralized configuration management
- Database integration
- gRPC configuration distribution
- No proxy traffic handling
- **Use Case**: Distributed deployments

#### **Data Plane Mode (`data_plane.rs`)**
- Proxy traffic only
- gRPC configuration from Control Plane
- No database or Admin API
- **Use Case**: Scalable traffic processing

### **7. DNS System (`src/dns/`)**

Async DNS resolution with caching capabilities:

**Key Features**:
- In-memory caching with TTL
- Static DNS overrides
- Per-proxy DNS configuration
- Startup cache warmup

## 🔄 Request Flow

### **HTTP Request Processing**

```
1. Client Request
   ↓
2. TLS Termination (if HTTPS)
   ↓
3. Route Matching (longest prefix)
   ↓
4. Plugin Pipeline (auth → authz → rate limit)
   ↓
5. Connection Pool (get/create client)
   ↓
6. Backend Request (with mTLS if configured)
   ↓
7. Response Processing
   ↓
8. Plugin Response Pipeline
   ↓
9. Client Response
```

### **WebSocket Request Processing**

```
1. WebSocket Upgrade Request
   ↓
2. Route Matching
   ↓
3. Plugin Pipeline
   ↓
4. Connection Pool (with mTLS)
   ↓
5. Backend WebSocket Upgrade
   ↓
6. Bidirectional Proxying
```

## 🔧 Configuration Hierarchy

Configuration follows a clear priority order:

1. **Proxy-specific configuration** (highest priority)
2. **Global environment variables**
3. **Default values** (lowest priority)

Example for mTLS:
```yaml
# Proxy-specific (highest priority)
proxies:
  - id: "api"
    backend_tls_client_cert_path: "/path/to/proxy-cert.pem"
    backend_tls_client_key_path: "/path/to/proxy-key.pem"
```

```bash
# Global environment variables (fallback)
export FERRUM_BACKEND_TLS_CA_BUNDLE_PATH="/path/to/ca-bundle.pem"
export FERRUM_BACKEND_TLS_CLIENT_CERT_PATH="/path/to/global-cert.pem"
export FERRUM_BACKEND_TLS_CLIENT_KEY_PATH="/path/to/global-key.pem"
```

## 🧪 Testing Strategy

The project uses comprehensive testing at multiple levels:

### **Unit Tests**
- Located in `src/` files alongside implementation
- Test individual functions and modules
- Fast execution with minimal dependencies

### **Integration Tests**
- Located in `tests/` directory
- Test component interactions
- Include end-to-end scenarios

### **Plugin Testing**
- `plugin_utils.rs` provides shared test utilities
- Each plugin has dedicated test files
- Test plugin lifecycle and configuration

### **Performance Testing**
- `perftest/` directory contains performance benchmarks
- Automated performance regression testing
- Load testing scenarios

## 🚀 Getting Started for New Developers

### **1. Development Setup**

```bash
# Clone and build
git clone https://github.com/your-org/ferrum-gateway.git
cd ferrum-gateway
cargo build

# Run tests
cargo test

# Start with example config
FERRUM_MODE=file \
FERRUM_FILE_CONFIG_PATH=examples/config.yaml \
cargo run
```

### **2. Understanding the Codebase**

1. **Start with `src/main.rs`** - Understand application startup
2. **Read `src/config/types.rs`** - Learn core data structures
3. **Study `src/proxy/mod.rs`** - Understand proxy state management
4. **Explore `src/plugins/mod.rs`** - Learn plugin system
5. **Review operating modes** - Choose a mode to understand deeply

### **3. Adding New Features**

#### **New Plugin**
1. Create plugin file in `src/plugins/`
2. Implement `Plugin` trait
3. Add to plugin registry in `src/plugins/mod.rs`
4. Add configuration to `src/config/types.rs`
5. Write tests in `tests/`

#### **New Configuration Option**
1. Add field to appropriate struct in `src/config/types.rs`
2. Add environment variable parsing in `src/config/env_config.rs`
3. Update documentation
4. Add tests

#### **New Admin API Endpoint**
1. Add handler in `src/admin/handlers/`
2. Register route in `src/admin/mod.rs`
3. Add authentication/authorization as needed
4. Write integration tests

### **4. Code Style Guidelines**

- Follow Rust idioms and `rustfmt` formatting
- Use `tracing` for structured logging
- Write comprehensive tests for new features
- Update documentation for API changes
- Use `anyhow` for error handling
- Prefer async/await for I/O operations

### **5. Common Patterns**

#### **Error Handling**
```rust
use anyhow::{Result, Context};

fn example_function() -> Result<String> {
    let value = some_operation()
        .context("Failed to perform operation")?;
    Ok(value)
}
```

#### **Logging**
```rust
use tracing::{info, warn, error, debug};

info!("Gateway starting up");
warn!("Configuration issue detected");
error!("Failed to process request: {}", error);
debug!("Processing request for path: {}", path);
```

#### **Configuration**
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MyConfig {
    #[serde(default)]
    pub my_field: String,
    #[serde(default = "default_value")]
    pub my_number: u32,
}
```

## 🔄 Development Workflow

### **1. Feature Development**
1. Create feature branch from `main`
2. Implement changes with tests
3. Run full test suite
4. Update documentation
5. Submit pull request

### **2. Testing**
```bash
# Run all tests
cargo test

# Run specific test
cargo test test_name

# Run with output
cargo test -- --nocapture

# Run integration tests
cargo test --test '*'
```

### **3. Building**
```bash
# Development build
cargo build

# Release build
cargo build --release

# Run with examples
cargo run --example websocket_echo_server
```

## 📚 Additional Resources

- **`IMPLEMENTATION_ANALYSIS.md`** - Detailed implementation status
- **`docs/backend_mtls.md`** - Backend mTLS configuration guide
- **`tests/README.md`** - Test suite documentation
- **`perftest/README.md`** - Performance testing guide

## 🤝 Contributing

We welcome contributions! Please:

1. Read this architecture guide first
2. Check existing issues and pull requests
3. Follow the code style guidelines
4. Write comprehensive tests
5. Update documentation
6. Ensure all tests pass before submitting

For questions or guidance, reach out through GitHub issues or discussions.
