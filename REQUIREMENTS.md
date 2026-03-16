## Ferrum Gateway: Requirements Specification Document

**Version:** 1.0

**Project:** Ferrum Gateway - A high-performance API Gateway and Reverse Proxy built in Rust.

**1. Introduction & Goal**

This document specifies the requirements for building "Ferrum Gateway," a high-performance, extensible API Gateway and Reverse Proxy application. The primary implementation language is Rust. The application must leverage the `tokio` asynchronous runtime and the `hyper` library for core HTTP functionality. Key goals include high throughput, low latency, dynamic configuration, multiple operational modes, robust security features, protocol flexibility (HTTP, WebSockets, gRPC), and extensibility via a plugin system.

**2. Core Technical Stack**

The implementation MUST utilize the following core technologies:

*   **Language:** Rust (latest stable version)
*   **Asynchronous Runtime:** `tokio`
*   **HTTP Server/Client:** `hyper`
*   **gRPC Framework:** `tonic` (Required for CP/DP mode communication and potentially gRPC proxying)
*   **Serialization/Deserialization:** `serde` (for JSON and YAML configuration)
*   **Database Access:** `sqlx` (Recommended for asynchronous PostgreSQL, MySQL, SQLite support)
*   **Logging Framework:** `tracing` ecosystem (`tracing`, `tracing-subscriber`)
*   **TLS Implementation:** `rustls` (preferred) or `native-tls`
*   **WebSocket Handling:** `tokio-tungstenite` or `hyper-tungstenite` (or equivalent integrated hyper support)
*   **JWT Handling:** `jsonwebtoken` or a comparable, well-maintained crate
*   **Password/Secret Hashing:** `bcrypt` or `argon2` (for storing Consumer credentials securely)

**3. Operating Modes**

Ferrum Gateway MUST operate in one of three distinct modes, determined by the `FERRUM_MODE` environment variable at runtime.

*   **3.1. Database Mode (`FERRUM_MODE=database`)**
    *   **Functionality:** In this mode, a single gateway instance reads its configuration (Proxies, Consumers, Plugins) directly from a specified database, handles end-user proxy traffic, and provides an Admin API for configuration management.
    *   **Database Integration:** Connects to PostgreSQL, MySQL, or SQLite using connection parameters provided via environment variables (`FERRUM_DB_TYPE`, `FERRUM_DB_URL`).
    *   **Listeners:** Activates and listens on *both* the Proxy Traffic network interfaces (HTTP/HTTPS) *and* the Admin API network interfaces (HTTP/HTTPS).
    *   **Configuration Loading:**
        *   Loads the entire active configuration from the database upon startup.
        *   **Validation:** MUST validate that all `Proxy` resource `listen_path` values loaded from the database are unique. If duplicate paths are detected, log a critical error and terminate the application startup.
        *   Periodically polls the database (polling interval configured by `FERRUM_DB_POLL_INTERVAL_SECONDS`) to detect configuration changes.
        *   Applies detected configuration updates atomically and without interrupting active request processing (zero-downtime reload). Re-validate `listen_path` uniqueness on each reload.
    *   **Resilience:**
        *   Maintains an in-memory cache of the last successfully loaded configuration.
        *   If the database connection is temporarily lost, the gateway instance **MUST** continue to operate and serve proxy traffic using this cached configuration. Log appropriate warnings regarding the database connection status.
        *   During a database outage, Admin API operations that require database writes MUST fail gracefully (e.g., return HTTP 503 Service Unavailable).

*   **3.2. File Mode (`FERRUM_MODE=file`)**
    *   **Functionality:** In this mode, a gateway instance reads its entire configuration from local files (YAML or JSON). It only handles end-user proxy traffic and does not provide an Admin API.
    *   **Configuration Source:** Reads configuration from the file path(s) specified by the `FERRUM_FILE_CONFIG_PATH` environment variable.
    *   **Listeners:** Activates and listens *only* on the Proxy Traffic network interfaces (HTTP/HTTPS). The Admin API interfaces remain inactive.
    *   **Configuration Loading:**
        *   Parses and loads the configuration from the specified file(s) on startup.
        *   **Validation:** MUST validate that all `Proxy` resource `listen_path` values defined within the configuration file(s) are unique. If parsing fails or duplicate paths are detected, log a critical error and terminate the application startup.
        *   Implements a mechanism (e.g., listening for a `SIGHUP` signal) to trigger a reload of the configuration file(s).
        *   The reload process MUST be atomic, non-interrupting for active traffic, and MUST re-validate the uniqueness of `listen_path` values. If validation fails during reload, the reload MUST be aborted, and the gateway continues operating with the previous valid configuration, logging an error.

*   **3.3. Control Plane / Data Plane Mode**
    *   This mode involves two distinct node types running the Ferrum Gateway application with different configurations.
    *   **3.3.1. Control Plane (CP) Node (`FERRUM_MODE=cp`)**
        *   **Functionality:** Acts as the centralized configuration authority. It reads configuration from the database, provides the Admin API for management, and pushes configuration updates to connected Data Plane nodes via gRPC. It does **NOT** process end-user proxy traffic.
        *   **Database Integration:** Connects to the database (`FERRUM_DB_TYPE`, `FERRUM_DB_URL`). Relies on the database schema to enforce `Proxy.listen_path` uniqueness.
        *   **Listeners:** Activates and listens *only* on the Admin API network interfaces (HTTP/HTTPS) *and* a dedicated gRPC server interface (`FERRUM_CP_GRPC_LISTEN_ADDR`). Proxy Traffic listeners remain inactive.
        *   **gRPC Server:** Implements a `tonic` gRPC server providing services for Data Plane nodes to subscribe to configuration updates.
        *   **gRPC Security:** Mandates that connecting Data Plane nodes authenticate using an HS256 JWT. The JWT MUST be provided in the gRPC request metadata. The CP MUST verify this JWT using the secret key provided via `FERRUM_CP_GRPC_JWT_SECRET`. Unauthenticated connection attempts MUST be rejected.
        *   **Configuration Distribution:** Reads the active configuration from the database. Transmits the full initial configuration to newly connected, authenticated Data Plane nodes. Subsequently, pushes configuration updates (delta updates are preferred for efficiency if feasible, otherwise full configuration snapshots) to all subscribed Data Plane nodes via the established gRPC streams.
        *   **Resilience:** Caches the configuration read from the database. If the database connection is temporarily lost, the CP node MUST continue serving the last known valid configuration to connecting/reconnecting Data Plane nodes. Log appropriate warnings. Admin API operations requiring database writes MUST fail gracefully during the outage.
    *   **3.3.2. Data Plane (DP) Node (`FERRUM_MODE=dp`)**
        *   **Functionality:** Responsible solely for processing end-user proxy traffic according to the configuration received from a Control Plane. It does **NOT** connect to the database and does **NOT** expose an Admin API.
        *   **Listeners:** Activates and listens *only* on the Proxy Traffic network interfaces (HTTP/HTTPS). Admin API and gRPC server listeners remain inactive.
        *   **Control Plane Connection:** Establishes a persistent gRPC client connection to the Control Plane server's address, specified by `FERRUM_DP_CP_GRPC_URL`.
        *   **gRPC Security:** Authenticates itself to the Control Plane during the initial connection phase by sending a pre-configured HS256 JWT (provided via `FERRUM_DP_GRPC_AUTH_TOKEN`) in the gRPC request metadata.
        *   **Configuration Management:** Receives the initial configuration and subsequent updates from the Control Plane over the gRPC stream. The received configuration (assumed valid and containing unique `listen_path` values by the CP) is stored entirely in the DP node's memory and dictates its proxying behavior.
        *   **Resilience:** If the gRPC connection to the Control Plane is lost, the DP node **MUST** continue operating and serving proxy traffic using its last known valid configuration cache. It MUST implement a strategy to periodically attempt reconnection to the Control Plane. Log appropriate warnings regarding the connection status.

**4. Network Interface Configuration**

The gateway uses distinct network listeners for different traffic types. Default ports are provided but MUST be configurable via environment variables.

*   **Proxy Traffic Listeners (All Modes except CP):**
    *   HTTP Port: Configurable via `FERRUM_PROXY_HTTP_PORT` (Default: `8000`).
    *   HTTPS Port: Configurable via `FERRUM_PROXY_HTTPS_PORT` (Default: `8443`).
        *   TLS Certificate Path: `FERRUM_PROXY_TLS_CERT_PATH` (Required if HTTPS port is active).
        *   TLS Private Key Path: `FERRUM_PROXY_TLS_KEY_PATH` (Required if HTTPS port is active).
*   **Admin API Listeners (Database & CP Modes Only):**
    *   HTTP Port: Configurable via `FERRUM_ADMIN_HTTP_PORT` (Default: `9000`).
    *   HTTPS Port: Configurable via `FERRUM_ADMIN_HTTPS_PORT` (Default: `9443`).
        *   TLS Certificate Path: `FERRUM_ADMIN_TLS_CERT_PATH` (Required if Admin HTTPS port is active).
        *   TLS Private Key Path: `FERRUM_ADMIN_TLS_KEY_PATH` (Required if Admin HTTPS port is active).
*   **Control Plane gRPC Listener (CP Mode Only):**
    *   Listen Address: Configurable via `FERRUM_CP_GRPC_LISTEN_ADDR` (Example: `0.0.0.0:50051`).

**5. Environment Variable Configuration**

All operational parameters MUST be configurable via environment variables.

*   **Mode & Core:**
    *   `FERRUM_MODE`: (`database`, `file`, `cp`, `dp`) - **Required**.
    *   `FERRUM_LOG_LEVEL`: (`error`, `warn`, `info`, `debug`, `trace`) - Default: `info`.
*   **Network Ports & TLS:**
    *   `FERRUM_PROXY_HTTP_PORT`, `FERRUM_PROXY_HTTPS_PORT`, `FERRUM_PROXY_TLS_CERT_PATH`, `FERRUM_PROXY_TLS_KEY_PATH`
    *   `FERRUM_ADMIN_HTTP_PORT`, `FERRUM_ADMIN_HTTPS_PORT`, `FERRUM_ADMIN_TLS_CERT_PATH`, `FERRUM_ADMIN_TLS_KEY_PATH`
*   **Admin & CP/DP Security:**
    *   `FERRUM_ADMIN_JWT_SECRET`: (HS256 secret string) - **Required** in Database & CP modes.
    *   `FERRUM_CP_GRPC_JWT_SECRET`: (HS256 secret string) - **Required** in CP mode.
    *   `FERRUM_DP_GRPC_AUTH_TOKEN`: (HS256 JWT string) - **Required** in DP mode.
*   **Database (Database & CP Modes):**
    *   `FERRUM_DB_TYPE`: (`postgres`, `mysql`, `sqlite`) - **Required**.
    *   `FERRUM_DB_URL`: (Connection string) - **Required**.
    *   `FERRUM_DB_POLL_INTERVAL`: (Integer seconds) - Default: `30`.
    *   `FERRUM_DB_POLL_CHECK_INTERVAL`: (Integer seconds) - Default: `5`.
    *   `FERRUM_DB_INCREMENTAL_POLLING`: (Boolean) - Default: `true`.
*   **File Mode:**
    *   `FERRUM_FILE_CONFIG_PATH`: (Path to YAML/JSON file/directory) - **Required**.
*   **CP/DP Communication:**
    *   `FERRUM_CP_GRPC_LISTEN_ADDR`: (e.g., `0.0.0.0:50051`) - **Required** in CP mode.
    *   `FERRUM_DP_CP_GRPC_URL`: (e.g., `http://cp-hostname:50051`) - **Required** in DP mode.
*   **Request Handling Limits:**
    *   `FERRUM_MAX_HEADER_SIZE_BYTES`: (Integer bytes) - Default: `16384`.
    *   `FERRUM_MAX_BODY_SIZE_BYTES`: (Integer bytes, `0` for unlimited) - Default: `10485760` (10 MiB).
*   **DNS Caching:**
    *   `FERRUM_DNS_CACHE_TTL_SECONDS`: (Integer seconds) - Default: `300`.
    *   `FERRUM_DNS_OVERRIDES`: (JSON string map `{"hostname": "ip_address", ...}`) - Default: `{}`.

**6. Core Proxying Behavior**

This defines how the gateway processes requests on the Proxy Traffic listeners.

*   **Protocol Handling:** MUST accept incoming HTTP/1.1 and HTTP/2 and HTTP/3 requests. MUST be capable of proxying requests to backend services using `http`, `https`, `ws` (WebSocket), `wss` (Secure WebSocket), and `grpc` (over HTTP/2), as specified in the matched `Proxy` resource's `backend_protocol`.
*   **Routing Implementation:**
    *   MUST use **longest prefix matching** to select the appropriate `Proxy` resource. The matching is performed on the incoming request's URI path against the `Proxy.listen_path` values of all active Proxy resources.
    *   Given the requirement for unique `Proxy.listen_path` values, there will be at most one longest match.
    *   If no `Proxy.listen_path` provides a prefix match for the request path, the gateway MUST immediately respond with HTTP `404 Not Found`.
*   **Path Forwarding Logic:**
    *   Let `incoming_path` be the full path from the request URI.
    *   Let `listen_path` be the matched prefix from the selected `Proxy` resource.
    *   Let `remaining_path` be the portion of `incoming_path` that follows `listen_path`.
    *   Let `backend_path` be the optional prefix defined in `Proxy.backend_path`.
    *   If `Proxy.strip_listen_path` is `true` (the default): the path forwarded to the backend is `backend_path` concatenated with `remaining_path`.
    *   If `Proxy.strip_listen_path` is `false`: the path forwarded to the backend is `backend_path` concatenated with the full `incoming_path`.
*   **Backend Connection Management:**
    *   Utilize `hyper::Client` for `http`, `https`, and `grpc` backend connections. Implement connection pooling for efficiency.
    *   Utilize appropriate WebSocket client libraries (e.g., based on `tokio-tungstenite`) for `ws` and `wss` connections.
    *   Respect connection timeouts (`Proxy.backend_connect_timeout_ms`) and read/write timeouts (`Proxy.backend_read_timeout_ms`, `Proxy.backend_write_timeout_ms`) for backend interactions.
*   **Backend TLS/mTLS Handling:**
    *   Support TLS-encrypted connections (`https`, `wss`) to backends.
    *   By default (`Proxy.backend_tls_verify_server_cert: true`), verify the backend server's TLS certificate against the system's trust store or a custom CA bundle specified via `Proxy.backend_tls_server_ca_cert_path`. Allow disabling verification via the flag.
    *   Support mutual TLS (mTLS) authentication *to* the backend by presenting a client certificate, configured via `Proxy.backend_tls_client_cert_path` and `Proxy.backend_tls_client_key_path`.
*   **Header Propagation & Modification:**
    *   Append/update standard proxy headers: `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host`.
    *   Handle the `Host` header: If `Proxy.preserve_host_header` is `false` (default), set the `Host` header sent to the backend to the `Proxy.backend_host`. If `true`, forward the original `Host` header received from the client.
*   **Request/Response Streaming:** MUST handle request and response bodies as asynchronous streams (`hyper::Body`) to support large file uploads/downloads and persistent streaming protocols (WebSockets, gRPC) without excessive memory buffering.
*   **WebSocket & gRPC Proxying:** MUST correctly handle the HTTP upgrade request for WebSockets and subsequently proxy the bidirectional byte stream. MUST correctly proxy gRPC requests and responses (typically over HTTP/2).
*   **DNS Resolution & Caching:**
    *   Implement an asynchronous, in-memory cache for resolved IP addresses of backend hostnames defined in `Proxy` resources.
    *   **Startup DNS Warmup:** Immediately after loading the initial configuration upon application startup, the gateway MUST asynchronously initiate DNS lookups for all unique backend hostnames present in the configuration (respecting `dns_override`). The results should populate the DNS cache to minimize latency on initial requests. This warmup process MUST NOT block the gateway from starting its network listeners.
    *   Cached entries MUST expire based on a TTL, configurable globally via `FERRUM_DNS_CACHE_TTL_SECONDS` and overridable per-proxy via `Proxy.dns_cache_ttl_seconds`. Upon cache miss or expiry, perform a fresh asynchronous DNS lookup.
    *   Support global static hostname-to-IP mappings provided via `FERRUM_DNS_OVERRIDES`.
    *   Support per-proxy static IP overrides via `Proxy.dns_override`. These overrides take precedence over global overrides and DNS lookups.
*   **Request Size Limits:** Enforce the maximum allowed request header size (`FERRUM_MAX_HEADER_SIZE_BYTES`) and request body size (`FERRUM_MAX_BODY_SIZE_BYTES`). Requests exceeding these limits MUST be rejected immediately with appropriate HTTP status codes (e.g., 431 Request Header Fields Too Large, 413 Content Too Large).
*   **Zero-Downtime Configuration Updates:** All configuration changes loaded via database polling, file reload signal, or CP push MUST be applied atomically such that active request processing is not interrupted or negatively impacted. Target efficient handling of potentially thousands of `Proxy` resources.
*   **Graceful Shutdown:** Upon receiving a SIGTERM or SIGINT signal, the gateway MUST:
    1.  Stop accepting new incoming connections on all listeners.
    2.  Allow currently active requests to complete processing, up to a reasonable internal timeout.
    3.  Close backend connections gracefully.
    4.  Exit cleanly.

**7. Configuration Resources & Data Model**

Define Rust structs (using `serde` for serialization/deserialization) for the core configuration entities.

*   **7.1. `Proxy` Resource:**
    *   `id`: Unique identifier (Type depends on storage: e.g., `i64` for DB ID, `String` for UUID).
    *   `name`: `Option<String>`.
    *   `listen_path`: `String`. **Value MUST be unique across all configured Proxy resources.** Used for longest prefix matching.
    *   `backend_protocol`: Enum (`Http`, `Https`, `Ws`, `Wss`, `Grpc`).
    *   `backend_host`: `String`.
    *   `backend_port`: `u16`.
    *   `backend_path`: `Option<String>`.
    *   `strip_listen_path`: `bool` (Default: `true`).
    *   `preserve_host_header`: `bool` (Default: `false`).
    *   `backend_connect_timeout_ms`: `u64`.
    *   `backend_read_timeout_ms`: `u64`.
    *   `backend_write_timeout_ms`: `u64`.
    *   `backend_tls_client_cert_path`: `Option<String>`.
    *   `backend_tls_client_key_path`: `Option<String>`.
    *   `backend_tls_verify_server_cert`: `bool` (Default: `true`).
    *   `backend_tls_server_ca_cert_path`: `Option<String>`.
    *   `dns_override`: `Option<String>` (Contains IP address if set).
    *   `dns_cache_ttl_seconds`: `Option<u64>`.
    *   `auth_mode`: Enum (`Single`, `Multi`) (Default: `Single`).
    *   `plugins`: `Vec<PluginAssociation>` (Where `PluginAssociation` links to a `PluginConfig` ID or contains embedded config).
    *   `created_at`: `chrono::DateTime<Utc>`.
    *   `updated_at`: `chrono::DateTime<Utc>`.

*   **7.2. `Consumer` Resource:**
    *   `id`: Unique identifier.
    *   `username`: `String` (Unique identifier for ACLs, logging).
    *   `custom_id`: `Option<String>`.
    *   `credentials`: `std::collections::HashMap<String, serde_json::Value>` (Keys: `oauth2`, `jwt`, `keyauth`, `basicauth`. Values: JSON objects containing credential details. **Secrets MUST be stored securely hashed**).
    *   `created_at`: `chrono::DateTime<Utc>`.
    *   `updated_at`: `chrono::DateTime<Utc>`.

*   **7.3. `PluginConfig` Resource:**
    *   `id`: Unique identifier.
    *   `plugin_name`: `String` (Identifier of the plugin implementation).
    *   `config`: `serde_json::Value` (Plugin-specific configuration structure).
    *   `scope`: Enum (`Global`, `Proxy`).
    *   `proxy_id`: `Option<Proxy::id>` (Required if scope is `Proxy`).
    *   `enabled`: `bool`.
    *   `created_at`: `chrono::DateTime<Utc>`.
    *   `updated_at`: `chrono::DateTime<Utc>`.

*   **7.4. Database Schema (Required for Database & CP Modes):**
    *   Implement database tables corresponding to `Proxy`, `Consumer`, and `PluginConfig`.
    *   **CRITICAL:** The `proxies` table MUST enforce a `UNIQUE` constraint on the `listen_path` column at the database level.
    *   Use appropriate SQL types. Add indexes on frequently queried columns (e.g., `proxies.listen_path`, `consumers.username`).

**8. Admin API (Required for Database & CP Modes)**

*   **Access Control:** All Admin API endpoints (potentially excluding a `/health` check) MUST be protected. Access requires a valid HS256 JWT provided in the `Authorization: Bearer <token>` header. The JWT MUST be verified against the secret configured in `FERRUM_ADMIN_JWT_SECRET`. Failed authentication MUST result in an HTTP `401 Unauthorized` response.
*   **API Format:** Implement as a RESTful API communicating via JSON.
*   **Endpoints:** Provide CRUD (Create, Read, Update, Delete) operations for gateway resources:
    *   `/proxies` (GET: list, POST: create)
    *   `/proxies/{proxy_id}` (GET: read, PUT: update, DELETE: delete)
        *   POST/PUT operations MUST validate `listen_path` uniqueness against existing resources. Return `409 Conflict` on violation.
    *   `/consumers` (GET: list, POST: create)
    *   `/consumers/{consumer_id}` (GET: read, PUT: update, DELETE: delete)
        *   POST/PUT operations MUST hash any provided secrets before storing.
    *   `/consumers/{consumer_id}/credentials/{credential_type}` (PUT: create/update, DELETE: delete)
        *   PUT operation MUST hash secrets.
    *   `/plugins` (GET: list names of available plugin types)
    *   `/plugins/config` (GET: list all configs, POST: create global or proxy-scoped config)
    *   `/plugins/config/{config_id}` (GET: read, PUT: update, DELETE: delete)
    *   `/admin/metrics` (GET, Authenticated): Returns a JSON object containing runtime metrics:
        *   `mode`: Current `FERRUM_MODE`.
        *   `config_last_updated_at`: ISO8601 timestamp of last config load/update.
        *   `config_source_status`: (`online`, `offline`, `n/a`) - Status of DB or CP connection.
        *   `proxy_count`: Number of loaded proxies.
        *   `consumer_count`: Number of loaded consumers.
        *   `requests_per_second_current`: Approximate proxy request throughput in the last second.
        *   `status_codes_last_second`: Map of response status codes to counts observed in the last second (e.g., `{"200": 150, "401": 5, "503": 1}`).
    *   `/health` or `/status` (GET, Optional, Unauthenticated): Simple endpoint returning `200 OK` for basic liveness probes.

**9. Plugin System & Available Plugins**

*   **Architecture:** Implement a plugin execution pipeline. Define specific lifecycle hooks (e.g., `on_request_received`, `authenticate`, `authorize`, `before_proxy`, `after_proxy`, `log`). Plugins MUST be implemented as Rust modules/structs conforming to a defined plugin trait. Plugins receive request/response context and can modify data or terminate the request flow.
*   **Configuration:** Plugins are activated and configured via `PluginConfig` resources, either globally or associated with specific `Proxy` resources (per-proxy scope overrides global).
*   **Multi-Authentication Mode (`Proxy.auth_mode = "multi"`):**
    *   If a Proxy is configured for `multi` auth, execute *all* attached authentication plugins (OAuth2, JWT, KeyAuth, BasicAuth) sequentially for a given request.
    *   An individual auth plugin failure in `multi` mode **does not** immediately reject the request.
    *   The **first** authentication plugin in the sequence that successfully identifies a `Consumer` entity attaches that Consumer's context to the request. Subsequent authentication plugins in the chain are still executed but cannot overwrite the context if one has already been set.
    *   The `Access Control` plugin (or an implicit final check) **MUST** execute *after* all authentication plugins have run. This check verifies if *any* Consumer context was successfully attached during the authentication phase. If no Consumer was identified, the request MUST be rejected (e.g., `401 Unauthorized`). If a Consumer *was* identified, the `Access Control` plugin then proceeds with its configured allow/disallow logic based on that Consumer's identity.
*   **Required Plugin Implementations:**
    *   **`stdout_logging`:** Logs a summary of each transaction to standard output (JSON format preferred).
    *   **`http_logging`:** Sends the transaction summary as a JSON payload via HTTP POST to a configured URL. Config: `endpoint_url` (String), `authorization_header` (Optional String).
        *   **Transaction Summary Fields (for both logging plugins):** Timestamp Received, Client IP Address, Identified Consumer Username/ID (or null), HTTP Method, Request Path, Matched Proxy ID/Name, Backend Target URL (protocol://host:port/path - *excluding query parameters*), Final HTTP Response Status Code, Latency-Total (ms), Latency-GatewayProcessing (ms), Latency-BackendTTFB (ms), Latency-BackendTotal (ms), Request User-Agent Header.
    *   **`transaction_debugger`:** Logs verbose request/response details (headers, optional bodies) to standard output for debugging specific Proxies. Config: `log_request_body` (bool), `log_response_body` (bool). Enable per-proxy only.
    *   **`oauth2_auth`:** Performs OAuth2 authentication using Bearer tokens. Config: `validation_mode` (`introspection` or `jwks`), plus necessary parameters for each mode (e.g., `introspection_url`, `jwks_uri`, expected issuer/audience). Identifies `Consumer`. Integrates with `multi` auth mode.
    *   **`jwt_auth`:** Performs JWT Bearer token authentication (HS256 initially) based on `Consumer` credentials. Config: `token_lookup` (how to find token), `consumer_claim_field` (claim identifying consumer). Identifies `Consumer`. Integrates with `multi` auth mode.
    *   **`key_auth`:** Performs API Key authentication based on `Consumer` credentials. Config: `key_location` (header name or query parameter name). Identifies `Consumer`. Integrates with `multi` auth mode.
    *   **`basic_auth`:** Performs HTTP Basic authentication based on `Consumer` credentials (comparing hashed passwords). Identifies `Consumer`. Integrates with `multi` auth mode.
    *   **`access_control`:** Authorizes requests based on client IP address, CIDR range, and/or the `username` of the `Consumer` identified by a preceding authentication plugin. Config: `allowed_ips` (list of IPs/CIDRs), `blocked_ips` (list of IPs/CIDRs), `allowed_consumers` (list of usernames), `disallowed_consumers` (list of usernames). Blocked IPs take precedence over allowed IPs. Supports proper IPv4 CIDR bit-masking for any prefix length (/8, /16, /24, /32, etc.). Enforces consumer identification check in `multi` auth mode.
    *   **`request_transformer`:** Modifies the incoming request before it is proxied. Config: A list of rules defining operations (add/remove/update header, add/remove/update query parameter).
    *   **`response_transformer`:** Modifies the response received from the backend before it is sent to the client. Config: A list of rules defining operations (add/remove/update header).
    *   **`rate_limiting`:** Enforces request rate limits per time window. Config: `limit_by` (`consumer` or `ip`), `requests_per_second`, `requests_per_minute`, `requests_per_hour`. **State MUST be maintained strictly in-memory within each gateway node.** Requires identified `Consumer` if `limit_by` is `consumer`. Returns HTTP `429 Too Many Requests` when limits are exceeded.

**10. Non-Functional Requirements**

*   **Internal Logging:** Utilize the `tracing` framework extensively for detailed internal operational logging (not transaction logging). Control verbosity via `FERRUM_LOG_LEVEL`.
*   **Observability Metrics:** (Recommended) Expose internal performance counters and gauges (e.g., active connections, memory usage, cache statistics, plugin execution latencies) via a dedicated `/metrics` endpoint using the Prometheus exposition format.
*   **Testing Strategy:** Implement thorough unit tests for core logic components (routing, configuration parsing, individual plugins). Implement integration tests simulating real-world scenarios across all operating modes, including API interactions, various proxy request types (HTTP, WS, gRPC), configuration reloads, and failure conditions (backend errors, DB/CP outage).
*   **Code Standards:** Adhere to idiomatic Rust practices. Ensure code is well-commented, modular, and maintainable. Implement robust error handling using `Result` and custom error types where appropriate; avoid panics in request handling logic.
*   **Performance:** Design for high concurrency and low latency. Minimize blocking operations. Optimize critical code paths.

**11. Documentation (README.md Generation)**

The AI agent MUST generate a comprehensive `README.md` file for the project repository. This file must serve as the primary user documentation and include at least the following sections:

*   **Overview:** High-level description of Ferrum Gateway, its purpose, and core value proposition.
*   **Features:** Bulleted list of key capabilities.
*   **Operating Modes:** Detailed explanation of Database, File, and CP/DP modes, including setup and use cases for each.
*   **Prerequisites:** Required software (Rust toolchain version, potentially database).
*   **Installation:** Instructions for building the application (`cargo build --release`).
*   **Getting Started:** Example command-line invocations to run the gateway in each operating mode.
*   **Configuration:**
    *   Exhaustive list and detailed explanation of all supported Environment Variables.
    *   Specification of the configuration file format (YAML/JSON) for File Mode, with examples.
    *   Brief overview of the required Database Schema (for users setting up DB/CP modes).
*   **Admin API:**
    *   Instructions on authenticating (JWT usage).
    *   Detailed documentation of all Admin API endpoints, including request/response formats and `curl` examples.
    *   Explanation of the `/admin/metrics` endpoint fields.
*   **Plugin System:**
    *   Explanation of how plugins function, lifecycle hooks, global vs. proxy scope.
    *   Clear description of the Multi-Authentication (`multi`) mode.
    *   **Individual Plugin Documentation:** For *each* implemented plugin, describe its purpose, all configuration parameters (with types and defaults), and provide usage examples.
*   **Proxying Behavior:** Details on routing logic (longest prefix match, unique path necessity), path handling (`strip_listen_path`), WebSocket/gRPC support.
*   **Resilience & Caching:** Explanation of configuration caching, behavior during DB/CP outages, and DNS caching mechanics (including startup warmup).
*   **Security:** Notes on configuring TLS, managing JWT secrets, credential hashing.
*   **Troubleshooting:** Common issues and potential solutions.
*   **Contributing:** Guidelines for potential contributors.
*   **License:** Specify the project's software license.