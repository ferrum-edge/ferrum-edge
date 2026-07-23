<p align="center">
  <img src="assets/ferrum_edge.png" alt="Ferrum Edge" width="300">
</p>

<h1 align="center">Ferrum Edge</h1>

<p align="center">使用 Rust 构建的高性能边缘代理</p>

<p align="center">
  <a href="https://github.com/ferrum-edge/ferrum-edge/actions/workflows/ci.yml"><img src="https://github.com/ferrum-edge/ferrum-edge/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI"></a>
  <a href="https://github.com/ferrum-edge/ferrum-edge/actions/workflows/coverage.yml"><img src="https://github.com/ferrum-edge/ferrum-edge/actions/workflows/coverage.yml/badge.svg?branch=main" alt="Coverage"></a>
  <a href="https://github.com/ferrum-edge/ferrum-edge/releases/latest"><img src="https://img.shields.io/github/v/release/ferrum-edge/ferrum-edge" alt="Release"></a>
  <a href="https://github.com/ferrum-edge/ferrum-edge/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-PolyForm%20Noncommercial-blue" alt="License"></a>
  <a href="https://hub.docker.com/r/ferrumedge/ferrum-edge"><img src="https://img.shields.io/docker/pulls/ferrumedge/ferrum-edge" alt="Docker Pulls"></a>
</p>

[English](README.md) · [简体中文](README.zh-CN.md) · [日本語](README.ja.md)

## 概述

Ferrum Edge 是一款轻量、可扩展的边缘代理，专为现代微服务架构设计。它提供动态路由、多协议支持、强大的插件系统以及多种部署拓扑——从基于文件的单节点配置，到分布式控制平面（Control Plane）/ 数据平面（Data Plane）架构。

**主要亮点：**

- **多协议支持**：HTTP/1.1、HTTP/2、HTTP/3（QUIC）、WebSocket、gRPC，以及使用 TLS/DTLS 的原始 TCP/UDP
- **内置插件系统**：身份验证、授权、OPA 策略决策、自适应并发、WAF 内容威胁检测、OpenAPI 合约验证、速率限制、故障注入、压缩、响应安全标头、SSE 流处理、转换、响应模拟、规范暴露、无服务器函数、AI/LLM 专用插件（包括用于多提供商路由的 AI 联邦）、MCP / Agent Tool Gateway 路由、A2A 智能体网关可观测性/策略、负载测试、API 成本分摊和可观测性
- **八种运行模式**：Database、File、Control Plane、Data Plane、Mesh、Injector、Node Agent 和 Migrate
- **无锁热路径**：所有请求路径读取都使用 `ArcSwap` 或 `DashMap`——代理路径上没有互斥锁
- **配置零停机重载**：通过数据库轮询、SIGHUP 或 CP 推送实现原子配置交换
- **服务网格**：六种拓扑（sidecar、ambient、node waypoint、service waypoint、east-west gateway、egress）、原生 MeshSubscribe、xDS ADS 或本地化文件配置消费、SPIFFE 身份、HBONE、透明 DNS 代理、网格授权、REGISTRY_ONLY 出站策略，以及 Istio/GAMMA RED 指标。请参阅 [docs/mesh.md](docs/mesh.md)
- **运行时可观测性**：受 JWT 保护的 `/metrics/runtime` JSON 快照，包含系统/进程状态、HTTP 状态窗口、错误类别、DNS 结果、后端池变化、TCP 重置、日志计数器和过载状态
- **Kubernetes 网格转换**：Gateway API 和 Istio VirtualService 路由拆分、Istio AuthorizationPolicy/RequestAuthentication/PeerAuthentication，以及 sidecar 注入 webhook

完整功能列表请参阅 [FEATURES.md](FEATURES.md)。

## 运行模式

| 模式 | 环境变量 | 说明 | 管理 API | 代理 |
|------|---------|-------------|-----------|-------|
| **Database** | `FERRUM_MODE=database` | 单实例、数据库支持（PostgreSQL/MySQL/SQLite/MongoDB） | 读/写 | 是 |
| **File** | `FERRUM_MODE=file` | 单实例、YAML/JSON 配置、SIGHUP 重载 | 只读 | 是 |
| **Control Plane** | `FERRUM_MODE=cp` | 集中式配置权威，通过 gRPC 分发到 DP | 读/写 | 否 |
| **Data Plane** | `FERRUM_MODE=dp` | 可水平扩展的流量处理节点 | 只读 | 是 |
| **Mesh** | `FERRUM_MODE=mesh` | 服务网格数据平面，通过六种拓扑消费原生 MeshSubscribe、xDS ADS 或本地化配置文件 | 只读 | 是 |
| **Injector** | `FERRUM_MODE=injector` | 注入 Ferrum 网格 sidecar/初始化捕获的 Kubernetes 准入 webhook | 否 | 否 |
| **Node Agent** | `FERRUM_MODE=node_agent` | 用于 ambient 网格的每节点 eBPF 捕获管理器；无代理监听器。请参阅 [docs/node_agent.md](docs/node_agent.md) | 可选（只读） | 否 |
| **Migrate** | `FERRUM_MODE=migrate` | 运行数据库架构迁移后退出（显式 CLI / 外部 K8s Job；不是 Helm chart 模式） | 否 | 否 |

分布式部署详情请参阅 [docs/cp_dp_mode.md](docs/cp_dp_mode.md)。
在 Kubernetes 上，请按照
[docs/kubernetes_deployment.md](docs/kubernetes_deployment.md#binary-operating-mode-kubernetes-contract) 将每种模式映射到相应 chart 或外部合约。

## 前置要求

- **Rust** 工具链——最新稳定版（仓库将 `channel = "stable"` 固定在 `rust-toolchain.toml` 中；rustup 会在第一次调用 `cargo` 时自动安装）。CI 使用当前稳定版并以 `-D warnings` 运行 clippy，因此本地工具链必须保持一致。
- 用于生成 gRPC 代码的 **protoc**（Protocol Buffers 编译器）
- **数据库**（可选）：PostgreSQL、MySQL、SQLite 或 MongoDB（用于 database 和 CP 模式）

## 安装

### 从源码构建

```bash
git clone https://github.com/ferrum-edge/ferrum-edge.git
cd ferrum-edge
cargo build --release

# Install to PATH
sudo cp target/release/ferrum-edge /usr/local/bin/
ferrum-edge version
```

### 预构建二进制文件

请从 [GitHub Releases](https://github.com/ferrum-edge/ferrum-edge/releases) 下载 Linux x86_64/ARM64 和 macOS x86_64/ARM64 版本。

```bash
# Example: Linux x86_64
curl -LO https://github.com/ferrum-edge/ferrum-edge/releases/latest/download/ferrum-edge-x86_64-unknown-linux-gnu.tar.gz
tar xzf ferrum-edge-x86_64-unknown-linux-gnu.tar.gz
sudo mv ferrum-edge /usr/local/bin/
ferrum-edge version
```

### Docker

```bash
docker pull ghcr.io/ferrum-edge/ferrum-edge:latest

docker run -d --name ferrum-edge \
  -p 8000:8000 \
  -e FERRUM_MODE=database \
  -e FERRUM_DB_TYPE=sqlite \
  -e FERRUM_DB_URL="sqlite:////data/ferrum.db?mode=rwc" \
  -e FERRUM_ADMIN_JWT_SECRET="please-change-me-to-a-32+character-secret" \
  -e FERRUM_ADMIN_BIND_ADDRESS=127.0.0.1 \
  -v ferrum_data:/data \
  ghcr.io/ferrum-edge/ferrum-edge:latest
```

> **管理 API 暴露。** 管理 API 是管理平面。两个管理监听器（HTTP 和 HTTPS）默认都绑定到回环地址（`127.0.0.1`），因此该示例**不会**发布 9000 端口，网络也无法访问管理接口。在可写的 `database`/`cp` 模式中，如果明文管理监听器绑定到非回环地址（`0.0.0.0`、公网 IP 或私有/VPC 接口 IP），且没有 `FERRUM_ADMIN_ALLOWED_CIDRS` 允许列表，网关会**拒绝启动**。若要从容器外访问管理接口，必须设置 `FERRUM_ADMIN_BIND_ADDRESS=0.0.0.0`（或 `::`）——仅绑定回环地址无法通过已发布端口访问。然后请选择以下方式之一：(a) 通过 TLS 提供服务（`FERRUM_ADMIN_TLS_CERT_PATH`/`FERRUM_ADMIN_TLS_KEY_PATH`，发布 `9443`，设置 `FERRUM_ADMIN_HTTP_PORT=0` 禁用明文）和/或设置 `FERRUM_ADMIN_ALLOWED_CIDRS`；或 (b) 仅用于一次性本地测试时，设置 `FERRUM_ALLOW_INSECURE_ADMIN_HTTP=true` 并发布 `127.0.0.1:9000:9000`。

Docker Compose 示例和生产部署请参阅 [docs/docker.md](docs/docker.md)。

## 快速开始

### File 模式（最快启动）

```bash
# Using the CLI (recommended)
ferrum-edge run --spec tests/config.yaml -v

# Using environment variables
FERRUM_MODE=file \
FERRUM_FILE_CONFIG_PATH=tests/config.yaml \
FERRUM_LOG_LEVEL=info \
cargo run --release -- run
```

使用智能默认值时，如果当前目录中存在 `./ferrum.conf` 和 `./resources.yaml`：

```bash
ferrum-edge run
```

完整 CLI 参考请参阅 [docs/cli.md](docs/cli.md)。

### Database 模式（SQLite）

```bash
FERRUM_MODE=database \
FERRUM_DB_TYPE=sqlite \
FERRUM_DB_URL="sqlite://ferrum.db?mode=rwc" \
FERRUM_ADMIN_JWT_SECRET="change-me-dev-admin-secret-min-32-chars" \
FERRUM_ADMIN_BIND_ADDRESS=127.0.0.1 \
FERRUM_LOG_LEVEL=info \
cargo run --release -- run
```

### Database 模式（PostgreSQL）

```bash
FERRUM_MODE=database \
FERRUM_DB_TYPE=postgres \
FERRUM_DB_URL="postgres://user:pass@localhost/ferrum" \
FERRUM_ADMIN_JWT_SECRET="change-me-dev-admin-secret-min-32-chars" \
FERRUM_ADMIN_BIND_ADDRESS=127.0.0.1 \
cargo run --release -- run
```

### Database 模式（MongoDB）

```bash
FERRUM_MODE=database \
FERRUM_DB_TYPE=mongodb \
FERRUM_DB_URL="mongodb://user:pass@localhost:27017/ferrum?authSource=admin" \
FERRUM_MONGO_DATABASE=ferrum \
FERRUM_ADMIN_JWT_SECRET="change-me-dev-admin-secret-min-32-chars" \
FERRUM_ADMIN_BIND_ADDRESS=127.0.0.1 \
cargo run --release -- run
```

### Control Plane + Data Plane（本地开发）

CP→DP gRPC 通道携带数据平面身份验证 JWT 和完整网关配置，因此它以 **TLS 优先并默认安全**：除非配置了 TLS（或明确允许明文——见下文），否则 CP 会拒绝在非回环地址绑定明文 gRPC 监听器，DP 也会拒绝非回环的 `http://` CP URL。下面的回环快速入门示例可直接运行；任何网络化部署都必须使用 TLS。

```bash
# Control Plane (loopback + plaintext — local development only; secrets must be 32+ chars)
FERRUM_MODE=cp \
FERRUM_DB_TYPE=sqlite \
FERRUM_DB_URL="sqlite://ferrum.db?mode=rwc" \
FERRUM_ADMIN_JWT_SECRET="change-me-dev-admin-secret-min-32-chars" \
FERRUM_CP_GRPC_LISTEN_ADDR="127.0.0.1:50051" \
FERRUM_CP_DP_GRPC_JWT_SECRET="change-me-dev-cp-dp-secret-min-32-chars" \
cargo run --release -- run

# Data Plane (single CP, loopback — local development only)
FERRUM_MODE=dp \
FERRUM_DP_CP_GRPC_URLS="http://localhost:50051" \
FERRUM_CP_DP_GRPC_JWT_SECRET="change-me-dev-cp-dp-secret-min-32-chars" \
cargo run --release -- run

# Data Plane (multi-CP failover over TLS — production shape)
FERRUM_MODE=dp \
FERRUM_DP_CP_GRPC_URLS="https://cp1:50051,https://cp2:50051,https://cp3:50051" \
FERRUM_DP_GRPC_TLS_CA_CERT_PATH="/certs/ca.pem" \
FERRUM_CP_DP_GRPC_JWT_SECRET="change-me-dev-cp-dp-secret-min-32-chars" \
cargo run --release -- run
```

使用 TLS/mTLS 的生产 CP/DP 部署请参阅 [docs/cp_dp_mode.md](docs/cp_dp_mode.md#transport-security-tlsmtls)。若要有意在网络地址上运行明文配置同步（受信任网络，并有补偿控制），请在 CP 和 DP 上都设置 `FERRUM_CP_DP_GRPC_ALLOW_PLAINTEXT=true`。多区域高可用请参阅 [docs/multi_region_ha.md](docs/multi_region_ha.md)。

## 默认端口

| 端口 | 协议 | 用途 |
|------|----------|---------|
| `8000` | HTTP | 代理流量 |
| `8443` | HTTPS | 代理流量（TLS） |
| `9000` | HTTP | 管理 API |
| `9443` | HTTPS | 管理 API（TLS） |
| `50051` | gRPC | 控制平面 → 数据平面同步 |

所有端口均可通过环境变量（`FERRUM_PROXY_HTTP_PORT`、`FERRUM_PROXY_HTTPS_PORT`、`FERRUM_ADMIN_HTTP_PORT`、`FERRUM_ADMIN_HTTPS_PORT`、`FERRUM_CP_GRPC_LISTEN_ADDR`）配置。将任何明文端口设置为 `0` 可完全禁用其监听器，以用于仅 TLS 部署。

## 配置

Ferrum Edge 通过环境变量配置，并可使用可选的 `ferrum.conf` 文件提供默认值。环境变量优先。

### 基本变量

| 变量 | 必需 | 默认值 | 说明 |
|---|---|---|---|
| `FERRUM_MODE` | **是** | — | `database`、`file`、`cp`、`dp`、`mesh`、`injector`、`node_agent`、`migrate` |
| `FERRUM_LOG_LEVEL` | 否 | `warn` | `error`、`warn`、`info`、`debug`、`trace` |
| `FERRUM_LOG_BUFFER_CAPACITY` | 否 | `4096` | 每个接收器的硬记录上限；聚合字节数另受 `FERRUM_LOG_BUFFER_BYTES` 限制 |
| `FERRUM_PROXY_HTTP_PORT` | 否 | `8000` | HTTP 代理端口（`0` = 禁用） |
| `FERRUM_PROXY_HTTPS_PORT` | 否 | `8443` | HTTPS 代理端口 |
| `FERRUM_ACCEPT_THREADS` | 否 | `0`（自动检测） | 通过 SO_REUSEPORT 实现并行接受循环（0 = CPU 核心数；仅 Unix，非 Unix 回退为一个循环） |
| `FERRUM_ADMIN_HTTP_PORT` | 否 | `9000` | 管理 API HTTP 端口（`0` = 禁用） |
| `FERRUM_ADMIN_JWT_SECRET` | DB/CP | — | 管理 API 的 HS256 密钥（至少 32 个字符） |
| `FERRUM_DB_TYPE` | DB/CP | — | `postgres`、`mysql`、`sqlite`、`mongodb` |
| `FERRUM_DB_URL` | DB/CP | — | 数据库连接字符串 |
| `FERRUM_FILE_CONFIG_PATH` | File 模式 | — | YAML/JSON 配置文件路径 |

完整的 300 多个环境变量列表请参阅 [docs/configuration.md](docs/configuration.md)。

运维说明：所有日志都通过有界的**非阻塞写入器**（固定记录和字节准入 → 专用后台线程 → stdout/stderr），因此日志调用绝不会阻塞请求处理线程。默认将应用程序日志保留在 `stdout`/`stderr`。在容器中，让容器运行时或平台收集并轮换日志流。在 VM 上，优先通过 `systemd` 或其他监督程序运行 Ferrum Edge，并让 `journald`、`rsyslog`、`logrotate` 或主机日志代理处理保留和轮换。只有在确实需要本地日志文件时，才添加应用程序级文件日志。在极端吞吐量下，应同时调整 `FERRUM_LOG_BUFFER_CAPACITY` 和 `FERRUM_LOG_BUFFER_BYTES`；当字节预算已满时，仅提高记录上限无法增加准入量。达到任一界限后，新事件会被丢弃并计数，因此收集器背压不会拖慢网关。

### File 模式配置格式

```yaml
proxies:
  - id: "my-api"
    listen_path: "/api/v1"
    backend_scheme: http
    backend_host: "backend-service"
    backend_port: 3000
    strip_listen_path: true
    plugins:
      - plugin_config_id: "log-plugin"

consumers:
  - id: "user-1"
    username: "alice"
    credentials:
      keyauth:
        - key: "alice-api-key"
    acl_groups:
      - "engineering"

plugin_configs:
  - id: "log-plugin"
    plugin_name: "stdout_logging"
    config: {}
    scope: global
    enabled: true
```

流代理配置、服务发现和 `ferrum.conf` 参考请参阅 [docs/configuration.md](docs/configuration.md)。

## 管理 API

用于在运行时管理代理、消费者、插件和上游的 JWT 保护 REST API。

> 以下示例使用 `http://localhost:9000`，与本地快速入门配置一致（管理接口绑定到回环地址，使用明文）。在生产环境中，请通过 **HTTPS** 提供管理 API（设置 `FERRUM_ADMIN_TLS_CERT_PATH`/`FERRUM_ADMIN_TLS_KEY_PATH`，然后使用 `https://host:9443`），并通过 `FERRUM_ADMIN_HTTP_PORT=0` 禁用明文，或通过 `FERRUM_ADMIN_ALLOWED_CIDRS` 限制调用方。经明文 `http://` 发送的 Bearer 令牌会以明文穿过网络。在 `database`/`cp` 模式中，如果没有允许列表，网关会拒绝启动公开的明文管理监听器（请参阅 [docs/configuration.md](docs/configuration.md#admin-api)）。

```bash
# Liveness probe (no auth) — always {"status":"ok"}
curl http://localhost:9000/live

# Readiness/health (no auth returns status+ready; full diagnostics need auth)
curl http://localhost:9000/health

# List proxies
curl -H "Authorization: Bearer $TOKEN" http://localhost:9000/proxies

# Create a proxy
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"listen_path": "/api", "backend_scheme": "http", "backend_host": "backend", "backend_port": 3000}' \
  http://localhost:9000/proxies

# Backup / Restore
curl -H "Authorization: Bearer $TOKEN" http://localhost:9000/backup > backup.json
curl -X POST -H "Authorization: Bearer $TOKEN" -d @backup.json "http://localhost:9000/restore?confirm=true"
```

提交 OpenAPI/Swagger 规范可原子化配置一个代理、上游和插件——请参阅 [docs/api_specs.md](docs/api_specs.md)。

完整端点参考请参阅 [docs/admin_api.md](docs/admin_api.md)，OpenAPI 规范请参阅 [openapi.yaml](openapi.yaml)。

## 插件系统

Ferrum 内置大量插件，用于请求预检、身份验证、授权和后端准入、请求/响应转换、AI/智能体网关策略、协议桥接、流/WebSocket/UDP 处理和可观测性。插件在确定性的优先级管道中执行（数字越小越先执行），并能感知协议，因此网关会跳过不适用于当前协议的插件。

为避免 README 发生漂移，规范插件注册表和排序位于 README 之外：每个插件的详细配置请参阅 [docs/plugins.md](docs/plugins.md)，完整执行顺序和协议支持矩阵请参阅 [docs/plugin_execution_order.md](docs/plugin_execution_order.md)。


### AI / LLM 插件

面向 AI 和智能体网关用例的插件——记录审计、成本可见性、预算执行、语义策略、请求策略、PII 保护、输出防护、提示词压缩、流式和非流式提供商路由、MCP 工具路由以及响应缓存：

- **`ai_token_metrics`** —— 从 LLM 响应中提取令牌用量，仅用于可观测性（SSE 指标需要显式选择缓冲）
- **`ai_request_guard`** —— 强制执行模型允许列表、令牌限制和请求策略
- **`ai_rate_limiter`** —— 通过请求前预留和响应协调来执行令牌预算（支持集中式 Redis 模式；兼容任何 RESP 协议服务器：Redis、Valkey、DragonflyDB、KeyDB、Garnet）
- **`ai_prompt_shield`** —— 扫描 PII 并拒绝、遮盖或警告
- **`ai_prompt_compressor`** —— 对已准入的 OpenAI Chat/Text Completions 请求执行有界、无模型压缩（不依赖外部模型或服务）；保留匹配反引号的代码、URL、Unicode 数字、常见标识符和否定词，并以有界、故障安全方式清理 `preserve_tag` 标记
- **`ai_semantic_firewall`** —— 针对提示词注入、越狱、数据外泄意图、工具滥用和主题允许/拒绝策略的语义提示词/响应防火墙
- **`ai_semantic_cache`** —— 使用规范化精确匹配键、可选的基于嵌入的语义相似度，以及本地或 Redis 精确响应存储进行 LLM 响应缓存
- **`ai_response_guard`** —— 输出侧内容防护：PII 检测、禁用短语、响应格式验证
- **`ai_tool_governor`** —— 根据名称、参数、JSON Schema、正则表达式、风险和身份，对 AI 工具/函数调用执行确定性的允许/拒绝/遮盖/审批策略；检查请求工具定义、缓冲和流式响应工具调用（清除前保持，之后释放或截断），并可选检查 MCP/A2A 方法，还可使用审批 webhook
- **`ai_transcript_audit`** —— 用于合规的受控 AI 负载捕获：已遮盖的请求/响应摘录、规范哈希、模型/提供商、令牌/防护/工具/缓存元数据、采样和异步批量 HTTP 导出；除非配置为失败关闭，否则绝不阻塞热路径
- **`ai_stream_router`** —— `ai_federation` 的流式对应插件：接管 `"stream": true` 的 OpenAI Chat Completions，覆盖路由到匹配提供商，并在不缓冲的情况下将提供商原生 SSE（例如 Anthropic）规范化为 OpenAI `chat.completion.chunk` SSE
- **`ai_federation`** —— 仅限 HTTP 的 AI 网关，将最终转换后的非流式 Completions JSON 路由到受支持的提供商，具备有界响应、可安全重放的回退、严格端点策略和提供商原生工具/内容规范化；匹配的 `"stream": true` 请求返回 `501`
- **`mcp_gateway`** —— 用于 HTTP JSON-RPC MCP 流量的 MCP / Agent Tool Gateway：透明代理、聚合发现、带命名空间的工具/资源/提示词路由、会话中介、工具参数验证，以及供下游 Ferrum 插件使用的 `mcp.*` 元数据
- **`a2a_gateway`** —— 用于 HTTP/HTTPS JSON-RPC、HTTP+JSON/REST 和 gRPC/grpcs 流量的透明 Agent-to-Agent 网关：方法检测、轻量级方法策略、HTTP Agent Card URL 重写、流式安全直通，以及 `a2a.*` 元数据

自动检测 OpenAI、Anthropic、Google Gemini、Cohere、Mistral 和 AWS Bedrock 响应格式。配置和组合示例请参阅 [docs/plugins.md](docs/plugins.md#ai--llm-plugins)。

### 集中式速率限制

`rate_limiting` 和 `ai_rate_limiter` 支持通过 `sync_mode: "redis"` 使用集中式模式，在多个网关实例之间协调限额。`ws_rate_limiting` 也支持 `sync_mode: "redis"`，但仅用于在每插件/网关实例的 Redis 命名空间下外置每连接帧计数器——预算不会在实例间共享，也不能在重连/重建后移植。兼容任何 RESP 协议服务器（Redis、Valkey、DragonflyDB、KeyDB、Garnet）。Redis TLS 使用网关级 `FERRUM_TLS_CA_BUNDLE_PATH` 和 `FERRUM_TLS_NO_VERIFY` 设置。

### 自定义插件

通过 `custom_plugins/` 目录提供即插即用的自定义插件——构建时自动发现。自定义插件可通过 `plugin_migrations()` 声明自己的数据库迁移，用于创建和管理私有表，并与核心迁移分开跟踪。请参阅 [CUSTOM_PLUGINS.md](CUSTOM_PLUGINS.md)。

## 路由

- 对 `listen_path` 进行**最长前缀匹配**，并强制路径唯一
- **基于主机的路由**，支持精确匹配和通配符前缀（`*.example.com`）
- **仅主机路由**——在 HTTP 代理上省略 `listen_path`，即可匹配指定主机下的任何路径
- **正则路由**，自动锚定为完整路径匹配（以 `~` 开头）
- 通过每个代理的 `allowed_methods` 进行**方法过滤**（不匹配时返回 405）
- **路径转发**：`strip_listen_path`（默认 true；对仅主机代理不起作用），以及可选的 `backend_path` 前缀

详细路由行为请参阅 [docs/routing.md](docs/routing.md)。

### 特定协议代理

| 协议 | 配置 | 说明 |
|----------|--------|-------|
| **HTTP/1.1** | `backend_scheme: http` / `https` | 默认，使用连接池 |
| **HTTP/2** | 在 `https` 上协商 ALPN | 通过 `pool_enable_http2: true` 自动启用；启动时的能力分类决定何时使用直接 H2 池 |
| **HTTP/3** | `backend_scheme: https` | 启动时的能力分类会探测 HTTPS 后端是否支持 H3，并在支持时自动为普通 HTTP 流量使用 QUIC |
| **WebSocket** | 在任何 HTTP 系列代理上，根据 `Upgrade: websocket`（H1.1）或 `:protocol=websocket` Extended CONNECT（H2 RFC 8441、H3 RFC 9220）运行时检测 | `backend_scheme: http` → `ws://` 上游；`https` → `wss://`。三个前端使用相同插件管道；H3 会话由 `FERRUM_HTTP3_WEBSOCKET_ENABLED` 控制（默认开启） |
| **gRPC** | 在任何 HTTP 系列代理上，根据 `content-type: application/grpc*` 运行时检测 | HTTP/2，在 `http`（h2c）和 `https`（ALPN）方案上都支持 trailer |
| **TCP** | `backend_scheme: tcp` / `tcps` | 专用端口流代理（明文或 TLS） |
| **UDP** | `backend_scheme: udp` / `dtls` | 带会话跟踪的数据报代理（明文或 DTLS） |

TCP/UDP/DTLS 代理配置请参阅 [docs/tcp_udp_proxy.md](docs/tcp_udp_proxy.md)。

## 负载均衡与弹性

- **六种算法**：轮询、加权轮询、最少连接、最低延迟、一致性哈希、随机
- **健康检查**：主动探测（HTTP、TCP SYN、UDP）和被动监控
- **熔断器**：三态模式（Closed/Open/Half-Open）
- **重试**：连接级和 HTTP 级重试，采用固定/指数退避
- **服务发现**：DNS-SD、Kubernetes 和 Consul 提供商
- **配置缓存**：所有模式都维护内存配置缓存，以便在来源中断时保持弹性
- **启动故障转移**：用于 Kubernetes 数据库中断恢复的 `FERRUM_DB_CONFIG_BACKUP_PATH`
- **多 URL 故障转移**：用于数据库高可用的 `FERRUM_DB_FAILOVER_URLS`

请参阅 [docs/load_balancing.md](docs/load_balancing.md)、[docs/retry.md](docs/retry.md) 和 [docs/error_classification.md](docs/error_classification.md)。

## 连接池

无锁连接复用，使用每代理池键和 HTTP/2 流量控制调优。通过全局默认值和每代理覆盖实现混合配置。启动池预热会在 DNS 预热后预先建立后端连接，以消除首个请求的冷启动延迟。

容量规划指南和池预热配置请参阅 [docs/connection_pooling.md](docs/connection_pooling.md)。

## 安全

### TLS

- **前端 TLS/mTLS**：代理和管理 HTTPS，可选客户端证书验证——[docs/frontend_tls.md](docs/frontend_tls.md)
- **后端 mTLS**：用于后端身份验证的每代理客户端证书——[docs/backend_mtls.md](docs/backend_mtls.md)
- **数据库 TLS**：PostgreSQL 和 MySQL TLS/mTLS 连接——[docs/database_tls.md](docs/database_tls.md)
- **TLS 加固**：可配置密码套件、密钥交换组和协议版本——[docs/frontend_tls.md](docs/frontend_tls.md#tls-policy-hardening)

### 客户端 IP 解析

通过受信任代理配置和 `X-Forwarded-For` 从右向左遍历，安全检测源 IP。请参阅 [docs/client_ip_resolution.md](docs/client_ip_resolution.md)。

### DNS

内存异步 DNS 缓存，支持启动预热、过期时重新验证、每代理 TTL 覆盖和静态覆盖。请参阅 [docs/dns_resolver.md](docs/dns_resolver.md)。

## 性能

来自 `tests/performance/multi_protocol/` 的历史小负载多协议基准结果（本地 macOS Apple Silicon 运行，200 并发，10 秒，64 字节负载；本摘要未记录运行日期）：

| 协议 | 网关 RPS | 网关 P50 | 网关 P99 | 直连 RPS | 直连 P50 | 直连 P99 | 开销 |
|----------|------------|--------|--------|------------|------------|------------|----------|
| HTTP/1.1 | 102,183 | 1.89ms | 3.85ms | 209,910 | 939μs | 1.81ms | ~51% |
| HTTP/1.1+TLS | 101,317 | 1.90ms | 3.84ms | 209,361 | 941μs | 1.81ms | ~52% |
| HTTP/2 | 108,138 | 1.67ms | 6.38ms | 355,544 | 486μs | 1.53ms | ~70% |
| HTTP/3 (QUIC) | 53,085 | 3.51ms | 5.87ms | 83,592 | 2.38ms | 2.80ms | ~37% |
| gRPC | 68,352 | 2.53ms | 12.02ms | 205,927 | 821μs | 3.15ms | ~67% |
| WebSocket | 103,830 | 1.88ms | 3.15ms | 207,507 | 952μs | 1.72ms | ~50% |
| TCP | 108,841 | 1.83ms | 2.59ms | 214,113 | 928μs | 1.65ms | ~49% |
| TCP+TLS | 107,340 | 1.84ms | 2.68ms | 207,103 | 949μs | 1.78ms | ~48% |
| UDP | 82,042 | 2.46ms | 2.93ms | 276,526 | 682μs | 1.27ms | ~70% |
| UDP+DTLS | 76,107 | 2.61ms | 3.69ms | 101,839 | 1.96ms | 2.47ms | ~25% |

**自适应缓冲区大小调整**（默认启用）会根据观察到的流量模式，动态调节每个代理的 TCP/WebSocket 隧道复制缓冲区和 UDP 批处理上限。小消息代理使用较小缓冲区（节省内存），大批量传输代理使用较大缓冲区（减少系统调用）。调优请参阅 `FERRUM_ADAPTIVE_BUFFER_*` 环境变量。

**Linux 套接字调优**：（`TCP_FASTOPEN`、`IP_BIND_ADDRESS_NO_PORT`）、将 TLS 握手卸载到专用运行时、线程本地 Date 标头缓存、延迟超时初始化、频率感知的路由器缓存淘汰（Count-Min Sketch）、RED 风格自适应负载削减，以及响应缓存插件的可缓存性预测器。详情请参阅 [FEATURES.md](FEATURES.md)。

有关当前测试套件的方法和带日期的结果表，请参阅
[`tests/performance/`](tests/performance/) 和
[`tests/performance/multi_protocol/README.md`](tests/performance/multi_protocol/README.md)。

### 生产调优

**文件描述符限制**。在 Unix 上，Ferrum Edge 启动时调用一次 `setrlimit(RLIMIT_NOFILE, rlim_cur=rlim_max)`，将软上限提高到硬上限允许的值。该调用绝不会请求进程尚不具备的权限，因此在受沙箱/seccomp 限制的运行中会静默无效，而不会失败。*硬*上限必须在外部设置——Ferrum Edge 无法提高它。生产环境建议最低值：**65,536**。

| 环境 | 如何提高硬上限 |
|---|---|
| systemd 单元 | 设置 `LimitNOFILE=1048576`（位于 `[Service]` 部分） |
| Docker / Podman | `--ulimit nofile=1048576:1048576` |
| Kubernetes | 在节点/容器运行时中配置 nofile（例如 containerd/runc 或 kubelet/systemd 服务）；Pod `securityContext` 不提供 ulimit/nofile。 |
| 裸 shell（开发） | 启动二进制文件前运行 `ulimit -n 1048576` |
| `/etc/security/limits.conf` | `* hard nofile 1048576`（并配置匹配的软限制行） |

当启动后的有效软上限低于 65,536 时，Ferrum Edge 会在启动时发出一条结构化 `warn!` 日志（可通过 `"soft FD limit"` 搜索），然后继续运行。低于该最低值时，网关仍能提供服务，但其 95% FD 临界阈值会在负载下更早触发。

**并发规划**。每个入站 TCP/TLS 连接消耗约 1 个 FD；HTTP/2 将多个请求多路复用到一个连接上。Linux `splice(2)` 会为每个 TCP 中继增加 2 个管道 FD。设置 `nofile` 时，请按目标并发连接数的约 2–4 倍进行规划。

### 网关比较

历史本地比较摘要（macOS Apple Silicon，100 并发，30 秒；本摘要未记录运行日期）：

所有网关均在 Docker 容器中运行，以进行同等条件比较：

| 网关 | Key-Auth 请求/秒 | Key-Auth 延迟 | 与 Ferrum 相比 |
|---------|---------------|-----------------|-----------|
| **Ferrum Edge** | **27,979** | **3.44 ms** | — |
| Envoy 1.37 (Lua filter) | 26,787 | 3.64 ms | Ferrum 快 4% |
| Kong 3.14 | 25,009 | 3.91 ms | Ferrum 快 12% |
| Tyk v5.12 | 19,186 | 5.08 ms | Ferrum 快 46% |

Ferrum 还在 E2E TLS /api/users 测试中**取得了最高成绩**——29,808 请求/秒，是所有网关在所有场景中的最高吞吐量，比 Envoy 高 13%。得益于预计算的 `ConsumerIndex`、`Arc<Consumer>` 零复制凭据解析和无锁 `ArcSwap` 读取，Ferrum 的身份验证增加了实际为**零的开销**——已验证请求的吞吐量与未验证请求相当。可复现的 Docker 网关比较工具请参阅 [`comparison/README.md`](comparison/README.md) 和 [`comparison/run_comparison.sh`](comparison/run_comparison.sh)，基准来源检查清单请参阅 [`tests/performance/README.md`](tests/performance/README.md)。

## 故障排除

| 问题 | 解决方案 |
|-------|------|
| `FERRUM_MODE not set` | 设置 `FERRUM_MODE` 环境变量 |
| `duplicate listen_path` | 确保所有代理的 `listen_path` 值唯一 |
| `Database connection failed` | 验证 `FERRUM_DB_TYPE` 和 `FERRUM_DB_URL` |
| `401 on Admin API` | 检查 JWT 是否使用 `FERRUM_ADMIN_JWT_SECRET` 签名 |
| `404 on proxy request` | 验证请求路径是否匹配已配置的 `listen_path` |
| `502 Bad Gateway` | 后端不可达——查看 `X-Gateway-Error` 标头了解详情 |
| `504 Gateway Timeout` | 增大 `backend_read_timeout_ms` |
| `429 Too Many Requests` | 超过速率限制——检查插件配置 |
| DP not receiving config | 验证两端的 `FERRUM_CP_DP_GRPC_JWT_SECRET` 是否匹配 |

## 文档

| 主题 | 链接 |
|-------|------|
| 完整配置参考 | [docs/configuration.md](docs/configuration.md) |
| 插件参考 | [docs/plugins.md](docs/plugins.md) |
| 事务日志架构自定义 | [docs/log_schema.md](docs/log_schema.md) |
| 管理 API | [docs/admin_api.md](docs/admin_api.md) |
| 连接池 | [docs/connection_pooling.md](docs/connection_pooling.md) |
| 负载均衡 | [docs/load_balancing.md](docs/load_balancing.md) |
| CP/DP 分布式模式 | [docs/cp_dp_mode.md](docs/cp_dp_mode.md) |
| Kubernetes 部署 | [docs/kubernetes_deployment.md](docs/kubernetes_deployment.md) |
| 用于网格身份的 SPIRE 部署 | [docs/spire_deployment.md](docs/spire_deployment.md) |
| TCP/UDP/DTLS 代理 | [docs/tcp_udp_proxy.md](docs/tcp_udp_proxy.md) |
| 前端 TLS/mTLS | [docs/frontend_tls.md](docs/frontend_tls.md) |
| 后端 mTLS | [docs/backend_mtls.md](docs/backend_mtls.md) |
| 数据库 TLS | [docs/database_tls.md](docs/database_tls.md) |
| DNS 解析器 | [docs/dns_resolver.md](docs/dns_resolver.md) |
| 路由 | [docs/routing.md](docs/routing.md) |
| 重试逻辑 | [docs/retry.md](docs/retry.md) |
| 响应流 | [docs/response_body_streaming.md](docs/response_body_streaming.md) |
| 插件执行顺序 | [docs/plugin_execution_order.md](docs/plugin_execution_order.md) |
| 基础设施容量规划 | [docs/infrastructure_sizing.md](docs/infrastructure_sizing.md) |
| Docker 部署 | [docs/docker.md](docs/docker.md) |
| CI/CD 管道 | [docs/ci_cd.md](docs/ci_cd.md) |
| 数据库迁移 | [docs/migrations.md](docs/migrations.md) |
| 自定义插件 | [CUSTOM_PLUGINS.md](CUSTOM_PLUGINS.md) |
| 功能列表 | [FEATURES.md](FEATURES.md) |
| OpenAPI 规范 | [openapi.yaml](openapi.yaml) |
| Gateway API 一致性 | [docs/gateway_api_conformance.md](docs/gateway_api_conformance.md)（规范）——从 [CONFORMANCE.md](CONFORMANCE.md) 建立索引 |
| Istio + xDS 一致性矩阵 | [CONFORMANCE.md](CONFORMANCE.md)（运行 `cargo test --test conformance_tests` 刷新 `target/conformance/coverage.md`） |

## CI/CD

每次推送到 `main` 和每个 PR 时都会执行：格式检查、测试（单元 + 集成 + E2E）、clippy 和性能回归测试。版本标签会触发多平台发布构建和 Docker 镜像构建。

管道详情请参阅 [docs/ci_cd.md](docs/ci_cd.md)。

## 贡献

1. Fork 仓库
2. 创建功能分支（`git checkout -b feature/my-feature`）
3. 为新功能编写测试
4. 确保所有测试通过（`cargo test --all-features`）
5. 运行 `cargo clippy --all-targets --all-features -- -D warnings` 和 `cargo fmt`
6. 提交 pull request

## 许可证

Copyright (c) 2026 Ferrum Edge

根据 [PolyForm Noncommercial License 1.0.0](LICENSE) 授权。

**简而言之**：只要不转售我们的技术，即可免费使用。业余爱好者、学生、研究人员、非营利组织——尽情使用。公司为概念验证或演示评估 Ferrum？也完全没问题，欢迎试用。但如果要把它投入生产网络技术栈，烦请获取[商业许可证](LICENSE-COMMERCIAL.md)，帮助我们补充咖啡因。开源软件不靠曝光运行——它靠咖啡，而咖啡需要花钱。
