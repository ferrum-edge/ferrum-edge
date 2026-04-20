# Ferrum Edge — Codebase Refactoring Plan

Base: `origin/main` @ `c002287` ("Make Proxy listen_path optional and add host-only routing", #440). Analysis covers `src/` (~82k LOC), `tests/` (~80k LOC), `custom_plugins/`.

## 1. Goals & Guiding Principles

1. **DRY** — every piece of logic has a single, unambiguous representation.
2. **No regressions** — the hot path must not get slower. Every refactor that touches the request path must show equal-or-better numbers in `tests/performance/multi_protocol/`.
3. **No behavior changes** — refactors must be semantics-preserving. Functional/integration tests are the oracle; fix tests only if they codify duplication we are removing.
4. **One phase, one merge** — each phase is a standalone PR that ships independently, reviewable in <1 day, with its own test delta and before/after LOC counts.
5. **Strangler-fig, not big-bang** — new abstractions are introduced alongside existing code; call sites migrate incrementally; the old code is deleted in a separate cleanup PR.

## 2. Quantified Duplication (from deep-dive analysis)

| Area | Duplicate LOC (est.) | Files | Primary Pattern | Priority |
|------|---------------------:|------:|-----------------|----------|
| Plugin logging (batch/flush) | 1,250–1,500 | 5 | Template Method / Generic `BatchingLogger<T>` | P0 |
| Plugin auth flow | 1,200–1,400 | 6 | Template Method (`AuthPlugin` trait) | P0 |
| Admin CRUD handlers | 2,400–3,000 | 1 (4,528 LOC) | Template Method + generic `CrudResource<T>` | P0 |
| Functional test harnesses | 1,500–2,000 | ~19 files | Factory / Builder (`TestGateway`) | P0 |
| Backend TLS `ClientConfig` builders | 200 | 3 | Factory Method (`BackendTlsConfigBuilder`) | P1 |
| CA trust chain (3-tier fallback) | 150 | 5 | Extract Method + shared helper | P1 |
| Connection pool skeleton | 600–800 | 4 | Template Method (`PoolManager` trait) | P1 |
| Streaming body adapters | 500–600 | 1 (`body.rs`) | Strategy (coalescing trait) | P1 |
| Error classifiers | 350–400 | 3 | Substitute Algorithm (single classifier) | P1 |
| Rate-limiter algorithms | 400–500 | 4 | Strategy (`RateLimitAlgorithm`) | P1 |
| Env var parsing | 500 | 1 (`env_config.rs`) | Declarative macro | P2 |
| Secret backend dispatch | ~150 | 6 | Factory Method + registry | P2 |
| Plugin factory giant match | 150 | 1 (`plugins/mod.rs`) | Registry / self-registration | P2 |
| Size-limiter plugins | 120–180 | 3 | Template Method | P2 |
| Response header collection | 60 | 1 (`proxy/mod.rs`) | Extract Method (generic) | P2 |
| SQL dialect branching | 150+ | 1 (migrations) | Strategy (dialect abstraction) | P3 |

**Total conservative target: ~9,500 LOC eliminated** (~6–8% of the non-test codebase) while flattening many of the "must remember to update all N sites" invariants CLAUDE.md currently encodes as prose rules.

## 3. Phased Plan

Each phase is independently shippable. Phases within a priority tier can be parallelized across contributors. Phases across tiers should land in order (P0 → P1 → P2 → P3) because later phases depend on infrastructure introduced earlier.

---

### Phase 0 — Test Infrastructure First (P0, 1 week)

**Why first:** All subsequent refactors need a reliable, fast regression net. Consolidating 19 duplicated functional test harnesses up-front means later phases can add tests to the shared harness instead of another copy.

**Scope:**
- Create `tests/common/gateway_harness.rs`:
  - `TestGateway` struct with fluent builder (mode, db, ports, env vars).
  - `TestGateway::spawn().await` → `try_new()` wrapped in the 3-attempt retry documented in CLAUDE.md "Functional test port allocation — MUST use retry pattern".
  - `TestGateway::wait_for_health()`, `::auth_header()`, `::shutdown()`, `Drop` guard that `kill()`s the subprocess.
- Create `tests/common/echo_servers.rs`: shared HTTP/WS/gRPC/TCP/UDP echo spawners returning pre-bound listeners (eliminates the bind-drop-rebind race for same-process listeners).
- Create `tests/common/config_builder.rs`: typed builders for `GatewayConfig`, `Proxy`, `Consumer`, `Upstream`, `PluginConfig` that write YAML to the harness's temp dir.

**Migration strategy:**
1. Land the `tests/common/` module first (no existing tests touched). CI green.
2. One PR per ~5 migrated test files, each showing strict LOC reduction. Keep old harnesses until every caller is migrated.
3. Delete the duplicated `AdminTestHarness` pair and the 17 other copies in a final cleanup PR.

**Success criteria:**
- `wc -l tests/functional/*.rs` decreases by ≥1,500.
- `tests/common/` has no `#[ignore]` tests of its own; it's pure infra.
- Functional test wall-clock doesn't regress (shared binary builds should be faster, not slower).

**Patterns:** Factory Method (`TestGatewayBuilder::build`), Template Method (shared spawn → wait → yield → teardown flow), Extract Method (port retry, health polling).

---

### Phase 1 — Admin CRUD Generic Dispatcher (P0, 1–2 weeks)

**Target:** `src/admin/mod.rs` (4,528 LOC). 34 handlers × ~250 LOC boilerplate each.

**Design:**

```rust
// src/admin/crud.rs
pub trait AdminResource: Send + Sync + Serialize + DeserializeOwned + 'static {
    const RESOURCE_NAME: &'static str;  // "proxies", "consumers", ...
    type Id: AsRef<str>;

    fn id(&self) -> &str;
    fn set_id(&mut self, id: String);
    fn timestamps(&mut self, created_at: DateTime<Utc>, updated_at: DateTime<Utc>);
    fn normalize(&mut self);
    fn validate(&self, ctx: &ValidationCtx) -> Result<(), Vec<String>>;

    async fn db_get(db: &dyn DatabaseBackend, ns: &str, id: &str) -> DbResult<Option<Self>>;
    async fn db_list(db: &dyn DatabaseBackend, ns: &str, p: &Pagination) -> DbResult<Vec<Self>>;
    async fn db_create(db: &dyn DatabaseBackend, ns: &str, r: &Self) -> DbResult<()>;
    async fn db_update(db: &dyn DatabaseBackend, ns: &str, r: &Self) -> DbResult<()>;
    async fn db_delete(db: &dyn DatabaseBackend, ns: &str, id: &str) -> DbResult<()>;

    async fn check_uniqueness(db: &dyn DatabaseBackend, ns: &str, r: &Self, exclude_id: Option<&str>) -> DbResult<Option<String>>;
}

pub async fn handle_create<R: AdminResource>(state: &AdminState, body: &[u8], ns: &str) -> ApiResponse { ... }
pub async fn handle_get<R: AdminResource>(state: &AdminState, id: &str, ns: &str) -> ApiResponse { ... }
pub async fn handle_update<R: AdminResource>(state: &AdminState, id: &str, body: &[u8], ns: &str) -> ApiResponse { ... }
pub async fn handle_delete<R: AdminResource>(state: &AdminState, id: &str, ns: &str) -> ApiResponse { ... }
pub async fn handle_list<R: AdminResource>(state: &AdminState, q: &ListQuery, ns: &str) -> ApiResponse { ... }
```

Consumer-specific credential endpoints and batch endpoints stay hand-written but reuse the same validation/DB helpers.

**Migration:**
1. Introduce trait + generic handlers alongside existing code. No routes change yet.
2. Implement `AdminResource` for `Proxy`; route `/proxies/*` through generics. Run full admin test suite.
3. Repeat for `Upstream`, `PluginConfig`, `Consumer` (consumer last because of credential-specific endpoints).
4. Delete the 4 × 5 = 20 original handler functions.

**Patterns:** Template Method (CRUD skeleton), Strategy (per-resource uniqueness / validation), Pull Up Method (timestamps, normalize).

**Success criteria:** `src/admin/mod.rs` drops from 4,528 → ~1,800 LOC. All existing admin integration/functional tests pass unchanged. JWT auth, namespace scoping, and audit logging are untouched.

---

### Phase 2 — Plugin Logging Consolidation (P0, 2 weeks)

**Targets:** `http_logging.rs`, `tcp_logging.rs`, `kafka_logging.rs`, `loki_logging.rs`, `udp_logging.rs`, `ws_frame_logging.rs`, `statsd_logging.rs`, `stdout_logging.rs` (2,905 LOC total).

**Design:**

```rust
// src/plugins/utils/batching_logger.rs
pub struct BatchingLogger<T: Clone + Send + Sync + 'static> {
    sender: mpsc::Sender<T>,
    cfg: BatchConfig,
}

pub struct BatchConfig {
    pub batch_size: usize,      // parsed once from plugin config
    pub flush_interval: Duration,
    pub buffer_capacity: usize,
    pub max_retries: u32,
    pub retry_delay: Duration,
}

impl<T> BatchingLogger<T> {
    pub fn from_config<F, Fut>(cfg_json: &Value, flush: F) -> Result<Self, String>
    where
        F: Fn(Vec<T>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), String>> + Send,
    { /* spawn flush loop with retry + backpressure */ }

    pub fn try_send(&self, item: T) {
        if self.sender.try_send(item).is_err() {
            warn!(plugin = ..., "buffer full — dropping log entry");
        }
    }
}

pub type LogEntry = /* enum { Http(TransactionSummary), Stream(StreamTransactionSummary), WsFrame(WsFrameEvent) } */;
```

Each logging plugin shrinks to:
- Constructor: parse plugin-specific config (endpoint URL, API key, topic, labels), build flush closure, delegate to `BatchingLogger::from_config`.
- `log()` / `on_stream_disconnect()` / `on_ws_frame()` trait methods: single line `self.logger.try_send(entry)`.

**Patterns:** Template Method (flush loop shell), Strategy (flush closure varies per transport), Generic `<T>` (LogEntry variety).

**Success criteria:** logging plugins collectively drop from ~2,905 → ~1,400 LOC. Http-logging `custom_headers` field still works (passed into the flush closure). Kafka's non-rustls TLS path still works via librdkafka config (the flush closure owns the producer).

---

### Phase 3 — Plugin Auth Consolidation (P0, 2 weeks)

**Targets:** `jwt_auth.rs`, `key_auth.rs`, `basic_auth.rs`, `hmac_auth.rs`, `ldap_auth.rs`, `jwks_auth.rs`, `mtls_auth.rs` (2,222 LOC).

**Design:**

```rust
// src/plugins/utils/auth_flow.rs
#[async_trait]
pub trait AuthMechanism: Send + Sync {
    const NAME: &'static str;
    const CREDENTIAL_TYPE: &'static str;  // "jwt", "keyauth", "basicauth", ...

    fn extract_credential(&self, ctx: &RequestContext, headers: &HashMap<String, String>) -> Option<ExtractedCredential>;
    fn lookup_consumer(&self, cred: &ExtractedCredential, index: &ConsumerIndex) -> Option<Arc<Consumer>>;
    async fn verify(&self, cred: &ExtractedCredential, consumer: &Consumer) -> VerifyOutcome;
}

pub async fn run_auth<M: AuthMechanism>(
    mechanism: &M,
    ctx: &mut RequestContext,
    headers: &HashMap<String, String>,
    index: &ConsumerIndex,
) -> PluginResult {
    // 1. extract_credential  (None -> Continue or Reject 401)
    // 2. lookup_consumer     (None -> Reject 401)
    // 3. verify              (Fail -> Reject 401; Ok -> set ctx.identified_consumer, Continue)
}
```

JWKS/OIDC stays distinct because it populates `ctx.authenticated_identity` (external identity) instead of `ctx.identified_consumer`; a variant `run_auth_external_identity` covers that case.

**Patterns:** Template Method (shared flow), Strategy (each mechanism's extract/lookup/verify), Decorator (rejection response factory can wrap any mechanism).

**Migration:** one auth plugin at a time; JWT first (most complex), then key/basic/hmac/ldap. Plugin tests stay as-is — they should pass unchanged because `authenticate()` behavior is identical.

**Success criteria:** auth plugin code drops from ~2,222 → ~900 LOC. Multi-credential rotation (`FERRUM_MAX_CREDENTIALS_PER_TYPE`) is handled once in `run_auth`. Multi-mode auth (`AuthMode::Multi`) works without per-plugin special cases.

---

### Phase 4 — Backend TLS `ClientConfig` Factory (P1, 1 week)

**Targets:** `src/proxy/grpc_proxy.rs:614-662`, `src/proxy/http2_pool.rs:515-574`, `src/proxy/tcp_proxy.rs:288-354` (~200 LOC of rustls `ClientConfig` building).

**Design:**

```rust
// src/tls/backend.rs  (sibling of src/tls/mod.rs)
pub fn build_root_cert_store(
    proxy_ca: Option<&Path>,
    global_ca: Option<&Path>,
) -> Result<RootCertStore, TlsError> {
    // implements the CLAUDE.md CA trust chain: proxy > global > webpki
    // CA exclusivity: custom CA present → empty + only that CA
}

pub struct BackendTlsConfigBuilder<'a> {
    proxy: &'a Proxy,
    policy: &'a TlsPolicy,
    global_ca: Option<&'a Path>,
    global_verify: bool,
}

impl<'a> BackendTlsConfigBuilder<'a> {
    pub fn build_rustls(&self, crls: &[CertificateRevocationListDer]) -> Result<rustls::ClientConfig, TlsError>;
    pub fn build_reqwest(&self) -> Result<reqwest::ClientBuilder, TlsError>;
}
```

The rustls path centralizes: root-store construction (CA trust chain), `WebPkiServerVerifier` with CRLs, client mTLS cert/key loading, policy application, `Arc::new`.

**Patterns:** Factory Method, Extract Method (CA trust chain → one helper).

**Migration:** grpc_proxy first (smallest), then http2_pool, then tcp_proxy. Existing TLS tests (`tests/unit/gateway_core/tls_tests.rs`) must pass. Add a new test that calls the builder on a fixture proxy and asserts CA exclusivity + CRL application.

**Success criteria:** the 5 independent CA-trust-chain sites collapse to one. Adding a 9th backend path (e.g., future WebTransport) is a one-liner `BackendTlsConfigBuilder::build_rustls()` call instead of a copy-paste checklist in CLAUDE.md.

---

### Phase 5 — Connection Pool `PoolManager` Trait (P1, 2 weeks)

**Targets:** `src/connection_pool.rs` (632 LOC reqwest), `src/proxy/http2_pool.rs` (1,047), `src/http3/client.rs` (1,563), gRPC pool embedded in `src/proxy/grpc_proxy.rs` (~400).

**Design:**

```rust
// src/pool/mod.rs
pub trait PoolManager: Send + Sync + 'static {
    type Connection: Send + Sync + Clone + 'static;
    type Key: Eq + Hash + Clone + Send + Sync + 'static;

    fn build_key(&self, proxy: &Proxy, host: &str, port: u16, shard: usize) -> Self::Key;
    async fn create(&self, key: &Self::Key, proxy: &Proxy) -> Result<Self::Connection, PoolError>;
    fn is_healthy(&self, conn: &Self::Connection) -> bool;
    fn destroy(&self, conn: Self::Connection);
}

pub struct GenericPool<M: PoolManager> {
    manager: Arc<M>,
    entries: Arc<DashMap<M::Key, PoolEntry<M::Connection>>>,
    cfg: Arc<PoolConfig>,
    dns: Arc<DnsCache>,
}

impl<M: PoolManager> GenericPool<M> {
    pub async fn get(&self, proxy: &Proxy, target: &Target) -> Result<M::Connection, PoolError>;
    fn spawn_cleanup_loop(self: Arc<Self>);
    // shared: idle eviction, cleanup interval, cache hit fast path, metrics
}
```

Each protocol then has ~100 LOC of `impl PoolManager` instead of ~500 LOC of scaffolding.

**Hot-path correctness gate:** the zero-allocation thread-local pool-key buffer documented in CLAUDE.md ("Thread-local pool key buffers") MUST be preserved. The `build_key` signature writes into `&mut String` rather than returning a fresh `String`, and `GenericPool::get` uses the same `thread_local!` pattern.

**Benchmark gate:** `tests/performance/multi_protocol/` must show ≤2% P99 regression and ≥98% RPS retention. If not, revert — the pool is the hottest of the hot paths.

**Patterns:** Strategy (`PoolManager`), Template Method (`GenericPool::get` shell), Extract Method (cleanup loop, key formatting).

---

### Phase 6 — Error Classifier Consolidation (P1, 3 days)

**Targets:** `classify_reqwest_error` (retry.rs:225), `classify_grpc_proxy_error` (retry.rs:112), `classify_boxed_error` (retry.rs:148), `classify_h3_error` (proxy/mod.rs:8549), `classify_http2_pool_error`, `classify_http3_error`.

**Design:** one `classify_error(err: &(dyn Error + 'static)) -> ErrorClass` that walks the source chain once, does typed `downcast_ref` for `io::Error`, `hyper::Error`, `reqwest::Error`, `quinn::ConnectionError`, `h2::Error`, then falls back to string-pattern matching. Port-exhaustion detection lives here too.

**Patterns:** Substitute Algorithm (one classifier replaces six), Extract Method.

**Success criteria:** the 6 classifiers collapse to one. Existing callers adapt via thin wrappers that `Box<dyn Error>` the protocol-specific error and call the shared function. All existing error-classification tests pass.

---

### Phase 7 — Streaming Body Trait (P1, 1 week)

**Targets:** `CoalescingBody`, `CoalescingH2Body`, `CoalescingH3Body`, `DirectStreamBody`, `DirectH2Body`, `DirectH3Body` in `src/proxy/body.rs`.

**Design:**

```rust
trait FrameSource {
    type Error: Into<BoxError>;
    fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>>;
}

// impl FrameSource for reqwest stream, hyper Incoming, h3 RequestStream (wrapped async adapter)

pub struct Coalescing<S: FrameSource> {
    inner: S,
    target_bytes: usize,
    // buffer, stashed_error, stashed_trailer, done state
}

impl<S: FrameSource> Body for Coalescing<S> { ... }
```

H3's async `recv_data()` is wrapped in an adapter that implements `FrameSource` via an internal state machine.

**Patterns:** Strategy (`FrameSource` chooses the backend), Decorator (coalescing wraps any source), Generic trait abstraction.

**Trailer safety:** MUST keep CLAUDE.md's documented invariant — "non-data frames (TRAILERS) are stashed while buffered data is flushed first". A regression test asserting this for each transport should ship with this phase.

**Success criteria:** body.rs drops from ~1,500 → ~1,100 LOC. gRPC and H3 performance numbers are equal-or-better than before.

---

### Phase 8 — Rate-Limiter Algorithm Strategy (P1, 1 week)

**Targets:** `rate_limiting.rs`, `ai_rate_limiter.rs`, `ws_rate_limiting.rs`, `udp_rate_limiting.rs` (2,129 LOC).

**Design:**

```rust
// src/plugins/utils/rate_limit.rs
pub trait RateLimitAlgorithm: Send + Sync {
    fn check(&self, key: &str, weight: u64) -> RateLimitDecision;
    fn remaining(&self, key: &str) -> u64;
}

pub struct TokenBucket { ... }
pub struct SlidingWindow { ... }
pub struct FixedWindow { ... }  // already exists in redis_rate_limiter.rs

pub struct LocalLimiter<A: RateLimitAlgorithm> { ... }  // DashMap-backed
pub struct RedisLimiter<A: RateLimitAlgorithm> { ... }  // RedisRateLimitClient-backed
pub struct FailoverLimiter { local: LocalLimiter, redis: RedisLimiter }  // CLAUDE.md "resilience: if Redis goes down, fall back"
```

The four plugins pick their algorithm + backend via config; the plugin-specific code is ~50 LOC of config parsing + `FailoverLimiter::new`.

**Patterns:** Strategy (algorithm), Decorator (failover wraps Redis), Factory (`FailoverLimiter::from_plugin_config`).

**Success criteria:** TokenBucket defined once (currently in 3 places). Redis namespace-prefix rule from CLAUDE.md stays centralized in `RedisLimiter::new`.

---

### Phase 9 — Env-Config Declarative Macro (P2, 3 days)

**Target:** `src/config/env_config.rs` (2,226 LOC, ~114 `resolve_var*` sites).

**Design:**

```rust
env_config! {
    [admin]
    http_port: u16     = "FERRUM_ADMIN_HTTP_PORT"     => 9000;
    https_port: u16    = "FERRUM_ADMIN_HTTPS_PORT"    => 9443;
    jwt_secret: String = "FERRUM_ADMIN_JWT_SECRET"    => required_for(["database", "cp"]) min_len(32);
    jwt_max_ttl: u64   = "FERRUM_ADMIN_JWT_MAX_TTL"   => 3600;

    [tls]
    no_verify: bool    = "FERRUM_TLS_NO_VERIFY"       => false;
    ca_bundle: Option<PathBuf> = "FERRUM_TLS_CA_BUNDLE_PATH";
    ...
}
```

Macro generates: struct definition, `from_env() -> EnvConfig`, `reserved_gateway_ports()` stays hand-written because it's non-mechanical.

**Patterns:** Declarative macro (compile-time code gen), Extract Method for repeated `resolve_var_or(...).parse().unwrap_or()`.

**Risk:** macros can fight rust-analyzer. Acceptable trade-off given the 500 LOC saved.

**Success criteria:** `env_config.rs` drops by ~500 LOC. Adding a new env var is one line in the macro invocation + one line in `ferrum.conf`.

---

### Phase 10 — Plugin Registry (replace giant match) (P2, 3 days)

**Target:** `src/plugins/mod.rs:1393-1565` — 170-line match in `create_plugin_with_http_client()`.

**Design:**

```rust
pub struct PluginRegistry {
    factories: HashMap<&'static str, PluginFactory>,
}
type PluginFactory = Box<dyn Fn(&Value, PluginHttpClient) -> Result<Arc<dyn Plugin>, String> + Send + Sync>;

inventory::submit! { PluginEntry { name: "rate_limiting", factory: |c, h| Ok(Arc::new(RateLimiting::new(c, h)?)) } }
// ... one per plugin
```

Uses the `inventory` crate (already common in Rust CLI tools) for compile-time plugin self-registration. Each plugin file adds ONE `inventory::submit!` line; adding a new plugin no longer requires editing `mod.rs`.

**Patterns:** Factory Method + Registry + self-registration via linker.

**Success criteria:** `mod.rs` giant match drops to ~30 LOC (just the registry lookup). Custom plugins discovered by `build.rs` use the same registry mechanism.

---

### Phase 11 — Secondary / Smaller Wins (P2–P3, 1–2 weeks cumulative)

Each of these is small; they can be batched or scattered across sprints:

1. **Extract `collect_response_headers_generic<I: IntoIterator<Item=(HeaderName, HeaderValue)>>`** (`proxy/mod.rs:7729` + 7766). Shared hop-by-hop stripping. **~60 LOC, 2 hours.**
2. **`build_root_cert_store()`** shared helper (`src/tls/mod.rs`). Hardens CA trust chain at source, not in CLAUDE.md prose. **~120 LOC net, 1 day.**
3. **`SizeLimiter` trait** unifying `request_size_limiting` / `response_size_limiting` / `ws_message_size_limiting`. **~150 LOC, 2 days.**
4. **Secret backend registry** (`SecretBackend` trait + `SecretResolver` with suffix → backend map). Vault/AWS/Azure/GCP/file/env each implement one trait. **~150 LOC, 3 days.**
5. **Shared AI provider detection** (`src/plugins/utils/ai_providers.rs`): token extraction, model detection, OpenAI/Anthropic/Gemini/Bedrock format parsing. Used by ai_token_metrics, ai_rate_limiter, ai_semantic_cache. **~200 LOC, 3 days.**
6. **SQL dialect builder** (`SqlBuilder` with Postgres/MySQL/SQLite targets) — extracts the MySQL-vs-Postgres-vs-SQLite branching in `migrations/v001_initial_schema.rs`. **~200 LOC, 3 days.** P3 because it's small and SQL changes rarely.
7. **Validation pipeline / builder** (`ValidationPipeline::new(config).strict(true).validate()`) — consolidates the 3 entry-point sequences in `file_loader.rs` / `admin/mod.rs` / `db_loader.rs`. **~400 LOC, 3 days.**

---

## 4. Cross-Cutting Rules

### Performance Non-Regression Gates

Every phase that touches the hot path (Phase 5 pools, Phase 6 classifiers, Phase 7 body adapters) MUST:

1. Run `tests/performance/multi_protocol/run_protocol_test.sh all --duration 30 --concurrency 200` before and after.
2. Report per-protocol RPS and P99. Regression tolerance: ≤2% RPS drop, ≤5% P99 increase.
3. Preserve CLAUDE.md's hot-path invariants explicitly named in comments: lock-free hot path (`ArcSwap::load()` / `DashMap`), zero-allocation hot path (thread-local pool-key buffers, `Arc<UpstreamTarget>`), pre-computed indexes (RouterCache / PluginCache / ConsumerIndex).

### Correctness Non-Regression Gates

Every phase MUST:

1. Pass `cargo fmt --all --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`, `cargo test -- --ignored`.
2. Preserve all behavior documented as an invariant in CLAUDE.md. A grep of CLAUDE.md for "MUST NOT", "MUST", "never", "always" yields the checklist; each phase's PR description lists which invariants were touched and how they were preserved.
3. Not introduce `.unwrap()` / `.expect()` in production paths (CLAUDE.md code-quality rule).
4. Leave backwards-compatible public API (plugin trait, admin REST endpoints, env var names, config schema) unchanged unless explicitly called out.

### Migration Cadence

- 1 PR per phase, except Phase 1 (admin CRUD) and Phase 5 (pools) which should split into 3–4 PRs (one per resource / protocol).
- Each PR merges green CI and ships to `main` before the next PR in the sequence opens.
- The `cargo fmt` + clippy + unit + integration + E2E + perf gate from CLAUDE.md "Before every commit" and "PR Checklist" is non-negotiable.

### Risk Management

| Risk | Mitigation |
|------|-----------|
| Hot-path regression | Perf gate on every pool/body/classifier phase; revert if ≥2% drop. |
| Plugin API breakage | Plugin trait untouched; all refactors are internal consolidation. Custom plugins keep working. |
| Behavior drift in admin API | Every admin handler has functional test coverage. OpenAPI spec unchanged. |
| Test harness consolidation breaks CI | Phase 0 ships *additive* only; old harnesses coexist until every caller is migrated. |
| Macro debugging (Phase 9) | Keep a non-macro escape hatch for the 5–10 env vars with non-mechanical semantics. |
| Generic / trait bounds complexity | Favor `dyn Trait` + `Arc` when lifetimes get hairy. Avoid HRTB pyramids. |

## 5. Success Metrics

Aggregate targets when all P0 + P1 phases land:

- **LOC:** `src/` non-test code drops by ~7,000 (~9%). `tests/functional/` drops by ~1,500.
- **File count:** no net change (we create ~10 new `utils/` files, remove duplication inside existing files).
- **`cargo clippy` warnings:** 0 (unchanged, CI-enforced).
- **Hot-path benchmarks:** ≥98% RPS retention, ≤5% P99 growth for every protocol.
- **"Checklist in prose" rules in CLAUDE.md** (like "When adding new protocol paths: Must follow the same CA trust chain") converted to typed APIs that make the wrong thing un-representable.
- **New-plugin onboarding time:** "add a logging plugin" drops from ~300 LOC across 1 file to ~50 LOC (the flush closure + config parsing).
- **New-admin-resource onboarding:** "add a 5th resource type" drops from ~700 LOC of CRUD handlers to ~80 LOC (one `impl AdminResource` block).

## 6. Out of Scope

- Changes to the public plugin `Plugin` trait shape (breaks custom plugins — ecosystem concern).
- Changes to the `ferrum.conf` / env var / admin REST / gRPC CP-DP protocol surfaces.
- Changes to database schema or MongoDB indexes.
- Rewriting `src/proxy/mod.rs` into protocol-specific modules. This is desirable long-term but is a separate multi-month effort; this plan only extracts the duplicated logic inside it.
- Any behavior-changing refactor, performance "enhancement", or new feature. DRY only.

## 7. Execution Order Summary

```
P0 (must ship first, ~6 weeks)
├── Phase 0: tests/common/ harness                          (1 wk)
├── Phase 1: Admin CRUD generic                              (1-2 wk)
├── Phase 2: Plugin logging BatchingLogger<T>                (2 wk)
└── Phase 3: Plugin auth AuthMechanism trait                 (2 wk)

P1 (ship after P0, ~5 weeks, 2 of these can parallelize)
├── Phase 4: BackendTlsConfigBuilder                         (1 wk)
├── Phase 5: PoolManager trait                               (2 wk)
├── Phase 6: Unified error classifier                        (3 d)
├── Phase 7: FrameSource + Coalescing<T>                     (1 wk)
└── Phase 8: RateLimitAlgorithm strategy                     (1 wk)

P2 (quality-of-life, ~2 weeks)
├── Phase 9:  env_config! macro                              (3 d)
├── Phase 10: plugin registry (inventory)                    (3 d)
└── Phase 11: smaller wins (7 items, batched)                (1-2 wk)

P3 (low-priority, ship as time allows)
└── SQL dialect builder, validation pipeline builder          (1 wk)
```

**Total calendar time with one senior engineer, perf-gated:** ~14 weeks.
**Total calendar time with three engineers parallelizing after Phase 0:** ~6 weeks.

---

**Appendix A — Deep-Dive Analysis Sources**

This plan was built from parallel exploration of five subsystems; raw findings (800–1,500 words each with file:line citations) are available in the conversation transcript that produced this document. Key citations:

- Plugin duplication: `src/plugins/{http,tcp,loki,udp,kafka}_logging.rs`, `src/plugins/{jwt,key,basic,hmac,ldap}_auth.rs`, `src/plugins/{rate_limiting,ai_rate_limiter,ws_rate_limiting}.rs`, `src/plugins/mod.rs:1393-1565`.
- Protocol duplication: `src/proxy/mod.rs:7729,7766,8549`, `src/proxy/body.rs:924-1500`, `src/retry.rs:112,148,225`, the 4 pool files.
- Config duplication: `src/admin/mod.rs:738-1013,1453-1613,2803-2905,3378-3763`, `src/config/env_config.rs:109-122` + 114 call sites, `src/secrets/*.rs` (6 files).
- TLS duplication: `src/connection_pool.rs:235-260`, `src/proxy/grpc_proxy.rs:571-600,614-662`, `src/proxy/http2_pool.rs:471-501,515-574`, `src/proxy/tcp_proxy.rs:295-354`, `src/tls/mod.rs:480-498,576-668`.
- Test duplication: `tests/functional/functional_admin_operations_test.rs` vs `tests/functional/functional_admin_observability_test.rs` (near-identical AdminTestHarness), 17 other harness copies.
