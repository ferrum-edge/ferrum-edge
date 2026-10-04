# CLI Reference

Ferrum Edge provides a command-line interface for running, validating, and managing the gateway. A subcommand is required.

## Making the Binary Available

The `ferrum-edge` binary must be on your shell's `PATH` to be invoked by name. After building or downloading:

```bash
# From source
sudo cp target/release/ferrum-edge /usr/local/bin/

# From a pre-built release download (Linux x86_64 example)
# Pin an immutable semver tag (vX.Y.Z from the Releases page). Do not rely on a moving
# "latest" channel: GitHub /releases/latest skips prerelease tags.
set -euo pipefail
TAG=v0.9.11  # release draft: use only after publication, or choose an existing release
BASE="https://github.com/ferrum-edge/ferrum-edge/releases/download/${TAG}"
curl -fsSLO "${BASE}/ferrum-edge-linux-x86_64"
curl -fsSLO "${BASE}/ferrum-edge-linux-x86_64.sha256"
sha256sum -c ferrum-edge-linux-x86_64.sha256
chmod +x ferrum-edge-linux-x86_64
sudo install -m 0755 ferrum-edge-linux-x86_64 /usr/local/bin/ferrum-edge

# Verify
ferrum-edge version
```

Published Linux GNU artifacts (`ferrum-edge-linux-x86_64`, `ferrum-cni-linux-x86_64`, and the ARM64 pair) are dynamically linked against glibc. The declared runtime floor is **GLIBC_2.34** (RHEL 9 / Rocky Linux 9 / AlmaLinux 9, which also covers Ubuntu 22.04 and Debian 12). The x86_64 GNU binaries are built in a digest-pinned **AlmaLinux 8.10** sysroot (glibc 2.28); ARM64 GNU artifacts come from the Cross build. Beyond glibc, the only other dynamic libraries are `libgcc_s.so.1` and, when the Kafka stack does not static-link zlib, `libz.so.1`. The release job ABI-scans and smoke-tests the exact bytes it publishes and fails on any artifact that needs a newer glibc, links other libraries, targets the wrong architecture, or embeds an RPATH/RUNPATH.

Alternative approaches:
- **Symlink**: `sudo ln -s /path/to/ferrum-edge /usr/local/bin/ferrum-edge`
- **Add to PATH**: `export PATH="/path/to/dir:$PATH"` (in `~/.bashrc` or `~/.zshrc`)
- **Docker**: The official images include `ferrum-edge` on PATH — use `docker exec <container> ferrum-edge version`

## Subcommands

| Command | Description |
|---------|-------------|
| `run` | Start the gateway in the foreground |
| `validate` | Validate configuration files without starting the gateway |
| `reload` | Send a reload signal (SIGHUP) to a running gateway instance (Unix only) |
| `health` | Check gateway health by connecting to the admin API `/health` endpoint |
| `version` | Print version information |
| `ambient-udp-preflight` | One-shot Ambient UDP node preflight: retire predecessor placements and publish node-scoped cleanup proof |

## run

Start the gateway in the foreground. This is the primary command for both development and production use.

```
ferrum-edge run [OPTIONS]
```

### Options

| Flag | Short | Description |
|------|-------|-------------|
| `--settings <PATH>` | `-s` | Path to `ferrum.conf` (operational settings) |
| `--spec <PATH>` | `-c` | Path to resources YAML/JSON (proxies, consumers, upstreams, plugins) |
| `--mode <MODE>` | `-m` | Operating mode: `database`, `file`, `cp`, `dp`, `mesh`, `injector`, `node_agent`, `migrate` |
| `--fips-mode <MODE>` | | FIPS deployment mode: `off` (default) or `enforce`. Must be supplied via this flag or the environment — a value set only in `ferrum.conf` arrives after the crypto provider is installed and is refused. See [FIPS mode](fips.md) |
| `--verbose` | `-v` | Increase log verbosity (repeatable: `-v`=info, `-vv`=debug, `-vvv`=trace) |

### Examples

```bash
# Zero-config start (uses ./ferrum.conf and ./resources.yaml if present)
ferrum-edge run

# Explicit settings and spec paths
ferrum-edge run --settings /etc/ferrum/ferrum.conf --spec /etc/ferrum/resources.yaml

# Short flags
ferrum-edge run -s ferrum.conf -c resources.yaml

# Override mode and enable debug logging
ferrum-edge run --spec resources.yaml --mode file -vv

# Database mode with verbose logging
ferrum-edge run --settings ferrum.conf --mode database -v
```

### Mode Inference

`--spec` / `-c` sets only the resources path (`FERRUM_FILE_CONFIG_PATH`). It does **not** set or override the operating mode.

File mode is inferred as a smart default — the lowest-precedence mode source — only when a spec path is available (explicit `--spec`, process-environment `FERRUM_FILE_CONFIG_PATH`, or smart path discovery) **and** no mode is configured by any higher-precedence source:

1. CLI `--mode` (`run` / `validate`)
2. Process environment `FERRUM_MODE` (including values materialized from `FERRUM_MODE_FILE` / `_VAULT` / `_AWS` / `_AZURE` / `_GCP`)
3. `FERRUM_MODE` in the selected `ferrum.conf`

So `ferrum-edge run --settings ferrum.conf --spec resources.yaml` with `FERRUM_MODE=database` (or `cp`, etc.) in that settings file stays in that mode: the spec path is installed at CLI precedence, but mode inference never promotes the smart default over the conf file. The same rule applies to `validate`. When no mode is configured anywhere, `ferrum-edge run --spec resources.yaml` still infers file mode so a zero-config file-mode start works.

## validate

Parse and validate configuration files without starting the gateway. Exits with code 0 on success, **1** on failure (the same code used for settings, spec, FIPS, startup-security, and empty-namespace-filter failures). Useful for CI/CD pre-deploy checks. There is no `--format json` report; the human summary is stdout.

```
ferrum-edge validate [OPTIONS]
```

### Options

| Flag | Short | Description |
|------|-------|-------------|
| `--settings <PATH>` | `-s` | Path to `ferrum.conf` (operational settings) |
| `--spec <PATH>` | `-c` | Path to resources YAML/JSON, or a localized `{version?, mesh}` mesh slice when `-m mesh` selects file-protocol validation |
| `--mode <MODE>` | `-m` | Operating mode: `database`, `file`, `cp`, `dp`, `mesh`, `injector`, `node_agent`, `migrate` |
| `--fips-mode <MODE>` | | FIPS deployment mode: `off` (default) or `enforce`. Must be supplied via this flag or the environment — a value set only in `ferrum.conf` arrives after the crypto provider is installed and is refused. See [FIPS mode](fips.md) |
| `--verbose` | `-v` | Increase log verbosity (repeatable: `-v`=info, `-vv`=debug, `-vvv`=trace) |
| `--allow-empty-namespace` | | Accept a file-mode or mesh file-protocol document that contains namespaced resources but none survive `FERRUM_NAMESPACE` filtering. Without this flag that case is a validation failure (exit 1). Runtime (`run`) is unchanged. |

### What is validated

0. **External secrets** — before settings are parsed, `validate` resolves the `_FILE`, `_VAULT`, `_AWS`, `_AZURE`, and `_GCP` suffixes into their base `FERRUM_*` variables exactly as `run` does, so validation sees the same configuration the gateway would start with. Details are under [External secret resolution](#external-secret-resolution) below. When at least one source resolves, `validate` prints an `External secrets: OK` block on stdout **unconditionally** — it is part of the validate report, like `Settings (ferrum.conf): OK`, and is not gated on `FERRUM_LOG_LEVEL`/`RUST_LOG` or on `-v/--verbose`. The block lists only the resolved base variable and provider names, sorted by base variable name, never source references (file paths, Vault paths, cloud resource IDs) or secret values:

```text
External secrets: OK
  Loaded FERRUM_ADMIN_JWT_SECRET from file
  Resolved 1 env var(s) from external secret sources
Settings (ferrum.conf): OK
  Mode: Database
  Namespace: ferrum

Validation passed.
```

`run` reports the same non-secret facts as structured `info!` records instead, so serving modes keep normal log-level semantics.

1. **Settings** (`ferrum.conf`) — all 300+ environment variables are parsed and validated (ports, paths, TLS configuration, pool sizes, etc.)
2. **Spec** (resources YAML/JSON, file mode only):
   - YAML/JSON syntax and deserialization
   - Field-level validation on all proxies, consumers, upstreams, and plugin configs
   - Regex `listen_path` compilation
   - Unique `listen_path` enforcement
   - Stream proxy port conflict detection against gateway reserved ports
   - Plugin config validation (each plugin is instantiated to verify its config)
   - Shared runtime admission, including plugin security composition (such as duplicate effective `correlation_id` headers) and `tcp_connection_throttle` attachment compatibility
   - TLS certificate path existence checks
   - Upstream reference validation
   - Namespace filter summary: the active `FERRUM_NAMESPACE` (default `ferrum`) and post-filter resource counts. When the document contains at least one namespaced resource and zero resources survive namespace filtering, `validate` fails closed with **exit code 1** and a diagnostic naming the active namespace, the namespaces present in the document, and the counts. `--allow-empty-namespace` downgrades that case to a warning and exit 0. An empty document (no namespaced resources) is not a mismatch. Filtering itself is unchanged.
3. **Startup security** (env-level TLS/CIDR/metrics surfaces shared with `run`) — side-effect-free loaders that `serve()` also uses, so `validate` cannot report success for configs that refuse to start. Mode-scoped:
   - TLS policy (`TlsPolicy::from_env_config`) and CRLs (`FERRUM_TLS_CRL_FILE_PATH`) for file/database/cp/dp/mesh, and for `node_agent` when admin HTTPS security intent applies (complete HTTPS that would bind, or explicit nonzero HTTPS intent)
   - Strict `FERRUM_ADMIN_ALLOWED_CIDRS` and `FERRUM_METRICS_ALLOWED_CIDRS` / metrics bearer policy; node-agent validates these when any admin surface is active (plaintext HTTP or complete HTTPS), matching `run`
   - Frontend TLS material (missing, mismatched, expired, or malformed cert/key) when both `FERRUM_FRONTEND_TLS_CERT_PATH` and `FERRUM_FRONTEND_TLS_KEY_PATH` are set (file/database/dp; mesh validates an explicit frontend pair via the same identity loader `run` uses). Mesh also loads a configured `FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH` when the topology has an inbound TLS-terminating listener under the no-slice PERMISSIVE baseline (same byte loader as mesh `run`'s inbound TLS snapshot); missing/unreadable material fails closed. PEM/expiry parsing runs only when a mesh server identity is also configured (explicit frontend cert/key, gateway SVID file cert/key, or a non-`none` `FERRUM_MESH_CA_BACKEND`), as in `run`. Passthrough-only topologies such as `east_west_gateway`, and fully DISABLE mTLS modes, skip an unused client CA. Because `validate` cannot fetch the applied PeerAuthentication slice, it may validate a configured CA that a later all-DISABLE slice would leave unused.
   - Admin TLS material when admin HTTPS is enabled (`FERRUM_ADMIN_HTTPS_PORT != 0` and both admin cert/key paths are set). For `node_agent`, explicit nonzero HTTPS intent fails closed even when cert/key are missing; the inherited inactive default HTTPS port without TLS intent stays HTTP-only compatible.
   - DTLS frontend cert (+ optional client CA) expiry when both `FERRUM_DTLS_CERT_PATH` and `FERRUM_DTLS_KEY_PATH` are set (file/database/dp)
   - Does **not** bind sockets, spawn servers, mutate stores, mint random JWT secrets, or connect to a database/CP
4. **Mesh runtime** (mesh mode) — the same `MeshRuntimeConfig` admission `run` uses (protocol, stock xDS transport posture, topology). When the protocol is `file`, or is inferred from a localized `{version?, mesh}` document, Ferrum CP URLs and CP/DP JWT credentials are **not** required. `-c/--spec` supplies the local policy document for `file` and `stock_xds` validation and does not require a duplicate `FERRUM_MESH_FILE_CONFIG_PATH`; stock xDS uses its stricter policy-only loader and rejects documents that declare control-plane-owned services or workloads. Inference is shape-aware only: a document whose top-level keys are an optional `version` plus a `mesh` mapping may select file validation; a gateway resources document does not. Format is still extension-based (no content sniffing), and the document is loaded through the same bounded file reader and `deny_unknown_fields` parser as startup. Explicit `native`/`xds` plus a localized slice spec, or distinct `--spec` and `FERRUM_MESH_FILE_CONFIG_PATH` values, fail closed with a fixed diagnostic. Identity/CA environment is still required — this does not weaken workload identity or production guardrails. File-protocol validation prints the active namespace and post-filter workload / service / policy counts. When the localized document contains at least one namespaced resource and zero resources survive `FERRUM_NAMESPACE` scoping, `validate` fails closed with **exit code 1** unless `--allow-empty-namespace` is set. An empty `mesh: {}` document is not a mismatch. This check is validate-only; `run` is unchanged.

5. **Injector runtime** — the same runtime parser and serving TLS loader as `run`: TLS cert/key pairing and material, plaintext opt-in, trust domain, capture settings, CIDRs, JWT secret references, and container resource quantities. No webhook listener is bound.
6. **Node-agent runtime** — the same `NodeAgentConfig` parser as `run`, including the required node name and capture/fallback contract. No kernel probe, eBPF load, capture installation, or node-agent listener is started.
7. **Config migration input** (`migrate` mode with `FERRUM_MIGRATE_ACTION=config`) — the same bounded file reader, syntax parser, and required version detection as startup. Validation does not migrate the file or create a backup. Database migration actions (`up`/`status`) validate settings only; they do not connect to a database or inspect/apply its schema.

### External secret resolution

`run` and `validate` share these rules:

- **Empty values** — an empty suffixed variable is treated as unset in every build.
- **`_FILE` sources** — must resolve to a **regular file** (symlinks are followed and the opened target is type-checked, so Kubernetes projected secrets work) holding at most **64 KiB** of valid UTF-8 that is non-empty after trailing-whitespace trimming. A FIFO, socket, device, or directory is refused before any read. Failures name the suffixed variable and the failure class — `not a regular file`, `credential file exceeds the maximum of 65536 bytes`, `content is not valid UTF-8` — never the path. An absent file reports `Failed to read FERRUM_X_FILE: credential path not found`. A read on a stalled mount is abandoned after `FERRUM_SECRET_FETCH_TIMEOUT_SECONDS` instead of hanging.
- **Build-time providers** — `_FILE` works in every build; `_VAULT`, `_AWS`, `_AZURE`, and `_GCP` require the matching Cargo feature (`secrets-vault`, `secrets-aws`, `secrets-azure`, `secrets-gcp`, or the `cloud-secrets` umbrella). The default feature set compiles none of them, so on a default binary a non-empty cloud suffix fails the command with an unsupported-suffix error rather than being silently ignored. No setting can enable a provider that was not compiled in; the published Docker images build with `cloud-secrets`.
- **Conflicts** — an unreadable or unreachable non-empty source fails the command, and a base variable plus a non-empty suffixed source for the same key is a conflict (`Multiple secret sources configured for <NAME>`). Conflict detection is environment-only: the resolver runs before `ferrum.conf` is parsed, so a base variable set in the settings file is not a competing source — the suffixed source is materialized into the environment and silently wins under the normal env-over-`ferrum.conf` precedence. Keep secret base variables and their suffixed sources in the same layer.
- **Environment-only resolver settings** — because the resolver never reads `ferrum.conf`, `FERRUM_SECRET_FETCH_TIMEOUT_SECONDS` and `FERRUM_GCP_SECRET_MANAGER_ENDPOINT` are read from the environment only at this stage (see [configuration.md](configuration.md)). This is also why `FERRUM_CONF_PATH_FILE` is materialized into `FERRUM_CONF_PATH` *before* the settings file is opened.
- **Smart path discovery yields to a suffixed source** — when `FERRUM_CONF_PATH_FILE` (or its `_VAULT`/`_AWS`/`_AZURE`/`_GCP` equivalent) is set, `./ferrum.conf`, `./config/ferrum.conf`, and `/etc/ferrum/ferrum.conf` are **not** auto-discovered; the same holds for `FERRUM_FILE_CONFIG_PATH_FILE` and the `./resources.yaml` family. An **explicit** `-s/--settings` or `-c/--spec` path plus a suffixed source is still reported as a conflict.
- **Non-Unicode environment** — unrelated variables whose name or value is not valid UTF-8 are skipped. Three cases fail closed because ignoring them could silently drop configuration: a `FERRUM_*` variable whose **name** is not valid Unicode, a suffixed **source** variable whose value is not valid Unicode, and a direct `FERRUM_*` variable whose **value** is not valid Unicode (it would otherwise read as unset and be replaced by a `ferrum.conf` entry or default). They report `Environment variable <NAME> is not valid Unicode` (the last adds `Ferrum configuration values must be valid Unicode; fix or unset the variable.`), with the name reduced to its ASCII skeleton (`?` for every other byte). **Conflict takes precedence**: if a suffixed source competes with a non-Unicode direct value, the `Multiple secret sources` diagnostic is reported instead; unsupported-suffix and invalid-source-name failures are checked earlier still. Either way the command fails.
- **NUL bytes** — a resolved value containing a NUL byte cannot be placed in the environment and fails with `Secret resolved for FERRUM_X from file contains a NUL byte and cannot be placed in the process environment.`
- **Mode and spec from secrets** — a `FERRUM_MODE_FILE`/`_VAULT`/`_AWS`/`_AZURE`/`_GCP` source ranks with the environment for [mode inference](#mode-inference), and a spec path supplied by a suffixed source still infers file mode. Externalizing both together is supported.

Resource discovery runs after external secret resolution and settings loading. A `FERRUM_FILE_CONFIG_PATH` in the selected `ferrum.conf` suppresses resource discovery, and `--spec` overrides the environment and settings file. A bare `ferrum-edge` invocation prints usage and exits nonzero; use `run`.

**Externally sourced values are never printed.** Failure diagnostics name the base variable, the provider, and the reason, but not the source reference, even when a provider SDK echoes it (a one- or two-byte reference that cannot be removed safely causes the provider detail to be replaced with a fixed key-level failure). After materialization, externally sourced values are withheld from later settings and spec diagnostics, from warnings emitted during parsing (matched verbatim, trimmed, per list entry, case-normalized, and JSON-escaped), and from `validate` report fields. For example, a malformed `FERRUM_DB_PORT_FILE` reports `Invalid FERRUM_DB_PORT value <redacted: value from external secret source>. Expected a valid u16 integer`, and `FERRUM_MODE_FILE` containing `database` prints `Mode: <redacted: value from external secret source>` (`run` withholds its `Operating mode:` log line the same way). The overall result, including `Validation passed.` and spec counts, is unaffected. Rejection and startup diagnostics also withhold directly supplied scalar values, keeping field names, failure reasons, allowed bounds, and recovery guidance.

### Examples

```bash
# Validate a spec file
ferrum-edge validate --spec resources.yaml

# Validate with explicit settings
ferrum-edge validate --settings /etc/ferrum/ferrum.conf --spec /etc/ferrum/resources.yaml

# Validate a specific mode without mutating the shell environment
ferrum-edge validate -m file -c resources.yaml

# Validate a localized mesh slice without Ferrum CP URLs or JWT
ferrum-edge validate -m mesh -c slice.yaml

# Accept a multi-namespace document that filters to zero in this namespace
ferrum-edge validate -m file -c resources.yaml --allow-empty-namespace

# Use in CI/CD pipeline
ferrum-edge validate --spec resources.yaml || exit 1
```

### Sample Output

```
Settings (ferrum.conf): OK
  Mode: File
  Namespace: ferrum
Spec (/etc/ferrum/resources.yaml): OK
  Proxies: 12
  Consumers: 5
  Upstreams: 3
  Plugin configs: 18
Startup security (env TLS/CIDRs/metrics): OK

Validation passed.
```

Mesh file-protocol validation adds post-filter slice counts:

```
Settings (ferrum.conf): OK
  Mode: Mesh
  Namespace: ferrum
Mesh spec (/etc/ferrum/slice.yaml): OK
  Workloads: 1
  Services: 1
  Policies: 0
Startup security (env TLS/CIDRs/metrics): OK
Mesh runtime: OK

Validation passed.
```

On failure:

```
Settings (ferrum.conf): OK
  Mode: File
  Namespace: ferrum
Error: Spec validation failed: Configuration file not found: /nonexistent.yaml
```

A namespace-filter mismatch (document resources in `ferrum`, `FERRUM_NAMESPACE=other-ns`) looks like:

```
Settings (ferrum.conf): OK
  Mode: File
  Namespace: other-ns
Spec (/etc/ferrum/resources.yaml): OK
  Proxies: 0
  Consumers: 0
  Upstreams: 0
  Plugin configs: 0
Error: namespace filter mismatch: active namespace 'other-ns' left 0 surviving resources (proxies=0, consumers=0, upstreams=0, plugin_configs=0); document namespaces: ferrum. Set FERRUM_NAMESPACE to a namespace present in the document, or pass --allow-empty-namespace to accept an empty filtered document.
```

That failure uses **exit code 1**, the same code as other validation failures.

A startup-security failure (for example an expired frontend cert) looks like:

```
Settings (ferrum.conf): OK
  Mode: File
  Namespace: ferrum
Spec (/etc/ferrum/resources.yaml): OK
  Proxies: 0
  Consumers: 0
  Upstreams: 0
  Plugin configs: 0
Error: Startup security validation failed: Invalid TLS configuration: ...
```

### Diagnostic redaction

Startup and validation failures include the full cause chain, from the outer
operation to the underlying failure, without needing `-v`. They keep field
paths, line/column positions, expected types, missing/unknown/duplicate field
names, failure reasons, and allowed bounds, but withhold the configuration
**values** that caused them:

- Document scalars (including inline PEM and tokens) are removed when a
  deserialization error is captured. Paths and unknown-field messages still
  echo document **keys**; they are diagnostic context, not confidential value
  storage.
- When rendered, **each original cause** in both `run` and `validate` passes
  through the configured-URL and registered-secret scrubbers, then a
  quoted-span sanitizer: every double- or single-quoted span is withheld
  (through the end of that cause if unterminated); backticks remain. If
  credential scrubbing changes quote or escape syntax, that cause is withheld
  in full as `<redacted diagnostic>`.
- Credentials in the exact configured primary/replica/failover database URLs,
  and registered resolved external-secret values and their bounded derived
  forms, are redacted. The URL inventory reads raw settings only (it never
  fetches database TLS sources), so this final renderer is not a general
  secret detector.
- Rejected CIDRs, capture settings, annotation overrides, and localized mesh,
  stock-xDS, gateway migration, and backup `version` values are withheld;
  use the field path to locate the value. Backup, validation-pipeline, SQL/Mongo
  rejection, unknown-plugin, and capture-warning log records use the same
  sanitizer.

Database-mode `validate` checks a configured JSON backup through the same
loader without a database dial.

Contributor convention: validators must use backticks for schema names and
Debug-escaped double quotes (`{value:?}` for strings) for document values, or
omit the values. Interpolating a document scalar bare is a defect.

For example, `run -m mesh` with a localized mesh file missing a workload
selector reports the file-loading context followed by
`invalid mesh configuration document: mesh.workloads[0]`, the missing `selector`
field, and `at line 3 column 7`.
`validate -m mesh` reports the same field and position under its validation
context. The diagnostic includes neither the configuration document nor a
backtrace; `-v` is not required to see the causes and still selects log verbosity.

## reload

Send SIGHUP to a running gateway instance. Only supported on Unix platforms (Linux, macOS, BSDs).

SIGHUP triggers a hot config reload **in file mode**, and in mesh mode when the config source is a local file or xDS consumer. In every other mode (`database`, `cp`, `dp`, `injector`, `node_agent`, `migrate`, and mesh with native `MeshSubscribe`) the gateway logs the signal and ignores it; use database polling (`FERRUM_DB_POLL_INTERVAL`), control-plane push, or a rolling restart instead. The CLI cannot tell which mode the target runs in, so `reload` exits `0` whenever the signal is delivered and prints a second line describing this scope.

In file mode, SIGHUP re-reads the spec under the same fail-closed stability contract as startup (byte-identical consecutive probes; rejects non-atomic/torn updates), then atomically swaps a valid candidate without dropping connections. An unstable or invalid candidate keeps the last known-good live generation and marks authenticated `/health` as `degraded` with `config_rejected: true` until a later successful (Applied or Unchanged) reload clears it.

```
ferrum-edge reload [OPTIONS]
```

### Options

| Flag | Short | Description |
|------|-------|-------------|
| `--pid <PID>` | `-p` | PID of the running gateway. Auto-detected via `pgrep` if omitted |

### Examples

```bash
# Auto-detect PID and reload
ferrum-edge reload

# Explicit PID
ferrum-edge reload --pid 42195
```

### PID Auto-Detection

When `--pid` is omitted, the CLI uses `pgrep -x ferrum-edge` to find running processes, then excludes its own PID before selecting a target. A single other `ferrum-edge` process is reloaded automatically. If none remain after excluding self, it reports that no gateway was found. If multiple other instances remain, it reports their PIDs and asks you to specify one with `--pid`. Explicit `--pid` bypasses auto-detection entirely. There is no PID file.

`--pid 0` is rejected before signalling: POSIX `kill` would treat `0` as this process group, not a gateway. The CLI also refuses to signal its own PID. Other explicit PIDs are passed to `kill(SIGHUP)` without a prior identity probe (PID reuse would make that check racy).

## health

Check gateway health by connecting to the admin API. By default it probes readiness via `GET /health` (returns 503 until the gateway is ready). With `--live` it probes liveness via `GET /live`, which returns 200 whenever the process and admin listener are up — even during startup or while serving degraded. Designed for use as a Docker `HEALTHCHECK` or Kubernetes exec probe in distroless containers (no shell or curl needed).

Point a Kubernetes **livenessProbe** at `ferrum-edge health --live` and the **readinessProbe** at `ferrum-edge health`. Using `/health` for liveness would restart-loop an alive-but-unready pod (e.g. a `dp` that has lost its `cp`), whereas readiness only drops it from Service endpoints.

```
ferrum-edge health [OPTIONS]
```

### Options

| Flag | Short | Description |
|------|-------|-------------|
| `--settings <PATH>` | `-s` | Operational settings file for inferred host and ports (same path discovery as `run`) |
| `--port <PORT>` | `-p` | Admin API port (defaults to `FERRUM_ADMIN_HTTP_PORT` / 9000, or `FERRUM_ADMIN_HTTPS_PORT` / 9443 when TLS is used) |
| `--host <HOST>` | | Admin API host (default: effective `FERRUM_ADMIN_BIND_ADDRESS`) |
| `--tls` | | Connect via HTTPS instead of HTTP |
| `--tls-no-verify` | | Skip TLS certificate verification (for self-signed certs / testing) |
| `--live` | | Probe liveness (`GET /live`) instead of readiness (`GET /health`) |

### Auto-Detection

Health resolves the admin host and ports from environment variables (including
external secret suffixes), then the selected `ferrum.conf`, then defaults. Use
`--settings` for the same custom settings path passed to `run`, or
`FERRUM_CONF_PATH` (which also supports external suffixes); otherwise normal
settings discovery applies. Invalid endpoint settings fail the probe.

`--host` overrides the host; `--port` overrides the port and selects plaintext
unless `--tls` is given. Supplying both bypasses settings inference entirely.
With only `--port`, host inference still applies. IPv4 wildcard `0.0.0.0` probes
`127.0.0.1`; IPv6 wildcard `::` probes `::1`. Specific addresses are preserved.

The probe fetches only the settings path and endpoint fields it needs, through
the same provider/conflict checks as startup. It does not fetch unrelated
secrets, load server TLS private keys, or mutate the environment. Server TLS
verification remains enabled unless `--tls-no-verify` is explicitly supplied.
An explicitly selected port `0` fails as disabled.

When `FERRUM_ADMIN_HTTP_PORT=0` in either environment or settings (plaintext admin disabled), the health command automatically switches to TLS mode and uses port 9443 (or the value of `FERRUM_ADMIN_HTTPS_PORT`). No `--tls` flag is needed in this case.

### Examples

```bash
# Default — infer the gateway admin endpoint (127.0.0.1:9000 when unset)
ferrum-edge health

# Custom port
ferrum-edge health -p 9001

# TLS-only admin API (explicit)
ferrum-edge health --tls

# Self-signed or private-CA Admin HTTPS is not trusted by default — add
# --tls-no-verify for lab use only, or trust the CA in your probe environment.
ferrum-edge health --tls --tls-no-verify

# Auto-detected TLS when FERRUM_ADMIN_HTTP_PORT=0
FERRUM_ADMIN_HTTP_PORT=0 ferrum-edge health
# → connects to https://127.0.0.1:9443/health automatically

# Liveness probe — GET /live (200 while up, even before ready)
ferrum-edge health --live
```

### Docker HEALTHCHECK

```dockerfile
# Plaintext admin
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD ["/app/ferrum-edge", "health"]

# TLS-only admin (FERRUM_ADMIN_HTTP_PORT=0)
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD ["/app/ferrum-edge", "health", "--tls", "--tls-no-verify"]
```

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Healthy (HTTP 200 from `/health`, or `/live` with `--live`) |
| `1` | Unhealthy (non-200 response, connection refused, timeout) |

## version

Print version and build target information.

```
ferrum-edge version [OPTIONS]
```

### Options

| Flag | Description |
|------|-------------|
| `--json` | Output version info as JSON |

### Examples

```bash
$ ferrum-edge version
ferrum-edge 0.9.11 (aarch64-apple-darwin)

$ ferrum-edge version --json
{"version":"0.9.11","target":"aarch64-apple-darwin"}
```

## ambient-udp-preflight

Privileged one-shot Ambient UDP node preflight. Retires both
predecessor UDP placements on this node and publishes the node-scoped cleanup
proof the settled host placement requires. Exits non-zero without publishing
when it cannot prove completion.

The Helm chart runs it as an **init container in the Ambient DaemonSet's own
pod**, so Kubernetes guarantees it completes before the steady-state proxy
container starts. See
[the privileged node preflight](mesh.md#the-privileged-node-preflight).

Like `run` and `validate`, it applies `--settings`, the FIPS gate, and
external secret resolution before building any Kubernetes TLS client. It does
not parse the serving configuration or start any gateway listeners.

```
ferrum-edge ambient-udp-preflight [OPTIONS]
```

### Options

| Flag | Short | Description |
|------|-------|-------------|
| `--settings <PATH>` | `-s` | Path to `ferrum.conf` (operational settings) |
| `--timeout-seconds <N>` | | Wall-clock ceiling in seconds (default 300, clamped 1..=3600). Bounds owned `sh`/iptables/ip children **and** explicit-root host-proc target-PID scans used for netns-key reconcile and the stable netns handle open |
| `--host-proc-root <PATH>` | | Procfs root for **target** pid reads (default: this process's own `/proc`). The chart mounts the host's `/proc` read-only on this init container alone and passes `/host/proc`, which is what lets the settled host-netns placement drop pod-scoped `hostPID` from the long-running proxy. It never redirects `/proc/self/ns/net`. Validated as an absolute, readable directory containing `self/ns/net`; anything else fails closed rather than silently falling back to `/proc` |
| `--verbose` | `-v` | Increase log verbosity (repeatable: `-v`=info, `-vv`=debug, `-vvv`=trace) |

## Configuration Precedence

When using CLI subcommands, the configuration resolution order is (highest precedence first):

1. **CLI flag** (`--settings`, `--spec`, `--mode`, `--fips-mode`, `--verbose` on `run` and `validate`; `--settings` / `--verbose` on `ambient-udp-preflight`)
2. **Environment variable** (`FERRUM_CONF_PATH`, `FERRUM_FILE_CONFIG_PATH`, `FERRUM_MODE`, `FERRUM_FIPS_MODE`, `FERRUM_LOG_LEVEL`)
3. **Conf file value** (`ferrum.conf`)
4. **Smart path defaults** (see below)
5. **Hardcoded defaults**

## Smart Path Defaults

When `--settings` or `--spec` are omitted and the corresponding env var is not set, the CLI searches well-known locations:

### Settings (`ferrum.conf`)

1. `./ferrum.conf`
2. `./config/ferrum.conf`
3. `/etc/ferrum/ferrum.conf`

### Spec (resources file)

1. `./resources.yaml`
2. `./resources.json`
3. `./config/resources.yaml`
4. `./config/resources.json`
5. `/etc/ferrum/config.yaml`
6. `/etc/ferrum/config.json`

The first file that exists in the search order is used. If no file is found, the setting remains unset (which may cause an error if the setting is required, e.g., `FERRUM_FILE_CONFIG_PATH` in file mode).

### Path Resolution

- **Absolute paths** are used as-is
- **Relative paths** are resolved from the current working directory

## Invocation Examples

| Invocation | Behavior |
|---|---|
| `ferrum-edge run` | Start the gateway with smart defaults |
| `ferrum-edge run --spec resources.yaml` | Sets the spec path; infers file mode only when no CLI/env/conf mode is set |
| `ferrum-edge run --settings ferrum.conf --spec resources.yaml` | Spec path from CLI; mode from settings/env (never demoted by `--spec`) |
| `FERRUM_MODE=database ferrum-edge run` | Start the gateway in database mode from env vars |
