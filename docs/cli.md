# CLI Reference

Ferrum Edge provides a command-line interface for running, validating, and managing the gateway. A subcommand is required.

## Making the Binary Available

The `ferrum-edge` binary must be on your shell's `PATH` to be invoked by name. After building or downloading:

```bash
# From source
sudo cp target/release/ferrum-edge /usr/local/bin/

# From a pre-built release download
sudo mv ferrum-edge /usr/local/bin/

# Verify
ferrum-edge version
```

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

Parse and validate configuration files without starting the gateway. Exits with code 0 on success, 1 on failure. Useful for CI/CD pre-deploy checks.

```
ferrum-edge validate [OPTIONS]
```

### Options

| Flag | Short | Description |
|------|-------|-------------|
| `--settings <PATH>` | `-s` | Path to `ferrum.conf` (operational settings) |
| `--spec <PATH>` | `-c` | Path to resources YAML/JSON |
| `--mode <MODE>` | `-m` | Operating mode: `database`, `file`, `cp`, `dp`, `mesh`, `injector`, `node_agent`, `migrate` |
| `--verbose` | `-v` | Increase log verbosity (repeatable: `-v`=info, `-vv`=debug, `-vvv`=trace) |

### What is validated

0. **External secrets** — before settings are parsed, `validate` resolves the `_FILE`, `_VAULT`, `_AWS`, `_AZURE`, and `_GCP` suffixes into their base `FERRUM_*` variables exactly as `run` does. Empty suffixed variables are treated as unset in every build. Validation therefore sees the same configuration the gateway would start with, and the same failures apply: an unreadable or unreachable non-empty source fails the command, and a base variable combined with a non-empty suffixed source for the same key is a conflict. Which suffixes a binary can resolve is a **build-time** property: `_FILE` works in every build, while `_VAULT`, `_AWS`, `_AZURE`, and `_GCP` require the matching secret-backend Cargo feature (`secrets-vault`, `secrets-aws`, `secrets-azure`, `secrets-gcp`, or the `cloud-secrets` umbrella). The default feature set compiles none of them, so on a default binary a non-empty cloud suffix is not silently ignored — it fails the command with an unsupported-suffix error. No environment variable or settings value can enable a provider that was not compiled in; use a binary or image built with the required feature (the published Docker images build with `cloud-secrets`). Conflict detection is environment-only: the resolver runs before `ferrum.conf` is parsed and inspects only the process environment, so *both* the base variable and the suffixed source must be environment-provided and non-empty for the conflict to be reported. A base variable supplied by the settings file is not a competing source — the suffixed source is materialized into the environment and then wins under the normal env-over-`ferrum.conf` precedence, silently overriding the settings-file value. Keep secret base variables and their suffixed sources in the same layer. When at least one source resolves, `validate` prints an `External secrets: OK` block on stdout **unconditionally** — it is part of the validate report, like `Settings (ferrum.conf): OK`, and is not gated on `FERRUM_LOG_LEVEL`/`RUST_LOG` or on `-v/--verbose` (the report is a `println!`, not a tracing record, so it stays visible at the default warn log level). The block lists only the resolved base variable and provider names, never source references — file paths, Vault paths, cloud resource IDs — and never secret values:

```text
External secrets: OK
  Loaded FERRUM_ADMIN_JWT_SECRET from file
  Resolved 1 env var(s) from external secret sources
Settings (ferrum.conf): OK
  Mode: Database

Validation passed.
```

`run` reports the same non-secret facts as structured `info!` records instead, so serving modes keep normal log-level semantics.

The report lines are sorted by base variable name. Candidate sources are discovered by iterating the environment into a hash map, so without an explicit sort two runs on identical input could list them in different orders; sorting keeps `validate` output diffable between machines and CI runs.

Failures are held to the same disclosure rule as the success report. A failed fetch names the base variable, the provider, and the failure reason — an unreadable `_FILE` source reports `Failed to read FERRUM_X_FILE: No such file or directory` — but never the source reference itself, even when a provider SDK echoes the resource it was asked for. A one- or two-byte source reference cannot be removed selectively without corrupting arbitrary words, so if it appears in provider-controlled detail that detail is replaced by a fixed key-level failure instead of being echoed. Once external values are materialized into the environment they are also withheld from *subsequent* settings and spec diagnostics: a malformed `FERRUM_DB_PORT_FILE` reports `Invalid FERRUM_DB_PORT value <redacted: value from external secret source>. Expected a valid u16 integer` rather than printing the fetched secret. Variables that were not resolved from an external source are unaffected and still show their value, which is usually the fastest way to spot a typo.

The same rule holds for diagnostics that are *not* failures. A warning raised while settings are parsed — `FERRUM_TLS_EARLY_DATA_METHODS includes non-GET method '...'`, say — is emitted directly to the log sink and never passes through the command's exit status, so it is filtered at the point every record is serialized rather than only on the error path. Values are matched in the forms a validator can actually print them in, not just verbatim: trimmed, per-entry for comma-separated lists, case-normalized, and JSON-escaped. A run whose only externally resolved variable is a valid one therefore still succeeds, prints `External secrets: OK`, and shows `<redacted: value from external secret source>` in place of the value in any warning about it.

Discovery tolerates a non-Unicode environment. Secret resolution enumerates the environment before settings are parsed, and it does so without decoding: an unrelated variable whose name or value is not valid UTF-8 — common in POSIX environments — is skipped by a raw-byte `FERRUM_` prefix screen and cannot fail the command. Two cases do fail closed, because silently ignoring them could drop a configured secret source: a `FERRUM_*` variable whose **name** is not valid Unicode (the `_FILE`/`_VAULT`/… suffix sits at the end of the name, so an undecodable name may itself be a source), and a recognized suffixed **source** variable whose value is not valid Unicode (an unusable source reference). Both report `Environment variable <NAME> is not valid Unicode`, with the name reduced to its ASCII skeleton (`?` for every other byte) so undecodable bytes are never echoed. A **third** case fails closed for the same reason: an ordinary direct `FERRUM_*` variable — no suffix, no competing source — whose *value* is not valid Unicode. Every downstream resolver reads the environment with `std::env::var`, which reports undecodable bytes as `Err`, i.e. as **unset**, so such a value would otherwise be silently replaced by a `ferrum.conf` entry, a smart-discovered default such as `./ferrum.conf`, or a built-in default, and the gateway would come up on settings the operator never chose. It is reported as `Environment variable <NAME> is not valid Unicode. Ferrum configuration values must be valid Unicode; fix or unset the variable.`, with the name reduced to its ASCII skeleton — the undecodable bytes are never echoed. Smart path discovery checks these variables for *presence* rather than decodability, so an undecodable `FERRUM_CONF_PATH` or `FERRUM_FILE_CONFIG_PATH` is never overwritten before the resolver can reject it.

**Conflict takes precedence.** A non-Unicode direct value also still counts as a directly configured source, so when a suffixed source competes for the same key the specific `Multiple secret sources configured for <NAME>` diagnostic is reported instead — it is the more actionable of the two, and it is checked first. The unsupported-suffix and invalid-source-name failures above are checked earlier still. In every ordering the command fails; only which message you get changes.

Two ordering properties matter for a `validate` that reads its own settings path from a secret source. `FERRUM_CONF_PATH_FILE` is materialized into `FERRUM_CONF_PATH` *before* the settings file is opened, so the resolved path is the one validated. That requires the resolver itself never to read `ferrum.conf`, which is why both `FERRUM_SECRET_FETCH_TIMEOUT_SECONDS` and `FERRUM_GCP_SECRET_MANAGER_ENDPOINT` are read from the environment only at this stage (see [configuration.md](configuration.md)). And a `_FILE` source pointing at a FIFO or a stalled mount fails after that timeout instead of hanging the command — the read is abandoned rather than waited on.

A resolved value that cannot be placed in the process environment is reported rather than fatal: a source whose contents contain a NUL byte (binary material behind a `_FILE` path, say) fails with `Secret resolved for FERRUM_X from file contains a NUL byte and cannot be placed in the process environment.` The value is never named.

Smart path discovery yields to a suffixed source. When `FERRUM_CONF_PATH_FILE` (or the `_VAULT`/`_AWS`/`_AZURE`/`_GCP` equivalent) is set, `validate` and `run` do **not** auto-discover `./ferrum.conf`, `./config/ferrum.conf`, or `/etc/ferrum/ferrum.conf`, and the same holds for `FERRUM_FILE_CONFIG_PATH_FILE` and the `./resources.yaml` family. A discovered default is the lowest-precedence source there is, so treating it as a competing one would fail the command with a multiple-sources error in any working directory that merely happened to contain a settings or resources file. An **explicit** `-s/--settings` or `-c/--spec` path is different — that is a genuine two-sources-for-one-key mistake and is still reported as a conflict.

File-mode inference is likewise the *lowest*-precedence mode source, and it runs after secrets are resolved so that every source above it is visible first. `run` and `validate` fall back to `FERRUM_MODE=file` only when a spec path is configured **and** no mode was set by any higher-precedence source — matching the documented `CLI > env > conf file > smart defaults > hardcoded` order. Both commands check `-m/--mode` first (via `apply_run_overrides` / `apply_validate_overrides`), then `FERRUM_MODE` in the environment, then a `FERRUM_MODE_FILE`/`_VAULT`/`_AWS`/`_AZURE`/`_GCP` source, then `FERRUM_MODE` in `ferrum.conf`. A spec path that is itself supplied by a suffixed source still infers file mode, because it has been materialized into `FERRUM_FILE_CONFIG_PATH` by then. Externalizing the mode and the spec path together is therefore supported: neither shadows the other, and the inference never manufactures a second competing source for `FERRUM_MODE`.

The report withholds externally sourced values, not just the ones that appear in errors. `validate` prints its findings with plain stdout writes, which are not log records and are not an error return, so each value-bearing field is filtered where it is printed. A field whose variable was resolved from an external source is withheld by name — `FERRUM_MODE_FILE` containing `database` prints `Mode: <redacted: value from external secret source>`, not `Mode: Database` — while the surrounding validation result, including `Validation passed.` and the spec-document counts, is unaffected. `run` withholds the same value on its own startup log line for the same reason: `Operating mode:` re-renders the resolved value as the `Database` enum variant, a form the log-record redactor deliberately does not derive, so that line is withheld by variable name too.

1. **Settings** (`ferrum.conf`) — all 300+ environment variables are parsed and validated (ports, paths, TLS configuration, pool sizes, etc.)
2. **Spec** (resources YAML/JSON, file mode only):
   - YAML/JSON syntax and deserialization
   - Field-level validation on all proxies, consumers, upstreams, and plugin configs
   - Regex `listen_path` compilation
   - Unique `listen_path` enforcement
   - Stream proxy port conflict detection against gateway reserved ports
   - Plugin config validation (each plugin is instantiated to verify its config)
   - TLS certificate path existence checks
   - Upstream reference validation

### Examples

```bash
# Validate a spec file
ferrum-edge validate --spec resources.yaml

# Validate with explicit settings
ferrum-edge validate --settings /etc/ferrum/ferrum.conf --spec /etc/ferrum/resources.yaml

# Validate a specific mode without mutating the shell environment
ferrum-edge validate -m file -c resources.yaml

# Use in CI/CD pipeline
ferrum-edge validate --spec resources.yaml || exit 1
```

### Sample Output

```
Settings (ferrum.conf): OK
  Mode: File
Spec (/etc/ferrum/resources.yaml): OK
  Proxies: 12
  Consumers: 5
  Upstreams: 3
  Plugin configs: 18

Validation passed.
```

On failure:

```
Settings (ferrum.conf): OK
  Mode: File
Error: Spec validation failed: Configuration file not found: /nonexistent.yaml
```

## reload

Send SIGHUP to a running gateway instance to trigger a hot config reload. Only supported on Unix platforms (Linux, macOS, BSDs). In file mode, SIGHUP causes the gateway to re-parse the spec file and atomically swap the config without dropping connections.

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

When `--pid` is omitted, the CLI uses `pgrep -x ferrum-edge` to find running processes, then excludes its own PID before selecting a target. A single other `ferrum-edge` process is reloaded automatically. If none remain after excluding self, it reports that no gateway was found. If multiple other instances remain, it reports their PIDs and asks you to specify one with `--pid`. Explicit `--pid` bypasses auto-detection entirely.

## health

Check gateway health by connecting to the admin API. By default it probes readiness via `GET /health` (returns 503 until the gateway is ready). With `--live` it probes liveness via `GET /live`, which returns 200 whenever the process and admin listener are up — even during startup or while serving degraded. Designed for use as a Docker `HEALTHCHECK` or Kubernetes exec probe in distroless containers (no shell or curl needed).

Point a Kubernetes **livenessProbe** at `ferrum-edge health --live` and the **readinessProbe** at `ferrum-edge health`. Using `/health` for liveness would restart-loop an alive-but-unready pod (e.g. a `dp` that has lost its `cp`), whereas readiness only drops it from Service endpoints.

```
ferrum-edge health [OPTIONS]
```

### Options

| Flag | Short | Description |
|------|-------|-------------|
| `--port <PORT>` | `-p` | Admin API port (defaults to `FERRUM_ADMIN_HTTP_PORT` / 9000, or `FERRUM_ADMIN_HTTPS_PORT` / 9443 when TLS is used) |
| `--host <HOST>` | | Admin API host (default: `127.0.0.1`) |
| `--tls` | | Connect via HTTPS instead of HTTP |
| `--tls-no-verify` | | Skip TLS certificate verification (for self-signed certs / testing) |
| `--live` | | Probe liveness (`GET /live`) instead of readiness (`GET /health`) |

### Auto-Detection

When `FERRUM_ADMIN_HTTP_PORT=0` (plaintext admin disabled), the health command automatically switches to TLS mode and uses port 9443 (or the value of `FERRUM_ADMIN_HTTPS_PORT`). No `--tls` flag is needed in this case.

### Examples

```bash
# Default — connect to http://127.0.0.1:9000/health
ferrum-edge health

# Custom port
ferrum-edge health -p 9001

# TLS-only admin API (explicit)
ferrum-edge health --tls

# TLS with self-signed cert
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
ferrum-edge 0.9.0 (aarch64-apple-darwin)

$ ferrum-edge version --json
{"version":"0.9.0","target":"aarch64-apple-darwin"}
```

## Configuration Precedence

When using CLI subcommands, the configuration resolution order is (highest precedence first):

1. **CLI flag** (`--settings`, `--spec`, `--mode`, `--verbose` on `run` and `validate`)
2. **Environment variable** (`FERRUM_CONF_PATH`, `FERRUM_FILE_CONFIG_PATH`, `FERRUM_MODE`, `FERRUM_LOG_LEVEL`)
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
