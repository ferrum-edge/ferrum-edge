# CLI Reference

Ferrum Edge provides a command-line interface for running, validating, and managing the gateway. The CLI is fully backwards compatible — invoking `ferrum-edge` with no arguments uses the existing environment-variable-only startup path.

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

When no subcommand is given, Ferrum Edge falls through to the legacy env-var-only mode. Every existing deployment (Docker, systemd, CI) continues to work unchanged.

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
| `--mode <MODE>` | `-m` | Operating mode: `database`, `file`, `cp`, `dp`, `migrate` |
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

When `--spec` is provided (or a spec file is found via smart defaults) and no mode is configured anywhere (CLI, env var, or conf file), the CLI automatically sets `FERRUM_MODE=file`. This means `ferrum-edge run --spec resources.yaml` works without needing `--mode file`.

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

### What is validated

1. **Settings** (`ferrum.conf`) — all 90+ environment variables are parsed and validated (ports, paths, TLS configuration, pool sizes, etc.)
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

When `--pid` is omitted, the CLI uses `pgrep -x ferrum-edge` to find the running process. If multiple instances are found, it reports all PIDs and asks you to specify one.

## health

Check gateway health by connecting to the admin API `/health` endpoint. Designed for use as a Docker `HEALTHCHECK` or Kubernetes exec probe in distroless containers (no shell or curl needed).

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
| `0` | Healthy (HTTP 200 from `/health`) |
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

1. **CLI flag** (`--settings`, `--spec`, `--mode`, `--verbose`)
2. **Environment variable** (`FERRUM_CONF_PATH`, `FERRUM_FILE_CONFIG_PATH`, `FERRUM_MODE`, `FERRUM_LOG_LEVEL`)
3. **Conf file value** (`ferrum.conf`)
4. **Smart path defaults** (see below)
5. **Hardcoded defaults**

When invoked with no subcommand (legacy mode), CLI flags are not available and the precedence is: env var > conf file > hardcoded default (unchanged from previous behavior).

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

## Backwards Compatibility

The CLI is fully backwards compatible with existing deployments:

| Invocation | Behavior |
|---|---|
| `ferrum-edge` | Legacy env-var-only mode, identical to pre-CLI behavior |
| `FERRUM_MODE=file ferrum-edge` | Legacy mode, unchanged |
| `ferrum-edge run` | CLI mode with smart defaults |
| `ferrum-edge run --spec resources.yaml` | CLI mode, file mode inferred |
| `FERRUM_MODE=database ferrum-edge run` | CLI mode, database mode from env var |

Docker, systemd, and CI/CD scripts that set env vars and invoke `ferrum-edge` with no arguments continue to work without modification.
