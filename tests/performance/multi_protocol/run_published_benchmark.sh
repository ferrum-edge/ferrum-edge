#!/bin/bash
# Reproducible multi-protocol benchmark for published numbers.
#
# Wraps run_protocol_test.sh to produce a self-describing result directory:
#   - one release build, recorded with commit, toolchain, and host details
#   - N repeated runs per protocol; leg order alternates gateway-first /
#     direct-first so thermal drift does not always penalise the same leg
#   - throughput suites (saturating concurrency) per payload size, plus a
#     light-load latency suite (concurrency 1) that isolates the per-hop cost
#   - gateway process CPU per request for every gateway leg
#   - summary.json / summary.md with medians, spread, and validity flags
#
# Usage:
#   ./run_published_benchmark.sh [options]
#     --protocols "<list>"      Default: all ten protocols
#     --runs <n>                Repeated runs per suite (default 3)
#     --duration <secs>         Measured seconds per throughput leg (default 15)
#     --concurrency <n>         Throughput concurrency (default 200)
#     --payload-sizes "<list>"  Throughput payload sizes in bytes (default "64 10240")
#     --latency-duration <secs> Measured seconds per latency leg (default 10; 0 skips)
#     --cooldown <secs>         Idle pause before each leg (default 2)
#     --out <dir>               Result directory (default results/<UTC timestamp>)
#     --skip-build              Reuse existing release binaries

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

PROTOCOLS="http1 http1-tls http2 http3 ws grpc tcp tcp-tls udp udp-dtls"
RUNS=3
DURATION=15
CONCURRENCY=200
PAYLOAD_SIZES="64 10240"
LATENCY_DURATION=10
COOLDOWN=2
OUT=""
SKIP_BUILD=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --protocols) PROTOCOLS="$2"; shift 2 ;;
        --runs) RUNS="$2"; shift 2 ;;
        --duration) DURATION="$2"; shift 2 ;;
        --concurrency) CONCURRENCY="$2"; shift 2 ;;
        --payload-sizes) PAYLOAD_SIZES="$2"; shift 2 ;;
        --latency-duration) LATENCY_DURATION="$2"; shift 2 ;;
        --cooldown) COOLDOWN="$2"; shift 2 ;;
        --out) OUT="$2"; shift 2 ;;
        --skip-build) SKIP_BUILD=true; shift ;;
        -h|--help) sed -n '2,25p' "$0"; exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 2 ;;
    esac
done

STARTED_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
OUT="${OUT:-$SCRIPT_DIR/results/$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$OUT/raw"
OUT="$(cd "$OUT" && pwd)"

if ! $SKIP_BUILD; then
    echo "Building release binaries..."
    (cd "$PROJECT_ROOT" && cargo build --release --bin ferrum-edge)
    (cd "$SCRIPT_DIR" && cargo build --release)
fi
for bin in "$PROJECT_ROOT/target/release/ferrum-edge" "$SCRIPT_DIR/target/release/proto_bench" \
    "$SCRIPT_DIR/target/release/proto_backend"; do
    [ -x "$bin" ] || { echo "Missing release binary: $bin" >&2; exit 1; }
done

# Provenance manifest: everything needed to judge or reproduce the numbers.
python3 - "$OUT/manifest.json" "$PROJECT_ROOT" "$STARTED_UTC" <<PYEOF
import datetime, json, os, platform, subprocess, sys
out, root, started = sys.argv[1:]
def run(*cmd, cwd=None):
    try:
        return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=True).stdout.strip()
    except Exception:
        return None
def cpu_name():
    if platform.system() == "Darwin":
        return run("sysctl", "-n", "machdep.cpu.brand_string")
    try:
        for line in open("/proc/cpuinfo"):
            if line.startswith("model name"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or None
def memory_gib():
    if platform.system() == "Darwin":
        raw = run("sysctl", "-n", "hw.memsize")
        return round(int(raw) / 2**30, 1) if raw else None
    try:
        for line in open("/proc/meminfo"):
            if line.startswith("MemTotal"):
                return round(int(line.split()[1]) / 2**20, 1)
    except OSError:
        return None
def os_name():
    if platform.system() == "Darwin":
        return f"macOS {platform.mac_ver()[0]} ({platform.machine()})"
    return f"{platform.system()} {platform.release()} ({platform.machine()})"
# With --skip-build the binaries may predate HEAD: record when each was built
# and flag any older than the recorded commit, so the bundle cannot silently
# attribute an older build's numbers to this commit.
commit_time = run("git", "log", "-1", "--format=%ct", cwd=root)
binaries = {}
stale = []
for rel in ("target/release/ferrum-edge",
            "tests/performance/multi_protocol/target/release/proto_bench",
            "tests/performance/multi_protocol/target/release/proto_backend"):
    mtime = os.path.getmtime(os.path.join(root, rel))
    binaries[rel] = datetime.datetime.fromtimestamp(mtime, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if commit_time and mtime < int(commit_time):
        stale.append(rel)
version_raw = run(os.path.join(root, "target/release/ferrum-edge"), "version", "--json")
try:
    version = json.loads(version_raw).get("version") if version_raw else None
except ValueError:
    version = version_raw
manifest = {
    "started_utc": started,
    "suite": "tests/performance/multi_protocol/run_published_benchmark.sh",
    "git": {
        "commit": run("git", "rev-parse", "HEAD", cwd=root),
        "describe": run("git", "describe", "--tags", "--always", "--dirty", cwd=root),
        "dirty": bool(run("git", "status", "--porcelain", "--untracked-files=no", cwd=root)),
    },
    "gateway_version": version,
    "build_profile": "release",
    "binaries_built_utc": binaries,
    "binaries_older_than_commit": stale,
    "toolchain": run("rustc", "--version"),
    "environment": {
        "os": os_name(),
        "cpu": cpu_name(),
        "logical_cpus": os.cpu_count(),
        "memory_gib": memory_gib(),
        "load_average": [round(v, 2) for v in os.getloadavg()],
    },
    "args": {
        "protocols": "$PROTOCOLS".split(),
        "runs": int("$RUNS"),
        "duration_secs": int("$DURATION"),
        "concurrency": int("$CONCURRENCY"),
        "payload_sizes": [int(v) for v in "$PAYLOAD_SIZES".split()],
        "latency_duration_secs": int("$LATENCY_DURATION"),
        "latency_concurrency": 1,
        "cooldown_secs": int("$COOLDOWN"),
        "udp_payload_cap_bytes": 2048,
    },
}
with open(out, "w") as f:
    json.dump(manifest, f, indent=2)
    f.write("\n")
PYEOF

if python3 -c 'import json, sys; sys.exit(0 if json.load(open(sys.argv[1]))["binaries_older_than_commit"] else 1)' "$OUT/manifest.json"; then
    echo "WARNING: release binaries predate the recorded commit (see binaries_older_than_commit in manifest.json); rebuild without --skip-build before publishing." >&2
fi

FAILURES=0

# run_suite <suite name> <concurrency> <duration> <payload>
run_suite() {
    local suite="$1" concurrency="$2" duration="$3" payload="$4"
    local run order protocol dir
    for run in $(seq 1 "$RUNS"); do
        if (( run % 2 == 1 )); then order=gateway-first; else order=direct-first; fi
        dir="$OUT/raw/$suite/run$run"
        mkdir -p "$dir"
        for protocol in $PROTOCOLS; do
            echo "[$suite] run $run/$RUNS ($order) $protocol"
            rm -f "$dir/$protocol.cpu.jsonl"
            if ! BENCH_ORDER="$order" BENCH_COOLDOWN="$COOLDOWN" \
                BENCH_CPU_OUT="$dir/$protocol.cpu.jsonl" \
                "$SCRIPT_DIR/run_protocol_test.sh" "$protocol" --skip-build --json \
                    --duration "$duration" --concurrency "$concurrency" \
                    --payload-size "$payload" > "$dir/$protocol.log" 2>&1; then
                echo "  FAILED: see $dir/$protocol.log" >&2
                FAILURES=$((FAILURES + 1))
            fi
        done
    done
}

for payload in $PAYLOAD_SIZES; do
    run_suite "throughput_${payload}b" "$CONCURRENCY" "$DURATION" "$payload"
done
if [ "$LATENCY_DURATION" != "0" ]; then
    run_suite "latency_64b" 1 "$LATENCY_DURATION" 64
fi

python3 "$SCRIPT_DIR/summarize_published_benchmark.py" "$OUT"
echo ""
echo "Results: $OUT/summary.md"
if [ "$FAILURES" -gt 0 ]; then
    echo "$FAILURES protocol run(s) failed; their rows are marked incomplete-runs." >&2
    exit 1
fi
