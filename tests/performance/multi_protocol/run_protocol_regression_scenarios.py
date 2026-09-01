#!/usr/bin/env python3
"""Protocol regression extras: connection churn, soak/resource plateaus, reload.

Expects release-staged ferrum-edge / proto_backend / proto_bench binaries (same
layout as run_protocol_test.sh --skip-build). Authored as Python with literal
subprocess argv lists so tests/performance automation comparison does not grow
a new shell tooling surface under the trusted ARM64 policy.

Usage:
  python3 run_protocol_regression_scenarios.py --output-dir DIR
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parents[2]
GATEWAY_HTTP_PORT = 8000
GATEWAY_HTTPS_PORT = 8443
RESOURCE_SAMPLE_WARMUP_SECONDS = 6.0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True)
    return parser.parse_args()


def http_ok(url: str) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=2) as response:
            return 200 <= int(response.status) < 300
    except (urllib.error.URLError, TimeoutError, ValueError):
        return False


def wait_http(url: str, attempts: int = 20) -> bool:
    for _ in range(attempts):
        if http_ok(url):
            return True
        time.sleep(1)
    return False


def read_proc_metrics(pid: int) -> tuple[int, int, int]:
    rss = 0
    fds = 0
    tasks = 0
    status_path = Path(f"/proc/{pid}/status")
    if status_path.is_file():
        for line in status_path.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("VmRSS:"):
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        rss = int(parts[1]) * 1024
                    except ValueError:
                        rss = 0
            elif line.startswith("Threads:"):
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        tasks = int(parts[1])
                    except ValueError:
                        tasks = 0
    fd_dir = Path(f"/proc/{pid}/fd")
    if fd_dir.is_dir():
        try:
            fds = len(list(fd_dir.iterdir()))
        except OSError:
            fds = 0
    return rss, fds, tasks


def sample_resources(
    pid: int, out_path: Path, interval: float, initial_delay: float, stop_event
) -> None:
    out_path.write_text("", encoding="utf-8")
    if stop_event.wait(initial_delay):
        return
    while not stop_event.is_set():
        try:
            os.kill(pid, 0)
        except OSError:
            break
        rss, fds, tasks = read_proc_metrics(pid)
        with out_path.open("a", encoding="utf-8") as handle:
            handle.write(f"{int(time.time())} {rss} {fds} {tasks}\n")
        stop_event.wait(interval)


def gateway_env(config: Path, cert_dir: Path, extra: dict[str, str]) -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        {
            "FERRUM_MODE": "file",
            "FERRUM_FILE_CONFIG_PATH": str(config),
            "FERRUM_PROXY_HTTP_PORT": str(GATEWAY_HTTP_PORT),
            "FERRUM_PROXY_HTTPS_PORT": str(GATEWAY_HTTPS_PORT),
            "FERRUM_LOG_LEVEL": "error",
            "FERRUM_ADD_VIA_HEADER": "false",
            "FERRUM_ADD_FORWARDED_HEADER": "false",
            "FERRUM_MAX_REQUEST_BODY_SIZE_BYTES": "0",
            "FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES": "0",
            "FERRUM_RESPONSE_BUFFER_CUTOFF_BYTES": "0",
            "FERRUM_HTTP_HEADER_READ_TIMEOUT_SECONDS": "0",
            "FERRUM_MAX_CONNECTIONS": "0",
            "FERRUM_MAX_HEADER_COUNT": "0",
            "FERRUM_MAX_URL_LENGTH_BYTES": "0",
            "FERRUM_MAX_QUERY_PARAMS": "0",
            "FERRUM_POOL_IDLE_TIMEOUT_SECONDS": "120",
            "FERRUM_POOL_ENABLE_HTTP_KEEP_ALIVE": "true",
            "FERRUM_POOL_CLEANUP_INTERVAL_SECONDS": "30",
            "FERRUM_POOL_WARMUP_ENABLED": "true",
            "FERRUM_TLS_NO_VERIFY": "true",
            "FERRUM_FRONTEND_TLS_CERT_PATH": str(cert_dir / "cert.pem"),
            "FERRUM_FRONTEND_TLS_KEY_PATH": str(cert_dir / "key.pem"),
        }
    )
    env.update(extra)
    return env


def load_bench(path: Path):
    if not path.is_file():
        return None
    raw = path.read_text(encoding="utf-8")
    decoder = json.JSONDecoder()
    idx = raw.find("{")
    while idx != -1:
        try:
            obj, _ = decoder.raw_decode(raw, idx)
            return obj
        except json.JSONDecodeError:
            idx = raw.find("{", idx + 1)
    return None


def sample_total(sample):
    max_metric_count = (1 << 63) - 1
    try:
        req = sample.get("total_requests", 0)
        err = sample.get("total_errors", 0)
        if isinstance(req, bool) or isinstance(err, bool):
            return None
        req_i = int(req)
        err_i = int(err)
    except (TypeError, ValueError, OverflowError):
        return None
    if (
        req_i < 0
        or err_i < 0
        or req_i > max_metric_count
        or err_i > max_metric_count
    ):
        return None
    return req_i + err_i


def _finite_unit_rate(value):
    try:
        if isinstance(value, bool):
            return None
        number = float(value)
    except (TypeError, ValueError):
        return None
    if number != number or number in (float("inf"), float("-inf")):
        return None
    if number < 0.0 or number > 1.0:
        return None
    return number


def sample_usable(sample) -> bool:
    if not isinstance(sample, dict):
        return False
    total = sample_total(sample)
    if total is not None and total > 0:
        return True
    if total is None and ("total_requests" in sample or "total_errors" in sample):
        return False
    has_heartbeat = "heartbeat_success_rate" in sample
    has_connect = "connect_success_rate" in sample
    if not (has_heartbeat or has_connect):
        return False
    if has_heartbeat and _finite_unit_rate(sample.get("heartbeat_success_rate")) is None:
        return False
    if has_connect and _finite_unit_rate(sample.get("connect_success_rate")) is None:
        return False
    return True


def error_rate(sample) -> float:
    if not sample:
        return 1.0
    total = sample_total(sample)
    if total is None:
        return 1.0
    if total <= 0:
        if "heartbeat_success_rate" in sample:
            rate = _finite_unit_rate(sample.get("heartbeat_success_rate", 0.0))
            if rate is None:
                return 1.0
            return 1.0 - rate
        return 1.0
    return float(sample.get("total_errors", 0)) / float(total)


def main() -> int:
    # Import subprocess only inside main so module import stays side-effect free
    # for static contract readers; argv lists below stay literal constants.
    import subprocess
    from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
    from threading import Event

    args = parse_args()
    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    cert_dir = SCRIPT_DIR / "certs"
    min_resource_samples = int(os.environ.get("MIN_RESOURCE_SAMPLES", "3"))
    protocol_tool_env = os.environ.copy()
    # Resolve literal tool names only from the crate-local release directory.
    # This preserves the prior harness binaries while keeping their provenance
    # explicit to the trusted automation scanner.
    protocol_tool_env["PATH"] = str(SCRIPT_DIR / "target" / "release")

    backend = None
    gateway = None
    benchmark = None
    sampler_future = None
    sampler_stop = None
    executor = ThreadPoolExecutor(max_workers=1)

    def terminate_process(process) -> None:
        """Terminate and reap only a child process started by this harness."""
        if process is None or process.poll() is not None:
            return
        try:
            process.terminate()
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)

    def stop_sampler() -> None:
        nonlocal sampler_future, sampler_stop
        if sampler_stop is not None:
            sampler_stop.set()
        if sampler_future is not None:
            try:
                sampler_future.result(timeout=5)
            except FutureTimeoutError as exc:
                raise RuntimeError("resource sampler did not terminate") from exc
        sampler_future = None
        sampler_stop = None

    def cleanup() -> None:
        nonlocal backend, gateway, benchmark
        try:
            stop_sampler()
        except Exception as exc:
            print(f"::error::scenario harness cleanup: {exc}", file=sys.stderr)
        if benchmark is not None:
            terminate_process(benchmark)
            benchmark = None
        if gateway is not None:
            terminate_process(gateway)
            gateway = None
        if backend is not None:
            terminate_process(backend)
            backend = None
        executor.shutdown(wait=True, cancel_futures=True)

    try:
        print("== protocol regression scenarios ==")
        backend_log = output_dir / "backend.log"
        with backend_log.open("w", encoding="utf-8") as handle:
            backend = subprocess.Popen(
                ["proto_backend"],
                stdout=handle,
                stderr=subprocess.STDOUT,
                cwd=SCRIPT_DIR,
                env=protocol_tool_env,
            )
        if not wait_http("http://127.0.0.1:3010/health"):
            print("backend failed to start", file=sys.stderr)
            if backend_log.is_file():
                sys.stderr.write(backend_log.read_text(encoding="utf-8", errors="replace"))
            cleanup()
            return 1

        churn_rc = 0
        soak_rc = 0
        reload_rc = 0

        # Connection churn
        print("-- connection churn")
        gateway_log = output_dir / "gateway.log"
        for _ in range(10):
            if (cert_dir / "ca.pem").is_file() and (cert_dir / "cert.pem").is_file():
                break
            time.sleep(1)
        with gateway_log.open("w", encoding="utf-8") as handle:
            gateway = subprocess.Popen(
                ["./target/release/ferrum-edge"],
                stdout=handle,
                stderr=subprocess.STDOUT,
                cwd=PROJECT_ROOT,
                env=gateway_env(
                    SCRIPT_DIR / "configs" / "http1_perf.yaml",
                    cert_dir,
                    {
                        "FERRUM_POOL_MAX_IDLE_PER_HOST": "4",
                        "FERRUM_POOL_ENABLE_HTTP_KEEP_ALIVE": "false",
                    },
                ),
            )
        if not wait_http(f"http://127.0.0.1:{GATEWAY_HTTP_PORT}/health"):
            print("gateway failed to start", file=sys.stderr)
            if gateway_log.is_file():
                sys.stderr.write(gateway_log.read_text(encoding="utf-8", errors="replace"))
            cleanup()
            return 1
        with (output_dir / "connection_churn.json").open("w", encoding="utf-8") as out, (
            output_dir / "connection_churn.log"
        ).open("w", encoding="utf-8") as err:
            churn = subprocess.run(
                ["proto_bench",
                    "http1",
                    "--target",
                    "http://127.0.0.1:8000/echo",
                    "--duration",
                    "8",
                    "--concurrency",
                    "80",
                    "--payload-size",
                    "1024",
                    "--json",
                ],
                stdout=out,
                stderr=err,
                cwd=SCRIPT_DIR,
                env=protocol_tool_env,
                check=False,
            )
            churn_rc = int(churn.returncode)
        terminate_process(gateway)
        gateway = None

        # Soak + resource plateau
        print("-- soak + resource plateau")
        with gateway_log.open("w", encoding="utf-8") as handle:
            gateway = subprocess.Popen(
                ["./target/release/ferrum-edge"],
                stdout=handle,
                stderr=subprocess.STDOUT,
                cwd=PROJECT_ROOT,
                env=gateway_env(
                    SCRIPT_DIR / "configs" / "http1_tls_perf.yaml",
                    cert_dir,
                    {"FERRUM_POOL_MAX_IDLE_PER_HOST": "200"},
                ),
            )
        if not wait_http(f"http://127.0.0.1:{GATEWAY_HTTP_PORT}/health"):
            print("gateway failed to start", file=sys.stderr)
            cleanup()
            return 1
        sample_path = output_dir / "resource_samples.txt"
        sampler_stop = Event()
        sampler_future = executor.submit(
            sample_resources,
            gateway.pid,
            sample_path,
            1.0,
            RESOURCE_SAMPLE_WARMUP_SECONDS,
            sampler_stop,
        )
        with (output_dir / "soak.json").open("w", encoding="utf-8") as out, (
            output_dir / "soak.log"
        ).open("w", encoding="utf-8") as err:
            soak = subprocess.run(
                ["proto_bench",
                    "saturate",
                    "--target",
                    "https://127.0.0.1:8443/echo",
                    "--connections",
                    "200",
                    "--ramp-seconds",
                    "5",
                    "--hold-seconds",
                    "20",
                    "--heartbeat-interval-ms",
                    "1000",
                    "--payload-size",
                    "64",
                    "--json",
                ],
                stdout=out,
                stderr=err,
                cwd=SCRIPT_DIR,
                env=protocol_tool_env,
                check=False,
            )
            soak_rc = int(soak.returncode)
        stop_sampler()
        terminate_process(gateway)
        gateway = None

        # Reload under load
        print("-- reload under load")
        with gateway_log.open("w", encoding="utf-8") as handle:
            gateway = subprocess.Popen(
                ["./target/release/ferrum-edge"],
                stdout=handle,
                stderr=subprocess.STDOUT,
                cwd=PROJECT_ROOT,
                env=gateway_env(
                    SCRIPT_DIR / "configs" / "http1_perf.yaml",
                    cert_dir,
                    {"FERRUM_POOL_MAX_IDLE_PER_HOST": "200"},
                ),
            )
        if not wait_http(f"http://127.0.0.1:{GATEWAY_HTTP_PORT}/health"):
            print("gateway failed to start", file=sys.stderr)
            cleanup()
            return 1
        with (output_dir / "reload_under_load.json").open("w", encoding="utf-8") as out, (
            output_dir / "reload_under_load.log"
        ).open("w", encoding="utf-8") as err:
            benchmark = subprocess.Popen(
                ["proto_bench",
                    "http1",
                    "--target",
                    "http://127.0.0.1:8000/echo",
                    "--duration",
                    "12",
                    "--concurrency",
                    "50",
                    "--payload-size",
                    "1024",
                    "--json",
                ],
                stdout=out,
                stderr=err,
                cwd=SCRIPT_DIR,
                env=protocol_tool_env,
            )
            time.sleep(4)
            reload_signal_sent = False
            if gateway is not None and gateway.poll() is None:
                try:
                    os.kill(gateway.pid, signal.SIGHUP)
                    reload_signal_sent = True
                    print(f"sent SIGHUP to gateway pid={gateway.pid}")
                except OSError as exc:
                    print(f"failed to send SIGHUP to gateway: {exc}", file=sys.stderr)
            reload_rc = int(benchmark.wait())
            benchmark = None
        terminate_process(gateway)
        gateway = None

        rss: list[int] = []
        fds: list[int] = []
        tasks: list[int] = []
        if sample_path.is_file():
            for line in sample_path.read_text(encoding="utf-8").splitlines():
                parts = line.split()
                if len(parts) != 4:
                    continue
                _, rss_v, fd_v, task_v = parts
                try:
                    rss_n = float(rss_v)
                    fd_n = float(fd_v)
                    task_n = float(task_v)
                except ValueError:
                    continue
                if not all(
                    n == n and n not in (float("inf"), float("-inf")) and n >= 0.0
                    for n in (rss_n, fd_n, task_n)
                ):
                    continue
                rss.append(int(rss_n))
                fds.append(int(fd_n))
                tasks.append(int(task_n))

        churn_sample = load_bench(output_dir / "connection_churn.json")
        reload_sample = load_bench(output_dir / "reload_under_load.json")
        soak_sample = load_bench(output_dir / "soak.json")
        scenarios = {
            "connection_churn": {
                "error_rate": error_rate(churn_sample),
                "sample": churn_sample,
                "bench_exit_code": churn_rc,
            },
            "reload_under_load": {
                "error_rate": error_rate(reload_sample),
                "sample": reload_sample,
                "bench_exit_code": reload_rc,
                "sighup_sent": reload_signal_sent,
            },
            "soak": {
                "sample": soak_sample,
                "bench_exit_code": soak_rc,
            },
            "resource_plateau": {
                "rss_bytes": rss,
                "fd_count": fds,
                "task_count": tasks,
                "sample_count": len(rss),
            },
        }
        (output_dir / "scenarios.json").write_text(
            json.dumps(scenarios, indent=2) + "\n", encoding="utf-8"
        )

        errors: list[str] = []
        if churn_rc != 0:
            errors.append(f"connection_churn proto_bench exited {churn_rc}")
        if soak_rc != 0:
            errors.append(f"soak proto_bench exited {soak_rc}")
        if reload_rc != 0:
            errors.append(f"reload_under_load proto_bench exited {reload_rc}")
        if not reload_signal_sent:
            errors.append("reload_under_load SIGHUP was not delivered")
        if not sample_usable(churn_sample):
            errors.append("connection_churn missing usable measurement sample")
        if not sample_usable(reload_sample):
            errors.append("reload_under_load missing usable measurement sample")
        if not sample_usable(soak_sample):
            errors.append("soak missing usable measurement sample")
        for name, series in (("rss_bytes", rss), ("fd_count", fds), ("task_count", tasks)):
            if len(series) < min_resource_samples:
                errors.append(
                    f"resource_plateau insufficient {name} sampling "
                    f"(need >= {min_resource_samples}, got {len(series)})"
                )

        print(
            json.dumps(
                {
                    "scenarios_written": str(output_dir / "scenarios.json"),
                    "sample_count": len(rss),
                    "churn_rc": churn_rc,
                    "soak_rc": soak_rc,
                    "reload_rc": reload_rc,
                    "errors": errors,
                }
            )
        )
        if errors:
            for err in errors:
                print(f"::error::scenario harness: {err}", file=sys.stderr)
            cleanup()
            return 1
        print("scenarios complete")
        cleanup()
        return 0
    except Exception as exc:  # pragma: no cover - infrastructure path
        print(f"::error::scenario harness crashed: {exc}", file=sys.stderr)
        cleanup()
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
