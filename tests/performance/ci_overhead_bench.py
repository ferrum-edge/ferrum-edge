#!/usr/bin/env python3
"""
CI performance regression detector using self-relative overhead measurement.

Instead of comparing against stored baselines (which vary across CI runners),
this measures the gateway's overhead ratio vs direct backend access within the
same run. The ratio is stable across different hardware because both measurements
experience the same CPU/memory/scheduling characteristics.

Algorithm:
  1. Warmup both targets (2s each, results discarded)
  2. Run N iterations of: load-test gateway, load-test backend directly
  3. Compute per-iteration overhead ratio = 1 - (gateway_rps / direct_rps)
  4. Take median of the N ratios
  5. Gate: median overhead < threshold (default 50%)
  6. Gate: zero socket errors and zero non-2xx responses

Total runtime: ~60s (2s warmup x2 + 3 iterations x (5s+5s) + overhead)
"""

import argparse
import concurrent.futures
import http.client
import json
import statistics
import sys
import time
from urllib.parse import urlparse


def run_load_test(url, duration_secs=5, concurrency=50):
    """Run an HTTP load test and return RPS + error counts.

    Uses stdlib http.client with connection keep-alive in a thread pool.
    Python's GIL is released during socket I/O, so threading is fine for
    I/O-bound HTTP workloads. Absolute throughput is lower than wrk/hey,
    but since we only compare ratios, that doesn't matter.
    """
    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port
    path = parsed.path or "/"

    deadline = time.monotonic() + duration_secs

    def worker():
        completed = 0
        errors = 0
        non_2xx = 0
        conn = http.client.HTTPConnection(host, port, timeout=5)
        try:
            while time.monotonic() < deadline:
                try:
                    conn.request("GET", path, headers={"Connection": "keep-alive"})
                    resp = conn.getresponse()
                    resp.read()
                    if 200 <= resp.status < 300:
                        completed += 1
                    else:
                        non_2xx += 1
                except Exception:
                    errors += 1
                    try:
                        conn.close()
                        conn = http.client.HTTPConnection(host, port, timeout=5)
                    except Exception:
                        pass
        finally:
            try:
                conn.close()
            except Exception:
                pass
        return completed, errors, non_2xx

    start = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [pool.submit(worker) for _ in range(concurrency)]
        results = [f.result() for f in futures]
    elapsed = time.monotonic() - start

    total_completed = sum(r[0] for r in results)
    total_errors = sum(r[1] for r in results)
    total_non_2xx = sum(r[2] for r in results)
    rps = total_completed / elapsed if elapsed > 0 else 0

    return {
        "rps": round(rps, 1),
        "total_requests": total_completed,
        "errors": total_errors,
        "non_2xx": total_non_2xx,
        "duration_secs": round(elapsed, 2),
    }


def main():
    parser = argparse.ArgumentParser(
        description="Self-relative performance regression detector"
    )
    parser.add_argument(
        "--gateway-url",
        default="http://127.0.0.1:8000/api/users",
        help="URL to test through the gateway",
    )
    parser.add_argument(
        "--backend-url",
        default="http://127.0.0.1:3001/api/users",
        help="URL to test directly against the backend",
    )
    parser.add_argument(
        "--gateway-health-url",
        default="http://127.0.0.1:8000/health",
        help="Gateway health URL (tested in addition to the main endpoint)",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=50,
        help="Concurrent connections per test (default: 50)",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=5,
        help="Seconds per test iteration (default: 5)",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=3,
        help="Number of measurement iterations (default: 3)",
    )
    parser.add_argument(
        "--warmup",
        type=int,
        default=2,
        help="Warmup duration in seconds (default: 2)",
    )
    parser.add_argument(
        "--overhead-threshold",
        type=float,
        default=50.0,
        help="Max allowed overhead %% (default: 50)",
    )
    parser.add_argument(
        "--output",
        help="Write JSON results to file",
    )

    args = parser.parse_args()

    print("=" * 70)
    print("SELF-RELATIVE PERFORMANCE REGRESSION CHECK")
    print("=" * 70)
    print(f"  Gateway URL:     {args.gateway_url}")
    print(f"  Backend URL:     {args.backend_url}")
    print(f"  Concurrency:     {args.concurrency}")
    print(f"  Duration/iter:   {args.duration}s")
    print(f"  Iterations:      {args.iterations}")
    print(f"  Overhead limit:  {args.overhead_threshold}%")
    print()

    # ── Warmup ──────────────────────────────────────────────────────────
    print(f"Warming up gateway ({args.warmup}s)...")
    run_load_test(args.gateway_url, args.warmup, args.concurrency)
    print(f"Warming up backend ({args.warmup}s)...")
    run_load_test(args.backend_url, args.warmup, args.concurrency)
    print()

    # ── Health endpoint quick check ─────────────────────────────────────
    print(f"Health endpoint check ({args.duration}s)...")
    health_result = run_load_test(
        args.gateway_health_url, args.duration, args.concurrency
    )
    print(
        f"  Health: {health_result['rps']:.0f} RPS, "
        f"{health_result['errors']} errors, "
        f"{health_result['non_2xx']} non-2xx"
    )
    print()

    # ── Measurement iterations ──────────────────────────────────────────
    gateway_rps_samples = []
    backend_rps_samples = []
    overhead_samples = []
    total_errors = 0
    total_non_2xx = 0

    for i in range(1, args.iterations + 1):
        print(f"Iteration {i}/{args.iterations}:")

        gw = run_load_test(args.gateway_url, args.duration, args.concurrency)
        gateway_rps_samples.append(gw["rps"])
        total_errors += gw["errors"]
        total_non_2xx += gw["non_2xx"]
        print(
            f"  Gateway:  {gw['rps']:>10.0f} RPS  "
            f"({gw['total_requests']} reqs, {gw['errors']} err, {gw['non_2xx']} non-2xx)"
        )

        be = run_load_test(args.backend_url, args.duration, args.concurrency)
        backend_rps_samples.append(be["rps"])
        total_errors += be["errors"]
        total_non_2xx += be["non_2xx"]
        print(
            f"  Backend:  {be['rps']:>10.0f} RPS  "
            f"({be['total_requests']} reqs, {be['errors']} err, {be['non_2xx']} non-2xx)"
        )

        if be["rps"] > 0:
            overhead = (1.0 - gw["rps"] / be["rps"]) * 100.0
        else:
            overhead = 0.0
        overhead_samples.append(overhead)
        print(f"  Overhead: {overhead:>10.1f}%")
        print()

    # ── Results ─────────────────────────────────────────────────────────
    median_overhead = statistics.median(overhead_samples)
    median_gw_rps = statistics.median(gateway_rps_samples)
    median_be_rps = statistics.median(backend_rps_samples)

    # Coefficient of variation (stdev/mean) — measures noise level
    gw_cv = (
        (statistics.stdev(gateway_rps_samples) / statistics.mean(gateway_rps_samples) * 100)
        if len(gateway_rps_samples) > 1 and statistics.mean(gateway_rps_samples) > 0
        else 0
    )
    be_cv = (
        (statistics.stdev(backend_rps_samples) / statistics.mean(backend_rps_samples) * 100)
        if len(backend_rps_samples) > 1 and statistics.mean(backend_rps_samples) > 0
        else 0
    )

    print("=" * 70)
    print("RESULTS")
    print("=" * 70)
    print(f"  Gateway RPS (median):   {median_gw_rps:>10.0f}  (CV: {gw_cv:.1f}%)")
    print(f"  Backend RPS (median):   {median_be_rps:>10.0f}  (CV: {be_cv:.1f}%)")
    print(f"  Health RPS:             {health_result['rps']:>10.0f}")
    print(f"  Median overhead:        {median_overhead:>10.1f}%  (limit: {args.overhead_threshold}%)")
    print(f"  Per-iteration overhead: {', '.join(f'{o:.1f}%' for o in overhead_samples)}")
    print(f"  Total errors:           {total_errors}")
    print(f"  Total non-2xx:          {total_non_2xx}")
    print()

    # ── Write JSON output ───────────────────────────────────────────────
    results = {
        "gateway_rps_samples": gateway_rps_samples,
        "backend_rps_samples": backend_rps_samples,
        "overhead_samples": overhead_samples,
        "median_gateway_rps": median_gw_rps,
        "median_backend_rps": median_be_rps,
        "median_overhead_pct": round(median_overhead, 2),
        "health_rps": health_result["rps"],
        "gateway_cv_pct": round(gw_cv, 2),
        "backend_cv_pct": round(be_cv, 2),
        "total_errors": total_errors,
        "total_non_2xx": total_non_2xx,
        "config": {
            "concurrency": args.concurrency,
            "duration_secs": args.duration,
            "iterations": args.iterations,
            "overhead_threshold_pct": args.overhead_threshold,
        },
    }

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"Results written to {args.output}")

    # ── Gate checks ─────────────────────────────────────────────────────
    issues = []

    if median_overhead > args.overhead_threshold:
        issues.append(
            f"OVERHEAD: median {median_overhead:.1f}% exceeds {args.overhead_threshold}% threshold"
        )

    if total_errors > 0:
        issues.append(f"ERRORS: {total_errors} socket errors during test")

    if total_non_2xx > 0:
        issues.append(f"NON-2XX: {total_non_2xx} non-2xx responses during test")

    if health_result["errors"] > 0 or health_result["non_2xx"] > 0:
        issues.append(
            f"HEALTH: {health_result['errors']} errors, "
            f"{health_result['non_2xx']} non-2xx on health endpoint"
        )

    if gw_cv > 30:
        # High variance suggests the CI runner is very unstable — warn but don't fail
        print(
            f"WARNING: Gateway RPS coefficient of variation is {gw_cv:.1f}% "
            f"(>30%), results may be unreliable due to CI runner noise."
        )

    if issues:
        print("REGRESSION DETECTED:")
        for issue in issues:
            print(f"  - {issue}")
        print()
        print(
            "If this overhead is expected (e.g. a new plugin phase was added), "
            "increase --overhead-threshold."
        )
        return 1
    else:
        print("Performance check PASSED.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
