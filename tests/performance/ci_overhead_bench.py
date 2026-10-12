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
  6. Gate: error rate < 0.1% and non-2xx rate < 0.1% of attempted requests
  7. Gate: every timed gateway and backend run completed at least one
     successful (2xx) response. A run with no successes has no measured RPS,
     so it fails the check instead of producing an overhead or a 0% rate.

`--self-test` exercises the gate logic against synthetic samples without
opening any sockets.

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
        "attempted": total_completed + total_errors + total_non_2xx,
        "duration_secs": round(elapsed, 2),
    }


def attempted_requests(result):
    """Every request a run attempted: 2xx successes, non-2xx, and socket errors."""
    return result["total_requests"] + result["errors"] + result["non_2xx"]


def has_measured_success(result):
    """A timed run counts only if it completed 2xx work at a positive rate."""
    return result["total_requests"] > 0 and result["rps"] > 0


def iteration_overhead(gw, be):
    """Overhead percentage for one iteration, or None when it is unmeasurable.

    Without successful work on both sides there is no RPS ratio to report, so
    the caller must treat None as a failed measurement rather than 0%.
    """
    if not has_measured_success(gw) or not has_measured_success(be):
        return None
    return (1.0 - gw["rps"] / be["rps"]) * 100.0


def evaluate_gate(iterations, health_result, overhead_threshold):
    """Apply every gate to the timed samples and return (summary, issues).

    `iterations` is a list of (gateway_result, backend_result) pairs in the
    shape `run_load_test` returns. Pure function so `--self-test` can drive it.
    """
    issues = []
    overhead_samples = []
    total_errors = 0
    total_non_2xx = 0
    total_successes = 0
    total_attempted = 0

    if not iterations:
        issues.append("NO SAMPLES: no timed iterations ran")

    for index, (gw, be) in enumerate(iterations, start=1):
        for label, result in (("gateway", gw), ("backend", be)):
            total_errors += result["errors"]
            total_non_2xx += result["non_2xx"]
            total_successes += result["total_requests"]
            total_attempted += attempted_requests(result)
            if not has_measured_success(result):
                issues.append(
                    f"NO SUCCESS: iteration {index} {label} completed no successful "
                    f"(2xx) responses ({attempted_requests(result)} attempted, "
                    f"{result['errors']} socket errors, {result['non_2xx']} non-2xx)"
                )
        overhead_samples.append(iteration_overhead(gw, be))

    measured = [o for o in overhead_samples if o is not None]
    median_overhead = statistics.median(measured) if measured else None
    if median_overhead is not None and median_overhead > overhead_threshold:
        issues.append(
            f"OVERHEAD: median {median_overhead:.1f}% exceeds {overhead_threshold}% threshold"
        )

    # Allow a small error rate (0.1%) for transient CI runner noise (connection
    # resets, scheduling jitter). Hard-zero was too strict and caused flaky
    # failures. The denominator is every attempted request, so failed and
    # non-2xx work still counts; zero attempts is itself a failure above.
    if total_attempted > 0:
        error_rate_pct = total_errors / total_attempted * 100
        non_2xx_rate_pct = total_non_2xx / total_attempted * 100
    else:
        error_rate_pct = None
        non_2xx_rate_pct = None
        if iterations:
            issues.append("NO ATTEMPTS: timed iterations attempted no requests")

    if error_rate_pct is not None and error_rate_pct > 0.1:
        issues.append(
            f"ERRORS: {total_errors} socket errors ({error_rate_pct:.2f}% of "
            f"{total_attempted} attempted requests, threshold: 0.1%)"
        )

    if non_2xx_rate_pct is not None and non_2xx_rate_pct > 0.1:
        issues.append(
            f"NON-2XX: {total_non_2xx} non-2xx responses ({non_2xx_rate_pct:.2f}% of "
            f"{total_attempted} attempted requests, threshold: 0.1%)"
        )

    if health_result["errors"] > 0 or health_result["non_2xx"] > 0:
        issues.append(
            f"HEALTH: {health_result['errors']} errors, "
            f"{health_result['non_2xx']} non-2xx on health endpoint"
        )
    if not has_measured_success(health_result):
        issues.append("HEALTH: health endpoint completed no successful (2xx) responses")

    summary = {
        "overhead_samples": overhead_samples,
        "median_overhead": median_overhead,
        "total_errors": total_errors,
        "total_non_2xx": total_non_2xx,
        "total_successes": total_successes,
        "total_attempted": total_attempted,
        "error_rate_pct": error_rate_pct,
        "non_2xx_rate_pct": non_2xx_rate_pct,
    }
    return summary, issues


def _sample(successes, errors=0, non_2xx=0, duration=5.0):
    rps = round(successes / duration, 1) if duration > 0 else 0
    return {
        "rps": rps,
        "total_requests": successes,
        "errors": errors,
        "non_2xx": non_2xx,
        "attempted": successes + errors + non_2xx,
        "duration_secs": duration,
    }


def self_test():
    failures = []
    healthy = _sample(5000)
    threshold = 50.0

    def expect(name, iterations, health, want_prefixes):
        summary, issues = evaluate_gate(iterations, health, threshold)
        if not want_prefixes:
            if issues:
                failures.append(f"{name}: expected a pass, got {issues}")
            return summary
        for prefix in want_prefixes:
            if not any(issue.startswith(prefix) for issue in issues):
                failures.append(f"{name}: expected an issue starting {prefix!r}, got {issues}")
        return summary

    # Health succeeds first, then every timed attempt is a socket error on both
    # sides. Previously this reported 0% overhead and 0% error rate and passed.
    all_socket_errors = [(_sample(0, errors=40), _sample(0, errors=40))] * 3
    summary = expect("health-then-socket-errors", all_socket_errors, healthy, ["NO SUCCESS", "ERRORS"])
    if summary["median_overhead"] is not None:
        failures.append("health-then-socket-errors: zero successes must not yield an overhead value")

    # Health succeeds first, then every timed attempt returns non-2xx.
    all_non_2xx = [(_sample(0, non_2xx=900), _sample(0, non_2xx=900))] * 3
    expect("health-then-non-2xx", all_non_2xx, healthy, ["NO SUCCESS", "NON-2XX"])

    # A zero-success backend must not be read as "no overhead".
    zero_backend = [(_sample(4000), _sample(0, errors=10))] * 3
    summary = expect("zero-backend", zero_backend, healthy, ["NO SUCCESS"])
    if any(o is not None for o in summary["overhead_samples"]):
        failures.append("zero-backend: overhead must be unmeasurable without backend successes")

    # One iteration with zero gateway successes fails even if the others pass.
    one_empty = [(_sample(4000), _sample(5000)), (_sample(0), _sample(5000)), (_sample(4000), _sample(5000))]
    expect("one-empty-iteration", one_empty, healthy, ["NO SUCCESS"])

    # No timed iterations at all.
    expect("no-iterations", [], healthy, ["NO SAMPLES"])

    # Positive control: successes on both sides with modest overhead pass.
    good = [(_sample(4000), _sample(5000))] * 3
    summary = expect("positive-success", good, healthy, [])
    if summary["median_overhead"] is None or abs(summary["median_overhead"] - 20.0) > 0.01:
        failures.append(f"positive-success: expected 20% overhead, got {summary['median_overhead']}")

    # Positive backend RPS control: a real overhead above threshold still fails.
    slow_gateway = [(_sample(1000), _sample(5000))] * 3
    expect("positive-backend-rps-overhead", slow_gateway, healthy, ["OVERHEAD"])

    # Error-rate accounting over attempted work: 5 errors in ~2,005 attempts fail,
    # 5 errors in ~30,005 attempts stay under 0.1%.
    noisy = [(_sample(1000, errors=5), _sample(1000))]
    expect("error-rate-over-threshold", noisy, healthy, ["ERRORS"])
    quiet = [(_sample(15000, errors=5), _sample(15000))]
    expect("error-rate-under-threshold", quiet, healthy, [])

    # Health endpoint failures still fail even when timed samples are healthy.
    expect("health-errors", good, _sample(5000, errors=1), ["HEALTH"])
    expect("health-no-success", good, _sample(0, non_2xx=5), ["HEALTH"])

    if failures:
        for failure in failures:
            print(f"SELF-TEST FAILURE: {failure}")
        return 1
    print("ci_overhead_bench self-test passed.")
    return 0


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
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Exercise the gate logic against synthetic samples and exit",
    )

    args = parser.parse_args()
    if args.self_test:
        return self_test()
    if args.iterations < 1:
        parser.error("--iterations must be at least 1")

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
    iterations = []

    for i in range(1, args.iterations + 1):
        print(f"Iteration {i}/{args.iterations}:")

        # Alternate order: odd iterations run gateway first, even run backend
        # first. This prevents systematic bias from CI runner load fluctuations
        # that correlate with measurement position within each iteration.
        gateway_first = (i % 2 == 1)

        if gateway_first:
            gw = run_load_test(args.gateway_url, args.duration, args.concurrency)
            be = run_load_test(args.backend_url, args.duration, args.concurrency)
        else:
            be = run_load_test(args.backend_url, args.duration, args.concurrency)
            gw = run_load_test(args.gateway_url, args.duration, args.concurrency)

        iterations.append((gw, be))
        gateway_rps_samples.append(gw["rps"])
        print(
            f"  Gateway:  {gw['rps']:>10.0f} RPS  "
            f"({gw['total_requests']} reqs, {gw['errors']} err, {gw['non_2xx']} non-2xx)"
        )

        backend_rps_samples.append(be["rps"])
        print(
            f"  Backend:  {be['rps']:>10.0f} RPS  "
            f"({be['total_requests']} reqs, {be['errors']} err, {be['non_2xx']} non-2xx)"
        )

        overhead = iteration_overhead(gw, be)
        if overhead is None:
            print("  Overhead:   unmeasurable (no successful responses on a timed side)")
        else:
            print(f"  Overhead: {overhead:>10.1f}%")
        print()

    # ── Results ─────────────────────────────────────────────────────────
    summary, issues = evaluate_gate(iterations, health_result, args.overhead_threshold)
    overhead_samples = summary["overhead_samples"]
    median_overhead = summary["median_overhead"]
    total_errors = summary["total_errors"]
    total_non_2xx = summary["total_non_2xx"]
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
    if median_overhead is None:
        print(f"  Median overhead:        unmeasurable  (limit: {args.overhead_threshold}%)")
    else:
        print(f"  Median overhead:        {median_overhead:>10.1f}%  (limit: {args.overhead_threshold}%)")
    per_iteration = ", ".join("n/a" if o is None else f"{o:.1f}%" for o in overhead_samples)
    print(f"  Per-iteration overhead: {per_iteration}")
    print(f"  Total attempted:        {summary['total_attempted']}")
    print(f"  Total successes:        {summary['total_successes']}")
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
        "median_overhead_pct": (
            None if median_overhead is None else round(median_overhead, 2)
        ),
        "health_rps": health_result["rps"],
        "gateway_cv_pct": round(gw_cv, 2),
        "backend_cv_pct": round(be_cv, 2),
        "total_errors": total_errors,
        "total_non_2xx": total_non_2xx,
        "total_successes": summary["total_successes"],
        "total_attempted": summary["total_attempted"],
        "issues": issues,
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
