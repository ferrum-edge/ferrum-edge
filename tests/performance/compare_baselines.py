#!/usr/bin/env python3
"""
Compare current performance results against a stored baseline.
Exits with non-zero status if a regression is detected.

Regression thresholds (configurable via env vars):
  PERF_RPS_REGRESSION_PCT       - Max allowed RPS drop % (default: 15)
  PERF_LATENCY_REGRESSION_PCT   - Max allowed latency increase % (default: 25)
  PERF_P95_REGRESSION_PCT       - Max allowed p95 latency increase % (default: 30)
  PERF_ERROR_THRESHOLD          - Max allowed total errors (default: 10)
  PERF_OVERHEAD_MAX_PCT         - Max allowed gateway overhead % (default: 25)

CI environments have inherent variance, so thresholds are intentionally generous.
The goal is to catch major regressions, not micro-optimizations. P99 latency is
reported for visibility but not gated on — CI noise makes p99 too volatile for
reliable regression detection. P95 (interpolated from p90/p99) is used instead.
"""

import argparse
import json
import os
import sys


def get_threshold(env_var, default):
    return float(os.environ.get(env_var, default))


# Thresholds
RPS_REGRESSION_PCT = get_threshold("PERF_RPS_REGRESSION_PCT", 15)
LATENCY_REGRESSION_PCT = get_threshold("PERF_LATENCY_REGRESSION_PCT", 25)
P95_REGRESSION_PCT = get_threshold("PERF_P95_REGRESSION_PCT", 30)
ERROR_THRESHOLD = int(get_threshold("PERF_ERROR_THRESHOLD", 10))
OVERHEAD_MAX_PCT = get_threshold("PERF_OVERHEAD_MAX_PCT", 25)


def pct_change(old, new):
    """Percentage change from old to new."""
    if old == 0:
        return 0
    return ((new - old) / old) * 100


def _interpolate_p95(percentiles):
    """Interpolate P95 from P90 and P99 (wrk only reports 50/75/90/99).

    Uses linear interpolation: p95 = p90 + (p99 - p90) * 5/9.
    Returns None if either percentile is missing.
    """
    p90 = percentiles.get("p90_us")
    p99 = percentiles.get("p99_us")
    if p90 is not None and p99 is not None:
        return p90 + (p99 - p90) * (5.0 / 9.0)
    return None


def check_test(name, baseline_test, current_test, issues, warnings):
    """Compare a single test's metrics against baseline."""
    b = baseline_test
    c = current_test

    # --- RPS (higher is better) ---
    if "rps" in b and "rps" in c:
        rps_change = pct_change(b["rps"], c["rps"])
        if rps_change < -RPS_REGRESSION_PCT:
            issues.append(
                f"  REGRESSION [{name}] RPS dropped {abs(rps_change):.1f}% "
                f"(baseline: {b['rps']:.0f}, current: {c['rps']:.0f}, "
                f"threshold: {RPS_REGRESSION_PCT}%)"
            )
        elif rps_change < -(RPS_REGRESSION_PCT / 2):
            warnings.append(
                f"  WARNING [{name}] RPS dropped {abs(rps_change):.1f}% "
                f"(baseline: {b['rps']:.0f}, current: {c['rps']:.0f})"
            )
        elif rps_change > 5:
            warnings.append(
                f"  IMPROVED [{name}] RPS increased {rps_change:.1f}% "
                f"(baseline: {b['rps']:.0f}, current: {c['rps']:.0f})"
            )

    # --- Average latency (lower is better) ---
    if "latency_avg_us" in b and "latency_avg_us" in c:
        lat_change = pct_change(b["latency_avg_us"], c["latency_avg_us"])
        if lat_change > LATENCY_REGRESSION_PCT:
            issues.append(
                f"  REGRESSION [{name}] Avg latency increased {lat_change:.1f}% "
                f"(baseline: {b['latency_avg_us']:.0f}us, "
                f"current: {c['latency_avg_us']:.0f}us, "
                f"threshold: {LATENCY_REGRESSION_PCT}%)"
            )
        elif lat_change > (LATENCY_REGRESSION_PCT / 2):
            warnings.append(
                f"  WARNING [{name}] Avg latency increased {lat_change:.1f}% "
                f"(baseline: {b['latency_avg_us']:.0f}us, "
                f"current: {c['latency_avg_us']:.0f}us)"
            )

    # --- P95 latency (lower is better) ---
    # wrk only reports p50/p75/p90/p99; we interpolate p95 as the midpoint.
    # P99 is too volatile in CI (noisy neighbors, GC pauses) to gate on reliably.
    b_p95 = _interpolate_p95(b.get("percentiles", {}))
    c_p95 = _interpolate_p95(c.get("percentiles", {}))
    if b_p95 and c_p95:
        p95_change = pct_change(b_p95, c_p95)
        if p95_change > P95_REGRESSION_PCT:
            issues.append(
                f"  REGRESSION [{name}] P95 latency increased {p95_change:.1f}% "
                f"(baseline: {b_p95:.0f}us, current: {c_p95:.0f}us, "
                f"threshold: {P95_REGRESSION_PCT}%)"
            )
        elif p95_change > (P95_REGRESSION_PCT / 2):
            warnings.append(
                f"  WARNING [{name}] P95 latency increased {p95_change:.1f}% "
                f"(baseline: {b_p95:.0f}us, current: {c_p95:.0f}us)"
            )

    # --- Errors ---
    c_errors = c.get("errors", {})
    total_errors = sum(c_errors.values())
    if total_errors > ERROR_THRESHOLD:
        issues.append(
            f"  REGRESSION [{name}] {total_errors} socket errors detected "
            f"(threshold: {ERROR_THRESHOLD})"
        )

    non_2xx = c.get("non_2xx_responses", 0)
    if non_2xx > 0:
        total_req = c.get("total_requests", 1)
        error_rate = (non_2xx / total_req) * 100
        if error_rate > 1:
            issues.append(
                f"  REGRESSION [{name}] {error_rate:.1f}% non-2xx responses "
                f"({non_2xx}/{total_req})"
            )
        elif non_2xx > 0:
            warnings.append(
                f"  WARNING [{name}] {non_2xx} non-2xx responses "
                f"({error_rate:.2f}%)"
            )


def print_summary_table(baseline, current):
    """Print a human-readable comparison table."""
    print("\n" + "=" * 78)
    print("PERFORMANCE COMPARISON REPORT")
    print("=" * 78)

    for test_name in ["health", "users", "backend_baseline"]:
        b = baseline.get("tests", {}).get(test_name, {})
        c = current.get("tests", {}).get(test_name, {})
        if not b or not c:
            continue

        label = test_name.replace("_", " ").title()
        print(f"\n--- {label} ---")
        print(f"  {'Metric':<25} {'Baseline':>15} {'Current':>15} {'Change':>12}")
        print(f"  {'-'*25} {'-'*15} {'-'*15} {'-'*12}")

        if "rps" in b and "rps" in c:
            change = pct_change(b["rps"], c["rps"])
            sign = "+" if change >= 0 else ""
            print(
                f"  {'RPS':<25} {b['rps']:>15.0f} {c['rps']:>15.0f} {sign}{change:>10.1f}%"
            )

        if "latency_avg_us" in b and "latency_avg_us" in c:
            change = pct_change(b["latency_avg_us"], c["latency_avg_us"])
            sign = "+" if change >= 0 else ""
            b_display = b.get("latency_avg_display", f"{b['latency_avg_us']:.0f}us")
            c_display = c.get("latency_avg_display", f"{c['latency_avg_us']:.0f}us")
            print(
                f"  {'Avg Latency':<25} {b_display:>15} {c_display:>15} {sign}{change:>10.1f}%"
            )

        if "latency_max_us" in b and "latency_max_us" in c:
            change = pct_change(b["latency_max_us"], c["latency_max_us"])
            sign = "+" if change >= 0 else ""
            b_display = b.get("latency_max_display", f"{b['latency_max_us']:.0f}us")
            c_display = c.get("latency_max_display", f"{c['latency_max_us']:.0f}us")
            print(
                f"  {'Max Latency':<25} {b_display:>15} {c_display:>15} {sign}{change:>10.1f}%"
            )

        for pct in ["p50", "p75", "p90"]:
            b_val = b.get("percentiles", {}).get(f"{pct}_us")
            c_val = c.get("percentiles", {}).get(f"{pct}_us")
            if b_val and c_val:
                change = pct_change(b_val, c_val)
                sign = "+" if change >= 0 else ""
                b_display = b["percentiles"].get(f"{pct}_display", f"{b_val:.0f}us")
                c_display = c["percentiles"].get(f"{pct}_display", f"{c_val:.0f}us")
                print(
                    f"  {pct.upper() + ' Latency':<25} {b_display:>15} {c_display:>15} {sign}{change:>10.1f}%"
                )

        # P95 (interpolated from p90/p99) — this is the gated percentile
        b_p95 = _interpolate_p95(b.get("percentiles", {}))
        c_p95 = _interpolate_p95(c.get("percentiles", {}))
        if b_p95 and c_p95:
            change = pct_change(b_p95, c_p95)
            sign = "+" if change >= 0 else ""
            print(
                f"  {'P95 Latency (gated)':<25} {b_p95/1000:>14.2f}ms {c_p95/1000:>14.2f}ms {sign}{change:>10.1f}%"
            )

        # P99 — informational only, not gated (too volatile in CI)
        b_p99 = b.get("percentiles", {}).get("p99_us")
        c_p99 = c.get("percentiles", {}).get("p99_us")
        if b_p99 and c_p99:
            change = pct_change(b_p99, c_p99)
            sign = "+" if change >= 0 else ""
            b_display = b["percentiles"].get("p99_display", f"{b_p99:.0f}us")
            c_display = c["percentiles"].get("p99_display", f"{c_p99:.0f}us")
            print(
                f"  {'P99 Latency (info)':<25} {b_display:>15} {c_display:>15} {sign}{change:>10.1f}%"
            )

        b_errors = sum(b.get("errors", {}).values())
        c_errors = sum(c.get("errors", {}).values())
        print(f"  {'Socket Errors':<25} {b_errors:>15} {c_errors:>15}")

    # Overhead comparison
    b_overhead = baseline.get("overhead", {})
    c_overhead = current.get("overhead", {})
    if b_overhead and c_overhead:
        print(f"\n--- Gateway Overhead ---")
        print(
            f"  {'RPS Overhead':<25} {b_overhead.get('rps_reduction_pct', 0):>14.1f}% "
            f"{c_overhead.get('rps_reduction_pct', 0):>14.1f}%"
        )
        b_lat = b_overhead.get("latency_added_us", 0)
        c_lat = c_overhead.get("latency_added_us", 0)
        print(
            f"  {'Added Latency':<25} {b_lat:>13.0f}us {c_lat:>13.0f}us"
        )


def main():
    parser = argparse.ArgumentParser(
        description="Compare performance results against baseline"
    )
    parser.add_argument(
        "--baseline", required=True, help="Path to baseline JSON"
    )
    parser.add_argument(
        "--current", required=True, help="Path to current results JSON"
    )

    args = parser.parse_args()

    with open(args.baseline) as f:
        baseline = json.load(f)
    with open(args.current) as f:
        current = json.load(f)

    issues = []
    warnings = []

    # Compare each test
    for test_name in ["health", "users"]:
        b_test = baseline.get("tests", {}).get(test_name, {})
        c_test = current.get("tests", {}).get(test_name, {})
        if b_test and c_test:
            check_test(test_name, b_test, c_test, issues, warnings)

    # Check gateway overhead hasn't grown too much
    c_overhead = current.get("overhead", {})
    if c_overhead:
        overhead_pct = c_overhead.get("rps_reduction_pct", 0)
        if overhead_pct > OVERHEAD_MAX_PCT:
            issues.append(
                f"  REGRESSION [overhead] Gateway overhead is {overhead_pct:.1f}% "
                f"(threshold: {OVERHEAD_MAX_PCT}%)"
            )

    # Print comparison table
    print_summary_table(baseline, current)

    # Print findings
    if warnings:
        print(f"\nWarnings ({len(warnings)}):")
        for w in warnings:
            print(w)

    if issues:
        print(f"\nRegressions detected ({len(issues)}):")
        for issue in issues:
            print(issue)
        print(
            f"\nPerformance regression check FAILED. "
            f"If this is expected (e.g. adding necessary overhead), "
            f"update the baseline with: ./ci_perf_test.sh --save-baseline"
        )
        return 1
    else:
        print("\nPerformance regression check PASSED.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
