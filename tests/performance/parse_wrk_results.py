#!/usr/bin/env python3
"""
Parse wrk output files into a single JSON results file for CI comparison.
"""

import argparse
import json
import re
import sys
from datetime import datetime, timezone


def parse_latency_to_us(latency_str):
    """Convert latency string to microseconds for consistent comparison."""
    latency_str = latency_str.strip()
    if latency_str.endswith("ms"):
        return float(latency_str[:-2]) * 1000
    elif latency_str.endswith("us") or latency_str.endswith("μs"):
        return float(latency_str.replace("μ", "")[:-2])
    elif latency_str.endswith("s"):
        return float(latency_str[:-1]) * 1_000_000
    else:
        return float(latency_str)


def parse_wrk_output(file_path):
    """Parse a single wrk output file into structured metrics."""
    with open(file_path, "r") as f:
        content = f.read()

    metrics = {}

    # Requests/sec
    m = re.search(r"Requests/sec:\s+([\d.]+)", content)
    if m:
        metrics["rps"] = float(m.group(1))

    # Transfer/sec
    m = re.search(r"Transfer/sec:\s+([\d.]+\S+)", content)
    if m:
        metrics["transfer_per_sec"] = m.group(1)

    # Latency: Avg, Stdev, Max
    # wrk format: "Latency   1.23ms  456.78us  12.34ms"
    m = re.search(
        r"Latency\s+([\d.]+[munμ]?s)\s+([\d.]+[munμ]?s)\s+([\d.]+[munμ]?s)", content
    )
    if m:
        metrics["latency_avg_us"] = parse_latency_to_us(m.group(1))
        metrics["latency_stdev_us"] = parse_latency_to_us(m.group(2))
        metrics["latency_max_us"] = parse_latency_to_us(m.group(3))
        metrics["latency_avg_display"] = m.group(1)
        metrics["latency_max_display"] = m.group(3)

    # Latency distribution (percentiles)
    # wrk --latency format:
    #   50%    1.23ms
    #   75%    2.34ms
    #   90%    3.45ms
    #   99%    4.56ms
    percentiles = {}
    for pct_match in re.finditer(
        r"\s+(50|75|90|99)%\s+([\d.]+[munμ]?s)", content
    ):
        pct = f"p{pct_match.group(1)}"
        percentiles[f"{pct}_us"] = parse_latency_to_us(pct_match.group(2))
        percentiles[f"{pct}_display"] = pct_match.group(2)
    metrics["percentiles"] = percentiles

    # Total requests
    m = re.search(r"(\d+)\s+requests in", content)
    if m:
        metrics["total_requests"] = int(m.group(1))

    # Socket errors
    m = re.search(
        r"Socket errors: connect (\d+), read (\d+), write (\d+), timeout (\d+)",
        content,
    )
    if m:
        metrics["errors"] = {
            "connect": int(m.group(1)),
            "read": int(m.group(2)),
            "write": int(m.group(3)),
            "timeout": int(m.group(4)),
        }
    else:
        metrics["errors"] = {"connect": 0, "read": 0, "write": 0, "timeout": 0}

    # Non-2xx responses
    m = re.search(r"Non-2xx or 3xx responses:\s+(\d+)", content)
    if m:
        metrics["non_2xx_responses"] = int(m.group(1))
    else:
        # Also check custom script output
        m = re.search(r"Non-2xx responses:\s+(\d+)", content)
        metrics["non_2xx_responses"] = int(m.group(1)) if m else 0

    return metrics


def main():
    parser = argparse.ArgumentParser(
        description="Parse wrk results into JSON"
    )
    parser.add_argument("--health", required=True, help="Health check results file")
    parser.add_argument("--users", required=True, help="Users API results file")
    parser.add_argument("--backend", required=True, help="Backend baseline results file")
    parser.add_argument("--output", required=True, help="Output JSON file")

    args = parser.parse_args()

    results = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tests": {
            "health": parse_wrk_output(args.health),
            "users": parse_wrk_output(args.users),
            "backend_baseline": parse_wrk_output(args.backend),
        },
    }

    # Compute gateway overhead metrics
    users = results["tests"]["users"]
    backend = results["tests"]["backend_baseline"]
    if "rps" in users and "rps" in backend and backend["rps"] > 0:
        results["overhead"] = {
            "rps_reduction_pct": round(
                ((backend["rps"] - users["rps"]) / backend["rps"]) * 100, 2
            ),
            "latency_added_us": round(
                users.get("latency_avg_us", 0) - backend.get("latency_avg_us", 0), 2
            ),
        }

    with open(args.output, "w") as f:
        json.dump(results, f, indent=2)

    print(f"Results written to {args.output}")


if __name__ == "__main__":
    main()
