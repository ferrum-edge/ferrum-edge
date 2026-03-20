#!/usr/bin/env python3
"""
Generate HTML comparison report from multi-gateway wrk benchmark results.

Usage:
    python3 generate_comparison_report.py results/

Expects result files named: {gateway}_{protocol}_{endpoint}_results.txt
Example: ferrum_http_health_results.txt, kong_https_users_results.txt
"""

import os
import re
import sys
from datetime import datetime
from pathlib import Path


# ---------------------------------------------------------------------------
# wrk output parsing
# ---------------------------------------------------------------------------

def parse_wrk_output(file_path):
    """Parse wrk output including the machine-parseable comparison block."""
    with open(file_path, "r") as f:
        content = f.read()

    metrics = {}

    # --- Standard wrk header parsing (fallback) ---
    rps_match = re.search(r"Requests/sec:\s+([\d.]+)", content)
    if rps_match:
        metrics["rps"] = float(rps_match.group(1))

    transfer_match = re.search(r"Transfer/sec:\s+([\d.]+[KMGT]?B)", content)
    if transfer_match:
        metrics["transfer"] = transfer_match.group(1)

    latency_match = re.search(r"Latency\s+([\d.]+[munμ]?s)", content)
    if latency_match:
        metrics["latency_avg_str"] = latency_match.group(1)
        metrics["latency_avg_ms"] = _latency_to_ms(latency_match.group(1))

    requests_match = re.search(r"(\d+)\s+requests in", content)
    if requests_match:
        metrics["total_requests"] = int(requests_match.group(1))

    non2xx_match = re.search(r"Non-2xx or 3xx responses:\s+(\d+)", content)
    if non2xx_match:
        metrics["non2xx"] = int(non2xx_match.group(1))

    # --- Machine-parseable block from comparison_test.lua ---
    block = re.search(
        r"--- Comparison Results ---\n(.*?)--- End Results ---",
        content,
        re.DOTALL,
    )
    if block:
        for line in block.group(1).strip().splitlines():
            key, _, value = line.partition(":")
            key = key.strip()
            value = value.strip()
            try:
                metrics[key] = float(value)
            except ValueError:
                metrics[key] = value

        # Compute convenience fields from the machine block
        if "latency_mean_us" in metrics:
            metrics["latency_avg_ms"] = metrics["latency_mean_us"] / 1000.0
        if "latency_p50_us" in metrics:
            metrics["latency_p50_ms"] = metrics["latency_p50_us"] / 1000.0
        if "latency_p90_us" in metrics:
            metrics["latency_p90_ms"] = metrics["latency_p90_us"] / 1000.0
        if "latency_p99_us" in metrics:
            metrics["latency_p99_ms"] = metrics["latency_p99_us"] / 1000.0
        if "latency_p999_us" in metrics:
            metrics["latency_p999_ms"] = metrics["latency_p999_us"] / 1000.0
        if "errors_status" in metrics:
            metrics["error_count"] = int(
                metrics.get("errors_status", 0)
                + metrics.get("errors_connect", 0)
                + metrics.get("errors_read", 0)
                + metrics.get("errors_write", 0)
                + metrics.get("errors_timeout", 0)
            )

    return metrics


def _latency_to_ms(s):
    """Convert a human-readable latency string to milliseconds."""
    if s.endswith("us") or s.endswith("μs"):
        return float(re.sub(r"[^\d.]", "", s)) / 1000.0
    elif s.endswith("ms"):
        return float(s[:-2])
    elif s.endswith("s"):
        return float(s[:-1]) * 1000.0
    return float(s)


# ---------------------------------------------------------------------------
# Result file discovery
# ---------------------------------------------------------------------------

GATEWAYS = ["baseline", "ferrum", "kong", "tyk"]
PROTOCOLS = ["http", "https", "e2e_tls"]
ENDPOINTS = ["health", "users"]


def _gateway_labels(meta):
    """Build gateway display labels based on metadata (native vs Docker)."""
    kong_native = meta.get("kong_native", False)
    kong_ver = meta.get("kong_version", "")
    tyk_ver = meta.get("tyk_version", "")
    return {
        "baseline": "Direct Backend",
        "ferrum": "Ferrum Gateway (native)",
        "kong": f"Kong Gateway ({'native' if kong_native else 'Docker'})" if not kong_ver else f"Kong ({kong_ver})",
        "tyk": f"Tyk ({tyk_ver})" if tyk_ver else "Tyk Gateway (Docker)",
    }


# Default labels (overridden by metadata at report generation time)
GATEWAY_LABELS = _gateway_labels({})


def discover_results(results_dir):
    """Scan results_dir for files matching the naming convention.

    Returns dict[gateway][protocol][endpoint] = metrics
    """
    data = {}
    for fname in sorted(os.listdir(results_dir)):
        if not fname.endswith("_results.txt"):
            continue
        parts = fname.replace("_results.txt", "").split("_")
        if len(parts) != 3:
            continue
        gw, proto, ep = parts
        if gw not in GATEWAYS or proto not in PROTOCOLS or ep not in ENDPOINTS:
            continue
        data.setdefault(gw, {}).setdefault(proto, {})[ep] = parse_wrk_output(
            os.path.join(results_dir, fname)
        )
    return data


# ---------------------------------------------------------------------------
# HTML report generation
# ---------------------------------------------------------------------------

def _fmt(val, suffix="", decimals=2):
    if val is None:
        return "N/A"
    if isinstance(val, float):
        return f"{val:,.{decimals}f}{suffix}"
    return f"{val:,}{suffix}"


def _best_worst(values):
    """Return (best_idx, worst_idx) for a list of (value, is_lower_better) tuples."""
    nums = [(i, v) for i, (v, _) in enumerate(values) if v is not None]
    if not nums:
        return None, None
    lower_is_better = values[0][1] if values else True
    best = min(nums, key=lambda x: x[1]) if lower_is_better else max(nums, key=lambda x: x[1])
    worst = max(nums, key=lambda x: x[1]) if lower_is_better else min(nums, key=lambda x: x[1])
    return best[0], worst[0]


def _cell(val, suffix, idx, best_idx, worst_idx, decimals=2):
    css = ""
    if idx == best_idx:
        css = ' class="best"'
    elif idx == worst_idx:
        css = ' class="worst"'
    return f"<td{css}>{_fmt(val, suffix, decimals)}</td>"


def _build_table(data, protocol, endpoint, baseline_metrics):
    """Build an HTML table comparing gateways for one protocol+endpoint combo."""
    gws = [g for g in GATEWAYS if g != "baseline" and g in data and protocol in data[g] and endpoint in data[g][protocol]]
    if not gws:
        return "<p>No results available.</p>"

    rows_data = []
    for gw in gws:
        m = data[gw][protocol][endpoint]
        rows_data.append((gw, m))

    # Collect values for coloring
    rps_vals = [(m.get("rps"), False) for _, m in rows_data]
    lat_vals = [(m.get("latency_avg_ms"), True) for _, m in rows_data]
    p99_vals = [(m.get("latency_p99_ms"), True) for _, m in rows_data]
    err_vals = [(m.get("error_count", 0), True) for _, m in rows_data]

    rps_best, rps_worst = _best_worst(rps_vals)
    lat_best, lat_worst = _best_worst(lat_vals)
    p99_best, p99_worst = _best_worst(p99_vals)
    err_best, err_worst = _best_worst(err_vals)

    html = """<table>
<thead><tr>
  <th>Gateway</th><th>Requests/sec</th><th>Avg Latency</th>
  <th>P50</th><th>P99</th><th>Errors</th><th>vs Baseline</th>
</tr></thead><tbody>\n"""

    bl_rps = baseline_metrics.get("rps") if baseline_metrics else None

    for i, (gw, m) in enumerate(rows_data):
        rps = m.get("rps")
        overhead = ""
        if bl_rps and rps:
            pct = ((bl_rps - rps) / bl_rps) * 100
            if pct > 0:
                overhead = f'<span class="overhead-bad">-{pct:.1f}% RPS</span>'
            else:
                overhead = f'<span class="overhead-good">+{abs(pct):.1f}% RPS</span>'

        html += f"<tr><td><strong>{GATEWAY_LABELS.get(gw, gw)}</strong></td>"
        html += _cell(rps, "", i, rps_best, rps_worst, 0)
        html += _cell(m.get("latency_avg_ms"), " ms", i, lat_best, lat_worst)
        html += _cell(m.get("latency_p50_ms"), " ms", i, None, None)
        html += _cell(m.get("latency_p99_ms"), " ms", i, p99_best, p99_worst)
        html += _cell(m.get("error_count", 0), "", i, err_best, err_worst, 0)
        html += f"<td>{overhead}</td></tr>\n"

    html += "</tbody></table>"
    return html


def _build_tls_overhead_table(data):
    """Compare each gateway's HTTP vs HTTPS vs E2E TLS performance."""
    gws = [g for g in GATEWAYS if g != "baseline" and g in data]
    if not gws:
        return "<p>No TLS comparison data available.</p>"

    has_e2e = any(
        "e2e_tls" in data.get(gw, {}) for gw in gws
    )

    # Build header
    header_cols = "<th>Gateway</th><th>Endpoint</th>"
    header_cols += "<th>HTTP RPS</th><th>HTTPS RPS</th><th>RPS Drop</th>"
    header_cols += "<th>HTTP Latency</th><th>HTTPS Latency</th><th>Latency Increase</th>"
    if has_e2e:
        header_cols += "<th>E2E TLS RPS</th><th>E2E vs HTTP</th>"
        header_cols += "<th>E2E TLS Latency</th><th>E2E Lat. Increase</th>"

    html = f"""<table>
<thead><tr>
  {header_cols}
</tr></thead><tbody>\n"""

    for gw in gws:
        for ep in ENDPOINTS:
            http_m = data.get(gw, {}).get("http", {}).get(ep, {})
            https_m = data.get(gw, {}).get("https", {}).get(ep, {})
            e2e_m = data.get(gw, {}).get("e2e_tls", {}).get(ep, {})
            if not http_m or not https_m:
                continue

            http_rps = http_m.get("rps")
            https_rps = https_m.get("rps")
            http_lat = http_m.get("latency_avg_ms")
            https_lat = https_m.get("latency_avg_ms")

            rps_drop = ""
            if http_rps and https_rps:
                pct = ((http_rps - https_rps) / http_rps) * 100
                rps_drop = f"{pct:.1f}%"

            lat_inc = ""
            if http_lat and https_lat:
                diff = https_lat - http_lat
                lat_inc = f"+{diff:.2f} ms"

            html += f"<tr><td><strong>{GATEWAY_LABELS.get(gw, gw)}</strong></td>"
            html += f"<td>{ep}</td>"
            html += f"<td>{_fmt(http_rps, '', 0)}</td>"
            html += f"<td>{_fmt(https_rps, '', 0)}</td>"
            html += f"<td>{rps_drop}</td>"
            html += f"<td>{_fmt(http_lat, ' ms')}</td>"
            html += f"<td>{_fmt(https_lat, ' ms')}</td>"
            html += f"<td>{lat_inc}</td>"

            if has_e2e:
                e2e_rps = e2e_m.get("rps")
                e2e_lat = e2e_m.get("latency_avg_ms")

                e2e_drop = ""
                if http_rps and e2e_rps:
                    pct = ((http_rps - e2e_rps) / http_rps) * 100
                    e2e_drop = f"{pct:.1f}%"

                e2e_lat_inc = ""
                if http_lat and e2e_lat:
                    diff = e2e_lat - http_lat
                    e2e_lat_inc = f"+{diff:.2f} ms"

                html += f"<td>{_fmt(e2e_rps, '', 0)}</td>"
                html += f"<td>{e2e_drop}</td>"
                html += f"<td>{_fmt(e2e_lat, ' ms')}</td>"
                html += f"<td>{e2e_lat_inc}</td>"

            html += "</tr>\n"

    html += "</tbody></table>"
    return html


def generate_report(results_dir, output_path, meta=None):
    """Generate the full HTML comparison report."""
    global GATEWAY_LABELS
    data = discover_results(results_dir)
    if not data:
        print(f"No result files found in {results_dir}", file=sys.stderr)
        sys.exit(1)

    # Baseline metrics for /health and /users
    bl_health = data.get("baseline", {}).get("http", {}).get("health", {})
    bl_users = data.get("baseline", {}).get("http", {}).get("users", {})
    bl_https_health = data.get("baseline", {}).get("https", {}).get("health", {})
    bl_https_users = data.get("baseline", {}).get("https", {}).get("users", {})

    meta = meta or {}
    GATEWAY_LABELS = _gateway_labels(meta)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>API Gateway Comparison Report</title>
<style>
  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    margin: 0; padding: 20px; background: #f5f5f5;
  }}
  .container {{
    max-width: 1300px; margin: 0 auto; background: #fff;
    border-radius: 8px; box-shadow: 0 2px 12px rgba(0,0,0,0.1); overflow: hidden;
  }}
  .header {{
    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
    color: #fff; padding: 30px; text-align: center;
  }}
  .header h1 {{ margin: 0; font-size: 2.2em; font-weight: 400; }}
  .header p {{ margin: 8px 0 0; opacity: 0.85; }}
  .section {{ padding: 25px 30px; }}
  .section h2 {{ color: #1a1a2e; border-bottom: 2px solid #0f3460; padding-bottom: 8px; }}
  .section h3 {{ color: #333; margin-top: 20px; }}
  table {{
    width: 100%; border-collapse: collapse; margin: 15px 0;
    font-size: 0.95em;
  }}
  th {{
    background: #1a1a2e; color: #fff; padding: 10px 12px;
    text-align: left; font-weight: 500;
  }}
  td {{ padding: 9px 12px; border-bottom: 1px solid #e0e0e0; }}
  tr:hover {{ background: #f8f9ff; }}
  .best {{ background: #e6f9e6; font-weight: 600; }}
  .worst {{ background: #fde8e8; }}
  .overhead-bad {{ color: #c0392b; font-weight: 600; }}
  .overhead-good {{ color: #27ae60; font-weight: 600; }}
  .meta {{ background: #f8f9fa; padding: 20px 30px; font-size: 0.9em; color: #555; }}
  .meta strong {{ color: #333; }}
  .footer {{
    text-align: center; padding: 18px; color: #888; font-size: 0.85em;
    border-top: 1px solid #eee;
  }}
  .baseline-box {{
    background: #f0f4ff; border-left: 4px solid #0f3460;
    padding: 12px 18px; margin: 15px 0; border-radius: 0 6px 6px 0;
  }}
</style>
</head>
<body>
<div class="container">
<div class="header">
  <h1>API Gateway Comparison Report</h1>
  <p>Ferrum Gateway vs Kong vs Tyk &mdash; Performance Benchmark</p>
  <p style="font-size:0.85em; opacity:0.7;">{now}</p>
</div>

<div class="meta">
  <strong>Test Parameters:</strong>
  Duration: {meta.get('duration', '30s')} &bull;
  Threads: {meta.get('threads', '8')} &bull;
  Connections: {meta.get('connections', '100')} &bull;
  Kong: {meta.get('kong_version', 'N/A')} &bull;
  Tyk: {meta.get('tyk_version', 'N/A')} &bull;
  OS: {meta.get('os', 'N/A')}
</div>

<div class="section">
  <h2>Direct Backend Baseline</h2>
  <div class="baseline-box">
    <strong>HTTP /health:</strong> {_fmt(bl_health.get('rps'), ' req/s', 0)} &mdash;
    {_fmt(bl_health.get('latency_avg_ms'), ' ms avg')} &mdash;
    {_fmt(bl_health.get('error_count', 0), ' errors', 0)}<br>
    <strong>HTTP /api/users:</strong> {_fmt(bl_users.get('rps'), ' req/s', 0)} &mdash;
    {_fmt(bl_users.get('latency_avg_ms'), ' ms avg')} &mdash;
    {_fmt(bl_users.get('error_count', 0), ' errors', 0)}<br>
    <strong>HTTPS /health:</strong> {_fmt(bl_https_health.get('rps'), ' req/s', 0)} &mdash;
    {_fmt(bl_https_health.get('latency_avg_ms'), ' ms avg')} &mdash;
    {_fmt(bl_https_health.get('error_count', 0), ' errors', 0)}<br>
    <strong>HTTPS /api/users:</strong> {_fmt(bl_https_users.get('rps'), ' req/s', 0)} &mdash;
    {_fmt(bl_https_users.get('latency_avg_ms'), ' ms avg')} &mdash;
    {_fmt(bl_https_users.get('error_count', 0), ' errors', 0)}
  </div>
</div>

<div class="section">
  <h2>HTTP Performance (Plaintext)</h2>
  <h3>/health endpoint</h3>
  {_build_table(data, 'http', 'health', bl_health)}
  <h3>/api/users endpoint</h3>
  {_build_table(data, 'http', 'users', bl_users)}
</div>

<div class="section">
  <h2>HTTPS Performance (TLS Termination)</h2>
  <h3>/health endpoint</h3>
  {_build_table(data, 'https', 'health', bl_health)}
  <h3>/api/users endpoint</h3>
  {_build_table(data, 'https', 'users', bl_users)}
</div>

<div class="section">
  <h2>End-to-End TLS Performance (Full Encryption)</h2>
  <p>Client &rarr; HTTPS &rarr; Gateway &rarr; HTTPS &rarr; Backend. Both hops are encrypted. This is the most secure deployment pattern.</p>
  <h3>/health endpoint</h3>
  {_build_table(data, 'e2e_tls', 'health', bl_https_health)}
  <h3>/api/users endpoint</h3>
  {_build_table(data, 'e2e_tls', 'users', bl_https_users)}
</div>

<div class="section">
  <h2>TLS Overhead Comparison (HTTP vs HTTPS vs E2E TLS per Gateway)</h2>
  {_build_tls_overhead_table(data)}
</div>

<div class="section">
  <h2>Methodology &amp; Caveats</h2>
  <ul>
    <li><strong>Ferrum Gateway</strong> runs as a native binary on the host — zero container overhead.</li>
    <li><strong>Kong</strong> runs {"natively on the host (installed via package manager) — no container overhead." if meta.get("kong_native") else "inside a Docker container. On <strong>macOS</strong>, Docker Desktop runs containers in a Linux VM with userspace networking, which adds <strong>~0.1–0.5 ms per round-trip</strong> (port-mapped) plus higher CPU scheduling variance (~9.5x). On <strong>Linux</strong> with <code>--network host</code>, Docker overhead is negligible (&lt;5 &micro;s). To eliminate this overhead on Linux, install Kong natively via the official apt/yum packages."}</li>
    <li><strong>Tyk</strong> runs inside a Docker container (no official macOS binary; Linux-only native packages available via <a href="https://tyk.io/docs/apim/open-source/installation">packagecloud</a>). The same Docker overhead caveats as Kong apply. Additionally, Tyk requires Redis which also runs in a container.</li>
    <li><strong>HTTPS tests</strong> measure TLS termination at the gateway (client &rarr; HTTPS &rarr; gateway &rarr; HTTP &rarr; backend). <strong>E2E TLS tests</strong> measure full encryption (client &rarr; HTTPS &rarr; gateway &rarr; HTTPS &rarr; backend), the most secure pattern.</li>
    <li>All gateways run sequentially (one at a time) to avoid resource contention on the host.</li>
    <li>Each test includes a {meta.get("duration", "30s")} measured run preceded by a warm-up phase (results discarded).</li>
    <li>To get the fairest comparison on macOS, install Kong natively and run the benchmark again. Tyk results on macOS should be interpreted with Docker overhead in mind (~0.1–0.5 ms added latency, ~5-15% throughput reduction).</li>
  </ul>
</div>

<div class="footer">
  Generated by Ferrum Gateway Comparison Benchmark Suite
</div>
</div>
</body>
</html>"""

    with open(output_path, "w") as f:
        f.write(html)
    print(f"Report generated: {output_path}")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) < 2:
        print("Usage: generate_comparison_report.py <results_dir> [output.html]", file=sys.stderr)
        sys.exit(1)

    results_dir = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else os.path.join(results_dir, "comparison_report.html")

    # Read optional metadata from results/meta.json
    meta = {}
    meta_path = os.path.join(results_dir, "meta.json")
    if os.path.exists(meta_path):
        import json
        with open(meta_path) as f:
            meta = json.load(f)

    generate_report(results_dir, output_path, meta)


if __name__ == "__main__":
    main()
