#!/usr/bin/env python3
"""
Generate HTML performance report from wrk test results
"""

import argparse
import re
import sys
from datetime import datetime
from pathlib import Path

def parse_wrk_output(file_path):
    """Parse wrk output and extract key metrics"""
    with open(file_path, 'r') as f:
        content = f.read()
    
    metrics = {}
    
    # Extract requests per second
    rps_match = re.search(r'Requests/sec:\s+([\d.]+)', content)
    if rps_match:
        metrics['rps'] = float(rps_match.group(1))
    
    # Extract transfer per second
    transfer_match = re.search(r'Transfer/sec:\s+([\d.]+[KMGT]?B)', content)
    if transfer_match:
        metrics['transfer'] = transfer_match.group(1)
    
    # Extract latency statistics
    latency_avg_match = re.search(r'Latency\s+([\d.]+[mun]?s)', content)
    latency_stdev_match = re.search(r'StdDev\s+([\d.]+[mun]?s)', content)
    latency_max_match = re.search(r'Max\s+([\d.]+[mun]?s)', content)
    
    if latency_avg_match:
        metrics['latency_avg'] = latency_avg_match.group(1)
    if latency_stdev_match:
        metrics['latency_stdev'] = latency_stdev_match.group(1)
    if latency_max_match:
        metrics['latency_max'] = latency_max_match.group(1)
    
    # Extract total requests
    requests_match = re.search(r'(\d+)\s+requests in', content)
    if requests_match:
        metrics['total_requests'] = int(requests_match.group(1))
    
    # Extract socket errors
    errors_match = re.search(r'(\d+)\s+socket errors', content)
    if errors_match:
        metrics['socket_errors'] = int(errors_match.group(1))
    
    # Extract latency distribution
    latency_dist = {}
    dist_matches = re.findall(r'([\d.]+[mun]?s)\s+(\d+)%', content)
    for latency, percentage in dist_matches:
        latency_dist[latency] = percentage
    metrics['latency_distribution'] = latency_dist
    
    return metrics

def convert_latency_to_ms(latency_str):
    """Convert latency string to milliseconds"""
    if latency_str.endswith('μs') or latency_str.endswith('us'):
        # Handle both Greek mu and 'u' for microseconds
        return float(latency_str[:-2].replace('μ', '')) / 1000
    elif latency_str.endswith('ms'):
        return float(latency_str[:-2])
    elif latency_str.endswith('s'):
        return float(latency_str[:-1]) * 1000
    else:
        return float(latency_str)

def generate_html_report(gateway_metrics, backend_metrics, output_path):
    """Generate HTML performance report"""
    
    # Calculate overhead
    if 'rps' in gateway_metrics and 'rps' in backend_metrics:
        rps_overhead = ((backend_metrics['rps'] - gateway_metrics['rps']) / backend_metrics['rps']) * 100
    else:
        rps_overhead = 0
    
    if 'latency_avg' in gateway_metrics and 'latency_avg' in backend_metrics:
        gateway_latency_ms = convert_latency_to_ms(gateway_metrics['latency_avg'])
        backend_latency_ms = convert_latency_to_ms(backend_metrics['latency_avg'])
        latency_overhead = gateway_latency_ms - backend_latency_ms
    else:
        latency_overhead = 0
    
    html_template = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ferrum Gateway Performance Report</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        .header h1 {{
            margin: 0;
            font-size: 2.5em;
            font-weight: 300;
        }}
        .header p {{
            margin: 10px 0 0 0;
            opacity: 0.9;
        }}
        .metrics {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            padding: 30px;
        }}
        .metric-card {{
            background: white;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            border-left: 4px solid #667eea;
        }}
        .metric-card h3 {{
            margin: 0 0 15px 0;
            color: #333;
            font-size: 1.2em;
        }}
        .metric-value {{
            font-size: 2em;
            font-weight: bold;
            color: #667eea;
            margin-bottom: 5px;
        }}
        .metric-label {{
            color: #666;
            font-size: 0.9em;
        }}
        .comparison {{
            background: #f8f9fa;
            padding: 20px;
            margin: 20px 30px;
            border-radius: 8px;
        }}
        .comparison h3 {{
            margin: 0 0 15px 0;
            color: #333;
        }}
        .overhead {{
            color: #e74c3c;
            font-weight: bold;
        }}
        .overhead.good {{
            color: #27ae60;
        }}
        .footer {{
            text-align: center;
            padding: 20px;
            color: #666;
            font-size: 0.9em;
        }}
        .timestamp {{
            color: #999;
            font-size: 0.8em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚀 Ferrum Gateway Performance Report</h1>
            <p>Load testing results and performance analysis</p>
            <p class="timestamp">Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="metrics">
            <div class="metric-card">
                <h3>📈 Gateway Throughput</h3>
                <div class="metric-value">{gateway_metrics.get('rps', 'N/A')}</div>
                <div class="metric-label">Requests per second</div>
            </div>
            
            <div class="metric-card">
                <h3>⚡ Backend Throughput</h3>
                <div class="metric-value">{backend_metrics.get('rps', 'N/A')}</div>
                <div class="metric-label">Requests per second (direct)</div>
            </div>
            
            <div class="metric-card">
                <h3>🕐 Gateway Latency</h3>
                <div class="metric-value">{gateway_metrics.get('latency_avg', 'N/A')}</div>
                <div class="metric-label">Average response time</div>
            </div>
            
            <div class="metric-card">
                <h3>⚡ Backend Latency</h3>
                <div class="metric-value">{backend_metrics.get('latency_avg', 'N/A')}</div>
                <div class="metric-label">Average response time (direct)</div>
            </div>
        </div>
        
        <div class="comparison">
            <h3>📊 Performance Analysis</h3>
            <p><strong>Gateway Overhead:</strong> <span class="overhead {'good' if rps_overhead < 10 else ''}">{rps_overhead:.2f}% RPS reduction</span></p>
            <p><strong>Latency Impact:</strong> <span class="overhead {'good' if latency_overhead < 1 else ''}">{latency_overhead:.2f}ms additional latency</span></p>
            <p><strong>Total Requests (Gateway):</strong> {gateway_metrics.get('total_requests', 'N/A')}</p>
            <p><strong>Total Requests (Backend):</strong> {backend_metrics.get('total_requests', 'N/A')}</p>
            <p><strong>Gateway Socket Errors:</strong> {gateway_metrics.get('socket_errors', 'N/A')}</p>
            <p><strong>Backend Socket Errors:</strong> {backend_metrics.get('socket_errors', 'N/A')}</p>
        </div>
        
        <div class="footer">
            <p>Generated by Ferrum Gateway Performance Testing Suite</p>
        </div>
    </div>
</body>
</html>
"""
    
    with open(output_path, 'w') as f:
        f.write(html_template)
    
    print(f"✅ HTML report generated: {output_path}")

def main():
    parser = argparse.ArgumentParser(description='Generate performance report from wrk results')
    parser.add_argument('--gateway-results', required=True, help='Path to gateway test results')
    parser.add_argument('--backend-results', required=True, help='Path to backend test results')
    parser.add_argument('--output', required=True, help='Output HTML file path')
    
    args = parser.parse_args()
    
    # Parse metrics
    gateway_metrics = parse_wrk_output(args.gateway_results)
    backend_metrics = parse_wrk_output(args.backend_results)
    
    # Generate report
    generate_html_report(gateway_metrics, backend_metrics, args.output)

if __name__ == '__main__':
    main()
