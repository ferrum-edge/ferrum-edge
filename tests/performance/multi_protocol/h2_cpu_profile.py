"""Fixed HTTP/2 and gRPC CPU campaign metadata; capture uses the H1 supervisor.

Only the workload admission differs. PID-generation, clock, collector lifetime,
software-event validation and bounded ELF retention are shared with H1.
"""
import argparse
import hashlib
import json
import math
import re
import statistics
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
FIXTURES = {
    ('http2', 'ferrum'): 'http2_perf.yaml',
    ('grpcs', 'ferrum'): 'grpcs_e2e_perf.yaml',
    ('http2', 'envoy'): 'envoy/http2_tls.yaml',
    ('grpcs', 'envoy'): 'envoy/grpcs.yaml',
}
ENVIRONMENT = ('FERRUM_MODE', 'FERRUM_PROXY_HTTPS_PORT',
               'FERRUM_RESPONSE_BUFFER_CUTOFF_BYTES', 'FERRUM_POOL_HTTP2_ADAPTIVE_WINDOW',
               'FERRUM_POOL_HTTP2_INITIAL_STREAM_WINDOW_SIZE',
               'FERRUM_POOL_HTTP2_INITIAL_CONNECTION_WINDOW_SIZE')


def fixture(protocol, gateway):
    text = (HERE / 'configs' / FIXTURES[protocol, gateway]).read_text()
    prefix = '/etc/ferrum/tls' if gateway == 'ferrum' else '/certs'
    for token, filename in [('CERT_PATH', 'cert.pem'), ('KEY_PATH', 'key.pem'), ('CA_PATH', 'ca.pem')]:
        text = text.replace(token, prefix + '/' + filename)
    return text.encode()


def validate_runtime(binding, runtime, config, protocol):
    gateway = binding['arm']
    if (gateway not in ('ferrum', 'envoy') or runtime.get('gateway') != gateway
            or runtime.get('protocol') != protocol or runtime.get('pair') != binding['pair']
            or runtime.get('network_mode') != 'host' or runtime.get('running') is not True
            or not re.fullmatch(r'sha256:[0-9a-f]{64}', runtime.get('image_id', ''))):
        raise ValueError('H2 profile runtime/workload identity mismatch')
    if config != fixture(protocol, gateway) or hashlib.sha256(config).hexdigest() != runtime['config_sha256']:
        raise ValueError('effective config does not match the fixed H2/gRPC fixture')
    if gateway == 'ferrum':
        expected = dict(zip(ENVIRONMENT, ('file', '8443', '0', 'false', '8388608', '33554432')))
        if runtime.get('environment') != expected:
            raise ValueError('H2 profile Ferrum environment mismatch')
    if runtime.get('user') != '65532:65532' or runtime.get('cap_drop') != ['ALL']:
        raise ValueError('CPU campaign requires an ordinary UID and dropped capabilities')


def retain_runtime(args, container):
    # Keep only fixed configuration and identity; raw inspect can contain secrets.
    pid = container['State']['Pid']
    if type(pid) is not int or pid <= 0:
        raise ValueError('running container PID missing')
    from process_usage import parse_stat
    stat = parse_stat(Path(f'/proc/{pid}/stat').read_text(), 100, 4096)
    environment = dict(entry.split('=', 1) for entry in container['Config'].get('Env', []))
    config = Path(args.config).read_bytes()
    result = dict(container_id=container['Id'], image_id=container['Image'], host_pid=pid,
                  start_ticks=stat['start_ticks'], started_at=container['State']['StartedAt'],
                  running=container['State']['Running'], network_mode=container['HostConfig']['NetworkMode'],
                  user=container['Config']['User'], cap_drop=container['HostConfig']['CapDrop'],
                  gateway=args.gateway, protocol=args.protocol, pair=args.pair,
                  config_sha256=hashlib.sha256(config).hexdigest(),
                  environment={key: environment.get(key) for key in ENVIRONMENT} if args.gateway == 'ferrum' else {})
    validate_runtime(dict(arm=args.gateway, pair=args.pair), result, config, args.protocol)
    Path(args.output).write_text(json.dumps(result, indent=2) + '\n')


def stamp(path, mode):
    path = Path(path)
    sample = json.loads(path.read_text())
    sample['h2_cpu_profile'] = dict(mode=mode, diagnostic_only=True,
        user_stacks_only=mode == 'cpu', scheduler_counters=mode != 'off')
    path.write_text(json.dumps(sample, indent=2) + '\n')


def nonnegative(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def positive(value):
    return nonnegative(value) and value > 0


def report(root):
    from benchmark_validity import sample_issues
    root = Path(root)
    result = dict(schema=1, diagnostic_only=True, complete=False, issues=[], observations=[], calibration=[])
    indexed = {}
    for campaign, mode in (('control-before', 'off'), ('counters', 'counters'),
                           ('cpu', 'cpu'), ('control-after', 'off')):
        for pair in (1, 2):
            folder = root / campaign / 'pairs' / f'pair_{pair:03d}'
            for gateway in ('direct', 'ferrum', 'envoy'):
                paths = list(folder.glob(f'{gateway}_*.json'))
                row = dict(campaign=campaign, pair=pair, gateway=gateway, issues=[])
                result['observations'].append(row)
                if len(paths) != 1:
                    row['issues'].append('missing or ambiguous sample')
                    continue
                try:
                    sample = json.loads(paths[0].read_text())
                    if not isinstance(sample, dict):
                        raise ValueError('sample must be an object')
                except (OSError, ValueError):
                    row['issues'].append('unreadable or malformed sample')
                    continue
                marker = sample.pop('h2_cpu_profile', {})
                if (not isinstance(marker, dict) or marker.get('mode') != mode
                        or marker.get('diagnostic_only') is not True
                        or marker.get('user_stacks_only') is not (mode == 'cpu')
                        or marker.get('scheduler_counters') is not (mode != 'off')):
                    row['issues'].append('missing/mismatched diagnostic marker')
                if (sample.get('gateway') != gateway or sample.get('pair') != pair
                        or sample.get('sample_schema') != 2
                        or sample.get('protocol') not in ('http2', 'grpcs')
                        or sample.get('payload_size') not in (10240, 71680)
                        or sample.get('duration_secs') != 15
                        or sample.get('effective_concurrency') != 200):
                    row['issues'].append('sample does not match fixed campaign identity')
                # Diagnostic exclusion is for scoreboards. All underlying
                # traffic, error and completeness rules still apply here.
                try:
                    row['issues'].extend(sample_issues(sample))
                except (TypeError, ValueError, KeyError):
                    row['issues'].append('malformed benchmark evidence')
                row.update(rps=sample.get('rps'), payload=sample.get('payload_size'),
                           protocol=sample.get('protocol'), host_id=sample.get('host_id'))
                usage = sample.get('process_usage')
                usage = usage.get('measurement') if isinstance(usage, dict) else None
                row['usage'] = usage if isinstance(usage, list) else []
                expected_roles = {'backend', 'client'} | ({'gateway'} if gateway != 'direct' else set())
                roles = [p.get('role') for p in row['usage']
                         if isinstance(p, dict) and isinstance(p.get('role'), str)]
                if len(row['usage']) != len(expected_roles) or set(roles) != expected_roles:
                    row['issues'].append('missing/ambiguous process CPU roles')
                for process in row['usage']:
                    if not isinstance(process, dict):
                        row['issues'].append('malformed process CPU record')
                        continue
                    if (process.get('complete_bracket') is not True
                            or not positive(process.get('bracket_secs'))
                            or not all(nonnegative(process.get(key))
                                       for key in ('user_cpu_seconds', 'system_cpu_seconds'))):
                        row['issues'].append('incomplete user/kernel CPU bracket')
                    if mode != 'off':
                        counters = process if process.get('role') == 'client' else process.get('context_switches')
                        if (not isinstance(counters, dict)
                                or not all(type(counters.get(key)) is int and counters[key] >= 0
                                           for key in ('voluntary_ctxt_switches', 'nonvoluntary_ctxt_switches'))
                                or (process.get('role') != 'client'
                                    and counters.get('scope') != 'all process threads')):
                            row['issues'].append('incomplete all-thread scheduler bracket')
                if gateway != 'direct':
                    try:
                        runtime = json.loads((folder / 'diagnostics' / f'{gateway}_runtime.json').read_text())
                        config = (folder / 'diagnostics' / f'{gateway}_config.yaml').read_bytes()
                        validate_runtime(dict(arm=gateway, pair=pair), runtime, config, row['protocol'])
                        row['image_id'] = runtime['image_id']
                        row['config_sha256'] = runtime['config_sha256']
                    except (OSError, ValueError, KeyError, TypeError, AttributeError):
                        row['issues'].append('missing/mismatched retained gateway runtime')
                if mode == 'cpu' and gateway != 'direct':
                    trace = folder / 'traces' / f"{gateway}_{row['payload']}" / 'trace-manifest.json'
                    try:
                        capture = json.loads(trace.read_text())
                        if not isinstance(capture, dict):
                            raise ValueError('capture must be an object')
                        row['cpu'] = capture.get('cpu', {})
                        if (capture.get('mode') != 'cpu' or not isinstance(row['cpu'], dict)
                                or not positive(row['cpu'].get('samples'))):
                            row['issues'].append('missing CPU samples or wrong collector mode')
                        row['capture_complete'] = capture.get('capture_complete') is True
                        binding = capture.get('binding') or {}
                        if (not isinstance(binding, dict) or binding.get('arm') != gateway
                                or binding.get('pair') != pair or binding.get('payload') != row['payload']
                                or binding.get('h2_protocol') != row['protocol']):
                            row['issues'].append('CPU capture binding mismatch')
                        if not row['capture_complete']:
                            row['issues'].append('incomplete CPU capture')
                    except (OSError, ValueError):
                        row['issues'].append('missing CPU capture')
                indexed[campaign, pair, gateway] = row
    identities = {tuple(r.get(key) if type(r.get(key)) is kind else None
                        for key, kind in (('host_id', str), ('protocol', str), ('payload', int)))
                  for r in result['observations'] if 'rps' in r}
    if len(identities) != 1 or any(None in identity for identity in identities):
        result['issues'].append('mixed/missing host or workload identity')
    for gateway in ('ferrum', 'envoy'):
        runtimes = {(r.get('image_id'), r.get('config_sha256'))
                    for r in result['observations'] if r['gateway'] == gateway}
        if len(runtimes) != 1 or any(None in identity for identity in runtimes):
            result['issues'].append('mixed/missing runtime identity: ' + gateway)
    for gateway in ('direct', 'ferrum', 'envoy'):
        for campaign in ('counters', 'cpu'):
            values = []
            for pair in (1, 2):
                rows = [indexed.get((name, pair, gateway))
                        for name in ('control-before', campaign, 'control-after')]
                if any(row is None or row['issues'] or not row.get('rps') for row in rows):
                    continue
                before, observed, after = rows
                values.append(dict(pair=pair,
                    rps_overhead_percent=100 * (observed['rps'] / ((before['rps'] + after['rps']) / 2) - 1),
                    control_drift_percent=100 * (after['rps'] / before['rps'] - 1)))
            result['calibration'].append(dict(gateway=gateway, campaign=campaign, pairs=values,
                comparable=not result['issues'] and len(values) == 2 and all(abs(v['control_drift_percent']) <= 5 for v in values),
                median_rps_overhead_percent=statistics.median(v['rps_overhead_percent'] for v in values) if values else None))
    result['complete'] = not result['issues'] and all(not row['issues'] for row in result['observations'])
    result['limits'] = ['Shared-runner calibration; two pairs are diagnostic, not a throughput claim.',
                        'User stacks only; kernel cost comes from process CPU counters.',
                        'Unresolved/optimized-away/async frames remain explicit in CPU coverage.',
                        'Thread churn makes scheduler deltas unavailable instead of zero.']
    (root / 'h2-cpu-report.json').write_text(json.dumps(result, indent=2) + '\n')
    return 0 if result['complete'] else 1


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest='action', required=True)
    runtime = sub.add_parser('runtime')
    runtime.add_argument('--protocol', choices=('http2', 'grpcs'), required=True)
    runtime.add_argument('--gateway', choices=('ferrum', 'envoy'), required=True)
    runtime.add_argument('--pair', type=int, required=True)
    runtime.add_argument('--config', required=True)
    runtime.add_argument('--output', required=True)
    mark = sub.add_parser('stamp')
    mark.add_argument('path')
    mark.add_argument('mode', choices=('off', 'counters', 'cpu'))
    summary = sub.add_parser('report')
    summary.add_argument('root')
    args = parser.parse_args()
    if args.action == 'runtime':
        retain_runtime(args, json.load(sys.stdin))
    elif args.action == 'stamp':
        stamp(args.path, args.mode)
    else:
        return report(args.root)
    return 0


if __name__ == '__main__':
    sys.exit(main())
