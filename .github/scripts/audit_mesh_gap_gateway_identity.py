#!/usr/bin/env python3
"""Audit retained gateway image/PID/resource/count bindings; never run workloads.

Pass the exported campaign directory containing plan.json and gateway/. This
checks all 32 prescribed gateway cells using raw evidence, independently of the
derived observation flags. Positive product-error counts remain observations.
It does not qualify functionality, estimate performance, or rerun failed cells.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
import re
import stat

from mesh_gap_candidate import BASELINE
from mesh_gap_plan import gateway_blocks

MAX_FILE_BYTES = 8 * 1024**2
MAX_TOTAL_BYTES = 256 * 1024**2
SHA = re.compile(r'[0-9a-f]{40}')
IMAGE = re.compile(r'sha256:[0-9a-f]{64}')


def number(value, *, positive=False):
    return type(value) in (int, float) and math.isfinite(value) and (value > 0 if positive else value >= 0)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate_cell(block, cell, identity, manifest, status, raw, runtime, images, host):
    """Pure validation of one frozen gateway leg; errors do not imply bad data."""
    expected_image = images[cell['image_role']]
    expected_source = BASELINE if cell['image_role'] == 'baseline' else identity['candidate_sha']
    require(identity['pair'] == block['pair'] and identity['scenario'] == block['scenario']
            and identity['phase'] == block['phase'] and identity['directory'] == block['directory'],
            'block identity differs from prescribed position')
    member = identity['members'][block['members'].index(cell)]
    require(all(member.get(key) == value for key, value in cell.items())
            and member.get('image_id') == expected_image and member.get('runtime_source_sha') == expected_source,
            'leg source/image identity differs from prescribed position')
    expected_manifest = dict(gateways=['ferrum', 'ferrum-baseline'], pairs=1, tail_confirm_pair=block['pair'],
        duration=30, payload_sizes=[1048576], host_id=host, baseline_image=images['baseline'],
        h2_window='default', h2_observation_enabled=False)
    require(all(type(manifest.get(key)) is type(value) and manifest[key] == value for key, value in expected_manifest.items()),
            'frozen protocol manifest mismatch')
    require(status.get('state') == 'completed' and type(status.get('exit_code')) is int
            and status['exit_code'] == 0 and status.get('cleanup_errors') == [],
            'protocol execution/cleanup incomplete')
    expected_raw = dict(gateway=cell['arm'], pair=block['pair'], host_id=host, sample_schema=2,
        protocol='HTTP/1.1+TLS' if block['scenario'] == 'http1-tls' else 'HTTP/2',
        concurrency=50, effective_concurrency=50, payload_size=1048576, duration_secs=30,
        order_position=block['members'].index(cell) + 1,
        gateway_order=[member['arm'] for member in block['members']], target='https://127.0.0.1:8443/echo')
    require(all(type(raw.get(key)) is type(value) and raw[key] == value for key, value in expected_raw.items()),
            'raw count/latency sample belongs to a different cell')
    require(isinstance(runtime, list) and len(runtime) == 1 and isinstance(runtime[0], dict), 'runtime inspect shape')
    runtime = runtime[0]
    state, config = runtime['State'], runtime['Config']
    pid = state['Pid']
    require(runtime['Image'] == expected_image and state.get('Running') is True
            and type(pid) is int and pid > 1 and config.get('User') == '65532:65532'
            and '65532' in runtime['HostConfig'].get('GroupAdd', []), 'actual runtime image/nonroot/PID mismatch')
    phases, usage = raw['phases'], raw['process_usage']
    start = phases['measurement_start_unix_secs']
    require(number(start) and phases.get('measurement_secs') == 30
            and number(phases.get('measurement_elapsed_secs')) and 30 <= phases['measurement_elapsed_secs'] <= 31.5
            and phases.get('timed_out') is False, 'measurement phase incomplete')
    require(usage.get('available') is not False and not usage.get('error'), 'process resource capture unavailable')
    gateways = [item for item in usage['measurement'] if item.get('role') == 'gateway']
    require(len(gateways) == 1 and type(gateways[0].get('pid')) is int and gateways[0]['pid'] == pid,
            'measured gateway PID differs from actual image container PID')
    measurement = gateways[0]
    require(measurement.get('complete_bracket') is True and number(measurement.get('cpu_seconds'))
            and number(measurement.get('bracket_secs')) and 30 <= measurement['bracket_secs'] <= 31.5
            and number(measurement.get('boundary_slack_secs'))
            and math.isclose(measurement['bracket_secs'] - 30, measurement['boundary_slack_secs'], abs_tol=0.001),
            'gateway CPU bracket incomplete')
    timeline = []
    for snapshot in usage['timeline']:
        require(number(snapshot.get('unix_secs')), 'invalid resource snapshot time')
        processes = [item for item in snapshot['processes'] if item.get('role') == 'gateway']
        require(len(processes) == 1 and type(processes[0].get('pid')) is int and processes[0]['pid'] == pid,
                'gateway timeline PID differs from actual image container PID')
        process = processes[0]
        require(type(process.get('start_ticks')) is int and process['start_ticks'] > 0
                and number(process.get('cpu_seconds')) and number(process.get('rss_bytes'), positive=True),
                'gateway timeline resource identity/counters incomplete')
        timeline.append((snapshot['unix_secs'], process))
    require(timeline == sorted(timeline, key=lambda item: item[0])
            and len({item[1]['start_ticks'] for item in timeline}) == 1,
            'gateway timeline unordered or process generation changed')
    before = [item for item in timeline if item[0] <= start]
    after = [item for item in timeline if item[0] >= start + 30]
    within = [item for item in timeline if start <= item[0] <= start + 30]
    require(before and after and within, 'gateway timeline does not bracket measurement')
    left, right = before[-1], after[0]
    require(math.isclose(right[0] - left[0], measurement['bracket_secs'], abs_tol=0.001)
            and math.isclose(right[1]['cpu_seconds'] - left[1]['cpu_seconds'], measurement['cpu_seconds'], abs_tol=1e-9)
            and all(b[1]['cpu_seconds'] >= a[1]['cpu_seconds'] for a, b in zip(timeline, timeline[1:])),
            'CPU summary differs from matching gateway timeline')
    for key in ('total_requests', 'total_bytes', 'total_errors', 'drain_requests', 'drain_bytes', 'warmup_requests'):
        require(type(raw.get(key)) is int and raw[key] >= 0, 'invalid nonnegative count: ' + key)
    require(raw['total_bytes'] == raw['total_requests'] * 1048576
            and raw['drain_bytes'] == raw['drain_requests'] * 1048576
            and number(raw.get('rps')) and math.isclose(raw['rps'], raw['total_requests'] / 30, rel_tol=1e-9),
            'success/drain byte or useful-completion throughput accounting mismatch')
    if raw['total_requests']:
        quantiles = [raw.get(key + '_us') for key in ('p50', 'p95', 'p99')]
        require(all(number(value, positive=True) for value in quantiles) and quantiles == sorted(quantiles),
                'successful completion-window quantiles invalid')
    rss = [item[1]['rss_bytes'] for item in within]
    return dict(image_id=expected_image, runtime_pid=pid, process_start_ticks=timeline[0][1]['start_ticks'],
        cpu_seconds=measurement['cpu_seconds'], rss_mean=sum(rss) / len(rss), rss_peak=max(rss),
        total_errors=raw['total_errors'], total_requests=raw['total_requests'], drain_requests=raw['drain_requests'],
        zero_error_capacity=raw['total_errors'] == 0 and raw['total_requests'] > 0)


class Evidence:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.bytes = 0
        self.hashes = {}

    def read(self, relative):
        relative = Path(relative)
        require(not relative.is_absolute() and '..' not in relative.parts, 'evidence path escapes campaign')
        path = self.root / relative
        require(all(not parent.is_symlink() for parent in (path, *path.parents) if parent != self.root.parent),
                'symlink evidence is unsupported')
        info = path.stat()
        require(stat.S_ISREG(info.st_mode) and info.st_size <= MAX_FILE_BYTES, 'evidence must be a bounded regular file')
        with path.open('rb') as stream:
            data = stream.read(MAX_FILE_BYTES + 1)
        self.bytes += len(data)
        require(len(data) <= MAX_FILE_BYTES and self.bytes <= MAX_TOTAL_BYTES, 'evidence read budget exceeded')
        self.hashes[relative.as_posix()] = hashlib.sha256(data).hexdigest()
        return json.loads(data, parse_constant=lambda value: (_ for _ in ()).throw(ValueError('nonfinite JSON: ' + value)))


def audit(root, candidate_sha, harness_sha):
    reader = Evidence(root)
    report = dict(audit_valid=False, expected_gateway_cells=32, valid_gateway_cells=0, issues=[], cells=[],
        expected_candidate_sha=candidate_sha, expected_harness_sha=harness_sha,
        scope='Raw gateway image/PID/CPU/RSS/count binding only; no reruns, performance inference or functionality qualification.',
        latency_scope='Successful completion-window quantiles exclude drains and failed requests; no admitted-cohort tail claim.')
    try:
        require(SHA.fullmatch(candidate_sha) is not None and candidate_sha != BASELINE
                and SHA.fullmatch(harness_sha) is not None, 'exact expected candidate and harness SHAs required')
        plan, source = reader.read('plan.json'), reader.read('provenance.json')
        chosen, images = source['selection'], source['image_ids']
        require(plan['selection'] == chosen and plan['source'] == source and plan['gateway'] == gateway_blocks()
                and chosen['baseline_sha'] == BASELINE and chosen['candidate_sha'] == candidate_sha
                and chosen['harness_sha'] == harness_sha and chosen['phase'] == 'gap-compare', 'source/plan selection mismatch')
        require(plan.get('state') == 'completed' and plan.get('errors') == [] and plan.get('cleanup_complete') is True,
                'campaign execution/cleanup incomplete')
        require(all(IMAGE.fullmatch(images[role]) is not None for role in ('baseline', 'candidate')), 'immutable image IDs required')
        for role, sha in (('baseline', BASELINE), ('candidate', candidate_sha)):
            build = source['builds'][role]
            require(build['selection'] == chosen and build['source_sha'] == sha and build['image_id'] == images[role]
                    and build.get('complete') is True and build.get('errors') == [], 'build/source/image receipt mismatch')
        for block in gateway_blocks():
            prefix = Path(block['directory'])
            for cell in block['members']:
                item = dict(block=block['directory'], cell=cell, valid=False, issues=[])
                try:
                    identity = reader.read(prefix / 'identity.json')
                    identity['candidate_sha'] = candidate_sha
                    pair = prefix / 'protocol/pairs' / f"pair_{block['pair']:03d}"
                    bindings = validate_cell(block, cell, identity, reader.read(prefix / 'protocol/manifest.json'),
                        reader.read(prefix / 'protocol/status.json'),
                        reader.read(pair / f"{cell['arm']}_{block['scenario']}_1048576.json"),
                        reader.read(pair / 'diagnostics' / f"{cell['arm']}_runtime.json"), images, plan['host_id'])
                    item.update(valid=True, bindings=bindings)
                except (OSError, ValueError, KeyError, TypeError, IndexError, AttributeError, ArithmeticError) as error:
                    item['issues'].append(str(error))
                report['cells'].append(item)
        report['valid_gateway_cells'] = sum(item['valid'] for item in report['cells'])
        report['audit_valid'] = report['valid_gateway_cells'] == 32
    except (OSError, ValueError, KeyError, TypeError, IndexError, AttributeError, ArithmeticError) as error:
        report['issues'].append(str(error))
    report.update(evidence_sha256=reader.hashes, evidence_bytes_read=reader.bytes)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('campaign', type=Path)
    parser.add_argument('--candidate-sha', required=True)
    parser.add_argument('--harness-sha', required=True)
    args = parser.parse_args()
    report = audit(args.campaign, args.candidate_sha, args.harness_sha)
    print(json.dumps(report, indent=2, allow_nan=False))
    return 0 if report['audit_valid'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
