#!/usr/bin/env python3
"""Audit retained gateway image/PID/resource/count bindings; never run workloads.

Pass the exported campaign directory containing plan.json and gateway/. This
checks all 32 prescribed gateway cells using raw evidence, independently of the
derived observation flags. Positive product-error counts remain observations.
It does not qualify functionality, estimate performance, or rerun failed cells.
Reused builds require the trusted current-run verification receipt and separate
current checks bytes; private image/recipe hashes are verified remotely only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat

from mesh_gap_candidate import BASELINE
from mesh_gap_plan import gateway_blocks
import mesh_gap_baseline_reuse as reuse
from mesh_gap_build import checked_receipt

MAX_FILE_BYTES = 8 * 1024**2
MAX_TOTAL_BYTES = 256 * 1024**2
SHA = re.compile(r'[0-9a-f]{40}')
IMAGE = re.compile(r'sha256:[0-9a-f]{64}')
REUSE_VERIFICATION = 'baseline-reuse-verification.json'


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

    def read_bytes(self, relative):
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
        return data

    def read(self, relative):
        return json.loads(self.read_bytes(relative), parse_constant=lambda value: (_ for _ in ()).throw(ValueError('nonfinite JSON: ' + value)))


def run_context(run_id, attempt, repository, repository_id):
    require(all(type(value) is int and value > 0 for value in (run_id, attempt, repository_id))
            and isinstance(repository, str) and re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository) is not None,
            'trusted current run/attempt/repository identity required for reused baseline audit')
    return dict(run_id=run_id, attempt=attempt, repository=repository, repository_id=repository_id)


def retained_reuse(reader, source, checks, context):
    """Verify bounded public bytes; the separately trusted receipt attests private archive checks."""
    require(checks is not None, 'current checks receipt required for reused baseline audit')
    chosen = source['selection']
    metadata = Evidence(reader.root.parent / 'images/baseline')
    original, wrapper = metadata.read('receipt.json'), metadata.read('baseline-reuse.json')
    image = metadata.read('image.json')
    metadata.read_bytes('compiler-native-packages.log')
    check_reader = Evidence(Path(checks).parent)
    check_reader.read(Path(checks).name)
    checked_receipt(chosen, checks)
    checks_hash = check_reader.hashes[Path(checks).name]
    require(source.get('baseline_reuse') == wrapper and source['builds']['baseline'] == original
            and source.get('checks_receipt_sha256') == checks_hash, 'public reuse chain differs from campaign provenance')
    require(type(wrapper.get('schema')) is int and wrapper['schema'] == 1 and wrapper.get('complete') is True and wrapper.get('rebuilt') is False
            and wrapper.get('errors') == [] and wrapper.get('current_selection') == chosen
            and wrapper.get('current_checks_receipt_sha256') == checks_hash,
            'reuse wrapper lacks exact current checks selection')
    request, origin = wrapper['request'], wrapper['origin']
    require(request == reuse.inputs(str(request['run_id']), str(request['attempt']), 'gap-compare', str(context['run_id'])),
            'reuse request is not an exact distinct origin run/attempt')
    reuse.validate_origin(request, context['repository'], context['repository_id'], origin['run'], origin['jobs'], origin['artifact'])
    require(wrapper.get('downloaded_artifact_sha256') == origin['artifact']['digest'].removeprefix('sha256:')
            and wrapper.get('downloaded_artifact_bytes') == origin['artifact']['size_in_bytes']
            and wrapper.get('original_receipt_sha256') == metadata.hashes['receipt.json'],
            'retained original receipt or artifact digest/size mismatch')
    # Exact source-file hashes and private archive/recipe bytes are checked by
    # validate_reuse on the remote runner before it mints this run's receipt.
    reuse.validate_original(original, chosen, origin['run']['head_sha'], original['source_file_sha256'])
    require(original['image_id'] == source['image_ids']['baseline'] and image.get('Id') == original['image_id']
            and image.get('Config', {}).get('Labels', {}).get('org.opencontainers.image.revision') == BASELINE
            and image['Config']['Labels'].get('io.ferrum.benchmark.profile') == 'release'
            and image['Config']['Labels'].get('io.ferrum.benchmark.features') == 'cloud-secrets'
            and original['compiler_native_packages_sha256'] == metadata.hashes['compiler-native-packages.log'],
            'retained baseline image/compiler metadata mismatch')
    hashes = {'campaign/provenance.json': reader.hashes['provenance.json'], 'checks/receipt.json': checks_hash}
    hashes.update({'images/baseline/' + name: value for name, value in metadata.hashes.items()})
    record = dict(schema=1, complete=True, current_run=context, current_selection=chosen, origin_request=request,
        baseline_image_id=original['image_id'], public_inputs_sha256=hashes,
        verified_private_inputs=dict(image_archive_sha256=original['image_archive_sha256'],
            dockerfile_sha256=original['dockerfile_sha256'], source_file_sha256=original['source_file_sha256'],
            original_build_helper_sha256=wrapper['original_build_helper_sha256']),
        scope='Full validate_reuse ran remotely on retained image.tar and Dockerfile.source; public audit rehashes bounded metadata and current checks only. No local image archive transfer or performance qualification.')
    return record, wrapper


def verify_reuse(root, candidate_sha, harness_sha, checks):
    """Remote-only full gate; export just its bounded, exact-current-run attestation."""
    reuse.require_remote()
    require(os.environ.get('GITHUB_SHA') == harness_sha, 'verification must run at the exact current workflow commit')
    context = run_context(int(os.environ['GITHUB_RUN_ID']), int(os.environ['GITHUB_RUN_ATTEMPT']),
                          os.environ['GITHUB_REPOSITORY'], int(os.environ['GITHUB_REPOSITORY_ID']))
    reader = Evidence(root)
    source = reader.read('provenance.json')
    chosen = source['selection']
    require(chosen['candidate_sha'] == candidate_sha and chosen['harness_sha'] == harness_sha
            and chosen['baseline_sha'] == BASELINE and chosen['phase'] == 'gap-compare', 'verification selection mismatch')
    record, wrapper = retained_reuse(reader, source, checks, context)
    # This is the original full validator, including archive/recipe bytes, fixed
    # baseline source inputs and original/current build-helper identity. No network.
    verified = reuse.validate_reuse(reader.root.parent / 'images/baseline', chosen, checks, reuse.requested(),
                                    context['repository'], context['repository_id'])
    require(verified == wrapper, 'full reuse validation returned a different wrapper')
    destination = reader.root / REUSE_VERIFICATION
    with destination.open('x') as stream:
        stream.write(json.dumps(record, indent=2, allow_nan=False) + '\n')
    return record


def audit(root, candidate_sha, harness_sha, *, checks=None, context=None):
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
        reused = source.get('baseline_reuse') is not None
        if reused:
            require(context is not None, 'trusted current run context required for reused baseline audit')
            context = run_context(**context)
            expected, _ = retained_reuse(reader, source, checks, context)
            proof = reader.read(REUSE_VERIFICATION)
            require(type(proof.get('schema')) is int and proof['schema'] == 1
                    and run_context(**proof['current_run']) == context and proof == expected,
                    'exact-current-run remote reuse verification missing or changed')
            report['baseline_reuse_verification'] = proof
        for role, sha in (('baseline', BASELINE), ('candidate', candidate_sha)):
            build = source['builds'][role]
            require((role == 'baseline' and reused or build['selection'] == chosen)
                    and build['source_sha'] == sha and build['image_id'] == images[role]
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
    parser.add_argument('--checks-receipt', type=Path, help='separately retained exact-current-run checks receipt; required for reuse')
    parser.add_argument('--run-id', type=int, help='trusted current comparison run ID; required for public reuse audit')
    parser.add_argument('--run-attempt', type=int, help='trusted current comparison attempt; required for public reuse audit')
    parser.add_argument('--repository', help='trusted current owner/repository; required for public reuse audit')
    parser.add_argument('--repository-id', type=int, help='trusted current repository ID; required for public reuse audit')
    parser.add_argument('--verify-baseline-reuse', action='store_true', help='remote-only full archive gate; writes bounded verification receipt before export')
    args = parser.parse_args()
    if args.verify_baseline_reuse:
        verify_reuse(args.campaign, args.candidate_sha, args.harness_sha, args.checks_receipt)
        print(json.dumps(dict(complete=True, receipt=REUSE_VERIFICATION, private_archive_verified_remotely=True)))
        return 0
    context = dict(run_id=args.run_id, attempt=args.run_attempt, repository=args.repository, repository_id=args.repository_id)
    report = audit(args.campaign, args.candidate_sha, args.harness_sha, checks=args.checks_receipt, context=context)
    print(json.dumps(report, indent=2, allow_nan=False))
    return 0 if report['audit_valid'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
