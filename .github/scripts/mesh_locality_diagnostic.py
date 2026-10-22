#!/usr/bin/env python3
"""Remote shipping-image worker-count discriminator; not a performance PR gate."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

import mesh_production_campaign as campaign

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / 'results/locality'
IMAGES = {
    'ferrum': 'ferrumedge/ferrum-edge@sha256:e95e7f8d0d19e5714cb4e93afb600ebe14a1703aab51e84ad5c2be822d82a4af',
    'envoy': 'envoyproxy/envoy@sha256:57e14a549d7bd43c8d3f6d03e8cfa653e037d4b38e133acd9b54f38c524401b4',
}
TOOLS = 'mesh-bench-tools:locality'
PHASE = 'worker-locality-diagnostic'


def plan():
    cells = []
    # Every second block reverses the complete product/worker sequence, and
    # payload order. No result-dependent sample selection or extension.
    arms = [('ferrum', 1), ('envoy', 1), ('ferrum', 4), ('envoy', 4)]
    for repetition in (1, 2):
        for payload in ((1024, 1048576) if repetition == 1 else (1048576, 1024)):
            for arm, workers in (arms if repetition == 1 else reversed(arms)):
                cells.append(dict(arm=arm, workers=workers, payload=payload,
                                  repetition=repetition, load='saturated', duration=30, rate=0))
    return cells


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, allow_nan=False) + '\n')


def require_remote():
    if os.environ.get('GITHUB_ACTIONS') != 'true' or os.uname().sysname != 'Linux' or os.uname().machine != 'x86_64':
        raise ValueError('locality measurements require remote GitHub Actions Linux x64')


def validate_workers(cell, resource, image_id):
    errors = []
    if not isinstance(resource, dict) or not isinstance(resource.get('production'), dict):
        return ['missing production worker receipts']
    measured = resource.get('containers')
    detail = resource['production'].get('proxy_containers')
    if any(not isinstance(items, list) or len(items) != 2 or not all(isinstance(item, dict) for item in items)
           for items in (measured, detail)):
        return ['missing both proxy identities/worker receipts']
    names = [item.get('name') for item in detail]
    pids = [item.get('pid') for item in detail]
    if (not all(isinstance(name, str) for name in names) or len(set(names)) != 2
            or not names[0].endswith('-client') or not names[1].endswith('-server')
            or not all(type(pid) is int and pid > 1 for pid in pids) or len(set(pids)) != 2):
        errors.append('invalid or duplicate ordered source/destination identities')
    for phase in ('begin', 'end'):
        snapshot = resource.get(phase)
        processes = snapshot.get('processes') if isinstance(snapshot, dict) else None
        if (not isinstance(processes, list) or len(processes) != 2
                or not all(isinstance(item, dict) for item in processes)
                or [item.get('pid') for item in processes] != pids):
            errors.append(phase + ' CPU counters do not match ordered proxy PIDs')
    for role, (current, actual) in enumerate(zip(measured, detail)):
        if any(actual.get(key) != current.get(key) for key in ('name', 'pid', 'image_id')):
            errors.append(f'role {role} measured/observed identity mismatch')
        if actual.get('image_id') != image_id or actual.get('cpu_limit_nanos') != 4_000_000_000 or current.get('cpu_limit_nanos') != 4_000_000_000:
            errors.append(f'role {role} image or fixed four-CPU ceiling mismatch')
        if actual.get('network_mode') != 'host' or actual.get('cpuset') or actual.get('memory_limit_bytes') != 0:
            errors.append(f'role {role} placement/resource mismatch')
        if cell['arm'] == 'ferrum':
            if actual.get('worker_environment') != [f"FERRUM_WORKER_THREADS={cell['workers']}"]:
                errors.append(f'role {role} Ferrum worker mismatch')
        else:
            args = actual.get('args')
            if not isinstance(args, list) or not all(isinstance(value, str) for value in args):
                errors.append(f'role {role} invalid Envoy process arguments')
                continue
            positions = [index for index, value in enumerate(args) if value == '--concurrency']
            if len(positions) != 1 or positions[0]+1 >= len(args) or args[positions[0]+1] != str(cell['workers']):
                errors.append(f'role {role} Envoy worker mismatch')
    return errors


def cell_root(cell):
    return OUTPUT / f"workers_{cell['workers']}"


def read_cell(cell, image_ids, runner_exit_code=None):
    campaign.ROOT = cell_root(cell)
    row = campaign.read_cell(cell, runner_exit_code=runner_exit_code)
    extra = validate_workers(cell, row['resources'], image_ids[cell['arm']])
    row['measurement_errors'].extend(extra)
    row['capacity_errors'].extend(extra)
    if extra:
        row.update(measurement_valid=False, valid=False, zero_error_capacity_qualified=False,
                   zero_error_observation=False, strict_zero_miss=False, observed_metrics=None,
                   cpu_us_per_completion=None, classification='harness_or_evidence_fault')
    return row


def prepare():
    require_remote()
    OUTPUT.mkdir(parents=True, exist_ok=False)
    changed = subprocess.check_output(['git', 'diff', campaign.RUNTIME_SHA, '--', 'src', 'vendor', 'Cargo.toml', 'Cargo.lock', 'Dockerfile'], cwd=ROOT, text=True)
    if changed.strip():
        raise ValueError('shipping diagnostic cannot modify runtime/build inputs')
    inspections = {}
    for arm, image in IMAGES.items():
        subprocess.run(['docker', 'pull', image], check=True, timeout=300)
        obj = json.loads(subprocess.check_output(['docker', 'inspect', image], timeout=10))[0]
        if arm == 'ferrum' and obj['Config'].get('Labels', {}).get('org.opencontainers.image.revision') != campaign.RUNTIME_SHA:
            raise ValueError('shipping Ferrum source revision differs from pin')
        inspections[arm] = obj
    with (OUTPUT / 'tools-build.log').open('w') as log:
        subprocess.run(['docker', 'build', '-f', 'tests/performance/mesh_runtime/Dockerfile.production-tools', '-t', TOOLS, 'tests/performance/mesh_runtime'], cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=1200)
    write(OUTPUT / 'plan.json', plan())
    write(OUTPUT / 'provenance.json', dict(phase=PHASE, runtime_sha=campaign.RUNTIME_SHA,
        harness_sha=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
        images=inspections, tools=json.loads(subprocess.check_output(['docker', 'inspect', TOOLS], timeout=10))[0],
        profile='release', features='cloud-secrets', allocation_instrumentation=False,
        cpu_ceiling_per_proxy=4, loadgen_and_backend='unrestricted on the same shared host',
        requested_workers=[1, 4], warmup_seconds=3,
        limits=['two balanced repetitions are a discriminator, not a fine speedup estimate',
                'worker count may change pool/connection topology as well as ownership; report actual sockets',
                'OS scheduler events do not count Tokio tasks or wakes',
                'static Envoy policy/telemetry differs from Ferrum; this is a within-product scaling diagnostic',
                'successful admitted-cohort latency excludes failed requests; errors remain separate',
                'full identity-bound workload telemetry remains unqualified as in the shipping ranking']))


def measure():
    require_remote()
    provenance = campaign.read_json(OUTPUT / 'provenance.json')
    image_ids = {arm: obj['Id'] for arm, obj in provenance['images'].items()}
    planned = campaign.read_json(OUTPUT / 'plan.json')
    if planned != plan():
        raise ValueError('saved plan differs from immutable diagnostic')
    for cell in planned:
        campaign.ROOT = cell_root(cell)
        directory, load_path, resource_path = campaign.cell_paths(cell)
        if directory.exists():
            raise ValueError('refusing to repeat or overwrite a planned cell')
        directory.mkdir(parents=True)
        env = {key: value for key, value in os.environ.items() if not key.startswith(('FERRUM_', 'BENCH_'))}
        env.update(FERRUM_IMAGE=IMAGES['ferrum'], ENVOY_IMAGE=IMAGES['envoy'], TOOLS_IMAGE=TOOLS,
                   BENCH_PHASE=PHASE, BENCH_PROXY_CPUS='4', BENCH_WORKERS=str(cell['workers']),
                   BENCH_PRODUCTION_OBSERVE='true', BENCH_CARGO_PROFILE='release',
                   BENCH_FERRUM_FEATURES='cloud-secrets', BENCH_RATE='0')
        command = ['timeout', '--signal=TERM', '--kill-after=10s', '450s', 'bash',
                   'tests/performance/mesh_runtime/run_mesh_runtime_bench.sh', cell['arm'],
                   '--payload-sizes', str(cell['payload']), '--duration', '30',
                   '--concurrency', '100', '--warmup', '3', '--output-dir', str(directory), '--skip-build']
        print('[locality] ' + json.dumps(cell), flush=True)
        with (directory / 'run.log').open('w') as log:
            status = subprocess.run(command, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT).returncode
        row = read_cell(cell, image_ids, status)
        classification = {key: value for key, value in row.items() if key not in ('report', 'resources', 'failed_report')}
        classification['runner_exit_code'] = status
        write(directory / 'cell-classification.json', classification)
        if not row['measurement_valid']:
            raise ValueError('structural qualification failed; retain evidence and all unexecuted planned cells')
        print('[locality] goodput=' + str(row['observed_metrics']['goodput_rps']) + ' errors=' + str(row['report']['total_errors']), flush=True)


def summarize():
    provenance = campaign.read_json(OUTPUT / 'provenance.json')
    image_ids = {arm: obj['Id'] for arm, obj in provenance['images'].items()}
    rows = [read_cell(cell, image_ids) for cell in plan()]
    comparisons = []
    for arm in IMAGES:
        for payload in (1024, 1048576):
            pairs = []
            for repetition in (1, 2):
                selected = {row['workers']: row for row in rows if row['arm'] == arm and row['payload'] == payload and row['repetition'] == repetition}
                ratios = {}
                for metric in ('goodput_rps', 'cpu_us_per_completion', 'cohort_p50_us', 'cohort_p95_us', 'cohort_p99_us'):
                    left, right = selected[1], selected[4]
                    a = left['observed_metrics'][metric] if left['measurement_valid'] else None
                    b = right['observed_metrics'][metric] if right['measurement_valid'] else None
                    ratios[metric] = b/a if campaign.finite_number(a, positive=True) and campaign.finite_number(b) else None
                pairs.append(dict(repetition=repetition, workers4_over_workers1=ratios,
                                  errors={workers: selected[workers]['report'].get('total_errors') if isinstance(selected[workers]['report'], dict) else None for workers in (1, 4)}))
            comparisons.append(dict(arm=arm, payload=payload, pairs=pairs))
    result = dict(planned_cells=16, measurement_valid_cells=sum(row['measurement_valid'] for row in rows),
                  zero_error_capacity_cells=sum(row['valid'] for row in rows),
                  measurement_valid=all(row['measurement_valid'] for row in rows), cells=rows,
                  comparisons=comparisons, limitations=provenance['limits'])
    write(OUTPUT / 'summary.json', result)
    print(f"Worker discriminator: {result['measurement_valid_cells']}/16 measurement-valid; {result['zero_error_capacity_cells']}/16 zero-error cells.")
    print('All workers4/workers1 pairs, including adverse/undefined observations:')
    print(json.dumps(comparisons, indent=2, allow_nan=False))
    return 0 if result['measurement_valid'] else 1


def main():
    action = argparse.ArgumentParser()
    action.add_argument('action', choices=['prepare', 'measure', 'summarize'])
    args = action.parse_args()
    return globals()[args.action]() or 0


if __name__ == '__main__':
    sys.exit(main())
