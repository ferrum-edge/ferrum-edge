#!/usr/bin/env python3
"""Serial, remote-only 48 mesh + 32 gateway candidate observations."""
from __future__ import annotations

import importlib.util
import json
import math
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid

from mesh_gap_candidate import BASELINE, GATEWAY_HARNESS, IMAGE, ROOT, digest, require_remote, selection, write
from mesh_gap_build import checked_receipt, command
from mesh_gap_plan import DECISION, comparisons, gateway_blocks, mesh_cells, screen
import mesh_production_campaign as production

OUTPUT = ROOT / 'results/gap/campaign'


def read(path):
    return production.read_json(Path(path))


def prepare_images(chosen):
    checks = ROOT / 'results/gap/checks/receipt.json'
    checked_receipt(chosen, checks)
    receipts = {}
    for role in ('baseline', 'candidate'):
        directory = ROOT / 'results/gap/images' / role
        receipt = read(directory / 'receipt.json')
        expected = BASELINE if role == 'baseline' else chosen['candidate_sha']
        if (receipt.get('selection') != chosen or receipt.get('role') != role or receipt.get('source_sha') != expected
                or receipt.get('complete') is not True or receipt.get('errors') != []
                or receipt.get('checks_receipt_sha256') != digest(checks)
                or receipt.get('dockerfile_sha256') != chosen['dockerfile_sha256']
                or IMAGE.fullmatch(str(receipt.get('image_id'))) is None
                or receipt.get('image_archive_sha256') != digest(directory / 'image.tar')
                or receipt.get('compiler_native_packages_sha256') != digest(directory / 'compiler-native-packages.log')):
            raise ValueError('unmatched or incomplete ' + role + ' build receipt')
        command(['docker', 'load', '--input', str(directory / 'image.tar')], OUTPUT, 'load-' + role, timeout=180)
        actual = json.loads(subprocess.check_output(['docker', 'image', 'inspect', receipt['image_id']], text=True))[0]
        labels = actual['Config']['Labels']
        if (actual['Id'] != receipt['image_id'] or labels.get('org.opencontainers.image.revision') != expected
                or labels.get('io.ferrum.benchmark.profile') != 'release'
                or labels.get('io.ferrum.benchmark.features') != 'cloud-secrets'):
            raise ValueError('loaded image differs from exact build receipt')
        receipts[role] = receipt
    if receipts['baseline']['compiler_native_packages_sha256'] != receipts['candidate']['compiler_native_packages_sha256']:
        raise ValueError('baseline/candidate compiler or native package metadata differ; no measurements allowed')
    tools_tag = 'mesh-gap-tools:' + uuid.uuid4().hex
    command(['docker', 'build', '--progress', 'plain', '-f', 'tests/performance/mesh_runtime/Dockerfile.production-tools',
             '-t', tools_tag, 'tests/performance/mesh_runtime'], OUTPUT, 'tools-build', timeout=1200)
    tools = json.loads(subprocess.check_output(['docker', 'image', 'inspect', tools_tag], text=True))[0]
    write(OUTPUT / 'tools-image.json', tools)
    source = dict(selection=chosen, builds=receipts,
        image_ids={role: item['image_id'] for role, item in receipts.items()} | {'tools': tools['Id']},
        same_image_aa=True, checks_receipt_sha256=digest(checks),
        limits=['fresh representative release comparison, not a shipping-image ranking',
                'synthetic localized file configuration and mTLS identities; no cross-node deployment',
                'shared-runner CPU, backend and load-generator contention retained in resources',
                'operational metrics enabled; full workload exporter telemetry remains separately unqualified',
                'OS scheduler switches are not Tokio task wakes; socket samples can miss short connections'])
    write(OUTPUT / 'provenance.json', source)
    return source


def load_gateway_module(checkout):
    spec = importlib.util.spec_from_file_location('gap_frozen_tail', checkout / '.github/scripts/mesh_tail_confirmation.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    original = module.sample_issues

    def observation_issues(raw):
        # The old gateway helper combines evidence and capacity. Remove only
        # its explicit positive product-error SLO item; retain every raw error.
        issues = original(raw)
        count = raw.get('total_errors')
        if type(count) is int and count > 0:
            issues = [issue for issue in issues if issue != f'{count} errors']
        if (raw.get('total_requests') == 0 and type(raw.get('total_requests')) is int
                and raw.get('total_bytes') == 0 and raw.get('rps') == 0):
            issues = [issue for issue in issues if issue not in ('no successful requests', 'non-positive/invalid throughput')]
        return issues

    module.sample_issues = observation_issues
    return module


def image_role(cell):
    return 'candidate' if cell['arm'] == 'candidate' else 'baseline'


def mesh_observation(cell, directory, source, exit_code):
    row = dict(cell=cell, measurement_valid=False, capacity_qualified=False, metrics={}, issues=[], runner_exit_code=exit_code)
    try:
        load_path = directory / f"ferrum_http1_{cell['payload']}.json"
        resource_path = directory / f"ferrum_http1_{cell['payload']}.resources.json"
        load, resource = read(load_path), read(resource_path)
        row.update(load=load, resources=resource)
        normalized = dict(cell, arm='ferrum')
        issues = production.validate_observation(normalized, load, resource)
        ordinary = type(load.get('total_errors')) is int and (load['total_errors'] > 0 or load.get('total_requests') == 0)
        if not (exit_code == 0 or exit_code == 1 and ordinary):
            issues.append('runner failure is not a conserved ordinary load outcome')
        image = source['image_ids'][image_role(cell)]
        containers = resource.get('containers', [])
        observed = resource.get('production', {}).get('proxy_containers', [])
        if (len(containers) != 2 or len(observed) != 2 or
                any(c.get('image_id') != image for c in containers + observed) or
                any(c.get('worker_environment') != ['FERRUM_WORKER_THREADS=4'] or c.get('network_mode') != 'host'
                    or c.get('cpu_limit_nanos') != 0 or c.get('cpu_quota') not in (0, -1) for c in observed)):
            issues.append('proxy image, worker, network or default CPU quota differs from plan')
        if (len({c.get('pid') for c in containers}) != 2 or any(type(c.get('pid')) is not int or c['pid'] <= 0 for c in containers)
                or [str(c.get('name', '')).rsplit('-', 1)[-1] for c in containers] != ['client', 'server']):
            issues.append('proxy roles require distinct ordered client/server process identities')
        for phase in ('begin', 'end'):
            measured = resource.get(phase, {}).get('processes', [])
            if [item.get('pid') for item in measured] != [item.get('pid') for item in containers]:
                issues.append('proxy CPU interval identity differs from image receipt')
        if any(any(c.get(key) != o.get(key) for key in ('name', 'pid', 'image_id')) for c, o in zip(containers, observed)):
            issues.append('proxy process/image receipt mismatch')
        if (resource.get('rss_samples', 0) <= 0 or not production.finite_number(resource.get('proxy_rss_bytes_mean'), positive=True)
                or not production.finite_number(resource.get('proxy_rss_bytes_peak'), positive=True)
                or resource['proxy_rss_bytes_peak'] < resource['proxy_rss_bytes_mean']
                or not production.finite_number(resource.get('host_cpu_steal_percent'))
                or resource['host_cpu_steal_percent'] > 5):
            issues.append('RSS or host steal resource gate failed')
        auth = directory / 'logs/auth_probes.log'
        text = auth.read_text()
        for expected in ('plaintext refused', 'valid client certificate handshake', 'no-client-cert refused', 'rogue-CA client certificate refused'):
            if '[auth-probe] ok: ' + expected not in text:
                issues.append('missing authentication proof: ' + expected)
        metric_receipts = {}
        for phase in ('before', 'after'):
            for role in (0, 1):
                path = directory / f'{phase}-{role}-metrics.json'
                capture = read(path)
                if capture.get('returncode') != 0 or not capture.get('body'):
                    issues.append('missing native metric snapshot: ' + path.name)
                metric_receipts[path.name] = digest(path)
        auxiliary = resource.get('production', {}).get('auxiliary_containers', [])
        if (len(resource.get('begin', {}).get('processes', [])) != 2
                or len(resource.get('end', {}).get('processes', [])) != 2
                or len(auxiliary) != 2 or len(resource.get('auxiliary_cpu', [])) != 2
                or any(item.get('image_id') != source['image_ids']['tools'] for item in auxiliary)):
            issues.append('missing proxy or backend/loadgen resource identities')
        cap = production.validate(normalized, load, resource)
        metrics = production.observed_metrics(normalized, load, resource) if not issues else {}
        if metrics:
            metrics.update({key: resource[key] for key in ('proxy_rss_bytes_mean', 'proxy_rss_bytes_peak')})
        interval = resource.get('elapsed_seconds', 0)
        per_role = []
        for index, (a, b) in enumerate(zip(resource.get('begin', {}).get('processes', []), resource.get('end', {}).get('processes', []))):
            cpu = (b['cpu_ticks'] - a['cpu_ticks']) / resource['clock_ticks_per_second']
            per_role.append(dict(role=('source', 'destination')[index], cpu_seconds=cpu, mean_cpu_cores=cpu / interval))
        row.update(load=load, resources=resource, issues=issues, measurement_valid=not issues,
                   capacity_qualified=not issues and not cap, capacity_issues=cap,
                   strict_zero_error_zero_miss=not issues and not cap and load['missed_requests'] == 0,
                   metrics=metrics, resource_headroom=dict(proxy_roles=per_role, auxiliary=resource.get('auxiliary_cpu'),
                    host_logical_cpus=os.cpu_count(), host_steal_percent=resource.get('host_cpu_steal_percent')),
                   evidence_sha256={load_path.name: digest(load_path), resource_path.name: digest(resource_path),
                                    'logs/auth_probes.log': digest(auth), **metric_receipts})
    except (OSError, ValueError, TypeError, KeyError, IndexError, ArithmeticError) as error:
        row['issues'].append(str(error))
    write(directory / 'observation.json', row)
    return row


def run_mesh(cell, source):
    directory = OUTPUT / cell['directory']
    directory.mkdir(parents=True, exist_ok=False)
    write(directory / 'identity.json', dict(cell=cell, image_id=source['image_ids'][image_role(cell)], selection=source['selection']))
    env = {k: v for k, v in os.environ.items() if not k.startswith(('FERRUM_', 'BENCH_', 'MESH_BENCH_'))}
    env.update(FERRUM_IMAGE=source['image_ids'][image_role(cell)], TOOLS_IMAGE=source['image_ids']['tools'],
               BENCH_CARGO_PROFILE='release', BENCH_FERRUM_FEATURES='cloud-secrets', BENCH_WORKERS='4',
               BENCH_PRODUCTION_OBSERVE='true', BENCH_RATE=str(cell['rate']), MESH_BENCH_RUN_ID=uuid.uuid4().hex)
    argv = ['timeout', '--signal=TERM', '--kill-after=10s', '450s', 'bash', 'tests/performance/mesh_runtime/run_mesh_runtime_bench.sh',
            'ferrum', '--payload-sizes', str(cell['payload']), '--duration', '30', '--concurrency', '100', '--warmup', '3',
            '--output-dir', str(directory), '--skip-build']
    print('mesh start ' + cell['directory'], flush=True)
    with (directory / 'run.log').open('w') as stream:
        result = subprocess.run(argv, cwd=ROOT, env=env, stdout=stream, stderr=subprocess.STDOUT)
    return mesh_observation(cell, directory, source, result.returncode)


def gateway_observation(module, block, cell, directory):
    row = dict(block=block, cell=cell, measurement_valid=False, capacity_qualified=False, metrics={}, issues=[])
    try:
        raw_path = directory / 'protocol/pairs' / f"pair_{block['pair']:03d}" / f"{cell['arm']}_{block['scenario']}_1048576.json"
        row['raw'] = read(raw_path)
        row['evidence_sha256'] = {str(raw_path.relative_to(directory)): digest(raw_path)}
        try:
            raw, evidence = module.observed(cell, block, directory)
        except ZeroDivisionError:
            # In the frozen helper the final CPU/completion division is the only
            # zero denominator; all identity/resource/accounting checks precede it.
            raw = read(directory / 'protocol/pairs' / f"pair_{block['pair']:03d}" / f"{cell['arm']}_{block['scenario']}_1048576.json")
            if raw.get('total_requests') != 0 or raw.get('rps') != 0 or raw.get('total_bytes') != 0:
                raise
            raw['cpu_per_request'] = None
            evidence = dict(zero_successful_window=True, cpu_per_completion='undefined; retained full process usage')
        # Retain successful-window service quantiles and independent error/drain counts.
        measurement = raw['process_usage']['measurement']
        proxies = [item for item in measurement if item['role'] == 'gateway']
        start = raw['phases']['measurement_start_unix_secs']
        samples = [sum(p['rss_bytes'] for p in item['processes'] if p['role'] == 'gateway')
                   for item in raw['process_usage'].get('timeline', []) if start <= item['unix_secs'] <= start + 30]
        if not samples or not all(samples):
            raise ValueError('gateway RSS measurement samples missing')
        metrics = dict(goodput_rps=raw['rps'], cpu_us_per_completion=raw['cpu_per_request'] * 1e6 if raw['cpu_per_request'] is not None else None,
            total_errors=raw['total_errors'], total_requests=raw['total_requests'], drained_requests=raw['drain_requests'],
            proxy_rss_bytes_mean=sum(samples) / len(samples), proxy_rss_bytes_peak=max(samples))
        for quantile in ('p50', 'p95', 'p99'):
            value = raw.get(quantile + '_us')
            if raw['total_requests'] == 0:
                metrics['completion_' + quantile + '_us'] = None
                continue
            if not production.finite_number(value, positive=True):
                raise ValueError('missing successful completion-window quantile')
            metrics['completion_' + quantile + '_us'] = value
        row.update(measurement_valid=True, capacity_qualified=raw['total_errors'] == 0 and raw['total_requests'] > 0,
                   raw=raw, evidence=evidence, metrics=metrics, resource_headroom=measurement)
    except (OSError, ValueError, TypeError, KeyError, IndexError, ArithmeticError) as error:
        row['issues'].append(str(error))
        # Raw files stay retained even when zero successful gateway completions
        # prevent the older gateway validity contract from qualifying the cell.
    write(directory / (cell['leg'] + '-observation.json'), row)
    return row


def run():
    require_remote()
    chosen = selection()
    if chosen['phase'] != 'gap-compare':
        raise ValueError('comparison requires explicit gap-compare phase')
    OUTPUT.mkdir(parents=True, exist_ok=False)
    plan = dict(selection=chosen, mesh=mesh_cells(), gateway=gateway_blocks(), planned_cells=80,
                decision_contract=DECISION, state='preparing', errors=[], cleanup_complete=False)
    write(OUTPUT / 'plan.json', plan)
    def interrupted(signum, frame):
        raise InterruptedError('campaign signal ' + str(signum))
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    owned = Path(tempfile.mkdtemp(prefix='mesh-gap-gateway-', dir=os.environ['RUNNER_TEMP']))
    checkout, fixture = owned / 'source', owned / 'fixture'
    run_id = uuid.uuid4().hex
    module = None
    started = time.monotonic()
    try:
        source = prepare_images(chosen)
        subprocess.run(['git', 'worktree', 'add', '--detach', str(checkout), GATEWAY_HARNESS], cwd=ROOT, check=True)
        command(['cargo', 'build', '--locked', '--release', '--manifest-path', 'tests/performance/multi_protocol/Cargo.toml',
                 '--bin', 'proto_bench', '--bin', 'proto_backend'], OUTPUT, 'gateway-tools-build', cwd=checkout, timeout=1200)
        write(OUTPUT / 'gateway-tools.json', dict(source_sha=GATEWAY_HARNESS,
            binaries={name: digest(checkout / 'tests/performance/multi_protocol/target/release' / name) for name in ('proto_bench', 'proto_backend')},
            rustc=subprocess.check_output(['rustc', '-Vv'], text=True), cargo=subprocess.check_output(['cargo', '-Vv'], text=True)))
        module = load_gateway_module(checkout)
        os.chdir(checkout)
        users = {role: module.gateway.image_identity(source['image_ids'][role], run_id, role) for role in ('baseline', 'candidate')}
        write(OUTPUT / 'image-users.json', users)
        fixture.mkdir()
        module.gateway.prepare_fixture(fixture)
        host = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        plan.update(state='running', host_id=host, source=source)
        write(OUTPUT / 'plan.json', plan)
        for cell in plan['mesh']:
            if time.monotonic() - started > 7200:
                raise ValueError('fixed campaign deadline reached; remaining cells stay pending')
            if not run_mesh(cell, source)['measurement_valid']:
                raise ValueError('structural mesh failure at ' + cell['directory'])
        for base in plan['gateway']:
            if time.monotonic() - started > 7200:
                raise ValueError('fixed campaign deadline reached; remaining gateway cells stay pending')
            directory = OUTPUT / base['directory']
            directory.mkdir(parents=True, exist_ok=False)
            block = dict(base, payload_size=1048576, duration_secs=30, effective_concurrency=50,
                host_id=host, image_ids=source['image_ids'], members=[dict(cell, image_id=source['image_ids'][cell['image_role']],
                    runtime_source_sha=BASELINE if cell['image_role'] == 'baseline' else chosen['candidate_sha']) for cell in base['members']])
            write(directory / 'identity.json', block)
            print('gateway start ' + base['directory'], flush=True)
            status = module.gateway.run_protocol(base['scenario'], directory / 'protocol', fixture, run_id,
                dict(candidate_image_id=source['image_ids']['candidate' if base['phase'] == 'ab' else 'baseline'],
                     baseline_image_id=source['image_ids']['baseline']), tail_pair=base['pair'], wall_secs=300)
            write(directory / 'status.json', status)
            rows = [gateway_observation(module, block, cell, directory) for cell in block['members']]
            if not all(row['measurement_valid'] for row in rows):
                raise ValueError('structural gateway failure at ' + base['directory'])
        plan['state'] = 'completed'
    except (OSError, ValueError, subprocess.SubprocessError, KeyError, TypeError) as error:
        plan.update(state='failed')
        plan['errors'].append(str(error))
    finally:
        os.chdir(ROOT)
        if module is not None:
            os.chdir(checkout)
            for role in ('baseline', 'candidate'):
                try:
                    module.gateway.runtime('identity-remove', timeout=28, RUN_ID=run_id, ROLE=role)
                except (OSError, subprocess.SubprocessError) as error:
                    plan['errors'].append('identity cleanup: ' + str(error))
            os.chdir(ROOT)
        cleanup = subprocess.run(['git', 'worktree', 'remove', '--force', str(checkout)], cwd=ROOT, capture_output=True, check=False)
        cleanup_errors = []
        if cleanup.returncode and checkout.exists():
            cleanup_errors.append('owned gateway worktree removal failed')
        try:
            shutil.rmtree(owned)
        except OSError as error:
            cleanup_errors.append('owned fixture removal: ' + str(error))
        plan['errors'].extend(cleanup_errors)
        plan.update(cleanup_complete=not cleanup_errors, elapsed_seconds=time.monotonic() - started)
        write(OUTPUT / 'plan.json', plan)
    return 0 if plan['state'] == 'completed' and not plan['errors'] else 1


def summarize():
    plan = read(OUTPUT / 'plan.json')
    mesh, gateway, issues = [], [], []
    if plan.get('mesh') != mesh_cells() or plan.get('gateway') != gateway_blocks() or plan.get('planned_cells') != 80 or plan.get('decision_contract') != DECISION:
        issues.append('complete prespecified plan mismatch')
    if plan.get('state') != 'completed' or plan.get('errors') or plan.get('cleanup_complete') is not True:
        issues.append('campaign execution or cleanup incomplete')
    for cell in mesh_cells():
        path = OUTPUT / cell['directory'] / 'observation.json'
        row = read(path) if path.exists() else dict(cell=cell, measurement_valid=False, capacity_qualified=False, metrics={}, issues=['pending/not measured'])
        if row.get('cell') != cell:
            issues.append('mesh identity mismatch')
        for name, expected in row.get('evidence_sha256', {}).items():
            evidence = path.parent / name
            if not evidence.is_file() or digest(evidence) != expected:
                issues.append('mesh raw evidence digest mismatch: ' + cell['directory'] + '/' + name)
        mesh.append(row)
    for block in gateway_blocks():
        for cell in block['members']:
            path = OUTPUT / block['directory'] / (cell['leg'] + '-observation.json')
            row = read(path) if path.exists() else dict(block=block, cell=cell, measurement_valid=False, capacity_qualified=False, metrics={}, issues=['pending/not measured'])
            if any(row.get('block', {}).get(key) != block[key] for key in ('pair', 'scenario', 'phase', 'directory')):
                issues.append('gateway identity mismatch')
            for name, expected in row.get('evidence_sha256', {}).items():
                evidence = path.parent / name
                if not evidence.is_file() or digest(evidence) != expected:
                    issues.append('gateway raw evidence digest mismatch: ' + block['directory'] + '/' + name)
            gateway.append(row)
    rows = mesh + gateway
    complete = not issues and len(rows) == 80 and all(row['measurement_valid'] for row in rows)
    capacity = complete and all(row['capacity_qualified'] for row in rows)
    pairs = comparisons(mesh, gateway)
    def total(group, raw_key, field):
        values = [row.get(raw_key, {}).get(field) for row in group]
        return sum(values) if all(type(v) is int and v >= 0 for v in values) else None
    report = dict(planned_cells=80, measured_valid_cells=sum(row['measurement_valid'] for row in rows),
        zero_error_capacity_cells=sum(row['capacity_qualified'] for row in rows),
        strict_zero_miss_mesh_cells=sum(row.get('strict_zero_error_zero_miss', False) for row in mesh),
        complete_valid_observations=complete, all_capacity_qualified=capacity, issues=issues,
        total_mesh_errors=total(mesh, 'load', 'total_errors'),
        total_mesh_misses=total(mesh, 'load', 'missed_requests'),
        total_gateway_errors=total(gateway, 'raw', 'total_errors'),
        comparisons=pairs, decision_contract=DECISION, screen=screen(pairs, complete, capacity), mesh=mesh, gateway=gateway,
        latency_scope='Mesh: successful admitted cohort service quantiles including drains; fixed scheduled quantiles separately named. Gateway: successful completion-window service quantiles excluding drains. Errors never have invented latency.')
    write(OUTPUT / 'report.json', report)
    lines = ['Remote candidate comparison', '', f"Valid observations: {report['measured_valid_cells']}/80; zero-error capacity: {report['zero_error_capacity_cells']}/80.",
        f"Mesh errors: {report['total_mesh_errors']}; fixed misses retained: {report['total_mesh_misses']}; gateway errors: {report['total_gateway_errors']}.",
        report['latency_scope'], '', report['screen']['decision'], '', '| Surface | Scenario | Metric | AA all4 | Candidate all4 | Median [min, max] |',
        '|---|---|---|---|---|---|']
    for item in pairs:
        values = item['candidate']
        lines.append(f"| {item['surface']} | {item['scenario']} | {item['metric']} | {item['aa']['all']} | {values['all']} | {values['median']} [{values['min']}, {values['max']}] |")
    lines += ['', 'No filtered samples, automatic reruns or automatic PR approval. Four pairs do not establish equivalence.']
    lines += ['- ' + reason for reason in report['screen']['reasons']]
    text = '\n'.join(lines) + '\n'
    (OUTPUT / 'report.md').write_text(text)
    print(text)
    return report


def export():
    destination = ROOT / 'results/gap/public'
    destination.mkdir(parents=True, exist_ok=False)
    total = 0
    sources = [(OUTPUT, 'campaign'), (ROOT / 'results/gap/images', 'images')]
    for source_root, label in sources:
        for path in source_root.rglob('*'):
            relative = path.relative_to(source_root)
            if (not path.is_file() or path.is_symlink() or any(part in ('runtime', 'target', 'fixture') for part in relative.parts)
                    or path.suffix not in ('.json', '.jsonl', '.log', '.txt', '.md', '.err') or path.name == 'image.tar'):
                continue
            content = path.read_bytes()
            if b'PRIVATE KEY-----' in content:
                raise ValueError('private key material found in public allowlist: ' + str(relative))
            total += len(content)
            if total > 256 * 1024**2:
                raise ValueError('public artifact exceeds fixed 256MiB bound')
            target = destination / label / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
    write(destination / 'export.json', dict(bytes=total, private_fixture_included=False, build_trees_included=False))


if __name__ == '__main__':
    action = sys.argv[1] if len(sys.argv) == 2 else ''
    if action == 'run':
        raise SystemExit(run())
    if action == 'summarize':
        summarize()
    elif action == 'export':
        export()
    elif action == 'accept':
        raise SystemExit(0 if read(OUTPUT / 'report.json')['all_capacity_qualified'] else 1)
    elif action != 'run':
        raise SystemExit('expected run, summarize, export or accept')
