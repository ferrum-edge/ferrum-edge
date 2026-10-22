#!/usr/bin/env python3
"""Fixed two-cell baseline observer; no ranking eligibility or runtime tuning."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

from mesh_gap_candidate import BASELINE, BUILDER, ROOT, digest, git, maintenance_origin, require_remote, write
from mesh_gap_checks import hyper_source_gates, run_command, source_hashes
from mesh_gap_build import command
import mesh_production_campaign as production

SOURCE_ORIGIN = 'cf6bf5981217f0e1906ed3c42dbfaff7ad634a56'
SOURCE = 'f0f6f6ad23604d29f3bc340833392e669f221efd'
FEATURES = 'cloud-secrets,bench-h2-upload-profile'
PHASES = ('h2-upload-vendor-preflight', 'h2-upload-diagnostic')
OUTPUT = ROOT / 'results/h2-upload'
VENDOR = 'vendor/hyper-1.10.0-ferrum-patched/'
MANIFEST = 'vendor/VENDOR_INTEGRITY.sha256'
VENDOR_DELTA = {VENDOR + p for p in ('Cargo.toml', 'src/ext/mod.rs', 'src/ext/h2_upload_diagnostic.rs',
                                  'src/ext/h2_upload_diagnostic_tests.rs', 'src/proto/h2/client.rs')}
CELLS = [dict(payload=1024, concurrency=100), dict(payload=1048576, concurrency=50)]


def validate_input(candidate, phase, extra_paths, parent):
    if not isinstance(candidate, str) or re.fullmatch('[0-9a-f]{40}', candidate) is None or phase not in PHASES:
        raise ValueError('exact diagnostic SHA and allowlisted phase required')
    if parent != BASELINE or set(extra_paths) - {MANIFEST}:
        raise ValueError('diagnostic must be pinned baseline observer plus generated manifest only')


def selection():
    candidate, phase = os.environ.get('GAP_CANDIDATE_SHA', ''), os.environ.get('BENCH_PHASE', '')
    if re.fullmatch('[0-9a-f]{40}', candidate) is None:
        raise ValueError('exact diagnostic SHA required')
    if os.environ.get('GAP_BASELINE_RUN_ID') or os.environ.get('GAP_BASELINE_RUN_ATTEMPT'):
        raise ValueError('baseline reuse inputs are outside this one-image diagnostic')
    extra = git('diff', '--name-only', SOURCE, candidate).splitlines()
    validate_input(candidate, phase, extra, git('show', '-s', '--format=%P', SOURCE_ORIGIN))
    if git('rev-parse', '--verify', candidate + '^{commit}') != candidate:
        raise ValueError('candidate must resolve exactly')
    subprocess.run(['git', 'merge-base', '--is-ancestor', SOURCE, candidate], cwd=ROOT, check=True)
    observed = dict(performance_eligible=False, baseline_sha=BASELINE, observer_source_sha=SOURCE,
        candidate_sha=candidate, phase=phase, harness_sha=git('rev-parse', 'HEAD'),
        maintenance_origin=maintenance_origin(), profile='release', features=FEATURES,
        builder_image=BUILDER, cells=CELLS, duration=30, warmup=3, workers=4, rate=0,
        allocation_instrumentation=False, perf_sampling=False,
        limits=['instrumented baseline distribution only; atomic contention can perturb scheduling',
                'whole warmup+measurement+drain population, not measurement-window-only',
                'localized shared-runner fixture; full workload exporter telemetry remains separately unqualified',
                'native finalized status is not body EOF; validated echo is independent completion proof',
                'no RPS, allocation-byte or saved-CPU inference; no automatic rerun'])
    observed['source_file_sha256'] = {path: hashlib.sha256(subprocess.check_output(
        ['git', 'show', candidate + ':' + path], cwd=ROOT)).hexdigest()
        for path in ('Cargo.toml', 'Cargo.lock', 'Dockerfile', '.dockerignore', 'rust-toolchain.toml', MANIFEST)}
    observed['fixture_file_sha256'] = {str(path.relative_to(ROOT)): digest(path)
        for path in sorted((ROOT / 'tests/performance/mesh_runtime/configs/ferrum').rglob('*')) if path.is_file()}
    observed['selection_sha256'] = hashlib.sha256(json.dumps(observed, sort_keys=True).encode()).hexdigest()
    return observed


def manifest_rows(text):
    result = {}
    for line in text.splitlines():
        if not line or line.startswith('#'):
            continue
        value, path = line.split(maxsplit=1)
        if path in result or re.fullmatch('[0-9a-f]{64}', value) is None:
            raise ValueError('malformed or duplicate manifest row')
        result[path] = value
    return result


def verify_generated(checkout, old_text):
    after = manifest_rows((checkout / MANIFEST).read_text())
    before = manifest_rows(old_text)
    changed = {path for path in before.keys() | after.keys() if before.get(path) != after.get(path)}
    if changed != VENDOR_DELTA:
        raise ValueError('generator changed rows outside the five diagnostic Hyper files')
    for path in changed:
        actual = hashlib.sha256((checkout / path).read_bytes().replace(b'\r', b'')).hexdigest()
        if actual != after[path]:
            raise ValueError('generated manifest differs from submitted source bytes')
    return dict(performance_eligible=False, changed_rows=sorted(changed),
                manifest_sha256=digest(checkout / MANIFEST), row_sha256={p: after[p] for p in sorted(changed)})


def standalone(checkout, scratch, output):
    hyper, h2 = scratch / 'hyper', scratch / 'h2'
    shutil.copytree(checkout / VENDOR, hyper)
    shutil.copytree(checkout / 'vendor/h2-0.4.20-ferrum-patched', h2)
    original = source_hashes(hyper)
    config = ['--config', 'patch.crates-io.h2.path="' + str(h2) + '"']
    run_command(['cargo', 'update', '--manifest-path', str(hyper / 'Cargo.toml'), *config], hyper, output, 'hyper-lock', vendor_lints=True)
    _, tree = run_command(['cargo', 'tree', '--locked', '--features', 'full,ferrum-h2-upload-diagnostic', '-i', 'h2', *config], hyper, output, 'hyper-tree', vendor_lints=True)
    expected = 'h2 v0.4.20 (' + str(h2) + ')'
    if [line for line in tree.splitlines() if line.startswith('h2 v')] != [expected]:
        raise ValueError('diagnostic standalone graph is not exact patched h2=0.4.20')
    lock = digest(hyper / 'Cargo.lock')
    shutil.copy2(hyper / 'Cargo.lock', output / 'hyper.Cargo.lock')
    run_command(['cargo', 'test', '--locked', '--lib', '--features', 'full,ferrum-h2-upload-diagnostic',
        'ferrum_h2_upload_diagnostic_tests', *config, '--', '--nocapture'], hyper, output,
        'hyper-counter-tests', test=True, expected_passed=2, vendor_lints=True)
    if source_hashes(hyper) != original or digest(hyper / 'Cargo.lock') != lock:
        raise ValueError('standalone check changed source or lock')
    write(output / 'hyper-graph.json', dict(performance_eligible=False, h2_resolution=expected,
        lock_sha256=lock, rustflags='--cap-lints=warn', scope='standalone counter tests only'))


def build_image(checkout, chosen, output, owned):
    token = uuid.uuid4().hex
    tag, builder, container = 'mesh-upload:' + token, 'mesh-upload-builder:' + token, 'mesh-upload-identity-' + token
    receipt = dict(performance_eligible=False, complete=False, selection_sha256=chosen['selection_sha256'],
                   source_sha=chosen['candidate_sha'], features=FEATURES, profile='release', errors=[])
    try:
        common = ['docker', 'build', '--platform', 'linux/amd64', '--progress', 'plain',
            '--build-arg', 'FEATURES=' + FEATURES, '--build-arg', 'CARGO_PROFILE=release',
            '-f', str(checkout / 'Dockerfile')]
        command([*common, '--target', 'builder', '-t', builder, str(checkout)], output, 'build-builder')
        command(['docker', 'run', '--rm', '--entrypoint', '/bin/sh', builder, '-c',
                 'rustc -Vv; cargo -Vv; cc --version; ld --version; dpkg-query -W'], output, 'compiler-native-packages', timeout=60)
        command([*common, '--target', 'runtime', '--label', 'org.opencontainers.image.revision=' + chosen['candidate_sha'],
                 '--label', 'io.ferrum.benchmark.profile=release', '--label', 'io.ferrum.benchmark.features=' + FEATURES,
                 '-t', tag, str(checkout)], output, 'build-runtime')
        obj = json.loads(subprocess.check_output(['docker', 'image', 'inspect', tag], text=True))[0]
        if obj['Architecture'] != 'amd64' or obj['Os'] != 'linux' or re.fullmatch('sha256:[0-9a-f]{64}', obj['Id']) is None:
            raise ValueError('unexpected diagnostic image identity')
        write(output / 'image.json', obj)
        command(['docker', 'create', '--name', container, obj['Id']], output, 'identity-create', timeout=30)
        binary = owned / 'ferrum-edge'
        command(['docker', 'cp', container + ':/app/ferrum-edge', str(binary)], output, 'identity-copy', timeout=30)
        command(['docker', 'run', '--rm', obj['Id'], 'version', '--json'], output, 'runtime-version', timeout=30)
        receipt.update(complete=True, image_id=obj['Id'], binary_sha256=digest(binary),
                       compiler_native_packages_sha256=digest(output / 'compiler-native-packages.log'))
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        receipt['errors'].append(str(error))
    finally:
        subprocess.run(['docker', 'rm', '-f', container], capture_output=True, timeout=30, check=False)
        write(output / 'receipt.json', receipt)
    if not receipt['complete']:
        raise ValueError('diagnostic image build failed; retained receipt is authoritative')
    return receipt


def observe_cell(cell, image, tools):
    directory = OUTPUT / ('payload_' + str(cell['payload']))
    directory.mkdir(exist_ok=False)
    env = {k: v for k, v in os.environ.items() if not k.startswith(('FERRUM_', 'BENCH_', 'MESH_BENCH_'))}
    for key in ('RUSTFLAGS', 'RUSTC_WRAPPER', 'CARGO_BUILD_RUSTC_WRAPPER'):
        env.pop(key, None)
    env.update(FERRUM_IMAGE=image, TOOLS_IMAGE=tools, BENCH_PHASE='h2-upload-diagnostic',
        BENCH_CARGO_PROFILE='release', BENCH_FERRUM_FEATURES=FEATURES, BENCH_WORKERS='4',
        BENCH_RATE='0', BENCH_PRODUCTION_OBSERVE='true')
    argv = ['timeout', '--signal=TERM', '--kill-after=10s', '450s', 'bash',
        'tests/performance/mesh_runtime/run_mesh_runtime_bench.sh', 'ferrum', '--payload-sizes', str(cell['payload']),
        '--duration', '30', '--concurrency', '100', '--warmup', '3', '--output-dir', str(directory), '--skip-build']
    result = dict(performance_eligible=False, cell=cell, accepted=False, errors=[])
    started = time.monotonic()
    try:
        with (directory / 'run.log').open('w') as stream:
            done = subprocess.run(argv, env=env, cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT, timeout=465)
        result.update(command=argv, exit_code=done.returncode, elapsed_seconds=time.monotonic() - started)
        load = json.loads((directory / f"ferrum_http1_{cell['payload']}.json").read_text())
        resources = json.loads((directory / f"ferrum_http1_{cell['payload']}.resources.json").read_text())
        epoch = json.loads((directory / 'upload-epoch/receipt.json').read_text())
        result.update(epoch=epoch, load=load, resources=resources)
        result['errors'] += production.validate_observation(dict(arm='ferrum', payload=cell['payload'], duration=30, rate=0), load, resources)
        if done.returncode != 0 or epoch.get('accepted') is not True or epoch.get('performance_eligible') is not False:
            result['errors'].append('fixture or branch/native conservation failed')
        proxies = resources.get('production', {}).get('proxy_containers', [])
        if len(proxies) != 2 or any(p.get('image_id') != image or p.get('worker_environment') != ['FERRUM_WORKER_THREADS=4']
                or p.get('network_mode') != 'host' or p.get('cpu_limit_nanos') != 0
                or p.get('cpu_quota') not in (-1, 0) for p in proxies):
            result['errors'].append('proxy image, workers, network or CPU ceiling differs')
        auxiliary = resources.get('production', {}).get('auxiliary_containers', [])
        if len(auxiliary) != 2 or any(p.get('image_id') != tools for p in auxiliary):
            result['errors'].append('backend/loadgen tool image identity differs')
        # Whole-epoch identities must also match ordinary resource observations.
        before_rows = epoch.get('before', {}).get('rows', [])
        if len(before_rows) != 2 or any(
                row.get('identity_before', {}).get('host_pid') != proxy.get('pid')
                or row.get('identity_before', {}).get('image_id') != proxy.get('image_id')
                for row, proxy in zip(before_rows, proxies)):
            result['errors'].append('native epoch differs from resource process identities')
        auth = (directory / 'logs/auth_probes.log').read_text()
        for expected in ('plaintext refused', 'valid client certificate handshake', 'no-client-cert refused', 'rogue-CA client certificate refused'):
            if '[auth-probe] ok: ' + expected not in auth:
                result['errors'].append('missing authentication proof: ' + expected)
        result['accepted'] = not result['errors']
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        result['errors'].append(str(error))
    write(directory / 'observation.json', result)
    return result


def run():
    require_remote()
    OUTPUT.mkdir(parents=True, exist_ok=False)
    result = dict(performance_eligible=False, complete=False, accepted=False, errors=[], observations=[])
    owned = Path(tempfile.mkdtemp(prefix='mesh-upload-', dir=os.environ['RUNNER_TEMP']))
    checkout = owned / 'source'
    try:
        chosen = selection()
        result['selection'] = chosen
        write(OUTPUT / 'selection.json', chosen)
        subprocess.run(['git', 'worktree', 'add', '--detach', str(checkout), chosen['candidate_sha']], cwd=ROOT, check=True)
        restored = ROOT / 'target'
        if restored.is_dir():
            shutil.move(str(restored), str(checkout / 'target'))
        checks = OUTPUT / 'checks'
        checks.mkdir()
        run_command(['rustc', '-Vv'], checkout, checks, 'rustc')
        run_command(['cargo', '-Vv'], checkout, checks, 'cargo')
        if chosen['phase'] == 'h2-upload-vendor-preflight':
            old = (checkout / MANIFEST).read_text()
            run_command(['bash', 'scripts/update_vendor_integrity.sh'], checkout, checks, 'vendor-manifest-generation', test=True)
            if git('diff', '--name-only', cwd=checkout).splitlines() != [MANIFEST]:
                raise ValueError('preflight must change only vendor manifest')
            result['manifest_proof'] = verify_generated(checkout, old)
            shutil.copy2(checkout / MANIFEST, checks / 'VENDOR_INTEGRITY.sha256')
            (checks / 'vendor-manifest.patch').write_text(git('diff', '--', MANIFEST, cwd=checkout) + '\n')
            result.update(complete=True, accepted=True, modified_checkout=True)
        else:
            hyper_source_gates(checkout, checks)
            run_command(['cargo', 'fmt', '--all', '--', '--check'], checkout, checks, 'fmt')
            standalone(checkout, owned / 'standalone', checks)
            run_command(['cargo', 'test', '--locked', '--features', FEATURES, '--test', 'integration_tests', 'vendor_integrity'], checkout, checks, 'vendor-integrity', test=True)
            run_command(['cargo', 'clippy', '--locked', '--features', FEATURES, '--lib', '--tests', '-p', 'ferrum-edge', '--', '-D', 'warnings'], checkout, checks, 'clippy')
            run_command(['cargo', 'build', '--locked', '--features', FEATURES, '--bin', 'ferrum-edge'], checkout, checks, 'functional-binary')
            run_command(['cargo', 'test', '--locked', '--features', FEATURES, '--test', 'functional_tests',
                'functional_admin_observability_test::test_metrics_gated_and_live_minimal', '--', '--ignored', '--nocapture'],
                checkout, checks, 'admin-auth-schema', test=True, expected_passed=1)
            if git('status', '--porcelain', '--untracked-files=normal', cwd=checkout):
                raise ValueError('definitive checks changed submitted source')
            image_output = OUTPUT / 'image'
            image_output.mkdir()
            image = build_image(checkout, chosen, image_output, owned)
            tag = 'mesh-upload-tools:' + uuid.uuid4().hex
            command(['docker', 'build', '--progress', 'plain', '-f', 'tests/performance/mesh_runtime/Dockerfile.production-tools',
                '-t', tag, 'tests/performance/mesh_runtime'], OUTPUT, 'tools-build', timeout=1200)
            tools = json.loads(subprocess.check_output(['docker', 'image', 'inspect', tag], text=True))[0]
            write(OUTPUT / 'tools-image.json', tools)
            for cell in CELLS:
                result['observations'].append(observe_cell(cell, image['image_id'], tools['Id']))
                write(OUTPUT / 'receipt.json', result)
            if git('status', '--porcelain', '--untracked-files=normal', cwd=checkout):
                raise ValueError('build changed submitted source')
            result.update(complete=True, accepted=all(x['accepted'] for x in result['observations']), modified_checkout=False)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        result['errors'].append(str(error))
    finally:
        result['performance_eligible'] = False
        write(OUTPUT / 'receipt.json', result)
        subprocess.run(['git', 'worktree', 'remove', '--force', str(checkout)], cwd=ROOT, capture_output=True, check=False)
        shutil.rmtree(owned, ignore_errors=True)
    print(json.dumps({k: result[k] for k in ('performance_eligible', 'complete', 'accepted', 'errors')}))
    return 0 if result['accepted'] and not result['errors'] else 1


def export():
    destination = ROOT / 'results/h2-upload-public'
    destination.mkdir(parents=True, exist_ok=False)
    total, hashes = 0, {}
    for path in sorted(OUTPUT.rglob('*')):
        relative = path.relative_to(OUTPUT)
        if (not path.is_file() or path.is_symlink() or any(part in ('runtime', 'target', 'fixture') for part in relative.parts)
                or path.suffix not in ('.json', '.jsonl', '.log', '.txt', '.md', '.err', '.patch', '.sha256', '.lock')):
            continue
        body = path.read_bytes()
        if b'PRIVATE KEY-----' in body:
            raise ValueError('private key in public allowlist')
        total += len(body)
        if total > 256 * 1024**2:
            raise ValueError('public artifact exceeds fixed256MiB bound')
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(body)
        hashes[str(relative)] = digest(target)
    write(destination / 'export.json', dict(performance_eligible=False, bytes=total, sha256=hashes,
        private_fixture_included=False, build_trees_included=False))


if __name__ == '__main__':
    action = sys.argv[1] if len(sys.argv) == 2 else ''
    if action == 'validate':
        require_remote()
        print(json.dumps(selection(), indent=2))
    elif action == 'run':
        raise SystemExit(run())
    elif action == 'export':
        export()
    else:
        raise SystemExit('expected validate, run, or export')
