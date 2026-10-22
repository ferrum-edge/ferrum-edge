#!/usr/bin/env python3
"""One representative own-image DWARF bracket; no shipping attribution or retry.

Only `prepare` and `measure` execute tools. `finalize` runs as root remotely to
stop this attempt's recorders, delete private raw traces/caches, and export an
explicit public allowlist. Pure qualification helpers support synthetic tests.
"""
from __future__ import annotations

import difflib
import json
import math
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid

from mesh_gap_candidate import ORIGINAL_BASELINE as BASELINE, BUILDER, IMAGE, ROOT, digest, require_remote, write
from mesh_gap_build import command
from mesh_gap_campaign import mesh_observation
import mesh_production_campaign as production
from mesh_gap_profile_capture import export_derived

OUTPUT = ROOT / 'results/gap-profile'
PUBLIC = ROOT / 'results/gap-profile-public'
PHASES = ('before', 'profile', 'after')
ROLES = ('source', 'destination')
SCOPE = ('Fresh representative release of baseline ' + BASELINE + '; own original-link symbol companion and '
         'same-image controls. User CPU leaf and synchronous inclusive sampled stacks only; overlapping inclusive '
         'rows are not additive. No shipping attribution, async request CPU, Tokio wake counts, or source-line claim. '
         'Three small-payload cells qualify this observer only, not a performance improvement or competitor ranking.')
REPLACEMENT = ('python3 -u "$SCRIPT_DIR/collect_resources.py"',
               'python3 -u "$SCRIPT_DIR/../../../.github/scripts/mesh_gap_profile_capture.py"')


def read(path):
    return json.loads(Path(path).read_text())


def build_dir():
    return Path(os.environ['RUNNER_TEMP']) / 'gap-profile-build'


def cell_dir(phase):
    if phase not in PHASES:
        raise ValueError('unknown profile phase')
    return OUTPUT / 'cells' / phase / 'payload_1024'


def transform_runner(original):
    if original.count(REPLACEMENT[0]) != 1:
        raise ValueError('collector substitution requires exactly one literal occurrence')
    return original.replace(*REPLACEMENT)


def preparation_errors(report):
    errors = []
    if (report.get('qualified') is not True or report.get('ready_for_dwarf_capture') is not True
            or report.get('source') != BASELINE or report.get('builder') != BUILDER
            or report.get('runtime_flags_changed') is not False or report.get('shipping_attribution_allowed') is not False
            or IMAGE.fullmatch(str(report.get('runtime_image', {}).get('Id'))) is None):
        errors.append('exact representative preparation not qualified')
    pair = report.get('own_pair', {})
    if (pair.get('qualified') is not True or not pair.get('shipping_build_id')
            or pair.get('shipping_build_id') != pair.get('diagnostic_build_id')):
        errors.append('own-image exact code/build-ID pairing missing')
    if report.get('unwind_preflight', {}).get('qualified_for_one_dwarf_attempt') is not True:
        errors.append('prespecified unwind preflight failed; no alternate build or flags')
    return errors


def prepare():
    OUTPUT.mkdir(parents=True, exist_ok=False)
    report = read(build_dir() / 'report.json')
    errors = preparation_errors(report)
    if errors or report.get('helper_sha256') != digest(Path(__file__).with_name('mesh_gap_profile_prepare.py')):
        raise ValueError('; '.join(errors) or 'prepare helper revision differs')
    image = report['runtime_image']['Id']
    actual = json.loads(subprocess.check_output(['docker', 'image', 'inspect', image], text=True))[0]
    if (actual['Id'] != image or actual['Architecture'] != 'amd64' or actual['Os'] != 'linux'
            or actual['Config']['Labels'].get('org.opencontainers.image.revision') != BASELINE):
        raise ValueError('prepared runtime image identity mismatch')
    token = uuid.uuid4().hex
    tools_tag = 'mesh-gap-profile-tools:' + token
    command(['docker', 'build', '--progress', 'plain', '-f', 'tests/performance/mesh_runtime/Dockerfile.production-tools',
             '-t', tools_tag, 'tests/performance/mesh_runtime'], OUTPUT, 'tools-build', timeout=1200)
    tools = json.loads(subprocess.check_output(['docker', 'image', 'inspect', tools_tag], text=True))[0]
    if IMAGE.fullmatch(tools['Id']) is None:
        raise ValueError('immutable load-tool image missing')
    write(OUTPUT / 'tools-image.json', tools)
    command(['docker', 'run', '--rm', '--network', 'none', '--entrypoint', '/bin/sh', report['builder_image']['Id'], '-c',
             'rustc -Vv; cargo -Vv; cc --version; ld --version; dpkg-query -W'], OUTPUT, 'compiler-native-packages', timeout=60)
    owned = Path(tempfile.mkdtemp(prefix='mesh-gap-profile-harness-', dir=os.environ['RUNNER_TEMP']))
    checkout = owned / 'source'
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    command(['git', 'worktree', 'add', '--detach', str(checkout), head], OUTPUT, 'harness-worktree', timeout=120)
    runner = checkout / 'tests/performance/mesh_runtime/run_mesh_runtime_bench.sh'
    original = runner.read_text()
    transformed = transform_runner(original)
    (OUTPUT / 'collector-wrapper.diff').write_text(''.join(difflib.unified_diff(
        original.splitlines(True), transformed.splitlines(True), fromfile='runner.original', tofile='runner.diagnostic')))
    before_hash = digest(runner)
    runner.write_text(transformed)
    write(OUTPUT / 'provenance.json', dict(schema=1, scope=SCOPE, baseline_sha=BASELINE, harness_sha=head,
        image_ids=dict(baseline=image, candidate=image, tools=tools['Id']), prepared_report_sha256=digest(build_dir() / 'report.json'),
        symbol_elf_sha256=digest(build_dir() / 'capture/ferrum-edge/symbols'),
        compiler_native_packages_sha256=digest(OUTPUT / 'compiler-native-packages.log'),
        disposable_checkout=str(checkout), runner_before_sha256=before_hash, runner_after_sha256=digest(runner),
        collector_wrapper_sha256=digest(checkout / '.github/scripts/mesh_gap_profile_capture.py'),
        plan=dict(phases=PHASES, payload=1024, concurrency=100, duration=30, warmup=3, rate=0, workers=4,
                  cpu_quota='default unchanged', sampling_hz=19, dwarf_stack_bytes=8192, control_bound=1.05,
                  attempts=1, fallback_builds=0, automatic_reruns=0)))


def measure():
    source = read(OUTPUT / 'provenance.json')
    if source['prepared_report_sha256'] != digest(build_dir() / 'report.json'):
        raise ValueError('prepared report changed')
    checkout = Path(source['disposable_checkout'])
    runner = checkout / 'tests/performance/mesh_runtime/run_mesh_runtime_bench.sh'
    if digest(runner) != source['runner_after_sha256']:
        raise ValueError('diagnostic runner changed')
    # All three cells use the same wrapper, including user/system CPU snapshots.
    # Finish the full bracket even if any cell fails. No retries or sample removal.
    for index, phase in enumerate(PHASES, 1):
        directory = cell_dir(phase)
        directory.mkdir(parents=True, exist_ok=False)
        cell = dict(arm='baseline_a', payload=1024, duration=30, rate=0, load='saturated', repetition=index, phase=phase)
        env = {key: value for key, value in os.environ.items() if not key.startswith(('BENCH_', 'FERRUM_', 'MESH_BENCH_'))}
        env.update(FERRUM_IMAGE=source['image_ids']['baseline'], TOOLS_IMAGE=source['image_ids']['tools'],
            BENCH_CARGO_PROFILE='release', BENCH_FERRUM_FEATURES='cloud-secrets', BENCH_WORKERS='4',
            BENCH_PRODUCTION_OBSERVE='true', BENCH_RATE='0', BENCH_PERF_LEAF='true' if phase == 'profile' else 'false',
            BENCH_SYMBOL_ELF=str(build_dir() / 'capture/ferrum-edge/symbols'),
            BENCH_SYMBOL_REPORT=str(build_dir() / 'report.json'), MESH_BENCH_RUN_ID=uuid.uuid4().hex)
        argv = ['timeout', '--signal=TERM', '--kill-after=10s', '450s', 'bash', str(runner), 'ferrum',
                '--payload-sizes', '1024', '--duration', '30', '--concurrency', '100', '--warmup', '3',
                '--output-dir', str(directory), '--skip-build']
        print('representative profile cell start: ' + phase, flush=True)
        start = time.monotonic()
        with (directory / 'run.log').open('w') as stream:
            result = subprocess.run(argv, cwd=checkout, env=env, stdout=stream, stderr=subprocess.STDOUT)
        write(directory / 'command.json', dict(argv=argv, exit_code=result.returncode, elapsed_seconds=time.monotonic() - start,
            environment={key: env[key] for key in sorted(env) if key.startswith(('BENCH_', 'FERRUM_IMAGE', 'TOOLS_IMAGE', 'MESH_BENCH_RUN_ID'))}))
        row = mesh_observation(cell, directory, source, result.returncode)
        failed_load = directory / 'ferrum_http1_1024.failed-output.json'
        load = row.get('load', {})
        if failed_load.is_file():
            load = read(failed_load)
            row['retained_failed_load'] = load
            row.setdefault('evidence_sha256', {})[failed_load.name] = digest(failed_load)
        row['descriptive_controls'] = descriptive_controls(load, row.get('resources', {}))
        write(directory / 'observation.json', row)
        print('representative profile cell complete: ' + phase + ' exit=' + str(result.returncode), flush=True)


def owned_recorders(private, proc=Path('/proc')):
    """Only exact root-owned perf record commands targeting these two raw paths."""
    targets = {str(private / role / 'perf.data') for role in ROLES}
    expected_pids = {}
    receipt = private / 'capture.json'
    if receipt.is_file():
        for role in read(receipt).get('roles', []):
            if role.get('role') in ROLES:
                pid = role.get('identity_before', {}).get('process', {}).get('pid')
                if type(pid) is int and pid > 1:
                    expected_pids[str(private / role['role'] / 'perf.data')] = str(pid)
    found = []
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            if entry.stat().st_uid != 0:
                continue
            argv = [part.decode() for part in (entry / 'cmdline').read_bytes().split(b'\0') if part]
            if not argv or Path(argv[0]).name != 'perf' or 'record' not in argv or argv.count('-o') != 1:
                continue
            if argv[argv.index('-o') + 1] not in targets or argv.count('-p') != 1 or not argv[argv.index('-p') + 1].isdigit():
                continue
            output, attached = argv[argv.index('-o') + 1], argv[argv.index('-p') + 1]
            if output in expected_pids and attached != expected_pids[output]:
                raise RuntimeError('owned recorder attachment differs from capture identity')
            fields = (entry / 'stat').read_text().rsplit(')', 1)[1].split()
            if fields[0] != 'Z':
                found.append(dict(pid=int(entry.name), starttime=int(fields[19]), argv=argv))
        except (OSError, ValueError, IndexError, UnicodeError):
            continue
    return found


def cleanup_private(private):
    receipt = dict(raw=[], stopped_recorders=[], removed_caches=[], errors=[], complete=False)
    if not private.exists():
        receipt.update(complete=True, capture_present=False)
        return receipt
    if private.is_symlink() or private.resolve() != private.absolute() or private.stat().st_uid != 0:
        raise ValueError('private capture root must be an exact root-owned nonsymlink directory')
    # PDEATHSIG is the primary orphan bound. This path-bound backstop handles
    # an interrupted collector before its finally block has reaped perf.
    for item in owned_recorders(private):
        try:
            fd = os.pidfd_open(item['pid'])
        except ProcessLookupError:
            continue
        try:
            if item not in owned_recorders(private):
                continue
            signal.pidfd_send_signal(fd, signal.SIGINT)
            receipt['stopped_recorders'].append(item)
            deadline = time.monotonic() + 5
            while item in owned_recorders(private) and time.monotonic() < deadline:
                time.sleep(0.1)
            if item in owned_recorders(private):
                signal.pidfd_send_signal(fd, signal.SIGKILL)
        except ProcessLookupError:
            pass
        finally:
            os.close(fd)
    deadline = time.monotonic() + 3
    while owned_recorders(private) and time.monotonic() < deadline:
        time.sleep(0.1)
    if owned_recorders(private):
        raise ValueError('owned recorder still alive; refusing raw cleanup or export')
    capture_path = private / 'capture.json'
    capture = read(capture_path) if capture_path.is_file() else dict(valid=False, errors=['capture receipt missing'], roles=[])
    for role in ROLES:
        directory = private / role
        if not directory.exists():
            continue
        if directory.is_symlink() or directory.stat().st_uid != 0:
            raise ValueError('unowned or symlink role directory')
        for path in directory.glob('perf.data*'):
            if path.name not in ('perf.data', 'perf.data.old'):
                raise ValueError('unexpected raw trace filename; refusing export')
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != 0:
                raise ValueError('raw trace is not a root-owned regular single-link file')
            record = dict(role=role, filename=path.name, bytes=info.st_size, sha256=digest(path),
                          derived_all_sample_count=None, coverage_fraction=None, loss_denominator=None,
                          decode_status='interrupted or incomplete; denominator unknown', raw_deleted=False)
            after = path.lstat()
            if any(getattr(after, key) != getattr(info, key) for key in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_nlink', 'st_uid', 'st_mode')):
                raise ValueError('raw trace changed while hashing')
            path.unlink()
            record['raw_deleted'] = not path.exists()
            receipt['raw'].append(record)
    if receipt['raw'] or receipt['stopped_recorders']:
        capture['valid'] = False
        capture.setdefault('errors', []).append('forced cleanup: interrupted trace or recorder; no qualified attribution')
    for role in ROLES:
        for path in (private / role / 'symfs',):
            if path.exists():
                if path.is_symlink() or path.stat().st_uid != 0:
                    raise ValueError('unowned or symlink cache')
                shutil.rmtree(path)
                receipt['removed_caches'].append(str(path.relative_to(private)))
    for name in ('elfs', 'buildid-cache', 'home'):
        path = private / name
        if path.exists():
            if path.is_symlink() or path.stat().st_uid != 0:
                raise ValueError('unowned or symlink cache')
            shutil.rmtree(path)
            receipt['removed_caches'].append(name)
    receipt['complete'] = True
    capture['campaign_private_cleanup'] = receipt
    write(capture_path, capture)
    return receipt


def descriptive_controls(load, resource):
    # A profile-only observer failure does not erase independently conserved
    # load and process-CPU counters. This never changes either validity flag.
    adjusted = dict(resource)
    profile_error = 'leaf profile failed identity, loss, or coverage qualification'
    excluded = resource.get('valid') is False and resource.get('errors') == [profile_error]
    if excluded:
        adjusted.update(valid=True, errors=[])
    errors = production.validate_observation(dict(arm='ferrum', payload=1024, duration=30, rate=0), load, adjusted)
    metrics = production.observed_metrics(dict(arm='ferrum', rate=0), load, adjusted) if not errors else {}
    return dict(scope='descriptive conserved load/process CPU only; does not qualify profile or cell',
                excluded_profile_gate_for_description_only=excluded, validation_issues=errors,
                goodput_rps=metrics.get('goodput_rps'), cpu_us_per_completion=metrics.get('cpu_us_per_completion'))


def qualify(rows, capture, prepared, cleanup):
    errors = preparation_errors(prepared)
    by_phase = {row.get('cell', {}).get('phase'): row for row in rows}
    if len(rows) != 3 or set(by_phase) != set(PHASES):
        errors.append('missing or duplicate planned cell; no subset inference')
    expected = prepared.get('runtime_image', {}).get('Id')
    for phase in PHASES:
        row = by_phase.get(phase, {})
        if row.get('measurement_valid') is not True or row.get('capacity_qualified') is not True:
            errors.append(phase + ': observation or zero-error capacity gate failed')
        resource = row.get('resources', {})
        containers = resource.get('containers', [])
        split = []
        try:
            begin, end = resource['begin']['processes'], resource['end']['processes']
            if len(begin) != 2 or len(end) != 2:
                raise ValueError('two CPU roles required')
            ticks = resource['clock_ticks_per_second']
            if type(ticks) not in (int, float) or ticks <= 0:
                raise ValueError('clock ticks must be positive')
            for index, (a, b) in enumerate(zip(begin, end)):
                for snapshot in (a, b):
                    if any(type(snapshot[key]) is not int or snapshot[key] < 0 for key in ('user_cpu_ticks', 'system_cpu_ticks', 'cpu_ticks')):
                        raise ValueError('invalid CPU tick counters')
                    if snapshot['user_cpu_ticks'] + snapshot['system_cpu_ticks'] != snapshot['cpu_ticks']:
                        raise ValueError('user/system CPU does not conserve total')
                user = (b['user_cpu_ticks'] - a['user_cpu_ticks']) / ticks
                system = (b['system_cpu_ticks'] - a['system_cpu_ticks']) / ticks
                if min(user, system) < 0:
                    raise ValueError('CPU counter regression')
                split.append(dict(role=ROLES[index], user_cpu_seconds=user, system_cpu_seconds=system))
        except (KeyError, ValueError, TypeError) as error:
            errors.append(phase + ': user/system CPU evidence failed: ' + str(error))
        row['user_system_cpu'] = split
        if len(containers) != 2 or any(item.get('image_id') != expected for item in containers):
            errors.append(phase + ': both proxy images must equal own prepared image')
    roles = capture.get('roles', [])
    if (capture.get('valid') is not True or len(roles) != 2 or [r.get('role') for r in roles] != list(ROLES)
            or any(r.get('valid') is not True or r.get('raw_trace_cleanup', {}).get('raw_deleted') is not True for r in roles)):
        errors.append('profile identity, coverage, loss, or raw deletion gate failed')
    if cleanup.get('complete') is not True or cleanup.get('raw') or cleanup.get('stopped_recorders'):
        errors.append('private capture cleanup incomplete or recovered an interrupted capture')
    controls = {}
    # Ratios remain defined whenever their raw validated inputs are positive,
    # including when another independent gate failed. Never hide adverse cells.
    for metric, suffix in (('goodput_rps', 'rps'), ('cpu_us_per_completion', 'cpu')):
        values = [by_phase.get(phase, {}).get('metrics', {}).get(metric,
                  by_phase.get(phase, {}).get('descriptive_controls', {}).get(metric)) for phase in PHASES]
        valid = all(type(v) in (int, float) and math.isfinite(v) and v > 0 for v in values)
        controls['after_before_' + suffix + '_ratio'] = values[2] / values[0] if valid else None
        controls['profiled_control_' + suffix + '_ratio'] = values[1] / math.sqrt(values[0] * values[2]) if valid else None
    if any(value is None or not 1 / 1.05 <= value <= 1.05 for value in controls.values()):
        errors.append('undefined control or observer/bracket drift outside prespecified 5% bound')
    return dict(schema=1, valid=not errors, scope=SCOPE, controls=controls, errors=errors,
                cells=[by_phase.get(phase, dict(cell=dict(phase=phase), missing=True)) for phase in PHASES],
                profile=capture, cleanup=cleanup, preparation=prepared)


def public_copy(source, target, manifest):
    if not source.exists():
        return
    info = source.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 64 * 1024**2:
        raise ValueError('public metadata file type or size bound: ' + str(source))
    data = source.read_bytes()
    if b'PRIVATE KEY-----' in data or data[:4] == b'\x7fELF' or data[:8] == b'PERFILE2':
        raise ValueError('private binary or key in public allowlist')
    if sum(item['bytes'] for item in manifest) + len(data) > 256 * 1024**2:
        raise ValueError('public metadata total exceeds 256 MiB')
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    target.chmod(0o644)
    manifest.append(dict(path=str(target.relative_to(PUBLIC)), bytes=len(data), sha256=digest(target)))


def finalize():
    if os.geteuid() != 0:
        raise ValueError('finalize requires root ownership matching the private collector')
    PUBLIC.mkdir(parents=True, exist_ok=False)
    OUTPUT.mkdir(parents=True, exist_ok=True)
    errors, cleanup, capture = [], {}, {}
    private = cell_dir('profile') / 'perf-leaf'
    try:
        cleanup = cleanup_private(private)
        if (private / 'capture.json').exists():
            capture = read(private / 'capture.json')
            export_derived(private, PUBLIC / 'derived')
    except (OSError, ValueError, KeyError, RuntimeError) as error:
        errors.append('private cleanup/export: ' + str(error))
    rows = []
    for phase in PHASES:
        try:
            rows.append(read(cell_dir(phase) / 'observation.json'))
        except (OSError, ValueError) as error:
            errors.append(phase + ': ' + str(error))
    try:
        prepared = read(build_dir() / 'report.json')
    except (OSError, ValueError) as error:
        prepared = {}
        errors.append('preparation: ' + str(error))
    result = qualify(rows, capture, prepared, cleanup)
    result['errors'].extend(errors)
    result['valid'] = not result['errors']
    manifest = []
    derived_manifest = PUBLIC / 'derived/export-manifest.json'
    if derived_manifest.exists():
        manifest = [dict(item, path='derived/' + item['path']) for item in read(derived_manifest)]
    try:
        # No recursive traversal of captures, build outputs, source or fixtures.
        for name in ('provenance.json', 'tools-image.json', 'tools-build.log', 'tools-build.command.json',
                     'compiler-native-packages.log', 'compiler-native-packages.command.json', 'collector-wrapper.diff'):
            public_copy(OUTPUT / name, PUBLIC / 'campaign' / name, manifest)
        for phase in PHASES:
            directory = cell_dir(phase)
            for path in [*directory.glob('*.json'), *directory.glob('*.log'), *directory.glob('logs/*.log'), *directory.glob('logs/*.json'),
                         *directory.glob('logs/*.txt'), *directory.glob('logs/*.err')]:
                public_copy(path, PUBLIC / 'cells' / phase / path.relative_to(directory), manifest)
        for label, directory in (('build', build_dir()), ('canary', Path(os.environ['RUNNER_TEMP']) / 'gap-profile-canary')):
            for name in ('report.json', 'Dockerfile.original', 'Dockerfile.diagnostic', 'Dockerfile.diff',
                         'capture/setup.txt', 'capture/ferrum-edge/receipt.json',
                         'canary/control.log', 'canary/capture.log', 'canary/capture/ferrum-edge/receipt.json'):
                public_copy(directory / name, PUBLIC / label / name, manifest)
            # Commands named source-archive/extract-* contain binary tar streams;
            # upload ONLY these fixed text command labels, never *.stdout broadly.
            allowed = {'source-commit', 'representative-runtime-build', 'representative-builder-export',
                       'runtime-image', 'builder-image', 'unwind-frames', 'canary-builder-pull', 'canary-builder-image', 'remote-canary'}
            report = read(directory / 'report.json') if (directory / 'report.json').exists() else {}
            for command_receipt in report.get('commands', []):
                if command_receipt.get('label') in allowed:
                    for key in ('stdout', 'stderr'):
                        name = command_receipt.get(key)
                        if not isinstance(name, str) or Path(name).name != name:
                            raise ValueError('invalid command log name')
                        public_copy(directory / name, PUBLIC / label / name, manifest)
        host = ROOT / 'results/gap-profile-host'
        for name in ('lscpu.txt', 'memory.txt', 'docker-version.txt', 'native-packages.txt', 'host-before.txt'):
            public_copy(host / name, PUBLIC / 'host' / name, manifest)
    except (OSError, ValueError, KeyError) as error:
        result['errors'].append('public metadata export: ' + str(error))
        result['valid'] = False
    write(PUBLIC / 'qualification.json', result)
    write(PUBLIC / 'metadata-export.json', manifest)
    print(json.dumps({key: result[key] for key in ('valid', 'scope', 'controls', 'errors')}, indent=2))
    # Failure is asserted after the always-run artifact step.
    return 0


def main():
    require_remote()
    action = sys.argv[1] if len(sys.argv) == 2 else ''
    if action == 'prepare':
        prepare()
    elif action == 'measure':
        measure()
    elif action == 'finalize':
        return finalize()
    elif action == 'accept':
        return 0 if read(PUBLIC / 'qualification.json').get('valid') is True else 1
    else:
        raise ValueError('expected prepare, measure, finalize or accept')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
