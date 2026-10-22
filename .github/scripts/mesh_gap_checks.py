#!/usr/bin/env python3
"""Remote correctness/preflight only; no image builds or performance samples."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time

from mesh_gap_candidate import BASELINE, HYPER_KINDS, ROOT, cargo_tests, digest, expected_telemetry_red, git, require_remote, selection, write


def batch_rustflags(control):
    if type(control) is not bool:
        raise ValueError('batch control selector must be a boolean')
    flags = '--cap-lints=warn --check-cfg=cfg(ferrum_h2_batch_control)'
    return flags + (' --cfg ferrum_h2_batch_control' if control else '')


def test_counts(text):
    summaries = re.findall(r'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;', text)
    return dict(passed=sum(int(passed) for passed, _, _ in summaries),
                failed=sum(int(failed) for _, failed, _ in summaries),
                ignored=sum(int(ignored) for _, _, ignored in summaries))


def require_test_counts(counts, expected_passed=None, expected_ignored=None):
    if expected_ignored is not None:
        # These five existing tests are compile contracts with ignored runtime
        # bodies. Zero matches, an added executed test, or fewer contracts fail.
        return counts == dict(passed=0, failed=0, ignored=expected_ignored)
    return (counts['failed'] == 0 and counts['passed'] > 0 and
            (expected_passed is None or counts['passed'] == expected_passed))


MEMORY_READ_BYTES = 4096
MEMINFO_KEYS = ('MemTotal', 'MemAvailable', 'SwapTotal', 'SwapFree')
CGROUP_MEMORY_FILES = ('memory.current', 'memory.peak', 'memory.max', 'memory.swap.current',
                       'memory.swap.max', 'memory.events', 'memory.events.local')
CGROUP_EVENT_KEYS = ('low', 'high', 'max', 'oom', 'oom_kill', 'oom_group_kill', 'sock_throttled')


def memory_snapshot(proc=Path('/proc'), cgroup=Path('/sys/fs/cgroup')):
    """Read at most16 fixed-size files; numeric memory evidence, no env/argv."""
    result = dict(schema='mesh_gap_check_memory.v1', captured_unix_seconds=time.time(),
                  host_meminfo_kib={}, cgroups=[], errors=[])

    def text(path):
        with path.open('rb') as stream:
            data = stream.read(MEMORY_READ_BYTES + 1)
        if len(data) > MEMORY_READ_BYTES:
            raise ValueError('memory evidence exceeds fixed read bound')
        return data.decode('ascii')

    def error(target, source, exception):
        # File paths and exception strings can contain external text. Retain
        # only an internal source label, exception type and numeric errno.
        target.append(dict(source=source, error=type(exception).__name__,
                           errno=getattr(exception, 'errno', None)))

    try:
        values = dict(re.findall(r'^([A-Za-z_]+):\s+(\d+) kB$', text(proc / 'meminfo'), re.MULTILINE))
        result['host_meminfo_kib'] = {key: int(values[key]) for key in MEMINFO_KEYS if key in values}
        if len(result['host_meminfo_kib']) != len(MEMINFO_KEYS):
            raise ValueError('required host memory fields unavailable')
    except (OSError, ValueError, UnicodeError) as exception:
        error(result['errors'], 'host_meminfo', exception)
    try:
        memberships = [line.split(':', 2) for line in text(proc / 'self/cgroup').splitlines()]
        v2 = [parts[2] for parts in memberships if len(parts) == 3 and parts[:2] == ['0', '']]
        if len(v2) != 1:
            raise ValueError('one current cgroup v2 membership required')
        relative = Path(v2[0])
        if not relative.is_absolute() or '..' in relative.parts:
            raise ValueError('invalid current cgroup path')
        current = cgroup.joinpath(*relative.parts[1:])
        scopes = [('current', current), ('root', cgroup)] if current != cgroup else [('root', cgroup)]
        for scope, directory in scopes:
            record = dict(scope=scope, current=directory == current, version=2, values={}, errors=[])
            for filename in CGROUP_MEMORY_FILES:
                try:
                    value = text(directory / filename).strip()
                    if filename in ('memory.events', 'memory.events.local'):
                        pairs = [line.split() for line in value.splitlines()]
                        if not pairs or len(pairs) > 32 or any(len(pair) != 2 or not re.fullmatch(r'[a-z_]{1,32}', pair[0])
                                                              or not pair[1].isdecimal() for pair in pairs):
                            raise ValueError('invalid numeric memory events')
                        record['values'][filename] = {key: int(count) for key, count in pairs if key in CGROUP_EVENT_KEYS}
                    elif value == 'max' and filename.endswith('.max'):
                        record['values'][filename] = 'max'
                    elif value.isdecimal():
                        record['values'][filename] = int(value)
                    else:
                        raise ValueError('invalid numeric memory counter')
                except (OSError, ValueError, UnicodeError) as exception:
                    error(record['errors'], filename, exception)
            result['cgroups'].append(record)
    except (OSError, ValueError, UnicodeError) as exception:
        error(result['errors'], 'cgroup_membership', exception)
    return result


def emit_memory_snapshot(name, phase):
    print('[gap-check-memory] ' + json.dumps(dict(check=name, phase=phase, **memory_snapshot()),
                                           sort_keys=True), flush=True)


def run_command(command, checkout, output, name, *, test=False, allow_failure=False,
                vendor_lints=False, batch_control=None, expected_passed=None, expected_ignored=None):
    env = {k: v for k, v in os.environ.items() if not k.startswith('FERRUM_')}
    for key in ('CARGO_TARGET_DIR', 'RUSTFLAGS', 'RUSTC_WRAPPER', 'CARGO_BUILD_RUSTC_WRAPPER', 'UPDATE_VENDOR_INTEGRITY'):
        env.pop(key, None)
    # Correctness-only resource settings; never inherited by release image builds.
    clippy = command[:2] == ['cargo', 'clippy']
    env.update(CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0', CARGO_BUILD_JOBS='1' if clippy else '2')
    if vendor_lints:
        env['RUSTFLAGS'] = '--cap-lints=warn'
    if batch_control is not None:
        if not vendor_lints:
            raise ValueError('batch cfg flags are confined to standalone vendored checks')
        env['RUSTFLAGS'] = batch_rustflags(batch_control)
    started = time.monotonic()
    print('[gap-check] start ' + name, flush=True)
    if clippy:
        emit_memory_snapshot(name, 'before')
    timed_out = False
    with (output / (name + '.log')).open('w') as log:
        process = subprocess.Popen(command, cwd=checkout, env=env, stdout=log,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        while True:
            try:
                exit_code = process.wait(timeout=30)
                break
            except subprocess.TimeoutExpired:
                elapsed = time.monotonic() - started
                print(f'[gap-check] {name}: elapsed={elapsed:.0f}s log_bytes={(output / (name + ".log")).stat().st_size}', flush=True)
                emit_memory_snapshot(name, 'heartbeat')
                if elapsed >= 7200:
                    import signal
                    timed_out = True
                    os.killpg(process.pid, signal.SIGKILL)
                    exit_code = process.wait()
                    break

    if clippy:
        emit_memory_snapshot(name, 'after')

    text = (output / (name + '.log')).read_text(errors='replace')
    counts = test_counts(text)
    passed = counts['passed']
    record = dict(command=command, exit_code=exit_code, timed_out=timed_out, rustflags=env.get('RUSTFLAGS'),
                  correctness_environment={key: env[key] for key in ('CARGO_PROFILE_DEV_DEBUG', 'CARGO_PROFILE_TEST_DEBUG', 'CARGO_BUILD_JOBS')},
                  elapsed_seconds=time.monotonic() - started, passed_tests=passed,
                  ignored_tests=counts['ignored'], expected_passed=expected_passed,
                  expected_ignored=expected_ignored, batch_control=batch_control)
    write(output / (name + '.json'), record)
    print(f'[gap-check] complete {name}: exit={exit_code} passed_tests={passed}', flush=True)
    if not allow_failure and (exit_code or timed_out or
            test and not require_test_counts(counts, expected_passed, expected_ignored)):
        raise ValueError(name + ' failed or matched no executed tests; retained log is authoritative')
    return record, text


TELEMETRY_UNIT_FILTERS = (
    'unit::plugins::mesh_telemetry_metric_families_tests::',
    'unit::plugins::plugin_trigger_gate_tests::',
    'unit::plugins::prometheus_metrics_tests::',
)
LIVE_SOURCE_FILTER = 'functional_mesh_live_source_capture'
LIVE_SOURCE_PREREQUISITES = ('sudo', 'unshare', 'nsenter', 'setpriv', 'timeout', 'ip', 'iptables', 'iptables-save')


def telemetry_unit_commands():
    # Match the ordinary/default-feature gateway used by the CI capture suite.
    return [['cargo', 'test', '--locked', '--test', 'unit_plugins_b_tests', test_filter]
            for test_filter in TELEMETRY_UNIT_FILTERS]


def functional_test_executable(text):
    """Select exactly one Cargo functional-test artifact, never a glob/latest."""
    binaries = []
    for line in text.splitlines():
        try:
            item = json.loads(line)
        except ValueError:
            # Cargo's rendered diagnostics/status messages share the retained log.
            continue
        if (isinstance(item, dict) and item.get('reason') == 'compiler-artifact'
                and isinstance(item.get('profile'), dict) and item['profile'].get('test') is True
                and isinstance(item.get('target'), dict)
                and item['target'].get('name') == 'functional_tests'
                and isinstance(item['target'].get('kind'), list) and 'test' in item['target']['kind']
                and item.get('executable') is not None):
            binaries.append(item['executable'])
    if len(binaries) != 1 or not isinstance(binaries[0], str) or not Path(binaries[0]).is_absolute():
        raise ValueError('expected exactly one absolute Cargo functional_tests executable')
    return Path(binaries[0])


def source_capture_command(binary):
    return ['sudo', '-n', 'env', 'FERRUM_LIVE_TESTS_REQUIRED=1', 'FERRUM_SKIP_GATEWAY_BUILD=1',
            'timeout', '--signal=KILL', '240s', str(binary), LIVE_SOURCE_FILTER,
            '--ignored', '--nocapture', '--test-threads=1']


def live_source_qualification(exit_code, text):
    summaries = re.findall(r'^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;', text, re.MULTILINE)
    # With --nocapture, libtest can place the marker after a test-name prefix.
    skips = [line for line in text.splitlines() if re.search(r'(?<!\w)SKIP:', line)]
    return dict(valid=type(exit_code) is int and exit_code == 0 and summaries == [('2', '0', '0')] and not skips,
                expected_passed=2, expected_ignored=0, test_counts=test_counts(text), skip_markers=skips)


def require_nonroot_telemetry_runner():
    if os.geteuid() == 0:
        raise ValueError('telemetry Cargo checks and builds require the nonroot runner user')


def telemetry_source_capture(checkout, output):
    """Reuse CI's two strict source-capture e2e tests; Cargo stays nonroot."""
    require_nonroot_telemetry_runner()
    missing = [name for name in LIVE_SOURCE_PREREQUISITES if shutil.which(name) is None]
    if missing:
        raise ValueError('strict source-capture prerequisites missing: ' + ', '.join(missing))
    run_command(['sudo', '-n', 'true'], checkout, output, 'telemetry-live-sudo-preflight')
    # The only iptables preflight runs inside a new, unnamed disposable netns.
    # It never changes host routing, firewall rules or security settings.
    run_command(['sudo', '-n', 'unshare', '--net', 'sh', '-c',
                 'ip link set lo up; iptables -t nat -L >/dev/null'],
                checkout, output, 'telemetry-live-netns-preflight')
    run_command(['cargo', 'build', '--locked', '--bin', 'ferrum-edge'],
                checkout, output, 'telemetry-functional-gateway-build')
    _, text = run_command(['cargo', 'test', '--locked', '--test', 'functional_tests', '--no-run',
                          '--message-format=json-render-diagnostics'],
                         checkout, output, 'telemetry-functional-test-build')
    binary = functional_test_executable(text)
    expected_directory = (checkout / 'target/debug/deps').resolve()
    if (not binary.is_file() or not os.access(binary, os.X_OK)
            or not binary.resolve().is_relative_to(expected_directory)):
        raise ValueError('Cargo functional executable is not in the owned default-feature debug target')
    gateway = checkout / 'target/debug/ferrum-edge'
    if not gateway.is_file() or not os.access(gateway, os.X_OK):
        raise ValueError('prebuilt default-feature gateway binary is unavailable')
    write(output / 'telemetry-functional-binaries.json', dict(source_sha=git('rev-parse', 'HEAD', cwd=checkout),
        features='manifest defaults; no explicit feature override', cargo_run_as_root=False,
        functional_binary=str(binary), functional_binary_sha256=digest(binary),
        gateway_binary=str(gateway), gateway_binary_sha256=digest(gateway),
        scope='existing CI Ambient UDP/HBONE and raw-TCP/mesh-mTLS source capture in throwaway netns'))
    record, text = run_command(source_capture_command(binary), checkout, output,
                               'telemetry-source-capture-live', test=True, expected_passed=2)
    qualification = live_source_qualification(record['exit_code'], text)
    write(output / 'telemetry-source-capture-qualification.json', qualification)
    if not qualification['valid']:
        raise ValueError('source capture requires exactly two passes, zero ignored tests and zero SKIP markers')


def standalone_hyper(checkout, scratch, output):
    """Two test-only graphs; unchanged source/manifests, recorded resolved locks."""
    source = checkout / 'vendor/hyper-1.10.0-ferrum-patched'
    run_command(['rustfmt', '--edition', '2021', '--check', str(source / 'src/proto/h2/client/ferrum_lazy_cancel_tests.rs')], checkout, output, 'hyper-new-tests-fmt')
    h2 = scratch / 'h2'
    shutil.copytree(checkout / 'vendor/h2-0.4.20-ferrum-patched', h2)
    for graph in ('stock', 'patched'):
        hyper = scratch / graph
        shutil.copytree(source, hyper)
        manifest = hyper / 'Cargo.toml'
        prefix = 'hyper-' + graph
        config = ['--config', 'patch.crates-io.h2.path="' + str(h2) + '"'] if graph == 'patched' else []
        base = ['cargo', 'update', '--manifest-path', str(manifest)]
        command = base + (['-p', 'h2', '--precise', '0.4.20'] if graph == 'stock' else config)
        run_command(command, hyper, output, prefix + '-lock', vendor_lints=True)
        _, tree = run_command(['cargo', 'tree', '--locked', '--manifest-path', str(manifest), '--features', 'full', '-i', 'h2', *config], hyper, output, prefix + '-tree', vendor_lints=True)
        expected = 'h2 v0.4.20' + (' (' + str(h2) + ')' if graph == 'patched' else '')
        if [line for line in tree.splitlines() if re.match(r'^h2 v', line)] != [expected]:
            raise ValueError(prefix + ' did not resolve the exact intended h2 graph')
        shutil.copy2(hyper / 'Cargo.lock', output / (prefix + '.Cargo.lock'))
        write(output / (prefix + '-graph.json'), dict(scope='standalone tests only',
            manifest_sha256=digest(manifest), original_manifest_sha256=digest(source / 'Cargo.toml'),
            h2_resolution=expected, lock_sha256=digest(hyper / 'Cargo.lock'), rustflags='--cap-lints=warn'))
        test_filter = 'ferrum_lazy_cancel_tests' if graph == 'stock' else 'ferrum_'
        run_command(['cargo', 'test', '--locked', '--manifest-path', str(manifest), '--lib', '--features', 'full', test_filter, *config, '--', '--nocapture'], hyper, output, prefix + '-tests', test=True, vendor_lints=True)
        if digest(manifest) != digest(source / 'Cargo.toml'):
            raise ValueError('standalone test changed governed manifest')


BATCH_TEST = 'src/proto/h2/client/ferrum_send_batch_tests.rs'
BATCH_HOOK = '\n#[cfg(test)]\n#[path = "client/ferrum_send_batch_tests.rs"]\nmod ferrum_send_batch_tests;\n'
HYPER_VENDOR = 'vendor/hyper-1.10.0-ferrum-patched'
H2_VENDOR = 'vendor/h2-0.4.20-ferrum-patched'


def copy_baseline_tree(relative, destination):
    """Read only the fixed Git tree; do not borrow a mutable worktree's source."""
    names = git('ls-tree', '-r', '--name-only', BASELINE, '--', relative).splitlines()
    if not names:
        raise ValueError('fixed baseline tree is empty: ' + relative)
    for name in names:
        target = destination / Path(name).relative_to(relative)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(subprocess.check_output(['git', 'show', BASELINE + ':' + name], cwd=ROOT))


def source_hashes(root):
    # Exclude only Cargo's generated lock and target tree. Inspect all other
    # source/manifest paths, including unexpected files created by a test.
    result = {}
    for child in sorted(root.iterdir()):
        if child.name in ('target', 'Cargo.lock'):
            continue
        paths = [child] if child.is_file() else sorted(child.rglob('*'))
        for path in paths:
            if path.is_file():
                result[str(path.relative_to(root))] = digest(path)
    return result


def validate_control_overlay(before, after, original_client, final_client, test_bytes, candidate_test_bytes):
    expected = set(before) | {BATCH_TEST}
    if set(after) != expected or BATCH_TEST in before:
        raise ValueError('baseline overlay changed the governed file set unexpectedly')
    if any(after[name] != value for name, value in before.items() if name != 'src/proto/h2/client.rs'):
        raise ValueError('baseline overlay changed source outside the test module declaration')
    if final_client != original_client + BATCH_HOOK.encode() or test_bytes != candidate_test_bytes:
        raise ValueError('baseline overlay must contain only the literal test hook and identical tests')


def standalone_hyper_groups(checkout, scratch, output):
    """Fixed 16-test paired control; four isolated copies, two frozen graphs."""
    source = checkout / HYPER_VENDOR
    run_command(['rustfmt', '--edition', '2021', '--config', 'skip_children=true', '--check',
                 str(source / BATCH_TEST)], checkout, output, 'hyper-groups-new-tests-fmt')
    scratch.mkdir(parents=True, exist_ok=False)
    baseline = scratch / 'baseline-source'
    copy_baseline_tree(HYPER_VENDOR, baseline)
    if (source / 'Cargo.toml').read_bytes() != (baseline / 'Cargo.toml').read_bytes():
        raise ValueError('group candidate must preserve the exact baseline Hyper manifest')
    h2 = scratch / 'h2'
    copy_baseline_tree(H2_VENDOR, h2)
    if source_hashes(h2) != source_hashes(checkout / H2_VENDOR):
        raise ValueError('group candidate must preserve the exact baseline h2 source')
    before = source_hashes(baseline)
    original_client = (baseline / 'src/proto/h2/client.rs').read_bytes()
    preparer = checkout / 'docs/upstream-hyper-patches/007-bounded-h2-response-groups/prepare_test_control.py'
    run_command(['python3', str(preparer), str(baseline)], checkout, output, 'hyper-groups-control-overlay')
    after = source_hashes(baseline)
    validate_control_overlay(before, after, original_client,
        (baseline / 'src/proto/h2/client.rs').read_bytes(),
        (baseline / BATCH_TEST).read_bytes(), (source / BATCH_TEST).read_bytes())
    write(output / 'hyper-groups-control-source.json', dict(base_sha=BASELINE,
        scope='isolated test-only overlay; no candidate runtime source',
        preparer_sha256=digest(preparer), before_sha256=before, after_sha256=after,
        literal_test_hook=BATCH_HOOK, runtime_bytes_preserved=True,
        shared_test_sha256=digest(source / BATCH_TEST)))
    candidate_hashes = source_hashes(source)
    baseline_hashes = source_hashes(baseline)
    write(output / 'hyper-groups-source.json', dict(candidate=candidate_hashes,
        baseline_with_test_overlay=baseline_hashes, h2=source_hashes(h2)))
    for graph in ('stock', 'patched'):
        config = ['--config', 'patch.crates-io.h2.path="' + str(h2) + '"'] if graph == 'patched' else []
        expected = 'h2 v0.4.20' + (' (' + str(h2) + ')' if graph == 'patched' else '')
        copies = {arm: scratch / (graph + '-' + arm) for arm in ('baseline', 'candidate')}
        for arm, original in (('baseline', baseline), ('candidate', source)):
            shutil.copytree(original, copies[arm])
        # Resolve once, then use the identical lock for both source arms. Neither
        # cfg flags nor a registry change between invocations can pick a new graph.
        candidate = copies['candidate']
        manifest = candidate / 'Cargo.toml'
        lock_prefix = 'hyper-groups-' + graph + '-resolve'
        run_command(['cargo', 'update', '--manifest-path', str(manifest),
                     *(['-p', 'h2', '--precise', '0.4.20'] if graph == 'stock' else config)],
                    candidate, output, lock_prefix, vendor_lints=True, batch_control=False)
        lock_hash = digest(candidate / 'Cargo.lock')
        shutil.copy2(candidate / 'Cargo.lock', copies['baseline'] / 'Cargo.lock')
        for arm in ('baseline', 'candidate'):
            hyper = copies[arm]
            manifest = hyper / 'Cargo.toml'
            control = arm == 'baseline'
            prefix = 'hyper-groups-' + graph + '-' + arm
            flags = dict(vendor_lints=True, batch_control=control)
            _, tree = run_command(['cargo', 'tree', '--locked', '--manifest-path', str(manifest),
                '--features', 'full', '-i', 'h2', *config], hyper, output, prefix + '-tree', **flags)
            if [line for line in tree.splitlines() if re.match(r'^h2 v', line)] != [expected]:
                raise ValueError(prefix + ' did not resolve the exact intended h2 graph')
            shutil.copy2(hyper / 'Cargo.lock', output / (prefix + '.Cargo.lock'))
            write(output / (prefix + '-graph.json'), dict(scope='standalone correctness only',
                source_arm=arm, source_sha=BASELINE if control else git('rev-parse', 'HEAD', cwd=checkout),
                test_only_overlay=control, manifest_sha256=digest(manifest),
                original_manifest_sha256=digest(source / 'Cargo.toml'), h2_resolution=expected,
                lock_sha256=lock_hash, rustflags=batch_rustflags(control),
                controlled_occupancy_only=True, production_occupancy_measured=False))
            command = ['cargo', 'test', '--locked', '--manifest-path', str(manifest), '--lib', '--features', 'full']
            run_command([*command, 'ferrum_send_batch_tests', *config, '--', '--nocapture'],
                        hyper, output, prefix + '-focused', test=True, expected_passed=16, **flags)
            if graph == 'patched':
                run_command([*command, 'ferrum_', *config, '--', '--nocapture'], hyper, output,
                            prefix + '-full-ferrum', test=True, **flags)
            run_command([*command, 'client::conn::http2::tests', *config], hyper, output,
                        prefix + '-executor-contracts', test=True, expected_ignored=5, **flags)
            if digest(hyper / 'Cargo.lock') != lock_hash:
                raise ValueError(prefix + ' changed the paired lock')
            expected_hashes = baseline_hashes if control else candidate_hashes
            # Cargo target/lock are outside this captured source file set.
            if source_hashes(hyper) != expected_hashes:
                raise ValueError(prefix + ' changed standalone source or manifest bytes')


def hyper_source_gates(checkout, output):
    run_command(['python3', 'scripts/check_vendored_patch_lifecycle.py'], checkout, output, 'vendor-lifecycle')
    run_command(['python3', '.github/scripts/verify_hyper_patch_stack.py', '--self-test'], checkout, output, 'hyper-reconstruction-self-test')
    archive = output / 'hyper-1.10.0.crate'
    run_command(['curl', '--fail', '--location', '--retry', '3', 'https://static.crates.io/crates/hyper/hyper-1.10.0.crate', '--output', str(archive)], checkout, output, 'hyper-archive')
    if digest(archive) != 'eb92f162bf56536459fc83c79b974bb12837acfed43d6bc370a7916d0ae15ecc':
        raise ValueError('Hyper archive checksum differs from fixed upstream source')
    run_command(['python3', '.github/scripts/verify_hyper_patch_stack.py', '--archive', str(archive), '--evidence', str(output / 'hyper-reconstruction')], checkout, output, 'hyper-reconstruction')


def main():
    require_remote()
    chosen = selection()
    output = ROOT / 'results/gap/checks'
    output.mkdir(parents=True, exist_ok=False)
    write(output / 'selection.json', chosen)
    result = dict(selection=chosen, complete=False, passed=False, performance_eligible=False,
                  modified_checkout=False, errors=[])
    write(output / 'receipt.json', result)
    checkout = Path(tempfile.mkdtemp(prefix='mesh-gap-checks-', dir=os.environ['RUNNER_TEMP'])) / 'source'
    subprocess.run(['git', 'worktree', 'add', '--detach', str(checkout), chosen['candidate_sha']], cwd=ROOT, check=True)
    try:
        # The restore-only action targets the harness checkout. Move its ignored
        # target into this one owned source checkout; never share targets between
        # worktrees or export them as artifacts. Cargo verifies fingerprints.
        restored = ROOT / 'target'
        result['restored_ci_target_moved'] = restored.is_dir()
        if restored.is_dir():
            shutil.move(str(restored), str(checkout / 'target'))
        (output / 'rustc.txt').write_text(subprocess.check_output(['rustc', '-Vv'], text=True))
        (output / 'cargo.txt').write_text(subprocess.check_output(['cargo', '-Vv'], text=True))
        (output / 'native-packages.txt').write_text(subprocess.check_output(['dpkg-query', '-W'], text=True))
        phase = chosen['phase']
        if phase == 'gap-telemetry-reproduce':
            command = ['cargo', 'test', '--locked', '--lib',
                'proxy::mesh_egress_observability::tests::set_target_stamps_principal_before_tcp_finalize_marker',
                '--', '--exact', '--test-threads=1']
            record, text = run_command(command, checkout, output, 'telemetry-reproduction', allow_failure=True)
            expected = 'configured builtin prometheus_metrics must observe real captured start'
            reproduced = expected_telemetry_red(record['exit_code'], text)
            result.update(complete=True, passed=reproduced, expected_red_reproduced=reproduced,
                          expected_assertion=expected, scope='correctness reproduction only; not a passing runtime test')
            if not reproduced:
                raise ValueError('expected exact runtime assertion was not reproduced; compile/environment failures do not qualify')
        elif phase == 'gap-telemetry-verify':
            require_nonroot_telemetry_runner()
            run_command(['cargo', 'fmt', '--all', '--', '--check'], checkout, output, 'fmt')
            run_command(['cargo', 'test', '--locked', '--lib', 'proxy::mesh_egress_observability::tests::',
                         '--', '--test-threads=1'], checkout, output, 'telemetry-lifecycle-tests', test=True)
            for index, command in enumerate(telemetry_unit_commands(), 1):
                run_command(command, checkout, output, 'telemetry-plugin-tests-' + str(index), test=True)
            run_command(['cargo', 'clippy', '--locked', '--lib', '--tests', '-p', 'ferrum-edge', '--', '-D', 'warnings'],
                        checkout, output, 'clippy')
            telemetry_source_capture(checkout, output)
            if git('status', '--porcelain', '--untracked-files=normal', cwd=checkout):
                raise ValueError('telemetry verification changed submitted source')
            result.update(complete=True, passed=True, performance_eligible=False,
                          scope='correctness only; manifest-default library/plugin tests and strict two-test source-capture e2e; no release images or performance samples')
        elif phase == 'gap-vendor-preflight':
            run_command(['bash', 'scripts/update_vendor_integrity.sh'], checkout, output, 'vendor-manifest-generation', test=True)
            changes = git('diff', '--name-only', cwd=checkout).splitlines()
            if changes != ['vendor/VENDOR_INTEGRITY.sha256']:
                raise ValueError('vendor preflight must change only the expected manifest')
            shutil.copy2(checkout / 'vendor/VENDOR_INTEGRITY.sha256', output / 'VENDOR_INTEGRITY.sha256')
            (output / 'vendor-manifest.patch').write_text(git('diff', '--', 'vendor/VENDOR_INTEGRITY.sha256', cwd=checkout) + '\n')
            result.update(complete=True, passed=True, modified_checkout=True,
                          scope='generated manifest only; apply/review/commit before definitive exact-head checks')
        else:
            if chosen['candidate_kind'] in HYPER_KINDS:
                hyper_source_gates(checkout, output)
            run_command(['cargo', 'fmt', '--all', '--', '--check'], checkout, output, 'fmt')
            if chosen['candidate_kind'] == 'h2-handoff':
                standalone_hyper(checkout, checkout.parent / 'standalone', output)
            elif chosen['candidate_kind'] == 'h2-response-groups':
                standalone_hyper_groups(checkout, checkout.parent / 'standalone-groups', output)
            for index, command in enumerate(cargo_tests(chosen['candidate_kind']), 1):
                run_command(command, checkout, output, 'targeted-' + str(index), test=True)
            run_command(['cargo', 'clippy', '--locked', '--features', 'cloud-secrets', '--lib', '--tests', '-p', 'ferrum-edge', '--', '-D', 'warnings'], checkout, output, 'clippy')
            run_command(['cargo', 'build', '--locked', '--features', 'cloud-secrets', '--bin', 'ferrum-edge'], checkout, output, 'functional-binary')
            for index, test_filter in enumerate(('functional_http1_direct_pool_test::', 'functional_grpc_test::', 'functional_mesh_sidecar_egress_routes_a_to_b_over_mtls', 'functional_mesh_sidecar_egress_grpc_routes_a_to_b_with_trailers', 'functional_mesh_mtls_retry_replays_exact_grpc_request_once_and_rejects_native_trailers'), 1):
                run_command(['cargo', 'test', '--locked', '--features', 'cloud-secrets', '--test', 'functional_tests', test_filter, '--', '--ignored'], checkout, output, 'functional-' + str(index), test=True)
            if git('status', '--porcelain', '--untracked-files=normal', cwd=checkout):
                raise ValueError('definitive checks changed the submitted checkout')
            result.update(complete=True, passed=True, performance_eligible=phase == 'gap-compare')
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        result['errors'].append(str(error))
    finally:
        result['final_tracked_diff'] = git('diff', '--name-only', cwd=checkout).splitlines()
        write(output / 'receipt.json', result)
        # Only this invocation's detached worktree is owned; retain no build tree.
        subprocess.run(['git', 'worktree', 'remove', '--force', str(checkout)], cwd=ROOT, check=False)
        shutil.rmtree(checkout.parent, ignore_errors=True)
    print(json.dumps(result, indent=2))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
