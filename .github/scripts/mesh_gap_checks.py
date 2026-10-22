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

from mesh_gap_candidate import ROOT, cargo_tests, digest, expected_telemetry_red, git, require_remote, selection, write


def run_command(command, checkout, output, name, *, test=False, allow_failure=False, vendor_lints=False):
    env = {k: v for k, v in os.environ.items() if not k.startswith('FERRUM_')}
    for key in ('CARGO_TARGET_DIR', 'RUSTFLAGS', 'RUSTC_WRAPPER', 'CARGO_BUILD_RUSTC_WRAPPER', 'UPDATE_VENDOR_INTEGRITY'):
        env.pop(key, None)
    # Correctness-only resource settings; never inherited by release image builds.
    env.update(CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0', CARGO_BUILD_JOBS='2')
    if vendor_lints:
        env['RUSTFLAGS'] = '--cap-lints=warn'
    started = time.monotonic()
    print('[gap-check] start ' + name, flush=True)
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
                if elapsed >= 7200:
                    import signal
                    timed_out = True
                    os.killpg(process.pid, signal.SIGKILL)
                    exit_code = process.wait()
                    break

    text = (output / (name + '.log')).read_text(errors='replace')
    passed = sum(int(x) for x in re.findall(r'test result: ok\. (\d+) passed', text))
    record = dict(command=command, exit_code=exit_code, timed_out=timed_out, rustflags=env.get('RUSTFLAGS'),
                  correctness_environment={key: env[key] for key in ('CARGO_PROFILE_DEV_DEBUG', 'CARGO_PROFILE_TEST_DEBUG', 'CARGO_BUILD_JOBS')},
                  elapsed_seconds=time.monotonic() - started, passed_tests=passed)
    write(output / (name + '.json'), record)
    print(f'[gap-check] complete {name}: exit={exit_code} passed_tests={passed}', flush=True)
    if not allow_failure and (exit_code or timed_out or test and not passed):
        raise ValueError(name + ' failed or matched no executed tests; retained log is authoritative')
    return record, text


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
            if chosen['candidate_kind'] == 'h2-handoff':
                hyper_source_gates(checkout, output)
            run_command(['cargo', 'fmt', '--all', '--', '--check'], checkout, output, 'fmt')
            if chosen['candidate_kind'] == 'h2-handoff':
                standalone_hyper(checkout, checkout.parent / 'standalone', output)
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
