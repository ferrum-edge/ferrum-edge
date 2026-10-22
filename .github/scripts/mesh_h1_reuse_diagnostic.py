#!/usr/bin/env python3
"""Remote-only paired correctness reproduction; never performance eligible.

Build the two exact debug sources serially in one disposable checkout, reusing
dependencies. Copy both executables before switching source. Run the original
11-test module and its failing singleton in separate ABBA blocks. Every planned
execution remains in the receipt, including failures, timeouts and zero matches.
No test assertion, runtime source, service setting or security setting is changed.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import platform
import re
import selectors
import shutil
import signal
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / 'results/h1-reuse-diagnostic'
SOURCES = {'baseline': '7bddb58ae8cf547c9bb875f597557dd842bcb786',
           'candidate': '2ec9074b37880bdbfe230c3490e4418d5e8c6450'}
MODULE = 'functional::functional_http1_direct_pool_test::'
SINGLETON = MODULE + 'direct_h1_streams_uploads_byte_exact'
ORDER = ('baseline', 'candidate', 'candidate', 'baseline')
MAX_LOG_BYTES = 16 * 1024**2


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def write(path, value):
    Path(path).write_text(json.dumps(value, indent=2, allow_nan=False) + '\n')


def planned():
    return [dict(index=index, mode=mode, arm=arm, source_sha=SOURCES[arm],
                 expected_tests=11 if mode == 'module' else 1, state='pending')
            for index, (mode, arm) in enumerate((mode, arm) for mode in ('module', 'singleton') for arm in ORDER)]


def test_counts(text):
    matches = re.findall(r'test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;', text)
    if len(matches) != 1:
        return None
    status, passed, failed, ignored = matches[0]
    return dict(status=status, passed=int(passed), failed=int(failed), ignored=int(ignored))


def execution_errors(row):
    if row.get('state') != 'completed':
        return ['execution incomplete']
    if row.get('timed_out') or row.get('log_limit_exceeded'):
        return ['execution exceeded fixed bound']
    counts = row.get('counts')
    if (not isinstance(counts, dict) or any(type(counts.get(key)) is not int or counts[key] < 0
                                          for key in ('passed', 'failed', 'ignored'))
            or counts['passed'] + counts['failed'] != row['expected_tests'] or counts['ignored'] != 0):
        return ['missing, malformed or unexpected test population']
    if type(row.get('exit_code')) is not int or row['exit_code'] != 0 or counts['failed'] or counts.get('status') != 'ok':
        return ['original correctness assertion failed']
    return []


def environment():
    env = {key: value for key, value in os.environ.items() if not key.startswith('FERRUM_')}
    for key in ('CARGO_TARGET_DIR', 'RUSTFLAGS', 'RUSTC_WRAPPER', 'CARGO_BUILD_RUSTC_WRAPPER',
                'UPDATE_VENDOR_INTEGRITY', 'CARGO_BIN_EXE_ferrum-edge'):
        env.pop(key, None)
    env.update(CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0', CARGO_BUILD_JOBS='2')
    return env


def stop_owned_group(pid):
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def command(argv, cwd, env, name, seconds):
    log = OUTPUT / (name + '.log')
    start = time.monotonic()
    record = dict(argv=[str(x) for x in argv], elapsed_seconds=0, timed_out=False,
                  log_limit_exceeded=False, exit_code=None)
    written = 0
    heartbeat = start + 30
    with log.open('wb') as stream:
        child = subprocess.Popen(argv, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 start_new_session=True)
        try:
            with selectors.DefaultSelector() as ready:
                ready.register(child.stdout, selectors.EVENT_READ)
                reading = True
                while reading or child.poll() is None:
                    elapsed = time.monotonic() - start
                    if time.monotonic() >= heartbeat:
                        print(f'{name}: elapsed={elapsed:.0f}s log_bytes={written}', flush=True)
                        heartbeat = time.monotonic() + 30
                    record['timed_out'] = elapsed >= seconds
                    if record['timed_out']:
                        break
                    if child.poll() is not None:
                        # A failed direct child may leave a fixture descendant
                        # holding the pipe. Stop only this command's session.
                        stop_owned_group(child.pid)
                    for key, _ in ready.select(timeout=0.25):
                        data = os.read(key.fd, 65536)
                        if not data:
                            ready.unregister(key.fileobj)
                            reading = False
                            continue
                        remaining = MAX_LOG_BYTES - written
                        stream.write(data[:remaining])
                        written += min(len(data), remaining)
                        if len(data) > remaining:
                            record['log_limit_exceeded'] = True
                            break
                    if record['log_limit_exceeded']:
                        break
        finally:
            # Do this even after the direct child exits: no gateway descendant
            # from one observation may survive into another ABBA position.
            stop_owned_group(child.pid)
            record['exit_code'] = child.wait(timeout=5)
            child.stdout.close()
    record.update(elapsed_seconds=time.monotonic() - start, log_sha256=digest(log), log_bytes=log.stat().st_size)
    write(OUTPUT / (name + '.json'), record)
    return record


def git(*args, cwd=ROOT):
    return subprocess.check_output(['git', *args], cwd=cwd, text=True).strip()


def clean(source, sha):
    if git('rev-parse', 'HEAD', cwd=source) != sha or git('status', '--porcelain', cwd=source):
        raise ValueError('source differs from exact unchanged commit')


def functional_executable(text):
    executables = []
    for line in text.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict):
            raise ValueError('nonobject Cargo artifact evidence')
        if (event.get('reason') == 'compiler-artifact' and event.get('target', {}).get('name') == 'functional_tests'
                and event.get('profile', {}).get('test') is True and event.get('executable')):
            executables.append(Path(event['executable']))
    if len(set(executables)) != 1:
        raise ValueError('missing unique compiled functional test executable')
    return executables[0]


def build(source, arm, private, env, receipt):
    sha = SOURCES[arm]
    subprocess.run(['git', 'checkout', '--detach', sha], cwd=source, check=True)
    clean(source, sha)
    argv = ['cargo', 'test', '--locked', '--features', 'cloud-secrets', '--test', 'functional_tests',
            '--no-run', '--message-format=json-render-diagnostics']
    result = command(argv, source, env, arm + '-compile', 3300)
    if result['exit_code'] or result['timed_out'] or result['log_limit_exceeded']:
        raise ValueError(arm + ': original functional target build failed')
    executable = functional_executable((OUTPUT / (arm + '-compile.log')).read_text())
    artifacts = private / arm
    artifacts.mkdir()
    for name, path in (('gateway', source / 'target/debug/ferrum-edge'), ('tests', executable)):
        if not path.is_file() or path.is_symlink() or not path.resolve().is_relative_to(source / 'target'):
            raise ValueError('unexpected binary provenance')
        shutil.copyfile(path, artifacts / name)
        (artifacts / name).chmod(0o500)
        receipt.setdefault('builds', {}).setdefault(arm, {})[name] = dict(sha256=digest(path), bytes=path.stat().st_size)
    clean(source, sha)
    receipt['builds'][arm].update(source_sha=sha, test_module_sha256=digest(source / 'tests/functional/functional_http1_direct_pool_test.rs'),
                                 harness_sha256=digest(source / 'tests/common/gateway_harness.rs'))


def main():
    if os.environ.get('GITHUB_ACTIONS') != 'true' or platform.system() != 'Linux' or platform.machine() != 'x86_64':
        raise ValueError('remote GitHub Actions Linux x64 only')
    OUTPUT.mkdir(parents=True, exist_ok=False)
    receipt = dict(schema=1, sources=SOURCES, plan=planned(), complete=False, all_tests_passed=False,
                   performance_eligible=False, errors=[],
                   scope='Focused debug correctness only. Original assertions and concurrency unchanged. No runtime performance verdict.')
    def interrupted(signum, frame):
        raise InterruptedError('focused diagnostic signal ' + str(signum))
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    write(OUTPUT / 'receipt.json', receipt)
    owned = Path(tempfile.mkdtemp(prefix='mesh-h1-reuse-', dir=os.environ['RUNNER_TEMP']))
    source = owned / 'source'
    private = owned / 'executables'
    private.mkdir()
    env = environment()
    try:
        free = os.statvfs(owned)
        if free.f_bavail * free.f_frsize < 20 * 1024**3:
            raise ValueError('insufficient disposable build disk reserve')
        subprocess.run(['git', 'worktree', 'add', '--detach', str(source), SOURCES['baseline']], cwd=ROOT, check=True)
        if (ROOT / 'target').is_dir():
            shutil.move(str(ROOT / 'target'), source / 'target')
            receipt['restored_dependency_target_moved'] = True
        tools = command(['rustc', '-Vv'], ROOT, env, 'rustc', 30)
        if tools['exit_code']:
            raise ValueError('compiler identity unavailable')
        if command(['cargo', '-Vv'], ROOT, env, 'cargo', 30)['exit_code']:
            raise ValueError('Cargo identity unavailable')
        for arm in SOURCES:
            build(source, arm, private, env, receipt)
            write(OUTPUT / 'receipt.json', receipt)
        for row in receipt['plan']:
            arm = row['arm']
            subprocess.run(['git', 'checkout', '--detach', SOURCES[arm]], cwd=source, check=True)
            clean(source, SOURCES[arm])
            selected = dict(env, FERRUM_EDGE_TEST_BIN=str(private / arm / 'gateway'), FERRUM_SKIP_GATEWAY_BUILD='1')
            argv = [str(private / arm / 'tests'), MODULE if row['mode'] == 'module' else SINGLETON, '--ignored', '--nocapture']
            if row['mode'] == 'singleton':
                argv.append('--exact')
            name = f"execution-{row['index']:02d}-{row['mode']}-{arm}"
            result = command(argv, source, selected, name, 300 if row['mode'] == 'module' else 120)
            row.update(result, state='completed', gateway_sha256=digest(private / arm / 'gateway'),
                       tests_sha256=digest(private / arm / 'tests'), counts=test_counts((OUTPUT / (name + '.log')).read_text()))
            row['errors'] = execution_errors(row)
            clean(source, SOURCES[arm])
            write(OUTPUT / 'receipt.json', receipt)
        receipt['complete'] = True
        receipt['all_tests_passed'] = all(not row['errors'] for row in receipt['plan'])
    except Exception as error:
        receipt['errors'].append(str(error))
    finally:
        result = subprocess.run(['git', 'worktree', 'remove', '--force', str(source)], cwd=ROOT, capture_output=True)
        if result.returncode and source.exists():
            receipt['errors'].append('owned source worktree cleanup failed')
        else:
            shutil.rmtree(owned)
        write(OUTPUT / 'receipt.json', receipt)
    print(json.dumps(receipt, indent=2), flush=True)
    return 0 if receipt['complete'] and receipt['all_tests_passed'] and not receipt['errors'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
