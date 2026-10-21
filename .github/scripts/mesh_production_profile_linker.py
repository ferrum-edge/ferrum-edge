#!/usr/bin/env python3
"""Temporary cc PATH shim: preserve the first link; capture a separate symbol twin.

Installed as /opt/mesh-link-capture/cc with adjacent config.json in a disposable
builder only. It never changes compiler options or overwrites the original ELF.
Secondary failures are receipts, not a changed return status for the first link.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shlex
import shutil
import signal
import subprocess
import sys
import time

LIMITS = dict(response_bytes=8 * 1024**2, argument_bytes=16 * 1024**2,
              arguments=200000, response_files=16, response_depth=4,
              elf_bytes=1024**3, log_bytes=16 * 1024**2, secondary_seconds=180)


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha256_file(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as source:
        for block in iter(lambda: source.read(1024**2), b''):
            h.update(block)
    return h.hexdigest()


def expand_response_files(args, cwd):
    """GCC/libiberty quoting; retain originals and bound recursion/expansion."""
    result, receipts = [], []
    total = 0

    def visit(rows, depth, active):
        nonlocal total
        require(depth <= LIMITS['response_depth'], 'response nesting bound')
        for arg in rows:
            if arg.startswith('@'):
                path = (cwd / arg[1:]).resolve()
                require(path not in active, 'response cycle')
                require(len(receipts) < LIMITS['response_files'], 'response count bound')
                require(path.is_file() and path.stat().st_size <= LIMITS['response_bytes'], 'response size bound')
                raw = path.read_bytes()
                total += len(raw)
                require(total <= LIMITS['argument_bytes'] and b'\0' not in raw, 'response byte bound/NUL')
                text = raw.decode('utf-8')
                receipts.append(dict(path=str(path), bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()))
                visit(shlex.split(text, comments=False, posix=True), depth + 1, active | {path})
            else:
                total += len(os.fsencode(arg)) + 1
                require(total <= LIMITS['argument_bytes'] and len(result) < LIMITS['arguments'], 'argument bound')
                result.append(arg)
    visit(args, 0, set())
    return result, receipts


def output_path(args, cwd):
    rows = []
    for i, arg in enumerate(args):
        if arg == '-o':
            require(i + 1 < len(args), 'missing output argument')
            rows.append(args[i + 1])
        elif arg.startswith('-o') and len(arg) > 2:
            rows.append(arg[2:])
    require(len(rows) <= 1, 'ambiguous output argument')
    return (cwd / rows[0]).absolute() if rows else None


def symbol_arguments(args, twin):
    result, removed, outputs, i = [], 0, 0, 0
    while i < len(args):
        arg = args[i]
        if arg == '-o':
            require(i + 1 < len(args), 'missing output argument')
            result.extend(('-o', str(twin)))
            outputs += 1
            i += 2
            continue
        if arg.startswith('-o') and len(arg) > 2:
            result.append('-o' + str(twin))
            outputs += 1
        elif arg in ('-s', '--strip-all'):
            removed += 1
        elif arg == '-Xlinker' and i + 1 < len(args) and args[i + 1] == '--strip-all':
            removed += 1
            i += 1
        elif arg.startswith('-Wl,'):
            parts = arg[4:].split(',')
            removed += parts.count('--strip-all')
            parts = [part for part in parts if part != '--strip-all']
            if parts:
                result.append('-Wl,' + ','.join(parts))
        else:
            result.append(arg)
        i += 1
    require(outputs == 1 and removed == 1, 'expected one output and one strip-all option')
    require(not any(a in ('--strip-debug', '-S') or
                    (a.startswith('-Wl,') and any(x in ('--strip-all', '--strip-debug', '-s', '-S')
                                               for x in a[4:].split(','))) for a in result),
            'unsupported remaining strip option')
    return result


def gcc_response(args):
    # GCC's response-file grammar accepts backslash escaping inside double quotes.
    require(all('\0' not in a and '\n' not in a and '\r' not in a for a in args), 'unsupported response argument')
    return '\n'.join('"' + a.replace('\\', '\\\\').replace('"', '\\"') + '"' for a in args) + '\n'


def selected(path, config):
    return path is not None and re.fullmatch(config['output_pattern'], str(path)) is not None


def write_json(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def capture(args, config, cwd, env):
    """Called only after the original process completes successfully."""
    expanded, responses = expand_response_files(args, cwd)
    original = output_path(expanded, cwd)
    if not selected(original, config):
        return
    slot = Path(config['capture_dir']) / 'ferrum-edge'
    slot.mkdir(parents=True, exist_ok=False)  # A second selected link fails qualification.
    receipt = dict(schema=1, captured=False, original_returncode=0, original_argv=args,
                   expanded_argv=expanded, responses=responses, cwd=str(cwd),
                   original_output=str(original), real_cc=config['real_cc'], source_sha256=config['source_sha256'], limits=LIMITS)
    started = time.monotonic()
    try:
        require(sha256_file(config['source_file']) == config['source_sha256'], 'real source identity changed')
        require(original.is_file() and not original.is_symlink() and
                config['minimum_elf_bytes'] <= original.stat().st_size <= LIMITS['elf_bytes'],
                'missing/oversize/dummy original ELF')
        before = sha256_file(original)
        receipt['original_sha256_before'] = before
        shutil.copyfile(original, slot / 'stripped')
        twin = slot / 'symbols'
        rewritten = symbol_arguments(expanded, twin)
        response = slot / 'symbols.rsp'
        response.write_text(gcc_response(rewritten))
        receipt['secondary_argv'] = ['cc', '@' + str(response)]
        receipt['secondary_response_sha256'] = sha256_file(response)
        receipt['real_cc_sha256'] = sha256_file(config['real_cc'])

        def child_limits():
            resource.setrlimit(resource.RLIMIT_FSIZE, (LIMITS['elf_bytes'], LIMITS['elf_bytes']))

        child = None
        with (slot / 'secondary.stdout').open('xb') as out, (slot / 'secondary.stderr').open('xb') as err:
            try:
                child = subprocess.Popen(receipt['secondary_argv'], executable=config['real_cc'], cwd=cwd,
                                         env=env, stdout=out, stderr=err, start_new_session=True,
                                         preexec_fn=child_limits)
                deadline = time.monotonic() + LIMITS['secondary_seconds']
                while child.poll() is None:
                    require(out.tell() <= LIMITS['log_bytes'] and err.tell() <= LIMITS['log_bytes'], 'secondary log bound')
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError('secondary link deadline')
                    try:
                        child.wait(timeout=min(0.2, remaining))
                    except subprocess.TimeoutExpired:
                        pass
                receipt['secondary_returncode'] = child.returncode
            finally:
                if child is not None and child.poll() is None:
                    os.killpg(child.pid, signal.SIGTERM)
                    try:
                        child.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        os.killpg(child.pid, signal.SIGKILL)
                        child.wait(timeout=3)
                if child is not None:
                    receipt['secondary_returncode'] = child.returncode
        require(receipt['secondary_returncode'] == 0, 'secondary link failed')
        require(twin.is_file() and 0 < twin.stat().st_size <= LIMITS['elf_bytes'], 'missing/oversize symbol ELF')
        require(all((slot / name).stat().st_size <= LIMITS['log_bytes']
                    for name in ('secondary.stdout', 'secondary.stderr')), 'secondary log bound')
        receipt['original_sha256_after'] = sha256_file(original)
        require(receipt['original_sha256_after'] == before, 'original ELF changed during secondary link')
        receipt['symbol_sha256'] = sha256_file(twin)
        receipt['captured'] = True
    except BaseException as error:
        receipt['failure'] = dict(type=type(error).__name__, reason=str(error)[:1000])
    finally:
        receipt['elapsed_seconds'] = time.monotonic() - started
        write_json(slot / 'receipt.json', receipt)


def run(args, config, shim_dir):
    env = dict(os.environ)
    env['PATH'] = os.pathsep.join(p for p in env.get('PATH', '').split(os.pathsep)
                                if Path(p).absolute() != shim_dir.absolute())
    # Keep argv, stdout/stderr, stdin and return status of the original cc call.
    # Capture errors never replace its successful output or status.
    child = subprocess.Popen(['cc', *args], executable=config['real_cc'], env=env)
    code = child.wait()
    if code == 0:
        try:
            capture(args, config, Path.cwd(), env)
        except BaseException as error:
            failure = Path(config['capture_dir']) / ('failure-' + str(os.getpid()) + '.json')
            failure.parent.mkdir(parents=True, exist_ok=True)
            write_json(failure, dict(type=type(error).__name__, reason=str(error)[:1000]))
    return code


def main():
    directory = Path(__file__).absolute().parent
    config = json.loads((directory / 'config.json').read_text())
    code = run(sys.argv[1:], config, directory)
    if code < 0:
        if -code not in (signal.SIGKILL, signal.SIGSTOP):
            signal.signal(-code, signal.SIG_DFL)
        os.kill(os.getpid(), -code)
    return code


if __name__ == '__main__':
    sys.exit(main())
