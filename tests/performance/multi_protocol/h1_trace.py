"""Hosted-only H1 passive supervisor. Never launches a gateway or a benchmark.

Only the synthetic fixture and fixed observer/perf inventory are executable here.
The ordinary harness owns gateway/client creation, work, and shutdown.
"""
import argparse
import contextlib
import ctypes
import hashlib
import functools
import json
import math
import os
from pathlib import Path
import platform
import resource
import re
import selectors
import signal
import socket
import stat
import struct
import subprocess
import sys
import time

from process_usage import capture, parse_stat
from transport_diagnostics import parse_diag
from h1_trace_contract import (BOUNDS, ELF_PACKAGE_BYTES, LOSSES, SYSCALLS, COUNTERS, validate_record,
                               syscall_coverage, fd_lifetimes, decode_cpu, clock_receipt_window)
# The shared hosted artifact scrubber's sibling import is scoped explicitly.
sys.path.insert(0, str(Path(__file__).resolve().parent / 'h3_proof'))
from hosted import scrub

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
STAGE = Path('/tmp/ferrum-h1-trace')
TICKS = os.sysconf('SC_CLK_TCK')
PAGE = os.sysconf('SC_PAGE_SIZE')
DEPENDENCY_PROVENANCE = json.loads((HERE / 'h1_profile_manifest.json').read_text())['external_trace']['dependency_provenance']


def write(path, value):
    path = Path(path)
    temporary = path.with_name(path.name + '.tmp')
    temporary.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')
    temporary.replace(path)


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def read_metadata(path, limit=256 * 1024):
    try:
        with Path(path).open('rb') as stream:
            data = stream.read(limit + 1)
        return dict(text=data[:limit].decode(errors='replace'), truncated=len(data) > limit)
    except OSError as error:
        return dict(errno=error.errno)


def prepare_artifacts(out):
    """Hand off only this stopped capture tree to the invoking runner.

    Never follow symlinks (including in the root path), modify hard-linked
    files, or broaden group/other permissions. Raw regular data stays intact;
    only verifier stderr uses the existing address scrub policy. Known perf
    control FIFOs carry no retained evidence and are removed without opening.
    This is also the workflow's always-run fallback after interrupted cleanup.
    """
    uid, gid = int(os.environ['SUDO_UID']), int(os.environ['SUDO_GID'])
    if uid <= 0 or gid <= 0:
        raise ValueError('artifact recipient must be the ordinary sudo caller')
    if '..' in Path(out).parts:
        raise ValueError('artifact root must not contain parent traversal')
    out = Path(os.path.abspath(out))
    if out == Path('/'):
        raise ValueError('artifact root must be a capture directory')
    report = dict(files=0, directories=0, control_fifos_removed=0, errors=[], error_count=0)

    def failed(path, error):
        report['error_count'] += 1
        if len(report['errors']) < 8:
            report['errors'].append(scrub(f'{path}: {type(error).__name__}: {error}')[:512])

    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    root = os.open('/', directory_flags)
    try:
        for part in out.parts[1:]:
            child = os.open(part, directory_flags, dir_fd=root)
            os.close(root)
            root = child
        device = os.fstat(root).st_dev
        for path, directories, files, directory in os.fwalk('.', topdown=True,
                follow_symlinks=False, dir_fd=root, onerror=lambda e: failed('walk', e)):
            # Prune foreign mounts and directory links before fwalk descends.
            for name in directories[:]:
                try:
                    info = os.stat(name, dir_fd=directory, follow_symlinks=False)
                    if not stat.S_ISDIR(info.st_mode) or info.st_dev != device:
                        raise ValueError('linked/foreign artifact directory')
                except (OSError, ValueError) as error:
                    directories.remove(name)
                    failed(f'{path}/{name}', error)
            for name in files:
                try:
                    info = os.stat(name, dir_fd=directory, follow_symlinks=False)
                    if stat.S_ISFIFO(info.st_mode) and name in ('perf.control', 'perf.ack'):
                        os.unlink(name, dir_fd=directory)
                        report['control_fifos_removed'] += 1
                        continue
                    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_dev != device:
                        raise ValueError('nonregular, linked or foreign artifact file')
                    flags = os.O_RDWR if name == 'loader.stderr' else os.O_RDONLY
                    fd = os.open(name, flags | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
                    try:
                        current = os.fstat(fd)
                        if (current.st_dev, current.st_ino, current.st_nlink) != (info.st_dev, info.st_ino, 1):
                            raise ValueError('artifact changed during handoff')
                        if name == 'loader.stderr':
                            if current.st_size > BOUNDS['raw_perf_bytes']:
                                raise ValueError('verifier stderr exceeds existing file cap')
                            with os.fdopen(os.dup(fd), 'r+b') as stream:
                                raw = stream.read(BOUNDS['raw_perf_bytes'] + 1)
                                if len(raw) > BOUNDS['raw_perf_bytes']:
                                    raise ValueError('verifier stderr grew past file cap')
                                redacted = scrub(raw.decode(errors='replace')).encode()
                                if redacted != raw:
                                    stream.seek(0); stream.write(redacted); stream.truncate()
                        os.fchown(fd, uid, gid)
                        os.fchmod(fd, (stat.S_IMODE(current.st_mode) & 0o777) | stat.S_IRUSR)
                        report['files'] += 1
                    finally:
                        os.close(fd)
                except (OSError, ValueError) as error:
                    failed(f'{path}/{name}', error)
            try:
                info = os.fstat(directory)
                os.fchown(directory, uid, gid)
                os.fchmod(directory, (stat.S_IMODE(info.st_mode) & 0o777) | stat.S_IRUSR | stat.S_IXUSR)
                report['directories'] += 1
            except OSError as error:
                failed(path, error)
    finally:
        os.close(root)
    report['status'] = 'error' if report['error_count'] else 'ready'
    print('H1 artifact retention ' + json.dumps(report, sort_keys=True), flush=True)
    return int(bool(report['error_count']))


def clock():
    before = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
    unix = time.time_ns()
    return dict(before_ns=before, unix_ns=unix,
                after_ns=time.clock_gettime_ns(time.CLOCK_MONOTONIC))


def clock_receipt():
    """Timestamp receipt in this producer's actual boot and time namespace."""
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    namespace = Path('/proc/self/ns/time').stat().st_ino
    return dict(clock(), kind='clock_receipt', clock='CLOCK_MONOTONIC',
                boot_id=boot, time_namespace=namespace)


def write_binding(output, *, runtime, config, sample, arm, pair, payload, raw_sample, client_exit,
                  h2_protocol=None):
    """Fixed data-only runner command; future client artifacts need not exist yet."""
    paths = dict(runtime=runtime, config=config, sample=sample,
                 raw_sample=raw_sample, client_exit=client_exit)
    if h2_protocol is not None:
        if (h2_protocol not in ('http2', 'grpcs') or arm not in ('ferrum', 'envoy')
                or type(pair) is not int or not 1 <= pair <= 2
                or type(payload) is not int or payload not in (10240, 71680)):
            raise ValueError('invalid H2 CPU trace binding selection')
    elif (arm not in ('ferrum', 'ferrum-baseline', 'ferrum-exp-cutoff-one')
          or type(pair) is not int or not 1 <= pair <= 4
          or type(payload) is not int or payload not in (10240, 71680, 512000, 1048576, 5242880)):
        raise ValueError('invalid H1 trace binding selection')
    for path in (output, *paths.values()):
        if not Path(path).is_absolute() or '..' in Path(path).parts:
            raise ValueError('H1 trace binding requires absolute artifact paths')
    destination = Path(output) / 'bind.json'
    if destination.exists():
        raise ValueError('H1 trace binding already exists')
    binding = dict(paths, arm=arm, pair=pair, payload=payload)
    if h2_protocol is not None:
        binding['h2_protocol'] = h2_protocol
    write(destination, binding)


def identity(pid):
    proc = Path('/proc') / str(pid)
    state = parse_stat((proc / 'stat').read_text(), TICKS, PAGE)
    cgroup = (proc / 'cgroup').read_text().strip().split('0::', 1)[1]
    status = dict(line.split(':', 1) for line in (proc / 'status').read_text().splitlines() if ':' in line)
    row = dict(pid=pid, start_ticks=state['start_ticks'], ticks=TICKS,
               cgroup=cgroup, cgroup_id=(Path('/sys/fs/cgroup') / cgroup.lstrip('/')).stat().st_ino,
               executable=os.readlink(proc / 'exe'), executable_sha256=digest(proc / 'exe'),
               boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
               namespaces={name: (proc / 'ns' / name).stat().st_ino for name in ('pid', 'mnt', 'net', 'time', 'user')},
               privileges={key: status.get(key, '').strip() for key in ('Uid', 'Gid', 'CapEff', 'CapPrm', 'CapAmb', 'NoNewPrivs', 'Seccomp')},
               clock=clock(), threads=[])
    tasks = sorted((proc / 'task').iterdir())
    if len(tasks) > BOUNDS['threads']:
        raise ValueError('thread inventory bound')
    for task in tasks:
        try:
            row['threads'].append(dict(tid=int(task.name), **parse_stat((task / 'stat').read_text(), TICKS, PAGE)))
        except FileNotFoundError:
            row.setdefault('thread_races', []).append(int(task.name))
    # Reject mixed /proc snapshots before using any of their ownership fields.
    if (parse_stat((proc / 'stat').read_text(), TICKS, PAGE)['start_ticks'] != row['start_ticks']
            or (proc / 'cgroup').read_text().strip().split('0::', 1)[1] != row['cgroup']):
        raise ValueError('process generation/cgroup changed during identity read')
    return row


def same_generation(before, after):
    return all(before.get(k) == after.get(k) for k in ('pid', 'start_ticks', 'cgroup_id', 'executable_sha256', 'boot_id', 'namespaces'))


def admit_runtime_target(runtime, previous=None):
    """Bind the recorded Docker generation before any privileged attachment."""
    from h1_trace_contract import trace_identity_issues
    if type(runtime.get('host_pid')) is not int or runtime['host_pid'] <= 0:
        raise ValueError('invalid recorded runtime PID')
    owner = identity(runtime['host_pid'])
    problems = trace_identity_issues(runtime, owner)
    if problems:
        raise ValueError('; '.join(problems))
    admit(owner)
    if previous is not None and not same_generation(previous, owner):
        raise ValueError('target identity changed adjacent to collector attachment')
    return owner


def target_alive(owner):
    try:
        raw = Path(f'/proc/{owner["pid"]}/stat').read_text()
    except FileNotFoundError:
        return False
    if parse_stat(raw, TICKS, PAGE)['start_ticks'] != owner['start_ticks']:
        raise RuntimeError('gateway PID generation changed')
    return raw[raw.rfind(')') + 2:].split()[0] not in ('Z', 'X', 'x')


def completion_evidence(binding):
    """Read retained client output, never infer drain from elapsed wall time.

    H1 prints this report only after Phases::finish joins all request workers.
    Aborted/timed-out drains cannot authorize teardown, even with exit code 0.
    Useful-work validity remains the independent benchmark validity contract.
    """
    paths = {key: Path(binding[key]) for key in ('sample', 'raw_sample', 'client_exit')}
    data = {key: path.read_bytes() for key, path in paths.items()}
    if data['client_exit'].strip() != b'0':
        raise ValueError('client exit failed/missing before teardown')
    sample, raw = (json.loads(data[key]) for key in ('sample', 'raw_sample'))
    phases = raw['phases']
    if (not isinstance(phases, dict) or sample['phases'] != phases or
            phases.get('timed_out') is not False or phases.get('stalled_workers') != [] or
            phases.get('transport_close_timed_out') is not False):
        raise ValueError('client request drain incomplete')
    for key in ('measurement_secs', 'measurement_elapsed_secs', 'drain_secs', 'drain_start_monotonic_secs'):
        value = phases.get(key)
        if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
            raise ValueError('missing/invalid client drain phase: ' + key)
    if not 0 < phases['measurement_secs'] <= phases['measurement_elapsed_secs']:
        raise ValueError('client measurement incomplete before drain')
    if (sample.get('gateway') != binding['arm'] or sample.get('pair') != binding['pair'] or
            sample.get('payload_size') != binding['payload']):
        raise ValueError('client completion binding mismatch')
    return dict(files={key: dict(path=str(paths[key]), sha256=hashlib.sha256(value).hexdigest())
                       for key, value in data.items()}, phases=phases)


class CaptureLifecycle:
    """Runner requests closure; only this live supervisor authorizes teardown."""
    def __init__(self, out, owner, binding, ready, collectors):
        self.out, self.owner, self.binding, self.ready = out, owner, binding, ready
        self.collectors = {name: c for name, c in collectors.items()
                           if c and c.ready.get('status') == 'supported'}
        self.teardown = None
        self.observations = {}
        self.target_gone = None

    def poll(self):
        before = clock()
        alive = target_alive(self.owner)
        if not alive:
            if self.teardown is None:
                raise RuntimeError('gateway exited before verified workload closure')
            if self.target_gone is None:
                self.target_gone = dict(observed_at=clock(), exact_exit_ns=None)
        for name, collector in self.collectors.items():
            row = self.observations.setdefault(name, {})
            status = collector.process.poll()
            after = clock()
            if status is None:
                row['last_alive'] = before
            else:
                row.setdefault('exit', dict(returncode=status, observed_at=after,
                    bounds_ns=[row.get('last_alive', before)['before_ns'], after['after_ns']],
                    exact_exit_ns=None))
                # The target can die between the initial /proc read and poll.
                if name == 'cpu' and status == 0 and self.teardown is not None and alive:
                    alive = target_alive(self.owner)
                    if not alive and self.target_gone is None:
                        self.target_gone = dict(observed_at=clock(), exact_exit_ns=None)
                if name != 'cpu' or status != 0 or self.teardown is None or alive:
                    raise RuntimeError('collector exited before workload closure or outside verified target teardown')
                row['exit']['expected_target_teardown'] = True
        return alive

    def authorize_teardown(self):
        if self.teardown is not None or not (self.out / 'teardown-request.json').exists():
            return
        request = json.loads((self.out / 'teardown-request.json').read_text())
        now = clock()
        if not isinstance(request, dict) or not isinstance(request.get('at'), dict):
            raise ValueError('stale/mismatched teardown request')
        at = request['at']
        if (request.get('session') != self.ready['session'] or
                request.get('binding_sha256') != self.ready['binding_sha256'] or
                request.get('owner') != self.owner or
                digest(self.out / 'bind.json') != self.ready['binding_sha256'] or
                not all(type(at.get(k)) is int for k in ('before_ns', 'after_ns', 'unix_ns')) or
                not self.ready['at']['after_ns'] <= at['before_ns'] <= at['after_ns'] <= now['before_ns']):
            raise ValueError('stale/mismatched teardown request')
        evidence = completion_evidence(self.binding)
        if request.get('evidence') != evidence:
            raise ValueError('client completion changed after retention')
        window = clock_receipt_window(evidence['phases'], [self.ready['at'], at],
            boot_id=self.owner['boot_id'], time_namespace=self.owner['namespaces']['time'])
        if not window.get('valid'):
            raise ValueError('completion does not bracket this capture measurement')
        self.acknowledge_teardown(request, dict(kind='retained_client_report', measurement=window))

    def acknowledge_teardown(self, request, completion):
        """Live transition shared with the hosted fixture's joined-work receipt."""
        if self.teardown is not None:
            raise RuntimeError('duplicate teardown transition')
        current = identity(self.owner['pid'])
        if not same_generation(self.owner, current):
            raise RuntimeError('gateway generation changed before teardown')
        # Poll AFTER reads: a queued marker must never forgive an already-dead
        # collector/target. No teardown state is installed until both are live.
        self.poll()
        self.teardown = dict(session=self.ready['session'], binding_sha256=self.ready['binding_sha256'],
            owner=current, request=request, at=clock(), phase='verified_teardown', completion=completion,
            collector_observations=json.loads(json.dumps(self.observations)))
        write(self.out / 'teardown-ready.json', self.teardown)

    def coverage_end(self, fallback):
        # Conservative lower bound on collector end, never supervisor/decode end.
        return min([fallback] + [r['last_alive']['before_ns'] for r in self.observations.values()
                                  if 'last_alive' in r])

    def usage(self):
        values = []
        for name, collector in self.collectors.items():
            if collector.process.poll() is not None:
                continue
            value = capture(collector.process.pid, TICKS, PAGE)
            if value is None:
                # perf can exit between poll and /proc read during removal.
                # Recheck the strict lifecycle; never forgive a live read failure.
                self.poll()
                if name != 'cpu' or collector.process.poll() is None:
                    raise RuntimeError('observer resource capture missing')
                self.observations[name]['resource_read_exit_race'] = dict(at=clock(), usage_unknown=True)
            else:
                values.append(value)
        return values

    def verify_stop(self):
        if self.teardown is None:
            raise RuntimeError('stop without verified client completion and request drain')
        if self.target_gone is None:
            raise RuntimeError('stop before owned gateway removal')
        if (digest(self.out / 'bind.json') != self.ready['binding_sha256'] or
                completion_evidence(self.binding) != self.teardown['request']['evidence']):
            raise ValueError('client completion/binding changed during teardown')

    def reaped(self, name, status):
        row = self.observations.setdefault(name, {})
        at = clock()
        row['reaped_at'] = at
        row.setdefault('exit', dict(returncode=status['returncode'], observed_at=at,
            bounds_ns=[row.get('last_alive', self.ready['at'])['before_ns'], at['after_ns']],
            exact_exit_ns=None, supervisor_stop=True))

    def report(self):
        return dict(teardown=self.teardown, collectors=self.observations, target_gone=self.target_gone,
                    exact_collector_end=False, gateway_removal_fully_observed=False,
                    limits='poll bounds, not exact exit clocks; no samples promised after target exit')


def request_teardown(out):
    """Unprivileged runner call only after client return, retention and stamping."""
    out = Path(out)
    ready = json.loads((out / 'ready.json').read_text())
    binding = json.loads((out / 'bind.json').read_text())
    request = dict(session=ready['session'], binding_sha256=digest(out / 'bind.json'),
                   owner=ready['owner'], evidence=completion_evidence(binding), at=clock_receipt())
    if (out / 'teardown-request.json').exists() or (out / 'teardown-ready.json').exists():
        raise ValueError('teardown handshake already exists')
    write(out / 'teardown-request.json', request)
    # Existing readiness wait budget, also capped by the original capture deadline.
    deadline = min(time.monotonic() + 30, ready['deadline_monotonic'])
    while time.monotonic() < deadline:
        if (out / 'stopped.json').exists():
            raise RuntimeError('supervisor stopped before teardown acknowledgement')
        if (out / 'teardown-ready.json').exists():
            ack = json.loads((out / 'teardown-ready.json').read_text())
            if ack.get('session') != ready['session'] or ack.get('request') != request:
                raise ValueError('stale teardown acknowledgement')
            return
        time.sleep(0.05)
    raise RuntimeError('teardown acknowledgement deadline')


def admit(row):
    p = row['privileges']
    if TICKS != 100 or any(int(x) == 0 for x in p['Uid'].split()) or any(int(p[k], 16) for k in ('CapEff', 'CapPrm', 'CapAmb')):
        raise ValueError('target must be native amd64 ordinary UID with no capabilities')
    if row['namespaces']['time'] != Path('/proc/self/ns/time').stat().st_ino:
        raise ValueError('target/observer time namespace mismatch')


def child_limits(file_limit=BOUNDS["raw_perf_bytes"]):
    # Only owned children; PDEATHSIG closes events even if this supervisor dies.
    resource.setrlimit(resource.RLIMIT_FSIZE, (file_limit, file_limit))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    parent = os.getppid()
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGTERM, 0, 0, 0) or os.getppid() != parent:
        os._exit(125)


def launch(action, *, stdout, stderr, stdin=None, file_limit=BOUNDS["raw_perf_bytes"], pass_fds=(), **data):
    allowed = {'netns', 'capacity', 'fault', 'denied', 'mode', 'pid', 'out', 'symfs', 'elf'}
    if data.keys() - allowed or not 4096 <= file_limit <= BOUNDS['raw_perf_bytes']:
        raise ValueError('unknown command data/resource bound')
    env = {key: os.environ[key] for key in ('GITHUB_ACTIONS', 'RUNNER_ENVIRONMENT', 'RUNNER_OS', 'RUNNER_ARCH',
           'GITHUB_SHA', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'ImageOS', 'ImageVersion') if key in os.environ}
    env.update(PATH='/usr/sbin:/usr/bin:/sbin:/bin', LANG='C.UTF-8', HOME='/nonexistent',
               H1_TRACE_ACTION=action, PERF_BUILDID_DIR=str(STAGE / 'buildid-cache'))
    env.update({f'H1_TRACE_{k.upper()}': str(v) for k, v in data.items()})
    return subprocess.Popen(['bash', 'tests/performance/multi_protocol/h1_trace_commands.sh'],
                            cwd=ROOT, env=env, stdin=stdin, stdout=stdout, stderr=stderr,
                            start_new_session=True, pass_fds=pass_fds, preexec_fn=functools.partial(child_limits, file_limit))


def reap(process, command=None):
    if process.poll() is None:
        try:
            if command and process.stdin:
                process.stdin.write(command); process.stdin.flush()
            else:
                os.killpg(process.pid, signal.SIGINT)
            process.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=3)
            return dict(returncode=process.returncode, forced=True)
    return dict(returncode=process.returncode, forced=False)


@contextlib.contextmanager
def directory_fd(path, *, create=False, root=None):
    """Walk directories without links, including the destination root's parents."""
    path = Path(path)
    if '..' in path.parts or (root is None and not path.is_absolute()):
        raise ValueError('unsafe directory path')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY) if root is None else os.dup(root)
    try:
        for part in path.parts:
            if part in (path.anchor, '.'):
                continue
            if create:
                try:
                    os.mkdir(part, 0o700, dir_fd=fd)
                except FileExistsError:
                    pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd
    finally:
        os.close(fd)


def output_fd(directory, name):
    try:
        return os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                       0o600, dir_fd=directory)
    except FileExistsError:
        pass
    # Pin and inspect before opening for I/O, including nonregular destinations.
    pin = os.open(name, os.O_PATH | os.O_NOFOLLOW, dir_fd=directory)
    try:
        info = os.fstat(pin)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError('unsafe command output')
        fd = os.open(f'/proc/self/fd/{pin}', os.O_WRONLY)
        try:
            if os.fstat(fd).st_nlink != 1:
                raise ValueError('command output gained a hard link')
            os.ftruncate(fd, 0)
            return fd
        except BaseException:
            os.close(fd)
            raise
    finally:
        os.close(pin)


def command(action, destination, *, limit=2 * 1024**2, timeout=30, elf_fd=None, output_directory_fd=None, **data):
    """Bound running and reaped output; pinned ELF input stays pinned in readelf."""
    out = Path(os.path.abspath(destination))
    if '..' in Path(destination).parts:
        raise ValueError('unsafe command output path')
    errors = out.with_suffix(out.suffix + '.stderr')
    if elf_fd is not None:
        if action != 'elf' or not stat.S_ISREG(os.fstat(elf_fd).st_mode):
            raise ValueError('pinned ELF descriptor required')
        data['elf'] = f'/proc/self/fd/{elf_fd}'
    with (directory_fd(out.parent) if output_directory_fd is None else
          contextlib.nullcontext(output_directory_fd)) as directory:
        with os.fdopen(output_fd(directory, out.name), 'wb') as stream, \
                os.fdopen(output_fd(directory, errors.name), 'wb') as err:
            process = launch(action, stdout=stream, stderr=err, file_limit=limit,
                             pass_fds=() if elf_fd is None else (elf_fd,), **data)
            deadline = time.monotonic() + timeout
            stopped = None
            while process.poll() is None:
                if time.monotonic() >= deadline or os.fstat(stream.fileno()).st_size + os.fstat(err.fileno()).st_size > limit:
                    stopped = 'deadline_or_output_cap'; break
                time.sleep(0.02)
            status = reap(process) if stopped else dict(returncode=process.wait(), forced=False)
            # Check after EVERY reaping path, including already-exited children.
            retained_bytes = os.fstat(stream.fileno()).st_size + os.fstat(err.fileno()).st_size
            if retained_bytes > limit:
                stopped = 'output_cap_after_reap'
            # Hash the pinned outputs, not a later replacement at the pathname.
            hashes = []
            for stream_fd in (stream.fileno(), err.fileno()):
                hashes.append(digest(f'/proc/self/fd/{stream_fd}'))
        status.update(action=action, incomplete=stopped, retained_bytes=retained_bytes,
                      output_limit=limit, stdout_sha256=hashes[0], stderr_sha256=hashes[1])
        with os.fdopen(output_fd(directory, out.name + '.status.json'), 'w') as receipt:
            json.dump(status, receipt, sort_keys=True, indent=2)
            receipt.write('\n')
    return status


def tcp_inventory(pid):
    """Prime TCP cookies in the actual socket namespace using INET_DIAG.

    The inode/FD inventory is only a bracketed initial observation. It NEVER
    assigns a cookie/role to a syscall or bridges descriptor reuse.
    """
    before = clock()
    proc = Path('/proc') / str(pid)
    original = os.open('/proc/self/ns/net', os.O_RDONLY)
    target = os.open(proc / 'ns/net', os.O_RDONLY)
    libc = ctypes.CDLL(None, use_errno=True)
    rows, fds, errors = [], [], []
    try:
        if os.fstat(original).st_ino != os.fstat(target).st_ino and libc.setns(target, 0):
            raise OSError(ctypes.get_errno(), 'setns')
        deadline = time.monotonic() + 0.5
        for family in (socket.AF_INET, socket.AF_INET6):
            with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 4) as netlink:
                netlink.settimeout(0.2)
                request = struct.pack('=BBBBI', family, socket.IPPROTO_TCP, 1 << 6, 0, 0xFFFFFFFF)
                request += bytes(40) + struct.pack('=II', 0xFFFFFFFF, 0xFFFFFFFF)
                netlink.sendto(struct.pack('=IHHII', 16 + len(request), 20, 0x301, 1, 0) + request, (0, 0))
                done = False
                while not done:
                    if time.monotonic() > deadline or len(rows) >= 8192:
                        raise ValueError('TCP diag deadline/row cap')
                    data, _, flags, _ = netlink.recvmsg(1024 * 1024)
                    if flags & socket.MSG_TRUNC:
                        raise ValueError('truncated TCP diag')
                    offset = 0
                    while offset + 16 <= len(data):
                        length, kind, flags, seq, _ = struct.unpack_from('=IHHII', data, offset)
                        if length < 16 or offset + length > len(data) or seq != 1 or flags & 0x10:
                            raise ValueError('invalid/interrupted TCP diag')
                        payload = data[offset + 16:offset + length]
                        if kind == 3:
                            done = True
                        elif kind == 2:
                            raise ValueError('TCP diag error ' + str(struct.unpack_from('=i', payload)[0]))
                        elif kind == 20:
                            rows.append(dict(parse_diag(payload), state=payload[1]))
                        offset += (length + 3) & ~3
        paths = list((proc / 'fd').iterdir())
        if len(paths) > BOUNDS['fd_rows_per_snapshot']:
            raise ValueError('FD inventory bound')
        for path in paths:
            try:
                link = os.readlink(path)
                if link.startswith('socket:['):
                    fds.append(dict(fd=int(path.name), inode=int(link[8:-1])))
            except FileNotFoundError:
                errors.append('fd_close_race')
    except (OSError, ValueError) as error:
        errors.append(type(error).__name__ + ':' + str(error))
    finally:
        if libc.setns(original, 0):
            raise OSError(ctypes.get_errno(), 'restore_netns')
        os.close(original); os.close(target)
    inodes = {row['inode'] for row in fds}
    return dict(clock=before, end_clock=clock(), fds=fds,
                sockets=[r for r in rows if r['inode'] in inodes], errors=errors,
                joins_authoritative=False, zero_transient_close_races='unknown; never backfilled')


@contextlib.contextmanager
def mapped_elf_fd(root, mapping):
    """Only a mapped regular inode, beneath the pinned target root, may be read.

    O_PATH does not open devices/FIFOs for I/O. All symlinks are deliberately
    unsupported, including intermediate and absolute links. /proc/self/fd is
    used only to reopen our already-pinned, verified regular inode for reading.
    """
    path = Path(mapping['path'])
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('unsafe mapped path')
    with directory_fd(path.parent, root=root) as parent:
        pin = os.open(path.name, os.O_PATH | os.O_NOFOLLOW, dir_fd=parent)
    try:
        info = os.fstat(pin)
        if (not stat.S_ISREG(info.st_mode) or
                (os.major(info.st_dev), os.minor(info.st_dev), info.st_ino) !=
                (mapping['device_major'], mapping['device_minor'], mapping['inode'])):
            raise ValueError('mapped inode replaced, linked or nonregular')
        fd = os.open(f'/proc/self/fd/{pin}', os.O_RDONLY | os.O_NONBLOCK)
        try:
            if os.fstat(fd) != info:
                raise ValueError('mapped inode changed before read')
            yield fd
        finally:
            os.close(fd)
    finally:
        os.close(pin)


def retain_mapped_elf(root, destination, mapping, budget, deadline):
    """Same FD for magic, copy and hash; budget charged before every write.

    Read at most the admitted initial size, never read-to-EOF on a growing file.
    Failed partial regular output is retained and cannot be certified/reused.
    """
    with mapped_elf_fd(root, mapping) as source:
        initial = os.fstat(source)
        if initial.st_size < 4 or initial.st_size > budget['remaining']:
            raise ValueError('retained ELF package cap/size')
        if time.monotonic() >= deadline:
            raise ValueError('DSO acquisition deadline')
        magic = os.read(source, 4)
        if magic != b'\x7fELF':
            raise ValueError('executable mapping is not ELF')
        os.lseek(source, 0, os.SEEK_SET)
        path = Path(mapping['path'])
        with directory_fd(path.parent, root=destination, create=True) as parent:
            try:
                target = os.open(path.name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=parent)
                existing = False
            except FileExistsError:
                pin = os.open(path.name, os.O_PATH | os.O_NOFOLLOW, dir_fd=parent)
                try:
                    info = os.fstat(pin)
                    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                        raise ValueError('unsafe retained ELF destination')
                    target = os.open(f'/proc/self/fd/{pin}', os.O_RDONLY)
                finally:
                    os.close(pin)
                existing = True
            try:
                info = os.fstat(target)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or (existing and info.st_size != initial.st_size):
                    raise ValueError('unsafe/partial retained ELF destination')
                metadata_reservation = 4 * 1024**2 + 4096
                needed = (0 if existing else initial.st_size) + metadata_reservation
                if needed > budget['package_remaining']:
                    raise ValueError('retained ELF package reservation cap')
                budget['package_remaining'] -= metadata_reservation
                sha, copied = hashlib.sha256(), 0
                def unchanged():
                    current = os.fstat(source)
                    if (current.st_dev, current.st_ino, current.st_nlink, current.st_size, current.st_mtime_ns, current.st_ctime_ns) != (
                            initial.st_dev, initial.st_ino, initial.st_nlink, initial.st_size, initial.st_mtime_ns, initial.st_ctime_ns):
                        raise ValueError('mapped ELF changed during acquisition')
                    if time.monotonic() >= deadline:
                        raise ValueError('DSO acquisition deadline')
                while copied < initial.st_size:
                    unchanged()
                    chunk = os.read(source, min(65536, initial.st_size - copied, budget['remaining']))
                    if not chunk:
                        raise ValueError('truncated ELF or package cap')
                    unchanged()
                    budget['remaining'] -= len(chunk)
                    copied += len(chunk)
                    sha.update(chunk)
                    if existing:
                        if os.read(target, len(chunk)) != chunk:
                            raise ValueError('retained ELF differs from mapped inode')
                    else:
                        budget['package_remaining'] -= len(chunk)
                        view = memoryview(chunk)
                        while view:
                            if time.monotonic() >= deadline:
                                raise ValueError('DSO acquisition deadline')
                            written = os.write(target, view)
                            if not written:
                                raise ValueError('short retained ELF write')
                            view = view[written:]
                unchanged()
                # Decode the pinned retained file; no pathname reopen of the ELF.
                # Keep every repeat's raw metadata, including failed decoders.
                metadata_name = path.name + '.elf-' + os.urandom(16).hex() + '.txt'
                reserved = os.open(metadata_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                   0o600, dir_fd=parent)
                os.close(reserved)
                metadata = f'/proc/self/fd/{parent}/{metadata_name}'
                with os.fdopen(os.open(f'/proc/self/fd/{target}', os.O_RDONLY), 'rb') as retained:
                    status = command('elf', metadata, elf_fd=retained.fileno(), output_directory_fd=parent,
                                     timeout=max(0.1, min(5, deadline - time.monotonic())))
                with os.fdopen(os.open(metadata_name, os.O_RDONLY | os.O_NOFOLLOW,
                                       dir_fd=parent), 'r') as text_file:
                    text = text_file.read(2 * 1024**2 + 1)
                return dict(mapping, sha256=sha.hexdigest(), bytes=copied,
                    metadata_path=str(path.with_name(metadata_name)),
                    build_id_lines=[l.strip() for l in text.splitlines() if 'Build ID:' in l],
                    eh_frame='.eh_frame' in text, debug_frame='.debug_frame' in text, decoder=status)
            finally:
                os.close(target)


def retain_dsos(pid, destination):
    """Bounded mapped ELF diagnostics; unsupported mappings never use host libc."""
    if '..' in Path(destination).parts:
        raise ValueError('unsafe DSO destination traversal')
    raw = read_metadata(f'/proc/{pid}/maps')
    if raw.get('truncated') or 'text' not in raw:
        return dict(complete=False, issue='maps unavailable/oversize', raw=raw)
    records, errors, mappings = [], [], {}
    for line in raw['text'].splitlines():
        fields = line.split(None, 5)
        if len(fields) < 2 or 'x' not in fields[1]:
            continue
        if len(fields) != 6 or not fields[5].startswith('/') or fields[5].endswith(' (deleted)'):
            errors.append('anonymous/deleted executable mapping: ' + line); continue
        try:
            major, minor = (int(v, 16) for v in fields[3].split(':'))
            mapping = dict(path=fields[5], device_major=major, device_minor=minor, inode=int(fields[4]))
            if mapping['inode'] <= 0 or (mapping['path'] in mappings and mappings[mapping['path']] != mapping):
                raise ValueError('inconsistent mapped identity')
            mappings[mapping['path']] = mapping
        except ValueError as error:
            errors.append(str(error))
    if len(mappings) > 128:
        return dict(complete=False, issue='DSO count bound', mappings=raw)
    budget = dict(remaining=ELF_PACKAGE_BYTES, package_remaining=ELF_PACKAGE_BYTES)
    deadline = time.monotonic() + 30
    # This one proc magic link is the admitted process's root. Subsequent source
    # and ALL destination components are descriptor-relative and no-follow.
    root = None
    try:
        root = os.open(f'/proc/{pid}/root', os.O_RDONLY | os.O_DIRECTORY)
        with directory_fd(Path(os.path.abspath(destination)), create=True) as target:
            # Include prior repeats and failed partial files in the shared package
            # reservation. Never create a fresh per-repeat package allowance.
            entries = 0
            for _, directories, files, directory in os.fwalk('.', dir_fd=target, follow_symlinks=False):
                for name in directories + files:
                    info = os.stat(name, dir_fd=directory, follow_symlinks=False)
                    entries += 1
                    if (time.monotonic() >= deadline or entries > 4096
                            or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode))
                            or (stat.S_ISREG(info.st_mode) and info.st_nlink != 1)):
                        raise ValueError('unsafe/oversize existing DSO package')
                    if stat.S_ISREG(info.st_mode):
                        budget['package_remaining'] -= info.st_size
                if budget['package_remaining'] < 0:
                    raise ValueError('existing DSO package cap')
            for mapping in sorted(mappings.values(), key=lambda row: row['path']):
                try:
                    record = retain_mapped_elf(root, target, mapping, budget, deadline)
                    records.append(record)
                    if record['decoder']['returncode'] or record['decoder']['incomplete']:
                        errors.append(mapping['path'] + ': ELF metadata decoder incomplete')
                except (OSError, ValueError) as error:
                    errors.append(f"{mapping['path']}: {type(error).__name__}: {error}")
                if time.monotonic() >= deadline:
                    errors.append('DSO metadata/acquisition deadline'); break
    except (OSError, ValueError) as error:
        errors.append(f'DSO package acquisition: {type(error).__name__}: {error}')
    finally:
        if root is not None:
            os.close(root)
    return dict(complete=not errors, errors=errors, mappings=raw, dsos=records,
                acquired_elf_bytes=ELF_PACKAGE_BYTES - budget['remaining'],
                retained_package_bytes=ELF_PACKAGE_BYTES - budget['package_remaining'],
                package_limit_bytes=ELF_PACKAGE_BYTES,
                package_bytes_basis='existing files plus acquired bytes plus conservative decoder output reservations',
                source='pinned target-root mapped device/inode; symlinks unsupported; never host libc substitution')


class Observer:
    def __init__(self, out, *, capacity='8192', fault='normal', denied='false'):
        self.out = out
        self.raw = (out / 'syscalls.jsonl').open('wb')
        self.err = (out / 'loader.stderr').open('wb')
        self.process = launch('observer', stdout=self.raw, stderr=self.err, stdin=subprocess.PIPE,
                              netns=Path('/proc/self/ns/net').stat().st_ino,
                              capacity=capacity, fault=fault, denied=denied)
        self.offset = 0
        self.pending = b''
        self.rows = []
        try:
            self.ready = self.wait_for('ready')
        except BaseException:
            self.finish(); raise

    def poll(self):
        with (self.out / 'syscalls.jsonl').open('rb') as stream:
            stream.seek(self.offset)
            data = stream.read(8 * 1024**2)
            self.offset += len(data)
        self.pending += data
        if len(self.pending) > 12 * 1024**2:
            raise ValueError('observer line cap')
        while b'\n' in self.pending:
            line, self.pending = self.pending.split(b'\n', 1)
            row = validate_record(json.loads(line))
            if row['phase'] in ('checkpoint', 'snapshot', 'final'):
                role_totals = {}
                for entry in row['rows']:
                    totals = role_totals.setdefault(str(entry['role']), {k: 0 for k in COUNTERS})
                    for key in COUNTERS:
                        totals[key] += entry[key]
                row['role_totals'] = role_totals
            if row['phase'] in ('checkpoint', 'snapshot'):
                row = dict(row, rows=[])  # full rows retained on disk; bounded consumer state
            self.rows.append(row)
            if len(self.rows) > 8260:
                raise ValueError('observer record cap')

    def wait_for(self, phase):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            self.poll()
            result = next((r for r in self.rows if r['phase'] == phase), None)
            if result:
                return result
            if self.process.poll() is not None:
                break
            time.sleep(0.02)
        raise RuntimeError('observer missing ' + phase)

    def bind(self, owner):
        self.process.stdin.write(('b %d %d %d %d %d\n' % (owner['pid'], owner['start_ticks'], TICKS,
                                  owner['cgroup_id'], owner['namespaces']['net'])).encode())
        self.process.stdin.flush()
        return self.wait_for('bound')

    def finish(self):
        status = reap(self.process, b'q')
        try:
            self.poll()
        except (OSError, ValueError, KeyError, TypeError) as error:
            status['parse_error'] = str(error)
        finally:
            self.raw.close(); self.err.close()
        # Match the H3 retained-verifier redaction: no raw kernel addresses.
        path = self.out / 'loader.stderr'
        path.write_text(scrub(path.read_text(errors='replace')))
        status['partial_record'] = bool(self.pending) or 'parse_error' in status
        return status


class CPU:
    def __init__(self, out, owner, *, file_limit=BOUNDS["raw_perf_bytes"]):
        self.out = out
        self.process = self.err = self.control = self.ack = None
        self.fifos = {}
        self.finished = None
        self.ready = None
        try:
            for name in ('perf.control', 'perf.ack'):
                os.mkfifo(out / name, 0o600)
                self.fifos[name] = (out / name).lstat().st_ino
            self.control = os.open(out / 'perf.control', os.O_RDWR | os.O_NONBLOCK)
            self.ack = os.open(out / 'perf.ack', os.O_RDWR | os.O_NONBLOCK)
            self.err = (out / 'perf.stderr').open('wb')
            self.process = launch('perf-record', stdout=subprocess.DEVNULL, stderr=self.err,
                                  pid=owner['pid'], out=out, file_limit=file_limit)
            os.write(self.control, b'enable\n')
            deadline = time.monotonic() + 10
            receipt = b''
            while time.monotonic() < deadline and self.process.poll() is None:
                try:
                    receipt += os.read(self.ack, 1024)
                except BlockingIOError:
                    pass
                if b'ack' in receipt:
                    self.ready = dict(status='supported', at=clock(), control_ack=receipt.decode(),
                                      event='cpu-clock:uS', frequency=99, stack_dump=8192, sample_read_enabled_running=True)
                    break
                time.sleep(0.02)
            if self.ready is None:
                self.ready = dict(status='unsupported', reason='no perf enable acknowledgement', at=clock())
                self.finish()
        except BaseException:
            self.finish(); raise

    def finish(self):
        if self.finished is not None:
            return self.finished
        status = reap(self.process) if self.process else dict(returncode=None, forced=False)
        if self.err:
            self.err.close()
        for name in ('control', 'ack'):
            fd = getattr(self, name, None)
            if fd is not None:
                os.close(fd); setattr(self, name, None)
        for name, inode in self.fifos.items():
            path = self.out / name
            info = path.lstat()
            if not stat.S_ISFIFO(info.st_mode) or info.st_ino != inode:
                raise ValueError('perf control FIFO changed before cleanup')
            path.unlink()
        self.finished = status
        return status


def read_cpu_attributes(path, status):
    """Verify one evlist event, never pool evidence from the metadata dummy.

    perf evlist -v emits one physical line per event. Its period/frequency
    union contains a comma; only freq=1 makes that value a frequency in Hz.
    Keep the original file and command receipt, including on parse failure.
    """
    result = dict(verified=False, event='cpu-clock:uS', line=None, fields={}, issues=[])
    issues = result['issues']
    if (type(status.get('returncode')) is not int or status['returncode'] != 0 or
            status.get('forced') is not False or 'incomplete' not in status or
            status['incomplete'] is not None):
        issues.append('perf evlist command failed/incomplete or missing status')
    # Match the existing metadata command cap; never read an unbounded file.
    limit = 2 * 1024**2
    try:
        with Path(path).open('rb') as stream:
            raw = stream.read(limit + 1)
        if len(raw) > limit:
            raise ValueError('perf evlist exceeds 2 MiB metadata cap')
        text = raw.decode('ascii')
        if any(byte not in (9, 10, 13) and not 32 <= byte <= 126 for byte in raw):
            raise ValueError('perf evlist contains non-text control bytes')
    except (OSError, UnicodeError, ValueError) as error:
        issues.append('perf evlist unavailable/invalid: ' + str(error))
        return result
    if hashlib.sha256(raw).hexdigest() != status.get('stdout_sha256'):
        issues.append('perf evlist retained output hash missing/mismatched')
    lines = text.split('\n')
    if len(lines) > 32 or any(len(line) > 16384 for line in lines):
        issues.append('perf evlist event/line bound exceeded')
        return result
    union = '{ sample_period, sample_freq }'
    field_pattern = re.compile(
        r'[ \t]*(\{[ \t]*sample_period[ \t]*,[ \t]*sample_freq[ \t]*\}|[a-z][a-z0-9_]*)'
        r'[ \t]*:[ \t]*([^,{}:\r\n]+)(?:,|$)')
    selected = []
    for number, line in enumerate(lines, 1):
        line = line.strip(' \t\r')
        if not line:
            continue
        event = re.fullmatch(r'([^\s,{}]+):[ \t]+(.+)', line)
        if not event:
            issues.append(f'perf evlist line {number}: malformed event record')
            continue
        name, payload = event.groups()
        fields, position = {}, 0
        if payload.endswith(','):
            issues.append(f'perf evlist line {number}: trailing field separator')
        while position < len(payload):
            field = field_pattern.match(payload, position)
            if not field:
                issues.append(f'perf evlist line {number}: malformed attribute at column {position + 1}')
                break
            key, value = field.groups()
            key = union if key.startswith('{') else key
            if key in fields:
                issues.append(f'perf evlist line {number}: duplicate attribute {key}')
                break
            fields[key] = value.strip()
            position = field.end()
        if name == result['event']:
            selected.append((number, fields))
    if len(selected) != 1:
        issues.append(f'expected exactly one cpu-clock:uS event, found {len(selected)}')
        return result
    result['line'], result['fields'] = selected[0]
    fields = result['fields']
    for alias in ('sample_period', 'sample_freq'):
        if alias in fields:
            issues.append('cpu-clock:uS unexpected standalone union attribute ' + alias)

    def numeric(key, annotation=None):
        value = fields.get(key)
        if value is None:
            issues.append('cpu-clock:uS missing attribute ' + key)
            return None
        suffix = r'(?:[ \t]+\(' + re.escape(annotation) + r'\))?' if annotation else ''
        match = re.fullmatch(r'(0x[0-9a-fA-F]{1,16}|[0-9]{1,20})' + suffix, value)
        if match:
            token = match[1]
            parsed = int(token, 16 if token.startswith('0x') else 10)
            if parsed < 2**64:
                return parsed
        issues.append(f'cpu-clock:uS invalid numeric attribute {key}: {value}')
        return None

    required = {'type': (1, 'software'), 'config': (0, 'PERF_COUNT_SW_CPU_CLOCK'),
                union: (99, None), 'freq': (1, None), 'inherit': (1, None),
                'exclude_kernel': (1, None), 'use_clockid': (1, None),
                'clockid': (1, None), 'sample_stack_user': (8192, None)}
    for key, (expected, annotation) in required.items():
        actual = numeric(key, annotation)
        if actual is not None and actual != expected:
            issues.append(f'cpu-clock:uS {key}: expected {expected}, got {actual}')
    if numeric('sample_regs_user') == 0:
        issues.append('cpu-clock:uS sample_regs_user: empty register mask')
    # perf omits zero-valued bitfields. Explicit exclusion of users is invalid.
    if 'exclude_user' in fields and numeric('exclude_user') != 0:
        issues.append('cpu-clock:uS exclude_user must be zero/absent')
    for key, required_bits in (
            ('sample_type', {'IP', 'TID', 'TIME', 'READ', 'REGS_USER', 'STACK_USER'}),
            ('read_format', {'TOTAL_TIME_ENABLED', 'TOTAL_TIME_RUNNING'})):
        value = fields.get(key, '')
        if not re.fullmatch(r'[A-Z][A-Z0-9_]*(?:\|[A-Z][A-Z0-9_]*)*', value):
            issues.append('cpu-clock:uS missing/invalid bit field ' + key)
            continue
        missing = required_bits - set(value.split('|'))
        if missing:
            issues.append(f'cpu-clock:uS {key} missing bits: ' + '|'.join(sorted(missing)))
    result['verified'] = not issues
    return result


def cpu_decode(out, owners, dsos, *, symfs=None):
    symfs = out / "symfs" if symfs is None else symfs
    decoded = command('perf-script', out / 'stacks.txt', limit=16 * 1024**2, timeout=30,
                      out=out, symfs=symfs)
    attributes = command('perf-attributes', out / 'perf-attributes.txt', out=out)
    header = command('perf-header', out / 'perf-header.txt', out=out)
    buildids = command('perf-buildids', out / 'perf-buildids.txt', out=out)
    # Stream the raw decoder, retain record headers/counts only. Raw stack memory
    # stays in bounded perf.data; hex expansion cannot exhaust trace artifacts.
    records, raw_error = [], None
    with (out / 'perf-raw.stderr').open('wb') as err:
        process = launch('perf-raw', stdout=subprocess.PIPE, stderr=err, out=out)
        os.set_blocking(process.stdout.fileno(), False)
        pending = b''
        deadline = time.monotonic() + 30
        seen = 0
        while True:
            if time.monotonic() > deadline or seen > 512 * 1024**2:
                raw_error = 'raw decoder deadline/stream cap'; break
            try:
                chunk = os.read(process.stdout.fileno(), 65536)
            except BlockingIOError:
                time.sleep(0.01); continue
            if not chunk:
                if process.poll() is not None:
                    break
                time.sleep(0.01); continue
            seen += len(chunk); pending += chunk
            while b'\n' in pending:
                line, pending = pending.split(b'\n', 1)
                if b'PERF_RECORD_' in line:
                    # Strip pointer/hex output. Keep event type and lost metadata
                    # as raw decoder text (user-only samples, never packet data).
                    tokens = line.decode(errors='replace').split('PERF_RECORD_', 1)[1]
                    records.append('PERF_RECORD_' + tokens[:256])
                if len(records) > 100000:
                    raw_error = 'raw record count cap'; break
            if raw_error:
                break
        raw_status = reap(process) if raw_error else dict(returncode=process.wait(timeout=3), forced=False)
        process.stdout.close()
    write(out / 'perf-records.json', dict(records=records, status=raw_status, incomplete=raw_error))
    result = decode_cpu((out / 'stacks.txt').read_text(errors='replace'), '\n'.join(records), set(owners))
    issues = []
    attribute_validation = read_cpu_attributes(out / 'perf-attributes.txt', attributes)
    attributes_verified = attribute_validation['verified']
    if not attributes_verified:
        issues.append('actual software sample attributes not verified')
        issues.extend('CPU attributes: ' + issue for issue in attribute_validation['issues'])
    build_id_by_path = {}
    for line in (out / 'perf-buildids.txt').read_text(errors='replace').splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2 and re.fullmatch(r'[a-fA-F0-9]{8,64}', parts[0]):
            build_id_by_path[parts[1].strip()] = parts[0].lower()
    retained_ids = {d['path']: [line.rsplit(' ', 1)[-1].lower() for line in d['build_id_lines']]
                    for d in dsos.get('dsos', [])}
    for path, build_id in build_id_by_path.items():
        if path.startswith('/') and build_id not in retained_ids.get(path, []):
            issues.append('recorded DSO build ID lacks matching retained ELF: ' + path)
    if not build_id_by_path or buildids['returncode'] or buildids['incomplete']:
        issues.append('recorded build IDs unavailable')
    if decoded['returncode'] or decoded['incomplete'] or raw_status['returncode'] or raw_error:
        issues.append('decoder failed/incomplete')
    if not result['samples'] or result['raw_sample_records'] != result['samples'] + result['foreign_samples']:
        issues.append('sample decoder coverage mismatch')
    if result['lost_records'] or result['throttle_records']:
        issues.append('lost or throttled samples')
    if result['foreign_samples']:
        issues.append('samples outside admitted process generations')
    if not dsos.get('complete') or any(not d['build_id_lines'] or not d['eh_frame'] for d in dsos.get('dsos', [])):
        issues.append('missing matching ELF/build IDs/CFI')
    if not result['mmap_records'] or not result['task_records']:
        issues.append('missing mapping/task provenance')
    if result['unresolved_samples'] or result['multi_frame_samples'] != result['samples']:
        issues.append('partial unwinding/unresolved samples')
    result.update(issues=issues, samples_complete=not issues, decoder_status=decoded,
                  header_status=header, buildid_status=buildids, attributes_status=attributes, attributes_verified=attributes_verified,
                  attribute_validation=attribute_validation,
                  raw_decoder_status=raw_status, unwind_complete=False,
                  inline_expansion=False,
                  enabled_running_time='PERF_SAMPLE_READ with TOTAL_TIME_ENABLED/RUNNING in raw perf.data; actual attributes retained',
                  kernel_stacks='not selected; user-mode cpu-clock only')
    write(out / 'cpu-coverage.json', {k: v for k, v in result.items() if k not in ('callchains', 'folded')})
    (out / 'stacks.folded').write_text(''.join(f'{k} {v}\n' for k, v in result['folded'].items()))
    return result


def capabilities(out):
    paths = ['/proc/sys/kernel/random/boot_id', '/proc/sys/kernel/perf_event_paranoid',
             '/proc/sys/kernel/perf_event_max_sample_rate', '/proc/sys/kernel/perf_event_max_stack',
             '/proc/sys/kernel/perf_event_mlock_kb', '/proc/sys/kernel/unprivileged_bpf_disabled',
             '/proc/self/status', '/proc/self/limits', '/proc/self/cgroup', '/proc/cpuinfo',
             '/sys/kernel/security/lockdown', '/etc/os-release', '/etc/apt/sources.list.d/ubuntu.sources',
             '/boot/config-' + platform.release()]
    result = dict(kernel=platform.uname()._asdict(), files={p: read_metadata(p) for p in paths},
                  dependency_provenance=DEPENDENCY_PROVENANCE, clock=clock(),
                  runner={k: os.environ.get(k) for k in ('GITHUB_SHA', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'ImageOS', 'ImageVersion')},
                  namespaces={n: Path('/proc/self/ns', n).stat().st_ino for n in ('pid', 'mnt', 'net', 'time', 'user')},
                  source_hashes={p.name: digest(p) for p in list(HERE.glob('h1_trace*')) +
                                 [HERE / 'h1_profile_manifest.json'] +
                                 [p for p in (HERE / 'h3_proof').iterdir() if p.suffix in ('.h', '.c')] if p.is_file()},
                  object_hashes={p.name: digest(p) for p in STAGE.iterdir() if p.is_file()},
                  discovered=True, loaded=False, attached=False, fixture_exercised=False, gateway_observed=False)
    try:
        result['btf_sha256'] = digest('/sys/kernel/btf/vmlinux')
    except OSError as error:
        result['btf_error'] = error.errno
    for action in ('perf-version', 'clang-version', 'cc-version', 'readelf-version', 'packages', 'package-origins'):
        result[action] = command(action, out / (action + '.txt'))
    result['perf_source'] = json.loads((STAGE / 'perf-source.json').read_text())
    try:
        notes = Path('/sys/kernel/notes').read_bytes()
        if len(notes) > 1024 * 1024:
            raise ValueError('kernel ELF note bound')
        result['kernel_notes_sha256'] = hashlib.sha256(notes).hexdigest()
        offset, ids = 0, []
        while offset + 12 <= len(notes):
            namesz, descsz, kind = struct.unpack_from('=III', notes, offset)
            offset += 12
            name = notes[offset:offset + namesz]
            offset += (namesz + 3) & ~3
            value = notes[offset:offset + descsz]
            offset += (descsz + 3) & ~3
            if name.rstrip(b'\0') == b'GNU' and kind == 3:
                ids.append(value.hex())
        result['kernel_build_ids'] = ids
    except (OSError, ValueError) as error:
        result['kernel_build_id_error'] = str(error)
    result['tracepoint_formats'] = {name: read_metadata('/sys/kernel/tracing/events/' + name + '/format')
        for name in ('raw_syscalls/sys_enter', 'raw_syscalls/sys_exit', 'sched/sched_process_fork',
                     'sched/sched_process_exec', 'sched/sched_process_exit')}
    write(out / 'capabilities.json', result)
    return result


def trace_bytes(out):
    # Build/debug/DSO packages are separately bounded and excluded by contract.
    return sum(p.stat().st_size for p in out.rglob('*') if p.is_file() and
               'symfs' not in p.relative_to(out).parts)


def campaign_trace_bytes(root):
    """One job-wide trace budget, including preflight and prior failed repeats."""
    total = 0
    for path in Path(root).rglob('*'):
        parts = path.relative_to(root).parts
        if ('traces' in parts or 'trace-preflight' in parts) and 'symfs' not in parts and path.is_file():
            total += path.stat().st_size
    return total


def boundary_report(sample, timeline, start, end, owner):
    phases = sample.get('phases') or {}
    window = clock_receipt_window(phases, [row.get('clock') for row in timeline],
        boot_id=owner['boot_id'], time_namespace=owner['namespaces']['time'])
    if window.get('valid') and (start > window['start_bounds_ns'][0] or end < window['end_bounds_ns'][1]):
        window = dict(valid=False, reason='capture does not cover full measurement')
    return dict(measurement=window, capture_start_ns=start, capture_end_ns=end,
                setup_warmup_drain='client completion verified before teardown; collector end conservatively bounded',
                exact_warmup_drain_boundaries=False,
                boundary_gap='existing phase report lacks absolute warmup/drain clocks; measurement is host-bracketed',
                cumulative_deltas='snapshot read intervals, not instantaneous phase counts')


def supervise(args):
    out = Path(args.output).resolve()
    out.mkdir(parents=True, exist_ok=True)
    mode = args.mode if args.enabled else 'none'
    result = dict(schema=1, mode=mode, selected_mode=args.mode, external_enabled=args.enabled,
                  dependency_provenance=DEPENDENCY_PROVENANCE, bounds=BOUNDS, complete=False, issues=[], timeline=[],
                  supervisor_started=clock(), supervisor_cpu_start=time.process_time(),
                  phase='waiting_for_owned_gateway', fully_profiled=False)
    observer = cpu = owner = lifecycle = None
    ended = result['supervisor_started']['after_ns']
    stop_requested = False
    parent = identity(args.parent)
    deadline = time.monotonic() + BOUNDS['seconds']
    try:
        if any((out / name).exists() for name in ('bind.json', 'ready.json', 'stop', 'stopped.json',
                'teardown-request.json', 'teardown-ready.json', 'trace-manifest.json')):
            raise RuntimeError('stale capture directory; lifecycle evidence must be fresh')
        if campaign_trace_bytes(Path(args.artifact_root)) >= BOUNDS['total_artifact_bytes'] - 32 * 1024**2:
            raise RuntimeError('job trace artifact reservation already exhausted')
        capabilities(out)
        # Supervisor exists before start_ferrum. This receipt is not collector readiness.
        write(out / 'supervisor-ready.json', dict(pid=os.getpid(), at=clock(), awaiting_binding=True))
        while not (out / 'bind.json').exists():
            if (out / 'stop').exists() or time.monotonic() >= deadline:
                raise RuntimeError('binding absent before stop/deadline')
            if parse_stat(Path(f'/proc/{args.parent}/stat').read_text(), TICKS, PAGE)['start_ticks'] != parent['start_ticks']:
                raise RuntimeError('parent generation changed')
            time.sleep(0.05)
        binding_bytes = (out / 'bind.json').read_bytes()
        binding = json.loads(binding_bytes)
        runtime_bytes = Path(binding['runtime']).read_bytes()
        runtime = json.loads(runtime_bytes)
        config = Path(binding['config']).read_bytes()
        result['input_hashes'] = dict(binding=hashlib.sha256(binding_bytes).hexdigest(),
            runtime=hashlib.sha256(runtime_bytes).hexdigest(), config=hashlib.sha256(config).hexdigest())
        h2_protocol = getattr(args, 'h2_protocol', None)
        if binding.get('h2_protocol') != h2_protocol:
            raise ValueError('trace binding protocol mismatch')
        if h2_protocol:
            if args.mode != 'cpu' or not args.enabled:
                raise ValueError('H2 extension permits only enabled user CPU sampling')
            from h2_cpu_profile import validate_runtime
            validate_runtime(binding, runtime, config, h2_protocol)
        else:
            expected = (HERE / 'configs/http1_tls_e2e_perf.yaml').read_text().replace('CA_PATH', '/etc/ferrum/tls/ca.pem').encode()
            if config != expected or hashlib.sha256(config).hexdigest() != runtime['config_sha256']:
                raise ValueError('effective config does not match exact H1 TLS fixture')
            env = runtime['environment']
            for key, value in {'FERRUM_MODE': 'file', 'FERRUM_PROXY_HTTPS_PORT': '8443',
                               'FERRUM_ADMIN_HTTP_PORT': '9000', 'FERRUM_ADMIN_BIND_ADDRESS': '127.0.0.1'}.items():
                if env.get(key) != value:
                    raise ValueError('runtime role configuration mismatch: ' + key)
            if env.get('FERRUM_RESPONSE_BUFFER_CUTOFF_BYTES') not in ('0', '1'):
                raise ValueError('unexpected cutoff')
        owner = admit_runtime_target(runtime)
        builds = Path(args.builds).resolve()
        matches = [str(p.relative_to(builds)) for p in builds.glob('*/ferrum-edge') if digest(p) == owner['executable_sha256']]
        envoy_cpu = h2_protocol and binding['arm'] == 'envoy'
        if not envoy_cpu and len(matches) != 1:
            raise ValueError('target ELF does not match exactly one retained release twin')
        result.update(identity=owner, runtime=runtime, matching_elf=None if envoy_cpu else matches[0], binding=binding)
        write(out / 'identity.json', owner)
        admit_runtime_target(runtime, owner)
        result['initial_sockets'] = tcp_inventory(owner['pid'])
        admit_runtime_target(runtime, owner)
        write(out / 'initial-sockets.json', result['initial_sockets'])
        # Envoy retains its actual mapped ELF and build IDs from the admitted
        # image, with unresolved/stripped symbols reported by the same decoder.
        symbol_package = builds / ('envoy' if envoy_cpu else str(Path(matches[0]).parent)) / 'symfs'
        result['symbol_package'] = str(symbol_package)
        dsos = retain_dsos(owner['pid'], symbol_package) if mode == 'cpu' else {}
        write(out / 'build-mappings.json', dsos)
        # Do not attach even the initially-unbound BPF programs before admission.
        # Metadata acquisition can take time: check again immediately at attach,
        # at BPF target bind, and after the attach/bind acknowledgement.
        admit_runtime_target(runtime, owner)
        if mode == 'syscalls':
            observer = Observer(out)
            admit_runtime_target(runtime, owner)
            result['ready'] = observer.ready
            if observer.ready.get('status') == 'supported':
                result['binding_receipt'] = observer.bind(owner)
            admit_runtime_target(runtime, owner)
        if mode == 'cpu':
            cpu = CPU(out, owner); result['ready'] = cpu.ready
            admit_runtime_target(runtime, owner)
        if mode == 'none':
            result['ready'] = dict(status='off', at=clock())
        started = time.monotonic_ns()
        ready = dict(status=result['ready']['status'], at=clock_receipt(), owner=owner,
                     session=os.urandom(16).hex(), binding_sha256=digest(out / 'bind.json'),
                     deadline_monotonic=deadline, cookie_priming_errors=result['initial_sockets']['errors'])
        lifecycle = CaptureLifecycle(out, owner, binding, ready, dict(cpu=cpu, observer=observer))
        lifecycle.poll()
        result['timeline'].append(dict(clock=ready['at'], ready=True))
        write(out / 'ready.json', ready)
        next_snapshot = 0
        while time.monotonic() < deadline:
            if observer:
                observer.poll()
            lifecycle.poll()
            lifecycle.authorize_teardown()
            if (out / 'stop').exists():
                stop_requested = True
                lifecycle.verify_stop()
                break
            if campaign_trace_bytes(Path(args.artifact_root)) >= BOUNDS['total_artifact_bytes'] - 32 * 1024**2:
                raise RuntimeError('trace artifact reservation exhausted')
            raw = out / 'perf.data'
            if raw.exists() and raw.stat().st_size >= BOUNDS['raw_perf_bytes']:
                raise RuntimeError('raw perf artifact cap reached')
            usage = lifecycle.usage()
            rss = sum(p['rss_bytes'] for p in usage if p)
            result['observer_peak_rss_bytes'] = max(result.get('observer_peak_rss_bytes', 0), rss)
            if rss + (BOUNDS['map_reservation_bytes'] if observer else 0) > BOUNDS['observer_rss_and_map_bytes']:
                raise RuntimeError('observer RSS/map reservation exceeded')
            if time.monotonic() >= next_snapshot:
                next_snapshot = time.monotonic() + 5
                sample = dict(clock=clock_receipt(), observer_usage=usage, observer_rss_bytes=rss)
                if len(result['timeline']) >= BOUNDS['metadata_snapshots']:
                    raise RuntimeError('metadata snapshot cap')
                try:
                    current = identity(owner['pid'])
                    if not same_generation(owner, current):
                        raise RuntimeError('gateway process/executable/namespace generation changed')
                    sample['identity'] = current
                    sample['tcp'] = tcp_inventory(owner['pid'])
                except FileNotFoundError:
                    if lifecycle.teardown is None:
                        raise RuntimeError('gateway vanished before verified teardown')
                    sample['gateway_gone'] = True
                result['timeline'].append(sample)
            if (not Path(f'/proc/{args.parent}').exists() or
                parse_stat(Path(f'/proc/{args.parent}/stat').read_text(), TICKS, PAGE)['start_ticks'] != parent['start_ticks']):
                raise RuntimeError('owned harness vanished/reused')
            time.sleep(0.05)
        if not stop_requested:
            raise RuntimeError('capture deadline: measurement/warmup/drain may be incomplete')
        ended = time.monotonic_ns()
        if len(result['timeline']) >= BOUNDS['metadata_snapshots']:
            raise RuntimeError('metadata snapshot cap')
        result['timeline'].append(dict(clock=clock_receipt(), terminal=True))
        sample = {}
        try:
            sample = json.loads(Path(binding['sample']).read_text())
        except (OSError, ValueError):
            result['issues'].append('missing/failed raw traffic sample')
        result['boundaries'] = boundary_report(sample, result['timeline'], started, lifecycle.coverage_end(ended), owner)
        if not result['boundaries']['measurement'].get('valid'):
            result['issues'].append('capture measurement clock/coverage incomplete')
        result['useful_work'] = dict(sample=str(binding['sample']), validity='independent existing benchmark_validity contract')
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RuntimeError) as error:
        result['issues'].append(type(error).__name__ + ': ' + str(error))
    finally:
        if observer:
            result['observer_exit'] = observer.finish()
            if lifecycle:
                lifecycle.reaped('observer', result['observer_exit'])
            result['syscalls'] = syscall_coverage(observer.rows, owner or {}, result.get('boundaries', {}))
            if result['observer_exit']['forced'] or result['observer_exit']['returncode'] or result['observer_exit']['partial_record']:
                result['issues'].append('observer exit incomplete')
            if not result['syscalls'].get('complete'):
                result['issues'].append('syscall coverage incomplete')
            write(out / 'syscalls.json', result['syscalls'])
            write(out / 'fd-lifetimes.json', fd_lifetimes(observer.rows))
        if cpu:
            result['perf_exit'] = cpu.finish()
            if lifecycle:
                lifecycle.reaped('cpu', result['perf_exit'])
            if (out / 'perf.data').exists():
                try:
                    decoded_cpu = cpu_decode(out, [owner['pid']] if owner else [], dsos, symfs=symbol_package)
                    from h1_trace_contract import cpu_phases
                    result['cpu'] = {k: v for k, v in decoded_cpu.items() if k not in ('callchains', 'folded')}
                    result['cpu']['phases'] = cpu_phases(decoded_cpu['callchains'], result.get('boundaries', {}).get('measurement', {}))
                    result['issues'].extend('CPU capture: ' + issue for issue in decoded_cpu['issues'] if issue not in (
                        'missing matching ELF/build IDs/CFI', 'partial unwinding/unresolved samples'))
                except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
                    result['issues'].append('CPU decoder failed: ' + str(error))
            if result['perf_exit']['forced'] or result['perf_exit']['returncode']:
                result['issues'].append('perf exit incomplete')
            if not (out / 'perf.data').exists():
                result['issues'].append('missing perf data')
        if lifecycle:
            result['lifecycle'] = lifecycle.report()
            result['lifecycle']['collectors_reaped_at'] = clock()
        result.update(stop_requested=stop_requested, ended=clock(), artifact_bytes=trace_bytes(out),
                      supervisor_cpu_seconds=time.process_time() - result['supervisor_cpu_start'])
        if result.get('ready', {}).get('status') not in ('supported', 'off'):
            result['issues'].append('collector unsupported/unavailable')
        result['job_trace_artifact_bytes'] = campaign_trace_bytes(Path(args.artifact_root))
        if result['job_trace_artifact_bytes'] > BOUNDS['total_artifact_bytes']:
            result['issues'].append('total trace artifact cap exceeded')
        result['coverage_gaps'] = ['gateway startup before verified binding', 'absolute warmup/drain phase boundaries',
                                   'full native allocation/copy coverage', 'optimized-away/async frames',
                                   'IPv6 role attribution and unproven shared-file-table lifetimes']
        # Full profiling cannot be certified by one separately selected dimension.
        result['complete'] = False
        result['capture_complete'] = stop_requested and not result['issues']
        try:
            capability = json.loads((out / 'capabilities.json').read_text())
            capability['loaded'] = mode == 'syscalls' and result.get('ready', {}).get('status') == 'supported'
            capability['attached'] = mode != 'none' and result.get('ready', {}).get('status') == 'supported'
            capability['gateway_observed'] = bool(result.get('cpu', {}).get('samples') or
                any(r.get('exits') for r in result.get('syscalls', {}).get('syscall_totals', [])))
            capability['capture_complete'] = result['capture_complete']
            write(out / 'capabilities.json', capability)
        except (OSError, ValueError):
            result['issues'].append('capability completion record missing')
            result['capture_complete'] = False
        result['artifacts'] = {str(p.relative_to(out)): dict(sha256=digest(p), bytes=p.stat().st_size)
            for p in out.rglob('*') if p.is_file() and 'symfs' not in p.relative_to(out).parts
            and p.name not in ('trace-manifest.json', 'stopped.json', 'supervisor.stdout', 'supervisor.stderr')}
        result['unhashed_live_logs'] = ['supervisor.stdout', 'supervisor.stderr']
        write(out / 'trace-manifest.json', result)
        write(out / 'stopped.json', dict(at=clock(), issues=result['issues'], capture_complete=result['capture_complete']))
    return 0 if result['capture_complete'] else 1


def stage(build):
    # A fresh public traversal path for ordinary-UID fixtures, never chmod checkout.
    STAGE.mkdir(mode=0o755)
    for name in ('observer', 'observer.bpf.o', 'h1_trace_fixture'):
        source = Path(build) / name
        destination = STAGE / name
        destination.write_bytes(source.read_bytes())
        destination.chmod(0o644 if name.endswith('.o') else 0o755)
    # Ubuntu's /usr/bin/perf wrapper often expects an unavailable Azure kernel
    # package. Retain the actual distro ELF from installed linux-tools-generic;
    # do not download a tool or assume its package version matches the kernel.
    candidates = sorted({p.resolve() for p in Path('/usr/lib/linux-tools').glob('*/perf') if p.is_file()})
    if not candidates:
        raise ValueError('installed Ubuntu perf ELF missing')
    perf = candidates[-1]
    with perf.open('rb') as source:
        if source.read(4) != b'\x7fELF':
            raise ValueError('perf is not an ELF')
    (STAGE / 'perf').write_bytes(perf.read_bytes())
    (STAGE / 'perf').chmod(0o755)
    write(STAGE / 'perf-source.json', dict(installed_path=str(perf), sha256=digest(perf)))
    (STAGE / 'buildid-cache').mkdir(mode=0o700)


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest='action', required=True)
    s = sub.add_parser('stage'); s.add_argument('--build', required=True)
    s = sub.add_parser('supervise')
    s.add_argument('--output', required=True); s.add_argument('--builds', required=True)
    s.add_argument('--artifact-root', required=True)
    s.add_argument('--mode', choices=('syscalls', 'cpu'), required=True)
    s.add_argument('--enabled', action='store_true'); s.add_argument('--parent', type=int, required=True)
    s.add_argument('--h2-protocol', choices=('http2', 'grpcs'))
    s = sub.add_parser('preflight'); s.add_argument('--output', required=True)
    s = sub.add_parser('prepare-artifacts'); s.add_argument('--output', required=True)
    s = sub.add_parser('request-teardown'); s.add_argument('--output', required=True)
    s = sub.add_parser('bind')
    for field in ('output', 'runtime', 'config', 'sample', 'raw-sample', 'client-exit', 'arm'):
        s.add_argument('--' + field, required=True)
    s.add_argument('--pair', type=int, required=True); s.add_argument('--payload', type=int, required=True)
    s.add_argument('--h2-protocol', choices=('http2', 'grpcs'))
    args = parser.parse_args()
    if (os.environ.get('GITHUB_ACTIONS'), os.environ.get('RUNNER_ENVIRONMENT'), platform.system(), platform.machine()) != (
            'true', 'github-hosted', 'Linux', 'x86_64'):
        raise SystemExit('hosted native amd64 passive supervisor only')
    if args.action == 'request-teardown':
        request_teardown(args.output); return 0
    if args.action == 'bind':
        write_binding(args.output, runtime=args.runtime, config=args.config, sample=args.sample,
                      arm=args.arm, pair=args.pair, payload=args.payload,
                      raw_sample=args.raw_sample, client_exit=args.client_exit, h2_protocol=args.h2_protocol)
        return 0
    if os.geteuid() != 0:
        raise SystemExit('hosted passive supervisor requires root')
    if args.action == 'stage':
        stage(args.build); return 0
    if args.action == 'prepare-artifacts':
        return prepare_artifacts(args.output)
    try:
        Path(args.output).mkdir(parents=True, exist_ok=True)
        if not Path('/sys/kernel/tracing/events').exists():
            command('tracefs', Path(args.output) / 'tracefs.txt')
        if args.action == 'supervise':
            status = supervise(args)
        else:
            from h1_trace_preflight import preflight
            status = preflight(Path(args.output))
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RuntimeError, subprocess.TimeoutExpired) as error:
        print('H1 trace failure ' + json.dumps(dict(action=args.action,
            error=scrub(f'{type(error).__name__}: {error}')[:2048])), flush=True)
        status = 1
    finally:
        retention_status = prepare_artifacts(args.output)
    return status or retention_status


if __name__ == '__main__':
    sys.exit(main())
