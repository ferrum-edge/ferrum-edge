"""Finite hosted H3 campaign. Root provisions/observes; workloads drop privileges.

Raw outputs are immutable sample inputs. Derived metadata never replaces a failed
benchmark's stdout. Every subprocess uses the literal, policy-visible inventory.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import shutil
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from benchmark_plan import gateway_order, paired_comparison
from benchmark_validity import sample_issues
from h3_experiment import envoy_config
from process_usage import IO_FIELDS, capture, parse_stat
from transport_diagnostics import (backend_distribution,
                                   snapshot, thread_snapshot, envoy_counter_provenance)
from live_contract import (ARMS, PAYLOADS, ENVOY, FAMILIES, assert_upstream_only, calibration,
                           manifest, owned_role, group_history, socket_lifetimes,
                           measurement_window, measurement_position, provenance_issues,
                           capture_interval, passive_bracket, natural,
                           validate_observer_record, observer_issues, smoke_issues,
                           sample_admission_issues, envoy_protocol_evidence)
from evidence import LOSSES
from socket_coverage import socket_coverage

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
STAGE = Path('/tmp/ferrum-h3-live')
TICKS = os.sysconf('SC_CLK_TCK')
PAGE = os.sysconf('SC_PAGE_SIZE')


def write(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def environment(action, **data):
    allowed = {'image', 'family', 'netns', 'cgroup', 'payload', 'workers', 'duration',
               'target', 'slice', 'name', 'arm', 'cpus', 'mode'}
    if data.keys() - allowed:
        raise ValueError('unknown command data')
    # No ambient FERRUM tuning or arbitrary env reaches a gateway/harness.
    keys = ('GITHUB_ACTIONS', 'RUNNER_ENVIRONMENT', 'RUNNER_OS', 'RUNNER_ARCH',
            'GITHUB_SHA', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'ImageOS', 'ImageVersion')
    env = {k: os.environ[k] for k in keys if k in os.environ}
    env.update(PATH='/usr/sbin:/usr/bin:/sbin:/bin', LANG='C.UTF-8', HOME='/nonexistent')
    env['H3_LIVE_ACTION'] = action
    env.update({f'H3_LIVE_{k.upper()}': str(v) for k, v in data.items()})
    return env


def launch(action, stdout, stderr, *, stdin=None, **data):
    return subprocess.Popen(['bash', 'tests/performance/multi_protocol/h3_proof/live_commands.sh'],
                            cwd=ROOT if action in ('source', 'tree', 'dirty') else STAGE, env=environment(action, **data), stdin=stdin,
                            stdout=stdout, stderr=stderr, start_new_session=True)


def signal_process_group(process, sig):
    # launch() gives each owned child its own session. A concurrent exit is
    # harmless; never use a process-name or an unrelated cgroup as the target.
    try:
        os.killpg(process.pid, sig)
    except ProcessLookupError:
        pass


def stop_process(process, timeout=10):
    forced = False
    try:
        if process.poll() is None:
            signal_process_group(process, signal.SIGTERM)
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            forced = True
            signal_process_group(process, signal.SIGKILL)
            process.wait(timeout=5)
    except BaseException:
        signal_process_group(process, signal.SIGKILL)
        process.wait(timeout=5)
        raise
    finally:
        if process.stdin is not None:
            process.stdin.close()
    return forced


def command(action, output, *, timeout=30, **data):
    # Paths are command data, not a JSON extension. Record the same path text
    # that environment() passes to the literal launcher; retain numeric types.
    data = {key: os.fspath(value) if isinstance(value, os.PathLike) else value
            for key, value in data.items()}
    status = {'action': action, 'data': data, 'start_ns': time.monotonic_ns(), 'returncode': None}
    # Serialization or artifact I/O failure must happen before child ownership.
    write(output.with_suffix('.json'), status)
    with output.with_suffix('.stdout').open('wb') as out, output.with_suffix('.stderr').open('wb') as err:
        process = launch(action, out, err, **data)
        try:
            status['returncode'] = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            status['timeout'] = True
            signal_process_group(process, signal.SIGKILL)
            status['returncode'] = process.wait(timeout=5)
        except BaseException:
            # Includes cancellation and unexpected wait errors. Reap before the
            # caller can remove cgroups or close the inherited output files.
            signal_process_group(process, signal.SIGKILL)
            process.wait(timeout=5)
            raise
        status['end_ns'] = time.monotonic_ns()
        write(output.with_suffix('.json'), status)
    if status['returncode'] != 0 or status.get('timeout'):
        raise RuntimeError(f'{action} failed: {status}')
    return output.with_suffix('.stdout').read_text()


def owner(pid, role):
    path = Path(f'/proc/{pid}')
    fields = parse_stat((path / 'stat').read_text(), TICKS, PAGE)
    cgroup = (path / 'cgroup').read_text().strip().split('::', 1)[1]
    return dict(pid=pid, role=role, start_ticks=fields['start_ticks'], ticks=TICKS,
                cgroup=cgroup, cgroup_id=Path('/sys/fs/cgroup', cgroup.lstrip('/')).stat().st_ino,
                netns=(path / 'ns/net').stat().st_ino,
                time_namespace=(path / 'ns/time').stat().st_ino,
                privileges=[line for line in (path / 'status').read_text().splitlines()
                            if line.startswith(('Uid:', 'Gid:', 'Cap', 'NoNewPrivs:', 'Seccomp:'))],
                executable=str((path / 'exe').resolve()), at_ns=time.monotonic_ns())


class Passive:
    """Same passive treatment in on/off arms, including sampler cost and raw series."""
    def __init__(self, scope, arm):
        self.scope, self.arm = scope, arm
        self.timeline, self.owners, self.errors, self.transitions = [], {}, [], []
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        while not self.stop.is_set():
            # This clock read precedes every resource read. Only the entire
            # [start, capture_end_ns] interval may authorize passive boundaries.
            start = time.monotonic_ns()
            clock = dict(before_ns=start, unix_ns=time.time_ns(), after_ns=time.monotonic_ns())
            sample = dict(unix_secs=clock['unix_ns'] / 1e9, monotonic_ns=start, clock=clock,
                          boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                          netns=os.stat('/proc/self/ns/net').st_ino,
                          processes=[], threads=[], sockets=[])
            try:
                inode_owners = {}
                for file in self.scope.rglob('cgroup.procs'):
                    role = 'backend' if file.parent.name == 'backend' else 'client' if file.parent.name == 'client' else 'gateway'
                    for pid in map(int, file.read_text().split()):
                        try:
                            o = owner(pid, role)
                            key = (pid, o['start_ticks'])
                            previous = self.owners.get(key)
                            if previous is None or previous['executable'] != o['executable'] or previous['privileges'] != o['privileges']:
                                self.transitions.append(o)
                            self.owners[key] = o
                            state = capture(pid, TICKS, PAGE)
                            if state:
                                sample['processes'].append(dict(state, pid=pid, role=role))
                            else:
                                self.errors.append(dict(at_ns=start, end_ns=time.monotonic_ns(),
                                                        pid=pid, error='process_capture_failed'))
                            sample['threads'].extend(thread_snapshot(pid, TICKS, parse_stat))
                            for fd in Path(f'/proc/{pid}/fd').iterdir():
                                try:
                                    target = os.readlink(fd)
                                    if target.startswith('socket:['):
                                        inode_owners.setdefault(int(target[8:-1]), []).append(dict(o, fd=int(fd.name)))
                                except (OSError, ValueError):
                                    continue
                        except (OSError, ValueError, IndexError) as error:
                            self.errors.append(dict(at_ns=start, end_ns=time.monotonic_ns(), pid=pid, error=str(error)))
                transport = snapshot(self.arm.startswith('envoy'))
                # The netlink dump may assign cookies. Only owned sockets persist.
                transport['sockets'] = [dict(row, owners=inode_owners[row['inode']])
                                        for row in transport.get('sockets', []) if row['inode'] in inode_owners]
                sample['transport'] = transport
                sample['sampler_cpu_ns'] = time.thread_time_ns()
                sample['softirq'] = Path('/proc/softirqs').read_text()
                sample['host_cpu'] = Path('/proc/stat').read_text()
            except (OSError, ValueError, KeyError, TypeError) as error:
                self.errors.append(dict(at_ns=start, end_ns=time.monotonic_ns(), error=str(error)))
            sample['capture_end_ns'] = time.monotonic_ns()
            sample['capture_ns'] = sample['capture_end_ns'] - start
            self.timeline.append(sample)
            if len(self.timeline) >= 1200:
                self.errors.append(dict(error='passive_sample_cap')); return
            self.stop.wait(0.5)

    def finish(self):
        self.stop.set()
        self.thread.join(timeout=3)
        return dict(timeline=self.timeline, owners=list(self.owners.values()), process_transitions=self.transitions, errors=self.errors,
                    capture_complete=not self.thread.is_alive(), available=True,
                    processes=[dict(o) for o in self.owners.values()])


class Observer:
    def __init__(self, family, scope, out):
        self.family, self.rows, self.error, self.files = family, [], None, []
        self.invocation = scope.name
        self.out = out
        err = (out / f'{family}.stderr').open('wb')
        self.files.append(err)
        self.raw = (out / f'{family}.jsonl').open('wb')
        self.files.append(self.raw)
        self.process = launch('observer', self.raw, err, stdin=subprocess.PIPE,
                              family=family, cgroup=scope, netns=os.stat('/proc/self/ns/net').st_ino)
        self.ready_event = threading.Event()
        self.ready = None
        self.cpu = []
        self.peak_rss_bytes = 0
        self.reader = threading.Thread(target=self.read, daemon=True)
        self.reader.start()
        if not self.ready_event.wait(10):
            self.error = 'readiness_timeout'
            self.finish()
            raise RuntimeError(f'{family}: missing observer readiness')
        # Keep error readiness as an error record; traffic may still be useful.
        if self.ready is None:
            self.error = self.error or 'missing_readiness'
        elif self.ready.get('status') == 'error':
            self.error = 'observer_implementation_error'

    def read(self):
        # The loader owns a real file descriptor, not a pipe to this parent.
        # PDEATHSIG can therefore detach and retain its final partial snapshot
        # even if the Python provisioner is killed.
        pending = b''
        size = 0
        try:
            with (self.out / f'{self.family}.jsonl').open('rb') as stream:
                while True:
                    chunk = stream.read(65536)
                    if chunk:
                        size += len(chunk)
                        pending += chunk
                        while b'\n' in pending:
                            line, pending = pending.split(b'\n', 1)
                            row = json.loads(line)
                            validate_observer_record(row, self.family)
                            self.rows.append(row)
                            if row.get('phase') == 'ready':
                                self.ready = row; self.ready_event.set()
                        if size > 10 * 1024 * 1024:
                            self.error = 'observer_artifact_cap'; self.process.terminate(); break
                    elif self.process.poll() is not None:
                        if pending: self.error = 'partial_observer_json_record'
                        break
                    else:
                        time.sleep(0.02)
        except (OSError, ValueError, KeyError, TypeError) as error:
            self.error = str(error)
        finally:
            self.ready_event.set()

    def sample_cpu(self):
        state = capture(self.process.pid, TICKS, PAGE)
        self.cpu.append(dict(at_ns=time.monotonic_ns(), state=state))
        if state: self.peak_rss_bytes = max(self.peak_rss_bytes, state['rss_bytes'])
        elif (self.ready or {}).get('status') == 'supported':
            self.error = 'observer_resource_capture_failed'
        return state['rss_bytes'] if state else 0

    def checkpoint(self):
        if self.process.poll() is None and self.ready and self.ready.get('status') == 'supported':
            try:
                self.process.stdin.write(b's'); self.process.stdin.flush()
                self.sample_cpu()
            except (OSError, BrokenPipeError) as error:
                self.error = str(error)

    def finish(self):
        if self.process.poll() is None:
            try:
                self.process.stdin.write(b'q'); self.process.stdin.flush()
                self.process.wait(timeout=8)
            except (OSError, subprocess.TimeoutExpired):
                self.error = 'forced_observer_stop'; self.process.kill(); self.process.wait()
        self.reader.join(timeout=3)
        if self.reader.is_alive():
            self.error = 'observer_reader_incomplete'
        for phase in ('ready', 'final', 'termination'):
            expected = 1 if phase == 'ready' or (self.ready or {}).get('status') == 'supported' else 0
            if sum(r.get('phase') == phase for r in self.rows) != expected:
                self.error = self.error or f'observer_{phase}_record_count'
        for file in self.files: file.close()
        return dict(family=self.family, invocation=self.invocation, ready=self.ready, returncode=self.process.returncode,
                    capture_complete=not self.reader.is_alive(),
                    error=self.error, process_usage=self.cpu, peak_rss_bytes=self.peak_rss_bytes,
                    final=next((r for r in self.rows if r.get('phase') == 'final'), None),
                    termination=next((r for r in self.rows if r.get('phase') == 'termination'), None))


def live_measurement_usage(usage, phases):
    """Strict live H3 CPU/I/O brackets; historical point-sampled callers stay separate."""
    timeline = usage.get('timeline', [])
    window = measurement_window(phases, timeline)
    by_process = {}
    for index, row in enumerate(timeline):
        for process in row.get('processes', []):
            if process['role'] == 'client':
                continue  # the client's own boundary snapshots remain authoritative
            key = (process['pid'], process['start_ticks'])
            by_process.setdefault(key, []).append((index, process))
    result = []
    for (pid, generation), values in by_process.items():
        bounds = passive_bracket(timeline, [i for i, _ in values], window)
        record = dict(pid=pid, start_ticks=generation, role=values[0][1]['role'],
                      complete_bracket=False, capture_bracket=bounds, peak_rss_bytes=None)
        if window.get('valid'):
            # RSS observations whose read intervals may overlap measurement;
            # no point timestamp or exact measurement-only peak is implied.
            within = [p['rss_bytes'] for i, p in values
                      if capture_interval(timeline[i])[1] >= window['start_bounds_ns'][0]
                      and capture_interval(timeline[i])[0] <= window['end_bounds_ns'][1]]
            record['peak_rss_bytes'] = max(within, default=None)
        record['rss_scope'] = 'passive_captures_possibly_overlapping_measurement'
        if bounds['complete_bracket']:
            left, right = bounds['left_sample_index'], bounds['right_sample_index']
            selected = [(i, p) for i, p in values if left <= i <= right]
            continuous = ([i for i, _ in selected] == list(range(left, right + 1))
                          and all(p['role'] == record['role'] for _, p in selected))
            counters = [p.get('cpu_seconds') for _, p in selected]
            monotonic = (all(type(v) in (int, float) and math.isfinite(v) and v >= 0 for v in counters)
                         and all(b >= a for a, b in zip(counters, counters[1:])))
            record['complete_bracket'] = continuous and monotonic
            if record['complete_bracket']:
                record['cpu_seconds'] = counters[-1] - counters[0]
                io = [p.get('io') for _, p in selected]
                if all(isinstance(v, dict) and all(natural(v.get(k)) for k in IO_FIELDS) for v in io):
                    if all(b[k] >= a[k] for a, b in zip(io, io[1:]) for k in IO_FIELDS):
                        record['io'] = {k: io[-1][k] - io[0][k] for k in IO_FIELDS}
                    else:
                        record['io_error'] = 'I/O counter decreased inside capture bracket'
                else:
                    record['io_error'] = 'I/O unavailable at one or more bracket samples'
            else:
                record['reason'] = 'process_generation_gap_or_invalid_cpu_counter'
        if not record['complete_bracket']:
            record['io_error'] = 'process capture bracket incomplete'
        result.append(record)
    client = phases.get('client_usage')
    if isinstance(client, dict):
        result.append(dict(client))
    return result


def passive_roles(usage, distribution, arm, phases, context=None):
    timeline = usage['timeline']
    window = measurement_window(phases, timeline)
    peers = {tuple((p['peer'].rsplit(':', 1)[0], int(p['peer'].rsplit(':', 1)[1]))) for p in distribution}
    records = {}
    population_issues = set()
    for index, row in enumerate(timeline):
        for sk in row.get('transport', {}).get('sockets', []):
            cookie = sk['cookie'][0] | sk['cookie'][1] << 32
            roles = set()
            for o in sk['owners']:
                local = (sk['local_address'], sk['local_port'])
                peer = (sk['peer_address'], sk['peer_port'])
                if o['role'] == 'backend' and local == ('127.0.0.1', 3445): roles.add('backend')
                if o['role'] == 'gateway':
                    if local == (('0.0.0.0', 8443) if arm == 'ferrum' else ('127.0.0.1', 8443)): roles.add('gateway_frontend')
                    if peer == ('127.0.0.1', 3445) or (local[0] in ('0.0.0.0', '127.0.0.1') and ('127.0.0.1', local[1]) in peers):
                        roles.add('gateway_upstream')
                if o['role'] == 'client' and (local[0] in ('0.0.0.0', '127.0.0.1')):
                    roles.add('client')
            if len(roles) != 1 or not cookie or sk['family'] != socket.AF_INET:
                interval = capture_interval(row)
                if (window.get('valid') and interval[1] >= window['start_bounds_ns'][0]
                        and interval[0] <= window['end_bounds_ns'][1]):
                    population_issues.add('unassigned_owned_socket')
                continue
            key = (cookie, next(iter(roles)))
            records.setdefault(key, []).append((index, sk))
    rows, probes = [], []
    for (cookie, role), values in records.items():
        bounds = passive_bracket(timeline, [i for i, _ in values], window)
        first, last = timeline[values[0][0]], timeline[values[-1][0]]
        observation = dict(cookie=cookie, role=role,
                           first_capture_bounds_ns=capture_interval(first),
                           last_capture_bounds_ns=capture_interval(last))
        if window.get('valid') and (capture_interval(last)[1] < window['start_bounds_ns'][0]
                or capture_interval(first)[0] > window['end_bounds_ns'][1]):
            probes.append(dict(observation, disposition='outside_measurement'))
            continue
        coverage = socket_coverage(timeline, values, bounds, window, cookie, context)
        equal = all(v.get('so_rcvbuf') == v.get('so_sndbuf') == 4194304 for _, v in values)
        if coverage['retirement'] is not None:
            equal = equal and coverage['retirement'].get('so_rcvbuf') == coverage['retirement'].get('so_sndbuf') == 4194304
        if not equal:
            coverage['issues'] = sorted(set(coverage['issues'] + ['wrong_buffer']))
        rows.append(dict(observation, complete_bracket=bounds['complete_bracket'] and coverage['lifetime_covered'],
                         capture_bracket=bounds, equal_buffers=equal, **coverage))
    required = {'backend', 'client'} | (set() if arm == 'direct' else {'gateway_frontend', 'gateway_upstream'})
    missing = sorted(required - {r['role'] for r in rows})
    if context and window.get('valid'):
        events = [e for stream in context['observers'] for e in stream.get('events', [])]
        bound = {(e['cookie'], (socket.inet_ntop(socket.AF_INET, struct.pack('=I', e['local_ipv4'])), e['local_port']))
                 for e in events if e['kind'] == 19 and e['result'] == 0}
        observed = {}
        for event in events:
            role = owned_role(event, usage.get('owners', []), bound, peers,
                              ('0.0.0.0', 8443) if arm == 'ferrum' else ('127.0.0.1', 8443))
            if role:
                observed.setdefault(event['cookie'], []).append(event['at_ns'])
        for cookie, times in observed.items():
            if (min(times) <= window['end_bounds_ns'][1] and max(times) >= window['start_bounds_ns'][0]
                    and cookie not in {r['cookie'] for r in rows}):
                population_issues.add('lifetime_without_passive_identity')
    issues = sorted({reason for r in rows for reason in r['issues']} | population_issues
                    | {f'missing_role:{role}' for role in missing})
    equal = bool(rows) and all(r['equal_buffers'] for r in rows)
    covered = (bool(rows) and window.get('valid') is True and not missing and not population_issues
               and all(r['lifetime_covered'] for r in rows))
    return dict(evidence_contract='socket-lifetime-v2', sockets=rows,
                probe_or_retired_outside_measurement=probes,
                role_join='owned_process_generation_full_endpoint_and_backend_peer',
                measurement_clock=window, missing_roles=missing, socket_evidence_issues=issues,
                observed_buffer_equality_verified=equal,
                observed_lifetime_drop_coverage_verified=covered,
                equal_socket_budget_verified=equal and covered and not issues,
                uncertainty='observed_socket_inventory_only;_short_unobserved_lifetimes_remain_partial;_no_exact_kernel_totals')


def proof(observers, usage, distribution, sample, provenance, namespace_lifetime, arm):
    rows = [r for o in observers for r in o.rows if r.get('phase') == 'lifecycle']
    bound = {(r['cookie'], (socket.inet_ntop(socket.AF_INET, struct.pack('=I', r['local_ipv4'])), r['local_port']))
             for r in rows if r['kind'] == 19 and r['result'] == 0}
    peers = {(r['peer'].rsplit(':', 1)[0], int(r['peer'].rsplit(':', 1)[1])) for r in distribution}
    identities = {}
    for row in rows:
        role = owned_role(row, usage['owners'], bound, peers,
                          ('0.0.0.0', 8443) if arm == 'ferrum' else ('127.0.0.1', 8443))
        if role:
            identities[(row['cookie'], row['pid'], row['process_start_ns'])] = role
    phases = sample.get('phases') or {}
    window = measurement_window(phases, usage['timeline'])
    if 'process_clock_namespace_unverified' in provenance_issues(usage, window, provenance['time_namespace']):
        window = dict(valid=False, reason='process_clock_namespace_unverified')
    cookie_roles = {}
    for (cookie, _, _), role in identities.items(): cookie_roles.setdefault(cookie, set()).add(role)
    operation_coverage = {}
    for observer in observers:
        final = next((r for r in observer.rows if r.get('phase') == 'final'), {})
        for row in final.get('rows', []):
            roles = cookie_roles.get(row['cookie'], set())
            if len(roles) == 1 and row['kind'] in (1, 2, 5, 6, 16):
                role = next(iter(roles))
                operation_coverage.setdefault(role, set()).add(row['kind'])
    witnesses, uncertain = [], []
    for observer in observers:
        for row in observer.rows:
            if row.get('phase') != 'witness' or row['kind'] not in (1, 5): continue
            role = identities.get((row['cookie'], row['pid'], row['process_start_ns']))
            if role and row['result'] == row['length'] and row['length'] > row['segment'] > 0:
                position = measurement_position(row['at_ns'], window)
                if position == 'measurement':
                    witnesses.append(dict(row, role=role, scope='this_sample_measurement_only'))
                elif position != 'outside':
                    uncertain.append(dict(row, role=role, phase_correlation=position))
    return dict(positive=witnesses, operation_coverage={k: sorted(v) for k, v in operation_coverage.items()},
                measurement_clock=window, uncorrelated_positive=uncertain,
                operation_coverage_scope='whole_arm_including_setup;_not_measurement_witness',
                completeness='partial', exact_totals=False, absence_claim_allowed=False,
                roles=[dict(cookie=k[0], pid=k[1], process_start_ns=k[2], role=v) for k, v in identities.items()],
                limitations=['bounded_witness_sampling', 'passive_process_polling_may_miss_short_lifetimes',
                             'reuseport_group_history_partial_on_site_or_event_loss',
                             'descriptor_alias_transitions_not_a_retirement_proof'],
                socket_lifetimes=socket_lifetimes(rows, provenance['boot_id'], namespace_lifetime),
                group_history=group_history(rows),
                process_events=[e for e in rows if e['kind'] in (27, 28, 29)],
                family_outcomes=[dict(family=o.family, ready=o.ready, error=o.error,
                     losses=dict(zip(LOSSES, next((r['losses'] for r in o.rows if r.get('phase') == 'final'), [])))) for o in observers],
                classic_execution='see_independent_classic_readiness; missing_run_bpf_filter_execution_site_is_unavailable',
                hardware_cycles=None, cpu_stack_claim=False)


def prepare(out):
    import yaml
    plan = manifest(HERE / 'live_campaign.json')
    build = Path(os.environ['H3_LIVE_BUILD']).resolve()
    inventory = json.loads((build / 'build.json').read_text())
    if inventory['source'] != os.environ['GITHUB_SHA']:
        raise ValueError('artifact/checkout SHA mismatch')
    for name, expected in inventory['lockfiles'].items():
        if digest(ROOT / name) != expected: raise ValueError('checkout lockfile mismatch')
    for name, expected in inventory['sha256'].items():
        if Path(name).name != name or digest(build / name) != expected:
            raise ValueError('artifact hash mismatch')
    STAGE.mkdir(mode=0o755)  # fail on any prior staging path
    target = STAGE / HERE.relative_to(ROOT)
    target.mkdir(parents=True)
    for path in HERE.iterdir():
        if path.is_file(): shutil.copyfile(path, target / path.name)
    (STAGE / 'build').mkdir()
    for name in ('observer', 'observer.bpf.o', 'proto_backend', 'proto_bench', 'ferrum-edge', 'h3_tls_fixture'):
        shutil.copyfile(build / name, STAGE / 'build' / name)
        (STAGE / 'build' / name).chmod(0o644 if name.endswith('.o') else 0o755)
        if digest(STAGE / 'build' / name) != inventory['sha256'][name]:
            raise ValueError('staged object hash mismatch')
    for path in HERE.iterdir():
        if path.is_file() and digest(path) != digest(target / path.name):
            raise ValueError('staged source hash mismatch')
    runtime = STAGE / 'runtime'
    runtime.mkdir(mode=0o755); os.chown(runtime, 65534, 65534)
    configs = STAGE / 'configs'; configs.mkdir()
    source = (HERE.parent / 'configs/envoy/http3.yaml').read_text()
    source = source.replace('CERT_PATH', '/certs/cert.pem').replace('KEY_PATH', '/certs/key.pem').replace('CA_PATH', '/certs/ca.pem')
    generated = {}
    for arm, limit in [('envoy', 100), ('envoy-limit-4', 4)]:
        text = envoy_config(source, limit, 4194304, upstream_only=True)
        (configs / f'{arm}.yaml').write_text(text)
        generated[arm] = yaml.safe_load(text)
    differences = assert_upstream_only(generated['envoy'], generated['envoy-limit-4'])
    (configs / 'ferrum.yaml').write_text((HERE.parent / 'configs/http3_perf.yaml').read_text().replace('CA_PATH', '/certs/ca.pem'))
    shutil.copytree(configs, out / 'configs')
    if command('source', out / 'source').strip() != inventory['source']:
        raise ValueError('checkout/source mismatch')
    if command('tree', out / 'tree').strip() != inventory['tree'] or command('dirty', out / 'dirty').strip():
        raise ValueError('checkout tree/dirty mismatch')
    info = json.loads(command('docker-info', out / 'docker-info'))
    if info['CgroupDriver'] != 'systemd' or info['CgroupVersion'] != '2':
        raise RuntimeError('this finite lane requires hosted cgroup v2/systemd Docker')
    images = {}
    for arm, image in [('ferrum', 'ferrum-h3-live:qualified'), ('envoy', ENVOY)]:
        images[arm] = json.loads(command('image-inspect', out / f'image-{arm}', image=image))[0]
        if images[arm]['Architecture'] != 'amd64' or images[arm]['Os'] != 'linux':
            raise ValueError('non-native gateway image')
    if images['ferrum']['Config']['Labels']['org.opencontainers.image.revision'] != inventory['source']:
        raise ValueError('Ferrum image/source mismatch')
    if not any(d.endswith(ENVOY.split('@')[1]) for d in images['envoy']['RepoDigests']):
        raise ValueError('Envoy digest mismatch')
    command('buffers', out / 'buffers')
    time_offsets = Path('/proc/self/timens_offsets').read_text()
    offsets = {name: (int(sec), int(ns)) for name, sec, ns in
               (line.split() for line in time_offsets.splitlines())}
    if offsets.get('monotonic') != (0, 0) or offsets.get('boottime') != (0, 0):
        raise ValueError('observer requires unshifted host clocks')
    if not Path('/sys/kernel/tracing/events/syscalls/sys_enter_recvmsg/format').exists():
        command('tracefs', out / 'tracefs')
    provenance = dict(plan=plan, build=inventory, images=images, configs_difference=differences,
        staged_hashes={p.name: digest(p) for p in (STAGE / 'build').iterdir()},
        source_hashes={str(p.relative_to(ROOT)): digest(p) for p in HERE.iterdir() if p.is_file()},
        boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
        netns=os.stat('/proc/self/ns/net').st_ino, kernel=platform.uname()._asdict(),
        time_namespace=os.stat('/proc/self/ns/time').st_ino, time_namespace_offsets=time_offsets,
        btf_sha256=digest('/sys/kernel/btf/vmlinux'), kernel_notes_sha256=digest('/sys/kernel/notes'),
        runner={k: os.environ.get(k) for k in ('ImageOS', 'ImageVersion', 'GITHUB_SHA', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT')},
        cpu=Path('/proc/cpuinfo').read_text(), frontend_tls_verification='existing_harness_insecure_policy',
        upstream_tls_policy=dict(connect_address='127.0.0.1:3445', sni='localhost',
                                 verification_name='localhost', verify_chain=True,
                                 envoy_san_type='DNS', behavioral_fixture='h3-fairness-v1'),
        argv_environment='fixed_live_commands_inventory', stack_sampling='not_collected')
    write(out / 'provenance.json', provenance)
    shutil.copyfile('/sys/kernel/notes', out / 'kernel-notes')
    for name in ('recvmsg', 'recvmmsg'):
        for phase in ('enter', 'exit'):
            path = Path(f'/sys/kernel/tracing/events/syscalls/sys_{phase}_{name}/format')
            if path.exists(): shutil.copyfile(path, out / f'{phase}-{name}-format.txt')
    command('tools', out / 'packages')
    return plan, provenance


def sample(out, arm, payload, pair, position, traced, duration, provenance, idle_fixture=False):
    out.mkdir()
    record = dict(status='error', reason='sample_not_completed', arm=arm, payload=payload,
                  pair=pair, order_position=position, traced=traced, start_ns=time.monotonic_ns(),
                  traffic_issues=['sample_not_completed'], proof_completeness='unavailable')
    write(out / 'sample.json', record)
    identity = f'h3live{os.getpid()}{int(time.monotonic_ns())}'
    scope = Path('/sys/fs/cgroup') / (identity + '.slice')
    scope.mkdir(); (scope / 'backend').mkdir(); (scope / 'client').mkdir()
    netns_handle = os.open('/proc/self/ns/net', os.O_RDONLY)
    namespace_lifetime = dict(inode=os.fstat(netns_handle).st_ino, opened_ns=time.monotonic_ns(), closed_ns=None)
    observers, children, files = [], [], []
    monitor = Passive(scope, arm)
    created = False
    usage, distribution, raw = {}, [], {}
    try:
        if traced:
            for family in FAMILIES:
                observers.append(Observer(family, scope, out))
        record['observer_ready_ns'] = time.monotonic_ns()
        write(out / 'sample.json', record)
        # No workload exists before every observer has delivered readiness/outcome.
        backend_log = (out / 'backend.log').open('wb'); files.append(backend_log)
        backend = launch('backend', backend_log, backend_log, cgroup=scope / 'backend')
        children.append(backend)
        deadline = time.monotonic() + 20
        while True:
            if backend.poll() is not None: raise RuntimeError('owned backend exited before readiness')
            try:
                with urllib.request.urlopen('http://127.0.0.1:3010/health', timeout=0.2) as response:
                    if response.status == 200 and (STAGE / 'runtime/certs/ca.pem').exists(): break
            except OSError: pass
            if time.monotonic() > deadline: raise RuntimeError('backend readiness timeout')
            time.sleep(0.05)
        # Ownership, not a foreign health responder, determines readiness.
        backend_owner = owner(backend.pid, 'backend')
        owns_health = any(sk['local_address'] == '127.0.0.1' and sk['local_port'] == 3445
                          and any(o['pid'] == backend.pid and o['start_ticks'] == backend_owner['start_ticks'] for o in sk['owners'])
                          for row in monitor.timeline for sk in row.get('transport', {}).get('sockets', []))
        if not owns_health:
            time.sleep(0.6)
            owns_health = any(sk['local_address'] == '127.0.0.1' and sk['local_port'] == 3445
                             and any(o['pid'] == backend.pid and o['start_ticks'] == backend_owner['start_ticks'] for o in sk['owners'])
                             for row in monitor.timeline for sk in row.get('transport', {}).get('sockets', []))
        if not owns_health: raise RuntimeError('backend does not own the configured H3 endpoint')
        record['backend_owner'] = backend_owner
        record['ca_sha256'] = digest(STAGE / 'runtime/certs/ca.pem')
        if arm != 'direct':
            # Own this unique name even if create succeeds but metadata fails.
            created = True
            command('create', out / 'create', slice=scope.name, name=identity, arm=arm, cpus=os.cpu_count())
            initial = json.loads(command('inspect', out / 'container-created', name=identity))[0]
            expected = provenance['images']['ferrum' if arm == 'ferrum' else 'envoy']['Id']
            if initial['Image'] != expected: raise ValueError('container image differs from qualified artifact')
            if arm.startswith('envoy') and not (STAGE / 'envoy-binary').exists():
                command('envoy-binary', out / 'envoy-binary-copy', name=identity)
                write(out / 'envoy-binary.json', dict(sha256=digest(STAGE / 'envoy-binary')))
                command('envoy-build-id', out / 'envoy-build-id')
            command('start', out / 'start', name=identity)
            # Readiness is tied to this container/process, then useful H3 work is the smoke.
            time.sleep(3)
            current = json.loads(command('inspect', out / 'container-running', name=identity))[0]
            if not current['State']['Running']: raise RuntimeError('owned gateway exited')
            record['container_id'] = current['Id']
            record['gateway_owner'] = owner(current['State']['Pid'], 'gateway')
        for obs in observers: obs.checkpoint()
        stdout = (out / 'benchmark.raw.json').open('wb'); stderr = (out / 'benchmark.stderr').open('wb')
        files.extend([stdout, stderr])
        client = launch('client', stdout, stderr, cgroup=scope / 'client', payload=payload,
                        workers=[200, 200, 200, 100, 50][PAYLOADS.index(payload)], duration=duration,
                        target='https://127.0.0.1:3445/echo' if arm == 'direct' else 'https://127.0.0.1:8443/echo')
        children.append(client)
        deadline = time.monotonic() + 210
        resource_checkpoint = 0
        while client.poll() is None:
            if time.monotonic() >= deadline:
                record['client_timeout'] = True; client.kill(); break
            if backend.poll() is not None: raise RuntimeError('backend died during useful work')
            if time.monotonic() - resource_checkpoint >= 1:
                rss = sum(obs.sample_cpu() for obs in observers)
                record['observer_peak_combined_rss_bytes'] = max(record.get('observer_peak_combined_rss_bytes', 0), rss)
                # Half the 64 MiB cap reserves bounded kernel maps/rings; RSS is
                # measured separately. Actual allocator overhead remains recorded uncertainty.
                if rss > 32 * 1024 * 1024: raise RuntimeError('observer_RSS_reservation_exceeded')
                resource_checkpoint = time.monotonic()
            time.sleep(0.2)
        record['client_returncode'] = client.wait(timeout=5)
        if idle_fixture:
            # Dedicated diagnostic only: keep unchanged gateways/backend alive
            # beyond the natural ~30 s upstream idle timeout after actual work.
            record['idle_hold_start_ns'] = time.monotonic_ns()
            record['idle_hold_start_unix_secs'] = time.time()
            hold_end = time.monotonic() + 40
            while time.monotonic() < hold_end:
                if backend.poll() is not None:
                    raise RuntimeError('backend died during idle fixture')
                if sum(obs.sample_cpu() for obs in observers) > 32 * 1024 * 1024:
                    raise RuntimeError('observer_RSS_reservation_exceeded')
                time.sleep(0.5)
            record['idle_hold_end_ns'] = time.monotonic_ns()
            record['idle_hold_end_unix_secs'] = time.time()
            if arm != 'direct':
                current = json.loads(command('inspect', out / 'container-after-idle', name=identity))[0]
                if not current['State']['Running']:
                    raise RuntimeError('gateway died during idle fixture')
        stdout.flush(); stderr.flush()
        for obs in observers: obs.checkpoint()
        if arm.startswith('envoy'):
            for endpoint in ('stats?format=json', 'runtime?format=json', 'config_dump'):
                with urllib.request.urlopen('http://127.0.0.1:15000/' + endpoint, timeout=5) as response:
                    (out / (endpoint.split('?')[0] + '.raw.json')).write_bytes(response.read(8 * 1024 * 1024))
        raw = json.loads((out / 'benchmark.raw.json').read_text())
        if not isinstance(raw, dict) or not isinstance(raw.get('phases'), dict):
            raw = {}
            raise ValueError('malformed_benchmark_document')
        record['status'] = 'captured'
        record.pop('reason', None)
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, subprocess.TimeoutExpired) as error:
        record.update(status='error', reason=str(error))
    finally:
        record['workload_teardown_ns'] = time.monotonic_ns()
        record['workload_teardown_unix_secs'] = time.time()
        for child in reversed(children):
            try:
                if stop_process(child): record['forced_workload_stop'] = True
            except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
                record.setdefault('cleanup_errors', []).append(str(error))
        if created:
            for action in ('logs', 'stop', 'inspect', 'remove'):
                try: command(action, out / f'final-{action}', name=identity)
                except (OSError, ValueError, TypeError, RuntimeError, subprocess.TimeoutExpired) as error:
                    record.setdefault('cleanup_errors', []).append(str(error))
        # Keep tracing through workload teardown; final map reads follow detach.
        time.sleep(0.2)
        observer_results = [obs.finish() for obs in observers]
        usage = monitor.finish()
        for file in files: file.close()
        os.close(netns_handle)
        namespace_lifetime['closed_ns'] = time.monotonic_ns()
        record['namespace_handle_lifetime'] = namespace_lifetime
        try:
            for path in sorted(scope.rglob('*'), key=lambda p: len(p.parts), reverse=True):
                if path.is_dir(): path.rmdir()
            scope.rmdir()
        except FileNotFoundError: pass
        except OSError as error: record.setdefault('cleanup_errors', []).append(str(error))
        write(out / 'process-transport.raw.json', usage)
        write(out / 'observers.json', observer_results)
        try:
            distribution = backend_distribution(out / 'backend.log', raw.get('phases') or {})
            write(out / 'backend-connections.json', distribution)
        except (OSError, ValueError, KeyError, TypeError) as error: record['backend_distribution_error'] = str(error)
        derived = dict(raw, gateway=arm, payload_size=payload, effective_concurrency=[200, 200, 200, 100, 50][PAYLOADS.index(payload)],
                       sample_schema=2, pair=pair, order_position=position, host_id=provenance['boot_id'])
        usage['measurement'] = live_measurement_usage(usage, raw.get('phases') or {})
        derived['process_usage'] = {k: v for k, v in usage.items() if k != 'timeline'}
        context = dict(invocation=scope.name, boot_id=provenance['boot_id'], netns=provenance['netns'],
                       namespace_lifetime=namespace_lifetime,
                       observers=[dict(result, events=[r for r in obs.rows if r.get('phase') == 'lifecycle'])
                                  for obs, result in zip(observers, observer_results)])
        budgets = passive_roles(usage, distribution, arm, raw.get('phases') or {}, context)
        derived['transport_diagnostics'] = budgets
        derived['envoy_counter_provenance'] = envoy_counter_provenance(ENVOY if arm.startswith('envoy') else None)
        issues = sample_issues(derived)
        if record.get('client_returncode') != 0: issues.append('client_exit_or_timeout')
        if not budgets['equal_socket_budget_verified']:
            issues.append('socket_budget_incomplete')
        issues.extend('socket_evidence:' + reason for reason in budgets['socket_evidence_issues'])
        if raw.get('phases', {}).get('transport_close_timed_out'): issues.append('endpoint_drain_incomplete')
        for o in usage['owners']:
            privilege = dict(line.split(':', 1) for line in o['privileges'])
            # Last observed exec state must be the declared ordinary workload.
            if o['role'] in ('backend', 'client', 'gateway'):
                if any(int(v) != 65534 for v in privilege.get('Uid', '').split()) or not privilege.get('Uid'):
                    issues.append('workload_uid_mismatch')
                if any(int(v.strip(), 16) for k, v in privilege.items() if k.startswith('Cap')):
                    issues.append('workload_capability_mismatch')
                if privilege.get('NoNewPrivs', '').strip() != '1': issues.append('workload_no_new_privileges_missing')
        if arm.startswith('envoy'):
            try:
                stats = json.loads((out / 'stats.raw.json').read_text())
                record['envoy_protocol_contract'] = envoy_protocol_evidence(stats)
            except (OSError, ValueError, KeyError, TypeError) as error:
                record['envoy_protocol_error'] = str(error)
                issues.append('envoy_protocol_retry_timeout_contract_incomplete')
        phases = raw.get('phases') or {}
        window = measurement_window(phases, usage['timeline'])
        record['measurement_clock'] = window
        issues.extend(provenance_issues(usage, window, provenance['time_namespace']))
        if record.get('backend_distribution_error'): issues.append('backend_distribution_incomplete')
        if record.get('cleanup_errors'): issues.append('cleanup_failed')
        evidence = proof(observers, usage, distribution, raw, provenance, namespace_lifetime, arm) if traced else dict(completeness='not_traced', positive=[])
        record['proof_completeness'] = evidence['completeness']
        write(out / 'proof.json', evidence)
        if duration == 2 and traced:
            record['smoke_issues'] = smoke_issues(evidence, observer_results, arm)
        record['observer_errors'] = observer_issues(observer_results) if traced else []
        record['end_ns'] = time.monotonic_ns()
        record['artifact_bytes_before_final_metadata'] = sum(p.stat().st_size for p in out.rglob('*') if p.is_file())
        issues = sample_admission_issues(record, issues)
        record['traffic_issues'] = issues
        derived['traffic_issues'] = record['traffic_issues']
        # All validity checks precede calibration/paired-summary admission.
        if issues: derived['error'] = '; '.join(record['traffic_issues'])
        record['useful_traffic_valid'] = not issues
        write(out / 'derived.json', derived)
        write(out / 'sample.json', record)
        # Include both final metadata files in the cap. Failure metadata is
        # retained even when the cap is exceeded; no raw artifact is discarded.
        artifact_bytes = sum(p.stat().st_size for p in out.rglob('*') if p.is_file())
        if artifact_bytes > 64 * 1024 * 1024:
            record.update(status='error', reason='artifact_cap_exceeded', artifact_cap_exceeded=True,
                          artifact_bytes=artifact_bytes, useful_traffic_valid=False)
            issues = sample_admission_issues(record, issues)
            record['traffic_issues'] = issues
            derived.update(traffic_issues=issues, error='; '.join(issues))
            write(out / 'derived.json', derived)
            write(out / 'sample.json', record)
    return dict(derived, sample_record=record, observer_ok=not issues
                and all(any(r['family'] == f and (r['ready'] or {}).get('status') == 'supported'
                            for r in observer_results) for f in ('tx', 'rx')))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--campaign', choices=['corrected-v1'], required=True)
    parser.add_argument('--payload', choices=['smoke'] + list(map(str, PAYLOADS)), required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if (os.geteuid() != 0 or os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'
            or platform.system() != 'Linux' or platform.machine() != 'x86_64'):
        parser.error('only privileged provisioner on Linux amd64 GitHub-hosted runners may launch this lane')
    out = args.output.resolve(); out.mkdir(parents=True, exist_ok=True)
    write(out / 'summary.json', dict(status='error', reason='campaign_not_completed', issue_5588_closed=False))
    plan, provenance = prepare(out)
    payload = 10240 if args.payload == 'smoke' else int(args.payload)
    results, pilots = [], {}
    if args.payload == 'smoke':
        for i, arm in enumerate(ARMS, 1):
            results.append(sample(out / arm, arm, payload, 1, i, True, 2, provenance))
    else:
        for arm in ARMS:
            pairs = []
            for pair in (1, 2):
                observed = {}
                for traced in ((False, True) if pair == 1 else (True, False)):
                    observed[traced] = sample(out / f'pilot-{arm}-{pair}-{int(traced)}', arm, payload,
                                             pair, int(traced), traced, 30, provenance)
                    results.append(observed[traced])
                pairs.append((observed[False], observed[True]))
            pilots[arm] = calibration(pairs)
        write(out / 'calibration.json', pilots)
        active = all(row['active_main'] for row in pilots.values())
        mains = {arm: [] for arm in ARMS}
        for pair in range(1, 5):
            for position, arm in enumerate(gateway_order(ARMS, pair), 1):
                row = sample(out / f'main-{pair}-{arm}', arm, payload, pair, position, active, 30, provenance)
                mains[arm].append(row); results.append(row)
            if not active:
                for position, arm in enumerate(gateway_order(ARMS, pair), 1):
                    results.append(sample(out / f'diagnostic-{pair}-{arm}', arm, payload, pair, position, True, 30, provenance))
        comparisons = {arm: paired_comparison(mains['direct'], mains[arm], 4) for arm in ARMS[1:]}
        write(out / 'comparisons.json', dict(comparisons=comparisons, active_observer=active,
              proof_scope='main_samples' if active else 'diagnostic_repeats_only', overhead_subtracted=False))
    errors = [r['sample_record'] for r in results if r['sample_record'].get('observer_errors')
              or r['sample_record'].get('status') == 'error']
    invalid = [r['sample_record'] for r in results if r['traffic_issues']]
    write(out / 'summary.json', dict(status='error' if errors or invalid else 'captured_partial_proof',
          samples=len(results), errors=errors, invalid=invalid, issue_5588_closed=False,
          no_performance_claim=True, calibration=pilots))
    return int(bool(errors or invalid))


if __name__ == '__main__':
    raise SystemExit(main())
