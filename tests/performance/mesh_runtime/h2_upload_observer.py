"""Bounded, cold-scrape upload observer; never used for ranking or live polling."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import subprocess
import time

PREFIX = 'ferrum_h2_upload_diagnostic_'
BRANCHES = ('post_eos_total', 'post_ready_ok_total', 'post_ready_err_total', 'post_pending_total')
TOTALS = (*BRANCHES, 'native_finalized_total', 'native_status200_total')
FIELDS = {'schema', 'pid', 'counter_overflow', 'native_state_present',
          'native_status200_present', 'native_active_requests', *TOTALS}
MAX_BODY = 4 * 1024**2
SETTLE_SECONDS, SETTLE_ATTEMPTS, INTERVAL = 6.5, 15, 0.5


def write(path, value):
    path.write_text(json.dumps(value, indent=2, allow_nan=False) + '\n')


def parse(body):
    values = {}
    if not isinstance(body, str) or len(body.encode()) > MAX_BODY:
        raise ValueError('invalid or oversized metric body')
    for line in body.splitlines():
        if line.startswith(PREFIX):
            match = re.fullmatch(PREFIX + r'([a-z0-9_]+) ([0-9]+)', line)
            if not match or match[1] not in FIELDS or match[1] in values:
                raise ValueError('malformed, duplicate or unexpected diagnostic field')
            number = int(match[2])
            if number > 2**64 - 1:
                raise ValueError('diagnostic integer exceeds u64')
            values[match[1]] = number
    if values.keys() != FIELDS:
        raise ValueError('missing diagnostic fields; absence is not zero')
    if (values['schema'] != 2 or values['pid'] <= 0 or values['counter_overflow'] != 0
            or values['native_state_present'] != 1 or values['native_status200_present'] != 1):
        raise ValueError('unsupported schema, overflow, or missing native state/status')
    return values


def read_identity(name, timeout):
    obj = json.loads(subprocess.check_output(['docker', 'inspect', name], timeout=timeout))[0]
    state = obj['State']
    pid = state['Pid']
    if state.get('Running') is not True or type(pid) is not int or pid <= 0:
        raise ValueError('proxy not running')
    stat = (Path('/proc') / str(pid) / 'stat').read_text().rsplit(')', 1)[1].split()
    status = (Path('/proc') / str(pid) / 'status').read_text()
    ns = [line.split()[1:] for line in status.splitlines() if line.startswith('NSpid:')]
    if len(ns) != 1 or not ns[0] or obj['RestartCount'] != 0:
        raise ValueError('missing namespace PID or restarted proxy')
    return dict(name=name, container_id=obj['Id'], image_id=obj['Image'], host_pid=pid,
                starttime=int(stat[19]), namespace_pid=int(ns[0][-1]),
                started_at=state['StartedAt'], restart_count=obj['RestartCount'])


def fetch(identity, port, timeout):
    # No environment proxies, credentials, config dump or filesystem requests.
    return subprocess.run(['nsenter', '-t', str(identity['host_pid']), '-n', 'curl',
        '--noproxy', '*', '--fail', '--silent', '--show-error', '--max-time', str(timeout),
        '--max-filesize', str(MAX_BODY), f'http://127.0.0.1:{port}/metrics'],
        capture_output=True, timeout=timeout)


def remaining(deadline, clock):
    left = deadline - clock()
    if left <= 0:
        raise ValueError('quiescence deadline exhausted')
    return min(0.5, left)


def capture(names, image, deadline, clock=time.monotonic):
    rows = []
    for role, (name, port) in enumerate(zip(names, (15120, 15020), strict=True)):
        row = dict(role=('source', 'destination')[role], performance_eligible=False)
        rows.append(row)
        try:
            before = read_identity(name, remaining(deadline, clock))
            row['identity_before'] = before
            done = fetch(before, port, remaining(deadline, clock))
            row.update(returncode=done.returncode, body=done.stdout[:MAX_BODY].decode(errors='replace'),
                       stderr=done.stderr[:4096].decode(errors='replace'),
                       body_sha256=hashlib.sha256(done.stdout).hexdigest())
            after = read_identity(name, remaining(deadline, clock))
            row['identity_after'] = after
            if done.returncode or len(done.stdout) > MAX_BODY:
                raise ValueError('metric scrape failed or exceeded size bound')
            if before != after or before['image_id'] != image:
                raise ValueError('proxy identity changed at scrape or wrong image')
            row['values'] = parse(row['body'])
            if row['values']['pid'] != before['namespace_pid']:
                raise ValueError('scrape namespace PID does not identify proxy process')
        except (OSError, ValueError, KeyError, IndexError, subprocess.SubprocessError) as error:
            row['error'] = str(error) if type(error) is ValueError else type(error).__name__
    if clock() > deadline:
        for row in rows:
            row["error"] = "boundary capture exceeded deadline"
    return rows


def snapshot_errors(rows):
    if len(rows) != 2 or any('error' in row for row in rows):
        return ['failed boundary capture']
    if len({row['identity_before']['container_id'] for row in rows}) != 2:
        return ['proxy roles share a container']
    if len({row['identity_before']['host_pid'] for row in rows}) != 2:
        return ['proxy roles share a process']
    return []


def same_state(left, right):
    return all(a['identity_before'] == b['identity_before'] and a['values'] == b['values']
               for a, b in zip(left, right, strict=True))


def settle(names, image, directory, *, clock=time.monotonic, wait=time.sleep, take=capture):
    directory.mkdir(exist_ok=False)
    started = clock()
    receipt = dict(performance_eligible=False, accepted=False, attempts=[], errors=[],
                   begin_monotonic=started, deadline_monotonic=started + SETTLE_SECONDS,
                   max_attempts=SETTLE_ATTEMPTS, interval_seconds=INTERVAL,
                   native_publication_cache_seconds=0, unrelated_registry_cache_seconds=5,
                   application_retries=0, cache_invalidation=False)
    previous = None
    try:
        for number in range(SETTLE_ATTEMPTS):
            rows = take(names, image, receipt['deadline_monotonic'], clock)
            path = directory / f'attempt-{number:02}.json'
            write(path, dict(performance_eligible=False, rows=rows, monotonic=clock()))
            receipt['attempts'].append(dict(path=path.name, sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
            if snapshot_errors(rows):
                raise ValueError('failed boundary capture; retained attempt is authoritative')
            if previous:
                for before, after in zip(previous, rows, strict=True):
                    if before['identity_before'] != after['identity_before']:
                        raise ValueError('proxy identity changed while settling')
                    if any(after['values'][key] < before['values'][key] for key in TOTALS):
                        raise ValueError('counter regressed while settling')
                if same_state(previous, rows) and all(row['values']['native_active_requests'] == 0 for row in rows):
                    remaining(receipt['deadline_monotonic'], clock)
                    receipt.update(accepted=True, selected=path.name, rows=rows)
                    break
            previous = rows
            left = receipt['deadline_monotonic'] - clock()
            if left <= 0 or number + 1 == SETTLE_ATTEMPTS:
                break
            wait(min(INTERVAL, left))
        if not receipt['accepted']:
            raise ValueError('quiescence deadline or attempt bound exhausted')
    except (OSError, ValueError, KeyError, IndexError, subprocess.SubprocessError) as error:
        receipt['errors'].append(str(error) if type(error) is ValueError else type(error).__name__)
    receipt['end_monotonic'] = clock()
    write(directory / 'receipt.json', receipt)
    return receipt


def qualify(before, after, load, payload, status):
    result = dict(performance_eligible=False, accepted=False, errors=[], source_deltas=None,
                  destination_deltas=None, population=None,
                  scope='instrumented baseline; whole warmup+measurement+drain; no RPS inference')
    try:
        if not before['accepted'] or not after['accepted'] or before['errors'] or after['errors']:
            raise ValueError('boundary did not qualify')
        keys = ('warmup_requests', 'cohort_requests', 'total_requests', 'drained_requests',
                'total_errors', 'warmup_errors', 'admitted_errors', 'total_bytes', 'drained_bytes')
        if any(type(load.get(key)) is not int or load[key] < 0 for key in keys):
            raise ValueError('missing or invalid native load accounting')
        population = load['warmup_requests'] + load['cohort_requests']
        result['population'] = population
        if (status != 0 or any(load[k] != 0 for k in ('total_errors', 'warmup_errors', 'admitted_errors'))
                or population <= 0 or load['cohort_requests'] != load['total_requests'] + load['drained_requests']
                or load['total_bytes'] != load['total_requests'] * payload
                or load['drained_bytes'] != load['drained_requests'] * payload):
            result['errors'].append('load failure or whole-epoch completion/byte accounting mismatch')
        for role, (left, right) in enumerate(zip(before['rows'], after['rows'], strict=True)):
            name = ('source', 'destination')[role]
            if left['identity_before'] != right['identity_before']:
                raise ValueError('proxy identity changed across whole epoch')
            a, b = left['values'], right['values']
            if any(b[key] < a[key] for key in TOTALS):
                raise ValueError('counter reset across whole epoch')
            delta = {key: b[key] - a[key] for key in TOTALS}
            result[name + '_deltas'] = delta
            if a['native_active_requests'] or b['native_active_requests']:
                result['errors'].append(name + ' has active requests at boundary')
            if delta['native_finalized_total'] != population or delta['native_status200_total'] != population:
                result['errors'].append(name + ' native finalized/200 counts do not conserve full echoes')
            expected = population if role == 0 else 0
            if sum(delta[key] for key in BRANCHES) != expected:
                result['errors'].append(name + ' H2 POST population does not conserve full echoes')
            if delta['post_ready_err_total'] or delta['post_eos_total']:
                result['errors'].append(name + ' unexpected eager error/EOS for nonempty successful POST')
        result['accepted'] = not result['errors']
        if result['accepted']:
            result['source_fractions'] = {key: result['source_deltas'][key] / population for key in BRANCHES}
    except (KeyError, ValueError, IndexError, TypeError) as error:
        result['errors'].append(str(error) if type(error) is ValueError else type(error).__name__)
    return result


class Epoch:
    def __init__(self, names, image, directory):
        self.names, self.image, self.directory = names, image, directory
        directory.mkdir(exist_ok=False)
        self.before = settle(names, image, directory / 'before')
        if not self.before['accepted']:
            write(directory / 'receipt.json', dict(performance_eligible=False, accepted=False,
                errors=['preflight did not settle outside epoch'], before=self.before))
            raise ValueError('upload diagnostic preflight boundary failed')

    def finish(self, path, payload, status):
        after = settle(self.names, self.image, self.directory / 'after')
        try:
            load = json.loads(path.read_text())
        except (OSError, ValueError):
            load = {}
        result = qualify(self.before, after, load, payload, status)
        result.update(before=self.before, after=after)
        write(self.directory / 'receipt.json', result)
        return result
