"""Finite hosted behavioral fixtures; never a campaign or performance result."""
import argparse
import copy
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import time
import urllib.request

import live
from live_contract import ipv4, natural
from socket_coverage import event_owner_matches

NEGATIVES = dict(untraced='missing_final_drop', missing_capture='missing_capture', wrong_buffer='wrong_buffer',
                 cookie_reuse='cookie_or_owner_reuse', namespace_change='boot_or_namespace_changed',
                 missing_initial_boundary='missing_initial_boundary', missing_final_drop='missing_final_drop',
                 missing_role='missing_role:client', foreign_invocation='retirement_capture_incomplete')


def log_rows(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.startswith('{')]


def wait_event(path, event, child, identity=None):
    end = time.monotonic() + 15
    while time.monotonic() < end:
        if child.poll() is not None:
            raise RuntimeError('owned TLS backend exited')
        rows = log_rows(path)
        if any(r.get('event') == event and (identity is None or r.get('identity') == identity) for r in rows):
            return
        time.sleep(0.05)
    raise RuntimeError('TLS backend readiness/transition missing')


def tls_fixture(out, arm, provenance):
    out.mkdir()
    record = dict(arm=arm, status='error',
                  cases=[dict(identity=i, status='not_run', accepted=False) for i in ('valid', 'wrong')],
                  issue_5588_closed=False)
    live.write(out / 'result.json', record)
    name = f'h3live{os.getpid()}{time.monotonic_ns()}'
    scope = Path('/sys/fs/cgroup') / (name + '.slice')
    scope.mkdir(); (scope / 'backend').mkdir(); (scope / 'client').mkdir()
    child, created, log = None, False, None
    try:
        live.command('tls-fixture', out / 'certificates', mode='certificates', cgroup=scope / 'backend')
        # Retain only public material. Both leaves come from this one CA and both
        # include the connect IP; the wrong one has no localhost DNS SAN.
        for filename in ('ca.pem', 'valid.pem', 'wrong.pem'):
            shutil.copyfile(live.STAGE / 'runtime/certs' / filename, out / filename)
        record['certificates'] = {f: live.digest(out / f) for f in ('ca.pem', 'valid.pem', 'wrong.pem')}
        log = (out / 'backend.jsonl').open('wb')
        child = live.launch('tls-fixture', log, log, stdin=subprocess.PIPE, mode='backend', cgroup=scope / 'backend')
        wait_event(out / 'backend.jsonl', 'ready', child)
        record['backend_owner'] = live.owner(child.pid, 'backend')
        # Cleanup owns the unique container name even if recording create fails.
        created = True
        live.command('create', out / 'create', slice=scope.name, name=name, arm=arm, cpus=os.cpu_count())
        current = json.loads(live.command('inspect', out / 'created', name=name))[0]
        if current['Image'] != provenance['images']['ferrum' if arm == 'ferrum' else 'envoy']['Id']:
            raise ValueError('TLS fixture image mismatch')
        live.command('start', out / 'start', name=name)
        time.sleep(3)
        current = json.loads(live.command('inspect', out / 'running', name=name))[0]
        if not current['State']['Running']:
            raise RuntimeError('owned TLS gateway exited')
        record['gateway_owner'] = live.owner(current['State']['Pid'], 'gateway')
        for index, identity in enumerate(('valid', 'wrong')):
            if index:
                child.stdin.write((identity + '\n').encode()); child.stdin.flush()
                wait_event(out / 'backend.jsonl', 'identity', child, identity)
                # Allow the explicit fixture connection-close to reach the pool;
                # there is still exactly one offered request and no retry.
                time.sleep(0.5)
            before = len(log_rows(out / 'backend.jsonl'))
            response = json.loads(live.command('tls-fixture', out / f'request-{index}-{identity}',
                                               mode='request', cgroup=scope / 'client'))
            time.sleep(0.2)
            events = log_rows(out / 'backend.jsonl')[before:]
            case = dict(identity=identity, status='captured', response=response, backend_events=events, accepted=False)
            record['cases'][index] = case
            if (response.get('protocol') != 'h3' or response.get('offered_requests') != 1
                    or response.get('offered_bytes') != 10240 or response.get('retries') != 0):
                raise ValueError('TLS fixture offered-work contract')
            if any(e.get('event') == 'tcp_fallback' for e in events):
                raise ValueError('TLS fixture attempted H1/H2 fallback')
            if identity == 'valid':
                case['accepted'] = (response.get('status') == 200 and response.get('exact_body') is True
                                    and response.get('bytes') == 10240
                                    and sum(e.get('event') == 'echo' and e.get('bytes') == 10240 for e in events) == 1)
            else:
                # Error status alone is insufficient: require an actual failed
                # H3 handshake with the wrong leaf and no delivered backend work.
                case['accepted'] = (response.get('status') in (502, 503) and response.get('exact_body') is False
                                    and any(e.get('event') == 'handshake_rejected' and e.get('identity') == 'wrong'
                                            and e.get('crypto_close') is True for e in events)
                                    and not any(e.get('event') == 'echo' for e in events))
            if identity == 'valid':
                handshakes = [e for e in log_rows(out / 'backend.jsonl') if e.get('event') == 'handshake']
                case['observed_sni'] = [e.get('sni') for e in handshakes]
                case['accepted'] = case['accepted'] and bool(handshakes) and all(e.get('sni') == 'localhost' for e in handshakes)
            if not case['accepted']:
                raise ValueError('TLS behavioral case failed: ' + identity)
        if arm.startswith('envoy'):
            with urllib.request.urlopen('http://127.0.0.1:15000/stats?format=json', timeout=5) as response:
                data = response.read(8 * 1024 * 1024)
            (out / 'stats.raw.json').write_bytes(data)
            record['envoy_protocol_contract'] = live.envoy_protocol_evidence(json.loads(data))
        record['status'] = 'passed'
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, subprocess.TimeoutExpired) as error:
        record['error'] = str(error)
    finally:
        if child is not None:
            try:
                if live.stop_process(child, timeout=5):
                    record['forced_workload_stop'] = True; record['status'] = 'error'
            except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
                record.setdefault('cleanup_errors', []).append(str(error)); record['status'] = 'error'
        if log:
            try: log.close()
            except OSError as error:
                record.setdefault('cleanup_errors', []).append(str(error)); record['status'] = 'error'
        if created:
            for action in ('logs', 'stop', 'inspect', 'remove'):
                try: live.command(action, out / ('final-' + action), name=name)
                except (OSError, ValueError, TypeError, RuntimeError, subprocess.TimeoutExpired) as error:
                    record.setdefault('cleanup_errors', []).append(str(error)); record['status'] = 'error'
        try:
            for path in sorted(scope.rglob('*'), key=lambda p: len(p.parts), reverse=True):
                if path.is_dir(): path.rmdir()
            scope.rmdir()
        except OSError as error:
            record.setdefault('cleanup_errors', []).append(str(error)); record['status'] = 'error'
        live.write(out / 'result.json', record)
    return record


def inputs(out, result, provenance):
    usage = json.loads((out / 'process-transport.raw.json').read_text())
    record = result['sample_record']
    streams = json.loads((out / 'observers.json').read_text())
    for stream in streams:
        stream['events'] = [r for r in log_rows(out / (stream['family'] + '.jsonl')) if r.get('phase') == 'lifecycle']
    context = dict(invocation=streams[0]['invocation'], boot_id=provenance['boot_id'], netns=provenance['netns'],
                   namespace_lifetime=record['namespace_handle_lifetime'], observers=streams)
    distribution = json.loads((out / 'backend-connections.json').read_text())
    return usage, distribution, context


def retirement_evidence(out, result):
    """Join real final backend work/close and actual kernel socket destruction."""
    backend = {}
    for line in (out / 'backend.log').read_text().splitlines():
        if line.startswith('H3_PROFILE '):
            row = json.loads(line.removeprefix('H3_PROFILE '))
            backend.setdefault(row['connection_id'], []).append(row)
    record = result['sample_record']
    events = [r for r in log_rows(out / 'destroy.jsonl') if r.get('kind') == 20
              and r['at_ns'] < record['workload_teardown_ns']]
    roles = {r['cookie'] for r in json.loads((out / 'proof.json').read_text())['roles'] if r['role'] == 'gateway_upstream'}
    usage = json.loads((out / 'process-transport.raw.json').read_text())
    sockets = []
    births = [r for r in log_rows(out / 'lifetime.jsonl') if r.get('kind') == 18]
    for event in events:
        if event['cookie'] not in roles:
            continue
        observed = [sk for row in usage['timeline'] for sk in row.get('transport', {}).get('sockets', [])
                    if (sk['cookie'][0] | sk['cookie'][1] << 32) == event['cookie']]
        birth = [r for r in births if r['cookie'] == event['cookie']]
        if (not observed or len(birth) != 1 or not birth[0]['at_ns'] < event['at_ns']
                or not event_owner_matches(birth[0], observed[0])
                or not all(event_owner_matches(event, sk) and sk['local_port'] == event['local_port'] for sk in observed)
                or not natural(event.get('drops')) or event.get('so_rcvbuf') != 4194304
                or event.get('so_sndbuf') != 4194304):
            raise ValueError('idle retirement identity/final counter incomplete')
        sockets.append(event)
    joined, claimed = [], set()
    for rows in backend.values():
        final = rows[-1]
        if not final.get('close_reason') or final['unix_secs'] >= record['workload_teardown_unix_secs']:
            continue
        if final['accepted'] != final['completed'] or final['bytes'] != final['completed'] * 10240:
            raise ValueError('idle retirement concealed incomplete backend work')
        address, port = final['peer'].rsplit(':', 1)
        matches = []
        for event in sockets:
            if (ipv4(event['local_ipv4']), event['local_port']) != (address, int(port)):
                continue
            anchor = min(usage['timeline'], key=lambda r: abs(r['clock']['before_ns'] - event['at_ns']))['clock']
            lo = (anchor['unix_ns'] + event['at_ns'] - anchor['after_ns']) / 1e9
            hi = (anchor['unix_ns'] + event['at_ns'] - anchor['before_ns']) / 1e9
            # Backend close polling is 500 ms. Retain a conservative 1 s
            # correlation allowance, never invent an exact close timestamp.
            if lo <= final['unix_secs'] + 1 and hi >= final['unix_secs'] - 1:
                matches.append(dict(event, unix_bounds_secs=[lo, hi]))
        if len(matches) > 1 or any(e['cookie'] in claimed for e in matches):
            raise ValueError('ambiguous reused endpoint in backend/socket retirement join')
        claimed.update(e['cookie'] for e in matches)
        joined.append(dict(connection_id=final['connection_id'], final=final,
                           work='used' if final['completed'] else 'unused',
                           kernel_retirements=matches))
    live.write(out / 'idle-retirements.json', dict(connections=joined, socket_retirements=sockets,
               scope='before_workload_teardown;_actual_backend_counters_and_kernel_events'))
    return joined


def negative_matrix(usage, distribution, context, result):
    """Fault injection into copies of this fixture's real evidence, never raw files."""
    target = next((r for r in result['transport_diagnostics']['sockets']
                   if r['role'] == 'gateway_upstream'
                   and r['lifetime_status'] == 'witnessed_retirement_with_final_drop'), None)
    if target is None:
        return [dict(case=case, passed=False, expected=reason, reason='no_admitted_measurement_retirement')
                for case, reason in NEGATIVES.items()] + [dict(case='premature_worker_retirement', passed=False,
                                                             reason='no_admitted_measurement_retirement')]
    cookie = target['cookie']
    def matches(sk): return (sk['cookie'][0] | sk['cookie'][1] << 32) == cookie
    matrix = []
    for case, expected in NEGATIVES.items():
        u, c = copy.deepcopy(usage), copy.deepcopy(context)
        values = [(i, sk) for i, row in enumerate(u['timeline']) for sk in row['transport'].get('sockets', []) if matches(sk)]
        if case == 'untraced': c['observers'] = []
        elif case == 'missing_capture':
            i = values[len(values) // 2][0]
            u['timeline'][i]['transport']['sockets'] = [sk for sk in u['timeline'][i]['transport']['sockets'] if not matches(sk)]
        elif case == 'wrong_buffer': values[len(values) // 2][1]['so_rcvbuf'] = 1024
        elif case == 'cookie_reuse': values[len(values) // 2][1]['inode'] += 1
        elif case == 'namespace_change': u['timeline'][values[len(values) // 2][0]]['netns'] += 1
        elif case == 'missing_initial_boundary':
            left = target['capture_bracket']['left_sample_index']
            for row in u['timeline'][:left + 1]:
                row['transport']['sockets'] = [sk for sk in row['transport'].get('sockets', []) if not matches(sk)]
        elif case == 'missing_final_drop':
            for stream in c['observers']:
                for event in stream['events']:
                    if event.get('cookie') == cookie and event.get('kind') == 20: event['drops'] = None
        elif case == 'missing_role':
            for row in u['timeline']:
                row['transport']['sockets'] = [sk for sk in row['transport'].get('sockets', [])
                                               if not any(o['role'] == 'client' for o in sk['owners'])]
        elif case == 'foreign_invocation':
            for stream in c['observers']: stream['invocation'] = 'diagnostic-repeat-not-this-invocation'
        assessed = live.passive_roles(u, distribution, result['gateway'], result['phases'], c)
        issues = assessed['socket_evidence_issues']
        matrix.append(dict(case=case, expected=expected, issues=issues,
                           passed=not assessed['equal_socket_budget_verified'] and expected in issues))
    worker = copy.deepcopy(result)
    worker['observed']['workers_retired_before_deadline'] = 1
    issues = live.sample_issues(worker)
    matrix.append(dict(case='premature_worker_retirement', issues=issues,
                       passed='missing observations or retired workers' in issues))
    return matrix


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if (os.geteuid() != 0 or os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'
            or platform.system() != 'Linux' or platform.machine() != 'x86_64'):
        parser.error('hosted Linux amd64 provisioner only')
    out = args.output.resolve(); out.mkdir(parents=True, exist_ok=True)
    arms = ('ferrum', 'envoy', 'envoy-limit-4')
    summary = dict(status='error', suite='h3-fairness-v1',
                   tls=[dict(arm=arm, status='not_run') for arm in arms],
                   idle=[dict(arm=arm, status='not_run') for arm in arms],
                   issue_5588_closed=False, no_performance_claim=True)
    live.write(out / 'summary.json', summary)
    _, provenance = live.prepare(out)
    for index, arm in enumerate(arms):
        summary['tls'][index] = tls_fixture(out / ('tls-' + arm), arm, provenance)
        live.write(out / 'summary.json', summary)
    # Exactly three long samples, never retries until a desired result appears.
    for index, arm in enumerate(arms):
        directory = out / ('idle-' + arm)
        result = live.sample(directory, arm, 10240, 1, 1, True, 40, provenance, idle_fixture=True)
        row = dict(arm=arm, status='error', traffic_issues=result['traffic_issues'])
        summary['idle'][index] = row
        matrix = [dict(case=case, expected=reason, passed=False, reason='source_capture_unavailable')
                  for case, reason in NEGATIVES.items()]
        matrix.append(dict(case='premature_worker_retirement', passed=False, reason='source_capture_unavailable'))
        if arm == 'envoy-limit-4':
            live.write(directory / 'negative-matrix.json', matrix)
        try:
            if arm == 'envoy-limit-4':
                matrix = negative_matrix(*inputs(directory, result, provenance), result)
                live.write(directory / 'negative-matrix.json', matrix)
            retired = retirement_evidence(directory, result)
            row['used_connections_closed'] = sum(r['work'] == 'used' for r in retired)
            row['unused_connections_closed'] = sum(r['work'] == 'unused' for r in retired)
            row['used_sockets_retired'] = sum(r['work'] == 'used' and bool(r['kernel_retirements']) for r in retired)
            row['unused_sockets_retired'] = sum(r['work'] == 'unused' and bool(r['kernel_retirements']) for r in retired)
            if result['traffic_issues']:
                raise ValueError('long sample admission failed')
            if arm == 'envoy-limit-4':
                if not row['used_sockets_retired'] or not row['unused_sockets_retired']:
                    raise ValueError('actual used and unused idle socket retirements not reproduced')
                if any(len(r['kernel_retirements']) != 1 for r in retired):
                    raise ValueError('Envoy backend close lacks unique socket retirement')
                if not all(r['passed'] for r in matrix): raise ValueError('negative evidence matrix failed')
                stats = json.loads((directory / 'stats.raw.json').read_text())['stats']
                counters = {s.get('name'): s.get('value') for s in stats if 'value' in s}
                row['idle_timeout_counters'] = {name: value for name, value in counters.items()
                                                if 'QUIC_NETWORK_IDLE_TIMEOUT' in name}
                row['upstream_local_destroy'] = counters.get('cluster.backend_h3.upstream_cx_destroy_local')
                if not any('QUIC_NETWORK_IDLE_TIMEOUT' in name and natural(value) and value > 0
                           for name, value in counters.items()):
                    raise ValueError('missing actual Envoy idle timeout counter')
                if not natural(row['upstream_local_destroy']) or row['upstream_local_destroy'] < len(retired):
                    raise ValueError('Envoy local-destroy counter does not cover backend closes')
            # Ferrum shares UDP endpoints: QUIC idle-close does not imply socket
            # destruction. Require real role teardown evidence, without inventing
            # a per-connection UDP socket or requiring an Envoy-shaped pool.
            evidence = json.loads((directory / 'proof.json').read_text())
            observers = json.loads((directory / 'observers.json').read_text())
            row['role_issues'] = live.smoke_issues(evidence, observers, arm)
            if row['role_issues']: raise ValueError('actual gateway lifecycle/operation evidence missing')
            row['status'] = 'passed'
        except (OSError, KeyError, TypeError, ValueError, StopIteration) as error:
            row['error'] = str(error)
        live.write(out / 'summary.json', summary)
    summary['status'] = 'passed' if all(r['status'] == 'passed' for r in summary['tls'] + summary['idle']) else 'error'
    live.write(out / 'summary.json', summary)
    return int(summary['status'] != 'passed')


if __name__ == '__main__':
    raise SystemExit(main())
