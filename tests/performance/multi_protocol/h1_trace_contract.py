"""Fixed H1 external evidence consumers. Unknown evidence never becomes zero."""
import collections
import hashlib
import os
import stat
import json
import math
import re
from pathlib import Path

SYSCALLS = {0: 'read', 1: 'write', 19: 'readv', 20: 'writev', 44: 'sendto',
            45: 'recvfrom', 46: 'sendmsg', 47: 'recvmsg', 299: 'recvmmsg', 307: 'sendmmsg'}
UNSUPPORTED = {17, 18, 40, 275, 276, 278, 295, 296, 327, 328, 425, 426, 427}
LOSSES = ('map_full', 'read_failed', 'unknown_cookie', 'nested', 'unmatched',
          'abandoned', 'ring_full', 'witness_cap', 'compat', 'generation', 'exec',
          'vector_bound', 'overflow', 'multi_socket', 'inner_unmatched', 'unsupported')
ROLES = {0: 'unknown', 1: 'frontend_send', 2: 'frontend_recv', 3: 'upstream_send',
         4: 'upstream_recv', 5: 'excluded_target_socket'}
COUNTERS = ('attempts', 'exits', 'positive', 'zero', 'errors', 'restarts', 'eof',
            'short_calls', 'offered', 'offered_known', 'accepted_bytes', 'accepted_known',
            'return_sum', 'effective_bytes', 'inner_calls', 'inner_bytes', 'inner_errors', 'elapsed_ns')
BOUNDS = dict(observer_rss_and_map_bytes=32 * 1024**2, map_reservation_bytes=8 * 1024**2,
              seconds=300, snapshots=64, raw_perf_bytes=64 * 1024**2,
              total_artifact_bytes=128 * 1024**2, aggregate_rows=8192, pending=512,
              vectors=16, witnesses=4096, lifecycle_rows=8192, metadata_snapshots=64,
              fd_rows_per_snapshot=2048, threads=512)
# Shared across repeat captures, separately from the raw trace-artifact bound.
# Production-profile binaries with line tables exceed 512 MiB. Keep both
# acquisition and evidence reads bounded while retaining its actual mapped ELF.
ELF_PACKAGE_BYTES = 1024 * 1024**2


def natural(value):
    return type(value) is int and 0 <= value <= 2**64 - 1


def clock_receipt_window(phases, receipts, *, boot_id, time_namespace):
    """Admit host clock receipts, without claiming any passive resource reads.

    Teardown and trace event placement need a common measurement clock. Resource
    deltas still require the separate H3 consumer's complete capture intervals.
    Keep the same 1 ms uncertainty / 1000 ppm slew and phase realtime checks.
    """
    invalid = dict(valid=False, reason='missing_or_invalid_clock_receipt')
    uncertainty = 1_000_000
    try:
        if (not isinstance(boot_id, str) or not boot_id or not natural(time_namespace)
                or not time_namespace or not 2 <= len(receipts) <= BOUNDS['metadata_snapshots']):
            return invalid
        start = phases['measurement_start_host_clock']
        lo, hi = start['before_ns'], start['after_ns']
        duration = phases['measurement_secs']
        if (start['clock'] != 'CLOCK_MONOTONIC' or not natural(lo) or not natural(hi)
                or not 0 < lo <= hi <= lo + uncertainty
                or type(duration) not in (int, float) or not math.isfinite(duration)
                or not 0 < duration <= BOUNDS['seconds']):
            return invalid
        span = math.ceil(duration * 1e9)
        for receipt in receipts:
            if (receipt['kind'] != 'clock_receipt' or receipt['clock'] != 'CLOCK_MONOTONIC'
                    or receipt['boot_id'] != boot_id or not natural(receipt['time_namespace'])
                    or receipt['time_namespace'] != time_namespace
                    or not all(natural(receipt[k]) for k in ('before_ns', 'after_ns', 'unix_ns'))
                    or not 0 < receipt['before_ns'] <= receipt['after_ns'] <= receipt['before_ns'] + uncertainty):
                return invalid
        for a, b in zip(receipts, receipts[1:]):
            if b['before_ns'] <= a['after_ns']:
                return dict(valid=False, reason='nonmonotonic_clock_receipt')
            slack = uncertainty + (b['after_ns'] - a['before_ns']) // 1000
            if (b['unix_ns'] - b['after_ns'] > a['unix_ns'] - a['before_ns'] + slack
                    or a['unix_ns'] - a['after_ns'] > b['unix_ns'] - b['before_ns'] + slack):
                return dict(valid=False, reason='realtime_clock_jump')
        before = [i for i, c in enumerate(receipts) if c['after_ns'] <= lo]
        after = [i for i, c in enumerate(receipts) if c['before_ns'] >= hi + span]
        if not before or not after:
            return dict(valid=False, reason='missing_clock_receipt_bracket')
        unix = phases['measurement_start_unix_secs']
        if type(unix) not in (int, float) or not math.isfinite(unix):
            return invalid
        anchor = receipts[before[-1]]
        slack = uncertainty + (hi - anchor['before_ns']) // 1000
        if not (lo + anchor['unix_ns'] - anchor['after_ns'] - slack <= unix * 1e9
                <= hi + anchor['unix_ns'] - anchor['before_ns'] + slack):
            return dict(valid=False, reason='phase_realtime_clock_mismatch')
        return dict(valid=True, basis='clock_receipts', clock='CLOCK_MONOTONIC',
                    boot_id=boot_id, time_namespace=time_namespace,
                    start_bounds_ns=[lo, hi], end_bounds_ns=[lo + span, hi + span],
                    uncertainty_ns=hi - lo, receipt_indices=[before[-1], after[0]],
                    realtime_check='1ms_read_uncertainty_plus_1000ppm_slew')
    except (KeyError, TypeError, ValueError, OverflowError):
        return invalid


def validate_record(row):
    if not isinstance(row, dict) or row.get('phase') not in (
            'ready', 'bound', 'h1_event', 'snapshot', 'checkpoint', 'final', 'termination'):
        raise ValueError('unknown H1 observer record')
    if row['phase'] in ('snapshot', 'checkpoint', 'final'):
        if len(row.get('losses', [])) != len(LOSSES) or not all(map(natural, row['losses'])):
            raise ValueError('loss schema')
        if not all(natural(row.get(k)) for k in ('before_ns', 'after_ns', 'pending', 'map_read_failures')):
            raise ValueError('snapshot metadata')
        if row['after_ns'] < row['before_ns'] or len(row['rows']) > BOUNDS['aggregate_rows']:
            raise ValueError('snapshot bounds')
        for item in row['rows'] + row['totals']:
            if not all(natural(item.get(k)) for k in COUNTERS) or item.get('id') not in SYSCALLS:
                raise ValueError('syscall counter schema')
            if row['phase'] == 'final' and item['exits'] != item['positive'] + item['zero'] + item['errors'] + item['restarts']:
                raise ValueError('return classification mismatch')
            if not all(type(item.get(k)) is int and -(2**63) <= item[k] < 2**63
                       for k in ('min_return', 'max_return')):
                raise ValueError('signed return schema')
        for item in row['rows']:
            if item.get('role') not in ROLES or not all(natural(item.get(k)) for k in
                    ('pid', 'process_ns', 'cgroup', 'cookie', 'netns')):
                raise ValueError('socket identity schema')
            if item['role'] in (1, 2, 3, 4) and not item['cookie']:
                raise ValueError('zero-cookie role join')
    return row


def syscall_coverage(rows, identity, boundaries):
    issues = []
    try:
        for row in rows:
            validate_record(row)
    except (ValueError, KeyError, TypeError) as error:
        return dict(available=False, complete=False, issues=['invalid producer: ' + str(error)])
    final = [r for r in rows if r['phase'] == 'final']
    ready = [r for r in rows if r['phase'] == 'ready']
    bound = [r for r in rows if r['phase'] == 'bound']
    terminal = [r for r in rows if r['phase'] == 'termination']
    if len(final) != 1 or len(ready) != 1 or ready[0].get('status') != 'supported':
        return dict(available=False, complete=False, issues=['missing supported ready/final'], ready=ready)
    final = final[0]
    losses = dict(zip(LOSSES, final['losses']))
    binding_valid = (len(bound) == 1 and all(
        natural(bound[0].get(k)) and bound[0][k] > 0 for k in ('pid', 'start_ticks', 'cgroup', 'netns', 'at_ns'))
        and all(bound[0][k] == v for k, v in dict(pid=identity.get('pid'),
            start_ticks=identity.get('start_ticks'), cgroup=identity.get('cgroup_id'),
            netns=identity.get('namespaces', {}).get('net')).items()))
    if not binding_valid:
        issues.append('process binding missing/mismatched')
    terminal_valid = (len(terminal) == 1 and terminal[0].get('requested_stop') is True
        and terminal[0].get('bound') is True and natural(terminal[0].get('at_ns'))
        and terminal[0]['at_ns'] >= final['after_ns']
        and all(type(terminal[0].get(k)) is int and terminal[0][k] == 0
                for k in ('lifecycle_omitted', 'checkpoints_omitted', 'snapshot_failures')))
    if not terminal_valid:
        issues.append('missing/invalid requested termination or omitted records')
    if final['pending'] or final['map_read_failures']:
        issues.append('pending calls or failed map reads')
    snapshots = [r for r in rows if r['phase'] in ('checkpoint', 'snapshot', 'final')]
    reset = False
    for a, b in zip(snapshots, snapshots[1:]):
        previous = {r['id']: r for r in a['totals']}
        current = {r['id']: r for r in b['totals']}
        if (any(i not in current or any(current[i][k] < v[k] for k in COUNTERS)
                for i, v in previous.items()) or any(y < x for x, y in zip(a['losses'], b['losses']))):
            reset = True
    if reset:
        issues.append('counter reset or inconsistent snapshot')
    total_loss = ('read_failed', 'map_full', 'nested', 'unmatched', 'abandoned', 'compat', 'generation', 'exec', 'overflow')
    observed_losses = {name: max(r['losses'][index] for r in snapshots) for index, name in enumerate(LOSSES)}
    issues.extend(name for name in total_loss if observed_losses[name])
    if not boundaries.get('measurement', {}).get('valid'):
        issues.append('missing measurement clock/coverage')
    attempted = {r['id']: r['attempts'] for r in final['totals']}
    if any(final['census'].get(str(call), 0) != attempted.get(call, 0) for call in SYSCALLS):
        issues.append('syscall census/attempt mismatch')
    for r in final['totals']:
        if r['attempts'] != r['exits']:
            issues.append('unpaired attempts/exits')
    phase_delta = dict(complete=False, reason='missing bracketing snapshots')
    window = boundaries.get('measurement', {})
    if window.get('valid') and 'start_bounds_ns' in window:
        before = [r for r in snapshots if r['after_ns'] <= window['start_bounds_ns'][0]]
        after = [r for r in snapshots if r['before_ns'] >= window['end_bounds_ns'][1]]
        if before and after and not reset:
            left, right = before[-1], after[0]
            prior = {r['id']: r for r in left['totals']}
            values = []
            for r in right['totals']:
                values.append(dict(id=r['id'], **{k: r[k] - prior.get(r['id'], {}).get(k, 0) for k in COUNTERS}))
            roles = {role: {k: v[k] - left.get('role_totals', {}).get(role, {}).get(k, 0) for k in COUNTERS}
                     for role, v in right.get('role_totals', {}).items()}
            phase_delta = dict(complete=True, totals=values, roles=roles,
                               left_read_ns=[left['before_ns'], left['after_ns']],
                               right_read_ns=[right['before_ns'], right['after_ns']],
                               boundary_uncertainty_ns=(window['start_bounds_ns'][1] - left['before_ns'] +
                                                        right['after_ns'] - window['end_bounds_ns'][0]),
                               crossing_calls='counts are exit-positioned; in-flight cross-boundary work cannot be split')
    foreign = [r for r in final['rows'] if r['pid'] != identity.get('pid') or
               r['process_ns'] // 10_000_000 != identity.get('start_ticks') or
               r['cgroup'] != identity.get('cgroup_id')]
    if foreign:
        issues.append('foreign process generation')
    socket_issues = [n for n in ('read_failed', 'unknown_cookie', 'vector_bound', 'multi_socket', 'inner_unmatched') if losses[n]]
    if any(r['role'] == 0 for r in final['rows']):
        socket_issues.append('unattributed process syscalls (includes non-socket descriptors)')
    unsupported = {k: v for k, v in final['census'].items() if int(k) in UNSUPPORTED}
    if unsupported or losses['compat']:
        socket_issues.append('unsupported path census')
    # Lifetimes are an event stream, distinct from totals. FD records never grant roles.
    # Shared admission/read/pending losses can suppress whole lifecycle calls.
    # A capped syscall witness stream alone does not invalidate aggregate totals.
    lifetime_complete = (binding_valid and terminal_valid and not foreign and not reset
        and not any(observed_losses[n] for n in (*total_loss, 'ring_full', 'inner_unmatched'))
        and not any(r['pending'] or r['map_read_failures'] for r in snapshots))
    return dict(available=True, complete=not issues, issues=sorted(set(issues)), losses=losses,
                observed_loss_maxima=observed_losses,
                syscall_totals=final['totals'], socket_rows=final['rows'], census=final['census'],
                unsupported_census=unsupported, reset=reset, measurement_delta=phase_delta,
                measurement_complete=not issues and phase_delta["complete"],
                offered_length_complete=not issues and all(r['offered_known'] == r['exits'] for r in final['totals']),
                successful_return_bytes_complete=not issues and all(r['accepted_known'] == r['exits'] for r in final['totals']),
                socket_roles_complete=not issues and not socket_issues,
                socket_role_issues=socket_issues, lifecycle_stream_complete=lifetime_complete,
                exact_lifetimes_complete=False,
                lifetime_limit='entry FD/dup/close intervals are observations; shared files, SCM_RIGHTS, close races and prebind lifetimes remain unproven',
                witness_complete=not losses['witness_cap'] and lifetime_complete,
                attribution='actual TCP context only; no exit-time FD joins',
                min_max_timestamp_consistency='approximate under concurrent writers; cumulative totals atomic',
                walltime_is_cpu=False, accepted_is_peer_delivery=False)


def fd_lifetimes(rows):
    """Conservative entry/exit intervals; never use these to assign a socket role."""
    active, intervals, hazards = {}, [], []
    for row in rows:
        if row.get('phase') != 'h1_event':
            continue
        if row.get('kind') == 4:
            hazards.append('task exit; file-table sharing unknown')
        if row.get('kind') != 2:
            continue
        key = (row['pid'], row['process_ns'], row['fd'])
        call, result = row['id'], row['result']
        record = {k: row[k] for k in ('pid', 'process_ns', 'tid', 'fd', 'id', 'entered_ns', 'exited_ns', 'result', 'arg1', 'arg2')}
        record.update(cookie=None, role='unknown', alias_of=None, closure_proven=False)
        if result >= 0 and call in (41, 43, 288, 32, 33, 292):
            new = (row['pid'], row['process_ns'], result)
            if new in active:
                active[new]['retired_by_reuse_at_ns'] = row['exited_ns']
            record['new_fd'] = result
            if call in (32, 33, 292):
                record['alias_of'] = row['fd']
            active[new] = record
        elif call == 3:
            previous = active.pop(key, None)
            if previous:
                previous['close_observation'] = record
        elif call in (53, 72, 272, 436, 438):
            hazards.append('socketpair/fcntl/unshare/close_range/pidfd_getfd requires unproven file-table association')
            active.clear()
        intervals.append(record)
    return dict(intervals=intervals, hazards=sorted(set(hazards)), exact_alias_join=False,
                inherited_and_SCM_RIGHTS='unsupported; no role propagation')


def decode_cpu(text, raw_text, target_pids):
    """Consume real perf script blocks; stack success requires multiple resolved PCs."""
    samples, chains, current = [], [], None
    # perf's default sample header after the explicit -F fields. Threads print pid/tid.
    header = re.compile(r'^\s*.+?\s+(\d+)/(\d+)\s+(\d+\.\d+):\s+cpu-clock(?::[ukhS]+)?:')
    frame = re.compile(r'^\s*([0-9a-fA-F]+)\s+(.+?)\s+\((.*?)\)\s*$')
    for line in text.splitlines() + ['']:
        match = header.match(line)
        if match:
            if current:
                samples.append(current)
            current = dict(pid=int(match[1]), tid=int(match[2]), time_secs=match[3], frames=[])
            # Some versions print the sampled frame on the header; preserve it separately.
            suffix = line[match.end():].strip()
            inline = frame.match(suffix)
            if inline:
                current['frames'].append(dict(ip=inline[1], symbol=inline[2], dso=inline[3]))
        elif current and (match := frame.match(line)):
            current['frames'].append(dict(ip=match[1], symbol=match[2], dso=match[3]))
        elif not line.strip() and current:
            samples.append(current); current = None
    tids, depths = collections.Counter(), collections.Counter()
    unresolved = foreign = multi = 0
    folded = collections.Counter()
    for sample in samples:
        if sample['pid'] not in target_pids:
            foreign += 1
            continue
        tids[str(sample['tid'])] += 1
        frames = sample['frames']
        depths[str(len(frames))] += 1
        resolved = [f for f in frames if f['symbol'] not in ('[unknown]', '0x0') and f['dso'] != '[unknown]']
        unresolved += len(resolved) != len(frames) or not frames
        multi += len(resolved) >= 2
        folded[';'.join(f['symbol'] for f in reversed(frames)) or '[unresolved]'] += 1
        chains.append(sample)
    lost = len(re.findall(r'PERF_RECORD_LOST(?:_SAMPLES)?\b', raw_text))
    throttle = len(re.findall(r'PERF_RECORD_THROTTLE\b', raw_text))
    unthrottle = len(re.findall(r'PERF_RECORD_UNTHROTTLE\b', raw_text))
    raw_samples = len(re.findall(r'PERF_RECORD_SAMPLE\b', raw_text))
    return dict(samples=len(chains), per_tid=dict(tids), depth_distribution=dict(depths),
                multi_frame_samples=multi, unresolved_samples=unresolved, foreign_samples=foreign,
                raw_sample_records=raw_samples, lost_records=lost, throttle_records=throttle,
                unthrottle_records=unthrottle,
                task_records=len(re.findall(r'PERF_RECORD_(?:FORK|EXIT|COMM)\b', raw_text)),
                mmap_records=len(re.findall(r'PERF_RECORD_MMAP2?\b', raw_text)),
                callchains=chains, folded=dict(folded),
                complete=False, stack_useful=multi > 0,
                truncated_stack_fraction=None,
                truncation_reason='8192-byte dump and optimized-away/tail/async frames cannot prove complete unwinding')


def cpu_phases(chains, window):
    if not window.get('valid'):
        return dict(complete=False, reason='missing validated host clock')
    counts = collections.Counter()
    for sample in chains:
        whole, fraction = sample['time_secs'].split('.', 1)
        at = int(whole) * 1_000_000_000 + int(fraction[:9].ljust(9, '0'))
        lo, hi = window['start_bounds_ns']
        end_lo, end_hi = window['end_bounds_ns']
        phase = 'measurement' if hi <= at < end_lo else 'outside_measurement' if at < lo or at >= end_hi else 'boundary_uncertain'
        counts[phase] += 1
    return dict(complete=True, samples=dict(counts), exact_warmup_drain=False,
                uncertainty_ns=window.get('uncertainty_ns'))


def nested_fixture_proof(chains):
    """Require one admitted perf leaf-to-caller chain, not a union of symbols.

    Decoder admission already excludes foreign PIDs. Compiler clones/offsets
    and intervening inline/unknown frames do not change the required order.
    Retain whole witnesses (including unknown frames) and PID/TID attribution.
    """
    expected = ('fixture_leaf', 'fixture_middle', 'fixture_outer')
    witnesses = []
    for sample in chains:
        positions = []
        for index, frame in enumerate(sample['frames']):
            if (frame['dso'] != '[unknown]' and
                    re.fullmatch(re.escape(expected[len(positions)]) +
                                 r'(?:\.[A-Za-z0-9_.]+)?(?:\+0x[0-9a-fA-F]+)?', frame['symbol'])):
                positions.append(index)
                if len(positions) == len(expected):
                    witnesses.append(dict(sample, matched_frame_indices=positions))
                    break
    return dict(proven=bool(witnesses), order='leaf_to_caller', expected=list(expected),
                witnesses=witnesses, complete_unwinding=False)


def trace_identity_issues(runtime, owner):
    """The same typed runtime/container binding is used live and after retention."""
    issues = []
    if not isinstance(runtime, dict) or not isinstance(owner, dict):
        return ['missing runtime/process identity']
    for recorded, observed in (('host_pid', 'pid'), ('start_ticks', 'start_ticks')):
        if (not natural(runtime.get(recorded)) or not runtime[recorded]
                or not natural(owner.get(observed)) or owner[observed] != runtime[recorded]):
            issues.append('runtime PID generation mismatch: ' + recorded)
    container = runtime.get('container_id')
    cgroup = owner.get('cgroup')
    if (not isinstance(container, str) or re.fullmatch(r'[0-9a-f]{64}', container) is None
            or not isinstance(cgroup, str) or not cgroup.startswith('/')
            or '..' in Path(cgroup).parts
            or not any(part in (container, 'docker-' + container + '.scope') for part in Path(cgroup).parts)):
        issues.append('runtime container/cgroup ownership mismatch')
    if (not natural(owner.get('cgroup_id')) or not owner['cgroup_id']
            or not isinstance(owner.get('boot_id'), str) or not owner['boot_id']
            or not sha256_value(owner.get('executable_sha256'))
            or not isinstance(owner.get('namespaces'), dict)
            or not all(natural(owner['namespaces'].get(k)) and owner['namespaces'][k] > 0
                       for k in ('pid', 'mnt', 'net', 'time', 'user'))):
        issues.append('missing/invalid process cgroup, ELF or namespace identity')
    return issues


def sha256_value(value):
    return isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value) is not None


def retained_file(root, relative, *, limit=BOUNDS['raw_perf_bytes'], keep=False):
    """Read only regular evidence beneath the caller's retained tree.

    Producer paths never select arbitrary files. Hash streaming is bounded and
    refuses links, replacement, growth, and nonregular evidence.
    """
    parts = Path(relative).parts
    if not parts or Path(relative).is_absolute() or '..' in parts:
        raise ValueError('unsafe retained evidence path')
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory); directory = child
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > limit:
                raise ValueError('nonregular/oversize retained evidence')
            sha, size, chunks = hashlib.sha256(), 0, []
            while True:
                chunk = os.read(fd, min(65536, limit - size + 1))
                if not chunk:
                    break
                size += len(chunk)
                if size > limit:
                    raise ValueError('retained evidence grew beyond bound')
                sha.update(chunk)
                if keep:
                    chunks.append(chunk)
            after = os.fstat(fd)
            if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (size, after.st_mtime_ns, after.st_ctime_ns):
                raise ValueError('retained evidence changed during validation')
            return dict(sha256=sha.hexdigest(), bytes=size), b''.join(chunks)
        finally:
            os.close(fd)
    finally:
        os.close(directory)


def load_trace(path, *, expected=None):
    """Validate a producer claim against THIS report observation and retained bytes.

    Keep the original claim even on failure, but never export its successful
    capture/dimension flags as validated evidence. This is integrity/association
    validation of local artifacts, not a cryptographic signature by the runner.
    """
    path = Path(path)
    result = dict(complete=False, capture_complete=False, validation_complete=False,
                  issues=[], producer_claim=None)
    issues = result['issues']
    def require(condition, message):
        if not condition:
            raise ValueError(message)
    def valid_clock(row):
        return (isinstance(row, dict) and all(natural(row.get(k)) for k in ('before_ns', 'after_ns', 'unix_ns'))
                and 0 < row['before_ns'] <= row['after_ns'])
    def document(name):
        return json.loads(retained_file(path.parent, name, keep=True, limit=16 * 1024**2)[1])
    try:
        claim = document(path.name)
        result['producer_claim'] = claim
        require(isinstance(claim, dict), 'trace manifest must be an object')
        require(isinstance(expected, dict), 'expected observation binding required')
        for key, value in dict(schema=1, selected_mode=expected['selected_mode'],
                external_enabled=expected['enabled'],
                mode=expected['selected_mode'] if expected['enabled'] else 'none').items():
            require(type(claim.get(key)) is type(value) and claim[key] == value, 'trace selection mismatch: ' + key)
        mode = claim['mode']
        require(claim.get('bounds') == BOUNDS and all(type(value) is int for value in claim['bounds'].values()),
                'missing/mismatched fixed capture bounds')
        require(claim['selected_mode'] in ('syscalls', 'cpu'), 'invalid selected trace mode')
        for key in ('capture_complete', 'stop_requested', 'complete', 'fully_profiled'):
            require(type(claim.get(key)) is bool, 'missing typed trace flag: ' + key)
        require(claim['complete'] is False and claim['fully_profiled'] is False, 'unsupported full-profile claim')
        require(isinstance(claim.get('issues'), list) and all(isinstance(v, str) for v in claim['issues']),
                'missing typed producer issues')
        binding = document('bind.json')
        require(binding == claim.get('binding'), 'retained binding differs from manifest')
        for key in ('arm', 'pair', 'payload'):
            require(type(binding.get(key)) is type(expected[key])
                    and type(claim['binding'].get(key)) is type(expected[key]) and binding[key] == expected[key],
                    'trace observation mismatch: ' + key)
        # Relocated artifact trees are supported. Original absolute paths must
        # still name the selected pair/arm, and only caller-selected files read.
        original = Path(binding['sample']).parent
        require(original.is_absolute() and '..' not in original.parts
                and original.name == f"pair_{expected['pair']:03d}", 'invalid original pair path')
        receipts = claim['input_hashes']
        require(isinstance(receipts, dict) and set(receipts) == {'binding', 'runtime', 'config'}
                and all(sha256_value(value) for value in receipts.values()), 'missing typed admission hashes')
        for key in ('runtime', 'config', 'sample', 'raw_sample', 'client_exit'):
            relative = expected['files'][key]
            require(binding[key] == str(original / relative), 'trace input path mismatch: ' + key)
            info, data = retained_file(expected['folder'], relative, keep=key in ('runtime', 'sample', 'raw_sample', 'client_exit'),
                                       limit=16 * 1024**2)
            if key in ('runtime', 'config'):
                require(sha256_value(receipts.get(key)) and receipts[key] == info['sha256'], 'input hash mismatch: ' + key)
            if key == 'runtime':
                runtime = json.loads(data)
                require(runtime == expected['runtime'] == claim['runtime'], 'runtime record substitution')
            elif key == 'sample':
                sample = json.loads(data)
            elif key == 'raw_sample':
                raw_sample = json.loads(data)
            elif key == 'client_exit':
                require(data.strip() == b'0', 'client exit incomplete')
        owner = claim['identity']
        problems = trace_identity_issues(runtime, owner)
        require(not problems, '; '.join(problems))
        require(document('identity.json') == owner, 'identity artifact substitution')
        require(owner['boot_id'] == expected['host_id'], 'trace host mismatch')
        artifacts = claim['artifacts']
        require(isinstance(artifacts, dict) and 0 < len(artifacts) <= 512, 'missing/bounded artifact inventory')
        required = {'bind.json', 'identity.json', 'ready.json', 'teardown-request.json', 'teardown-ready.json',
                    'capabilities.json', 'build-mappings.json', 'initial-sockets.json'}
        if mode == 'syscalls':
            required.update(('syscalls.jsonl', 'syscalls.json', 'fd-lifetimes.json', 'loader.stderr'))
        elif mode == 'cpu':
            required.update(('perf.data', 'perf.stderr', 'cpu-coverage.json', 'stacks.txt', 'stacks.folded',
                             'perf-records.json', 'perf-attributes.txt', 'perf-attributes.txt.status.json',
                             'perf-buildids.txt', 'perf-buildids.txt.status.json', 'perf-header.txt',
                             'perf-header.txt.status.json', 'stacks.txt.status.json'))
        require(required <= artifacts.keys(), 'mandatory retained artifacts missing')
        retained_bytes = 0
        for name, receipt in artifacts.items():
            require(isinstance(receipt, dict) and sha256_value(receipt.get('sha256'))
                    and natural(receipt.get('bytes')), 'invalid artifact receipt: ' + name)
            retained_bytes += receipt['bytes']
            require(retained_bytes <= BOUNDS['total_artifact_bytes'], 'retained trace artifact cap')
            actual, _ = retained_file(path.parent, name)
            require(actual == receipt, 'artifact hash/size mismatch: ' + name)
        binding_hash = artifacts['bind.json']['sha256']
        require(receipts.get('binding') == binding_hash, 'admission binding hash mismatch')
        ready = document('ready.json')
        require(ready['binding_sha256'] == binding_hash and ready['owner'] == owner
                and isinstance(ready['session'], str) and re.fullmatch(r'[0-9a-f]{32}', ready['session']) is not None,
                'ready identity/session/hash mismatch')
        require(ready['status'] == claim['ready']['status'] == ('off' if mode == 'none' else 'supported'),
                'collector readiness incomplete')
        teardown = document('teardown-ready.json')
        request = document('teardown-request.json')
        require(teardown == claim['lifecycle']['teardown'] and teardown['request'] == request,
                'termination artifact substitution')
        require(teardown['phase'] == 'verified_teardown' and claim['lifecycle']['target_gone'] is not None,
                'missing verified target teardown')
        for row in (request, teardown):
            require(row['session'] == ready['session'] and row['binding_sha256'] == binding_hash,
                    'termination session/binding mismatch')
            require(not trace_identity_issues(runtime, row['owner']) and
                    all(row['owner'][key] == owner[key] for key in
                        ('pid', 'start_ticks', 'cgroup_id', 'cgroup', 'executable_sha256', 'boot_id', 'namespaces')),
                    'termination identity mismatch')
        for key in ('sample', 'raw_sample', 'client_exit'):
            evidence = request['evidence']['files'][key]
            actual, _ = retained_file(expected['folder'], expected['files'][key], limit=16 * 1024**2)
            require(evidence['path'] == binding[key] and evidence['sha256'] == actual['sha256'],
                    'completion sample hash mismatch: ' + key)
        for row in (ready, request, teardown):
            require(valid_clock(row.get('at')), 'missing typed lifecycle clock')
        require(ready['at']['after_ns'] <= request['at']['before_ns']
                <= request['at']['after_ns'] <= teardown['at']['before_ns'], 'lifecycle clock order mismatch')
        require(valid_clock(claim['lifecycle']['target_gone'].get('observed_at')),
                'missing typed target removal receipt')
        phases = sample['phases']
        require(phases == raw_sample['phases'] == request['evidence']['phases']
                and phases.get('timed_out') is False and phases.get('stalled_workers') == []
                and phases.get('transport_close_timed_out') is False, 'client drain evidence incomplete')
        completion_window = clock_receipt_window(phases, [ready['at'], request['at']],
            boot_id=owner['boot_id'], time_namespace=owner['namespaces']['time'])
        require(completion_window['valid'] and teardown['completion'] == dict(
            kind='retained_client_report', measurement=completion_window), 'teardown completion clock mismatch')
        window = clock_receipt_window(phases, [row['clock'] for row in claim['timeline']],
                                      boot_id=owner['boot_id'], time_namespace=owner['namespaces']['time'])
        require(window['valid'] and claim['boundaries']['measurement'] == window,
                'measurement clock evidence mismatch')
        start, end = claim['boundaries']['capture_start_ns'], claim['boundaries']['capture_end_ns']
        require(natural(start) and natural(end) and start <= window['start_bounds_ns'][0]
                and end >= window['end_bounds_ns'][1], 'capture does not bracket measurement')
        collectors = claim['lifecycle']['collectors']
        require(isinstance(collectors, dict) and set(collectors) == (
            {'observer'} if mode == 'syscalls' else {'cpu'} if mode == 'cpu' else set()),
            'missing or unexpected collector lifecycle')
        for name, collector in collectors.items():
            require(valid_clock(collector.get('last_alive')) and valid_clock(collector.get('reaped_at'))
                    and collector['last_alive']['before_ns'] >= window['end_bounds_ns'][1]
                    and type(collector['exit'].get('returncode')) is int and collector['exit']['returncode'] == 0,
                    'collector did not cover measurement/reap successfully: ' + name)
        capability = document('capabilities.json')
        require(capability.get('capture_complete') is True and capability.get('discovered') is True
                and capability.get('attached') is (mode != 'none')
                and capability.get('loaded') is (mode == 'syscalls'), 'capability disposition incomplete')
        provenance = claim['dependency_provenance']
        require(provenance == capability['dependency_provenance'] and isinstance(provenance, dict)
                and isinstance(provenance.get('meaning'), str), 'dependency provenance mismatch')
        for group in ('initial_bases', 'integration_checkpoints', 'reviewed_checkpoints'):
            require(isinstance(provenance.get(group), dict) and set(provenance[group]) == {'h1', 'h3'}
                    and all(isinstance(value, str) and re.fullmatch(r'[0-9a-f]{40}', value) is not None
                            for value in provenance[group].values()), 'missing typed dependency checkpoint')
        for field, mandatory in (('source_hashes', ('h1_trace.py', 'h1_trace_contract.py', 'h1_syscalls.bpf.h', 'h1_loader.h')),
                                 ('object_hashes', ('observer', 'observer.bpf.o', 'perf', 'h1_trace_fixture'))):
            hashes = capability[field]
            require(isinstance(hashes, dict) and set(mandatory) <= hashes.keys()
                    and all(sha256_value(value) for value in hashes.values()), 'missing source/object/tool hashes')
        require(capability['runner']['GITHUB_SHA'] == expected['revision'], 'source revision mismatch')
        matching = claim['matching_elf']
        require(matching in ('off/ferrum-edge', 'on/ferrum-edge'), 'unknown retained release twin')
        elf, _ = retained_file(expected['builds'], matching, limit=ELF_PACKAGE_BYTES)
        require(elf['sha256'] == owner['executable_sha256'], 'retained gateway ELF mismatch')
        if mode == 'syscalls':
            raw = retained_file(path.parent, 'syscalls.jsonl', keep=True)[1]
            require(raw.endswith(b'\n'), 'truncated observer terminal record')
            rows = [json.loads(line) for line in raw.splitlines()]
            for row in rows:
                if row.get('phase') in ('snapshot', 'checkpoint', 'final'):
                    roles = {}
                    for entry in row['rows']:
                        totals = roles.setdefault(str(entry['role']), {k: 0 for k in COUNTERS})
                        for key in COUNTERS:
                            totals[key] += entry[key]
                    row['role_totals'] = roles
            checked = syscall_coverage(rows, owner, claim['boundaries'])
            require(checked == claim['syscalls'] == document('syscalls.json'), 'syscall coverage claim mismatch')
            require(checked['complete'], 'syscall evidence incomplete')
            result['syscalls'] = checked
            exit_status = claim['observer_exit']
            require(exit_status.get('partial_record') is False, 'partial observer termination')
        elif mode == 'cpu':
            coverage = document('cpu-coverage.json')
            require(coverage == {k: v for k, v in claim['cpu'].items() if k != 'phases'}, 'CPU coverage claim mismatch')
            for flag in ('samples_complete', 'stack_useful', 'complete', 'unwind_complete', 'attributes_verified'):
                require(type(coverage.get(flag)) is bool, 'missing typed CPU flag: ' + flag)
            require(coverage['attributes_verified'] and coverage['complete'] is False
                    and isinstance(coverage.get('issues'), list)
                    and all(issue in ('missing matching ELF/build IDs/CFI', 'partial unwinding/unresolved samples')
                            for issue in coverage['issues']), 'CPU capture issues/inconsistent flags')
            require(coverage['samples_complete'] == (not coverage['issues']), 'CPU sample completeness mismatch')
            from h1_trace import read_cpu_attributes
            attributes = read_cpu_attributes(path.parent / 'perf-attributes.txt', document('perf-attributes.txt.status.json'))
            require(attributes['verified'] and attributes == coverage['attribute_validation'], 'CPU attributes unverified')
            for filename, field in (('stacks.txt', 'decoder_status'), ('perf-buildids.txt', 'buildid_status'),
                                    ('perf-header.txt', 'header_status'), ('perf-attributes.txt', 'attributes_status')):
                status = document(filename + '.status.json')
                limit = (16 if filename == 'stacks.txt' else 2) * 1024**2
                require(coverage[field] == status and artifacts[filename]['bytes'] +
                        artifacts[filename + '.stderr']['bytes'] <= limit, 'CPU command output cap/receipt mismatch')
                require(type(status['returncode']) is int and status['returncode'] == 0
                        and status['forced'] is False and status['incomplete'] is None
                        and status['stdout_sha256'] == artifacts[filename]['sha256']
                        and status['stderr_sha256'] == artifacts[filename + '.stderr']['sha256'],
                        'CPU decoder receipt incomplete: ' + filename)
            records = document('perf-records.json')
            require(records['incomplete'] is None and type(records['status']['returncode']) is int
                    and records['status']['returncode'] == 0 and records['status']['forced'] is False, 'raw decoder incomplete')
            decoded = decode_cpu(retained_file(path.parent, 'stacks.txt', keep=True)[1].decode(),
                                 '\n'.join(records['records']), {owner['pid']})
            for key in ('samples', 'foreign_samples', 'unresolved_samples', 'multi_frame_samples',
                        'raw_sample_records', 'lost_records', 'throttle_records', 'mmap_records', 'task_records'):
                require(type(coverage.get(key)) is int and coverage[key] == decoded[key], 'CPU counter mismatch: ' + key)
            for key, value in decoded.items():
                if key not in ('callchains', 'folded'):
                    require(type(coverage.get(key)) is type(value) and coverage[key] == value,
                            'CPU decoded evidence mismatch: ' + key)
            require(decoded['samples'] > 0 and not decoded['foreign_samples'] and not decoded['lost_records']
                    and not decoded['throttle_records'] and decoded['samples'] == decoded['raw_sample_records'],
                    'CPU sample capture incomplete')
            require(cpu_phases(decoded['callchains'], window) == claim['cpu']['phases'], 'CPU phase evidence mismatch')
            dsos = document('build-mappings.json')
            require(type(dsos.get('complete')) is bool and isinstance(dsos.get('errors'), list)
                    and isinstance(dsos.get('dsos'), list), 'missing typed DSO disposition')
            require(dsos['complete'] == (not dsos['errors']), 'DSO completeness mismatch')
            for dso in dsos['dsos']:
                require(isinstance(dso['path'], str) and dso['path'].startswith('/')
                        and sha256_value(dso.get('sha256'))
                        and all(natural(dso.get(key)) for key in ('device_major', 'device_minor', 'inode', 'bytes'))
                        and dso['inode'] > 0 and type(dso.get('eh_frame')) is bool
                        and isinstance(dso.get('build_id_lines'), list)
                        and all(isinstance(line, str) for line in dso['build_id_lines']), 'invalid mapped DSO identity')
                actual, _ = retained_file(expected['builds'], str(Path(matching).parent / 'symfs') + dso['path'],
                                          limit=ELF_PACKAGE_BYTES)
                require(actual == {k: dso[k] for k in ('sha256', 'bytes')}, 'DSO artifact mismatch')
                metadata = dso['metadata_path']
                require(isinstance(metadata, str) and metadata.startswith('/')
                        and Path(metadata).parent == Path(dso['path']).parent, 'invalid DSO metadata path')
                relative = str(Path(matching).parent / 'symfs') + metadata
                for suffix, key in (('', 'stdout_sha256'), ('.stderr', 'stderr_sha256')):
                    actual, metadata_bytes = retained_file(expected['builds'], relative + suffix, keep=not suffix,
                                                           limit=2 * 1024**2)
                    require(actual['sha256'] == dso['decoder'][key], 'DSO metadata hash mismatch')
                    if not suffix:
                        metadata_text = metadata_bytes.decode()
                        require(dso['build_id_lines'] == [line.strip() for line in metadata_text.splitlines() if 'Build ID:' in line]
                                and dso['eh_frame'] == ('.eh_frame' in metadata_text), 'DSO ELF metadata claim mismatch')
                status = json.loads(retained_file(expected['builds'], relative + '.status.json', keep=True,
                                                 limit=4096)[1])
                require(status == dso['decoder'], 'DSO decoder receipt mismatch')
            build_ids = {}
            for line in retained_file(path.parent, 'perf-buildids.txt', keep=True)[1].decode().splitlines():
                parts = line.split(None, 1)
                if len(parts) == 2 and re.fullmatch(r'[a-fA-F0-9]{8,64}', parts[0]):
                    build_ids[parts[1].strip()] = parts[0].lower()
            retained_ids = {d['path']: [line.rsplit(' ', 1)[-1].lower() for line in d['build_id_lines']]
                            for d in dsos['dsos']}
            require(build_ids and all(not name.startswith('/') or build_id in retained_ids.get(name, [])
                    for name, build_id in build_ids.items()), 'recorded build ID lacks matching retained ELF')
            missing_cfi = not dsos['complete'] or any(not d['build_id_lines'] or not d['eh_frame'] for d in dsos['dsos'])
            partial = bool(decoded['unresolved_samples'] or decoded['multi_frame_samples'] != decoded['samples'])
            require(('missing matching ELF/build IDs/CFI' in coverage['issues']) == missing_cfi
                    and ('partial unwinding/unresolved samples' in coverage['issues']) == partial,
                    'CPU partial coverage disposition mismatch')
            require(coverage.get('unwind_complete') is False, 'unsupported complete unwinding claim')
            result['cpu'] = claim['cpu']
            exit_status = claim['perf_exit']
        else:
            exit_status = dict(returncode=0, forced=False)
        require(type(exit_status.get('returncode')) is int and exit_status['returncode'] == 0
                and exit_status.get('forced') is False, 'collector exit incomplete')
        require(claim['capture_complete'] and claim['stop_requested'] and not claim['issues'], 'producer capture incomplete')
        result.update(validation_complete=True, capture_complete=True, mode=mode)
    except (OSError, ValueError, KeyError, TypeError, AttributeError, IndexError, OverflowError, RecursionError) as error:
        issues.append('external trace validation: ' + str(error))
        # Partial producer dimension claims remain solely under producer_claim.
        result.pop('cpu', None)
        result.pop('syscalls', None)
    return result
