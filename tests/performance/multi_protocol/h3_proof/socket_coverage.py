"""Same-invocation socket accounting, separate from observed buffer equality.

No backend close, clean client row, or diagnostic repeat supplies a final kernel
counter. A retirement closes only that socket's observed lifetime, not a claim
of complete kernel population/packet coverage.
"""
from evidence import LOSSES
from live_contract import capture_interval, ipv4, natural, validate_observer_record

BUDGET = 4194304


def owner_identity(sk):
    return sorted({(o.get('pid'), o.get('start_ticks'), o.get('ticks'),
                    o.get('cgroup_id'), o.get('netns')) for o in sk['owners']})


def event_owner_matches(event, sk):
    return any(event.get('pid') == o.get('pid') and event.get('cgroup') == o.get('cgroup_id')
               and event.get('netns') == o.get('netns')
               and natural(o.get('ticks')) and o['ticks'] > 0
               and natural(o.get('start_ticks')) and natural(event.get('process_start_ns'))
               and o['start_ticks'] == event['process_start_ns'] * o['ticks'] // 1_000_000_000
               for o in sk['owners'])


def lifetime_events(context, cookie):
    """Only independently finalized birth/destroy streams from this invocation."""
    if not context or not context['observers']:
        return [], [], ['retirement_not_observed']
    events, issues = {}, []
    for family, kind in (('lifetime', 18), ('destroy', 20)):
        streams = [r for r in context['observers'] if r.get('family') == family]
        if len(streams) != 1:
            issues.append('retirement_capture_incomplete')
            continue
        stream = streams[0]
        selected = [r for r in stream.get('events', []) if r.get('cookie') == cookie and r.get('kind') == kind]
        events[family] = selected
        try:
            ready, final, stop = stream['ready'], stream['final'], stream['termination']
            for r in (ready, final, stop, *selected):
                validate_observer_record(r, family)
            if (stream.get('invocation') != context['invocation'] or stream.get('error')
                    or stream.get('capture_complete') is not True or stream.get('returncode') != 0
                    or ready['status'] != 'supported' or ready['netns'] != context['netns']
                    or final['phase'] != 'final' or stop['phase'] != 'termination'
                    or final['map_read_failures'] or final['ring_drops'] or final['verifier_log_truncated']
                    or stop['snapshot_failures'] or stop['lifecycle_omitted']
                    or not stop['requested_stop'] or stop['signal'] or stop['forced_or_parent_death']
                    or any(v for name, v in zip(LOSSES, final['losses']) if name not in ('attempts', 'recorded'))
                    or any(not ready['start_ns'] <= e['at_ns'] <= final['end_ns'] for e in selected)):
                issues.append('retirement_capture_incomplete')
        except (KeyError, TypeError, ValueError):
            issues.append('retirement_capture_incomplete')
    return events.get('lifetime', []), events.get('destroy', []), sorted(set(issues))


def socket_coverage(timeline, values, bounds, window, cookie, context=None):
    result = dict(lifetime_covered=False, drops=None, retirement=None, issues=[],
                  lifetime_status='unobserved_disappearance')
    issues = result['issues']
    if not window.get('valid'):
        issues.append('measurement_clock_unverified')
        return result
    # Every retained observation checks identity, even overlapping boundaries.
    base = values[0][1]
    if any(owner_identity(sk) != owner_identity(base) or sk['inode'] != base['inode']
           or (sk['local_address'], sk['local_port']) != (base['local_address'], base['local_port'])
           for _, sk in values):
        issues.append('cookie_or_owner_reuse')
    if context:
        ns = context['namespace_lifetime']
        if (not context.get('boot_id') or ns['inode'] != context['netns']
                or ns['opened_ns'] > capture_interval(timeline[values[0][0]])[0]
                or ns['closed_ns'] < capture_interval(timeline[values[-1][0]])[1]
                or any(timeline[i].get('boot_id') != context['boot_id']
                       or timeline[i].get('netns') != context['netns']
                       or any(o.get('netns') != context['netns'] for o in sk['owners']) for i, sk in values)):
            issues.append('boot_or_namespace_changed')
        if any(not o.get('cgroup', '').startswith('/' + context['invocation'] + '/')
               for _, sk in values for o in sk['owners']):
            issues.append('invocation_ownership_mismatch')
    left, right = bounds['left_sample_index'], bounds['right_sample_index']
    if left is None:
        # Born-during-window accounting is deliberately not inferred from first
        # observation: without a passive initial identity/budget it remains a gap.
        issues.append('missing_initial_boundary')
    last = values[-1][0] if right is None else right
    selected = [(i, sk) for i, sk in values if (left if left is not None else values[0][0]) <= i <= last]
    if [i for i, _ in selected] != list(range(selected[0][0], last + 1)):
        issues.append('missing_capture')
    counters = [sk.get('socket_drops') for _, sk in selected]
    if not all(natural(v) for v in counters):
        issues.append('missing_drop_counter')
    elif any(b < a for a, b in zip(counters, counters[1:])):
        issues.append('drop_counter_decreased')
    births, retirements, capture_issues = lifetime_events(context, cookie)
    if len(births) > 1 or len(retirements) > 1:
        issues.append('cookie_or_owner_reuse')
    if right is not None:
        result['lifetime_status'] = 'passive_full_boundary_bracket'
        if any(window['start_bounds_ns'][0] <= e['at_ns'] <= capture_interval(timeline[right])[1]
               for e in births + retirements):
            issues.append('lifecycle_conflicts_with_passive_bracket')
    else:
        issues.extend(capture_issues)
        if not retirements:
            issues.extend(['unobserved_disappearance', 'missing_final_drop'])
        else:
            end = retirements[0]
            # Retain the actual final value even if other evidence rejects it.
            result['retirement'] = dict(end)
            result['lifetime_status'] = 'witnessed_retirement_incomplete'
            if len(births) != 1:
                issues.append('missing_birth_witness')
            elif (not event_owner_matches(births[0], base)
                  or births[0]['result'] != 0 or births[0]['family'] != base['family']
                  or births[0]['at_ns'] < context['namespace_lifetime']['opened_ns']
                  or births[0]['at_ns'] > capture_interval(timeline[values[0][0]])[0]):
                issues.append('birth_identity_or_boundary_mismatch')
            if (not event_owner_matches(end, base) or end['result'] != 0 or end['family'] != base['family']
                    or (ipv4(end['local_ipv4']), end['local_port']) != (base['local_address'], base['local_port'])
                    or (base['peer_port'] and (ipv4(end['peer_ipv4']), end['peer_port'])
                        != (base['peer_address'], base['peer_port']))):
                issues.append('retirement_identity_mismatch')
            # Capture must positively see the socket until its actual retirement;
            # an intervening missing dump is not excused by a later close event.
            following = last + 1
            if (end['at_ns'] < capture_interval(timeline[last])[0]
                    or end['at_ns'] > window['end_bounds_ns'][1]
                    or end['at_ns'] > context['namespace_lifetime']['closed_ns']
                    or following >= len(timeline)
                    or end['at_ns'] > capture_interval(timeline[following])[1]):
                issues.append('unobserved_disappearance')
            if not natural(end.get('drops')):
                issues.append('missing_final_drop')
            elif counters and natural(counters[-1]) and end['drops'] < counters[-1]:
                issues.append('drop_counter_decreased')
            if end.get('so_rcvbuf') != BUDGET or end.get('so_sndbuf') != BUDGET:
                issues.append('wrong_buffer')
            counters.append(end.get('drops'))
    result['issues'] = sorted(set(issues))
    if not issues:
        result['lifetime_covered'] = True
        result['drops'] = {'socket_drops': counters[-1] - counters[0]}
        if right is None:
            result['lifetime_status'] = 'witnessed_retirement_with_final_drop'
    return result
