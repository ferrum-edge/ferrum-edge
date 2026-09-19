"""Data-only campaign validation, calibration and process/cookie role joins."""
import json
import math
import statistics
import struct
import socket
from pathlib import Path

from evidence import KINDS, LOSSES

ARMS = ["direct", "ferrum", "envoy", "envoy-limit-4"]
PAYLOADS = [10240, 71680, 512000, 1048576, 5242880]
ENVOY = "docker.io/envoyproxy/envoy@sha256:79c4e987d386b176721638187b511fb4d7041695f7a78e422ed27edd707b3eeb"
FAMILIES = ('tx', 'rx', 'attach', 'lifetime', 'destroy', 'group', 'process', 'classic')
CLOCK_UNCERTAINTY_NS = 1_000_000


def natural(value):
    return type(value) is int and value >= 0


def capture_interval(row):
    """Whole passive read interval; the realtime clock read is not the data read."""
    try:
        start, end, clock = row['monotonic_ns'], row['capture_end_ns'], row['clock']
        if (not all(natural(v) for v in (start, end, clock['before_ns'], clock['after_ns']))
                or not 0 < start == clock['before_ns'] <= clock['after_ns'] <= end
                or ('capture_ns' in row and (not natural(row['capture_ns'])
                                            or row['capture_ns'] != end - start))):
            return None
        return start, end
    except (KeyError, TypeError):
        return None


def passive_bracket(timeline, indices, window):
    """Select definite boundary captures, retaining intervals instead of midpoints.

    Indices refer to the unfiltered raw timeline. Consumers must also check
    population continuity through every intervening capture, including overlaps.
    """
    result = dict(complete_bracket=False, clock='CLOCK_MONOTONIC',
                  left_sample_index=None, right_sample_index=None)
    if not window.get('valid'):
        return dict(result, reason=window.get('reason', 'measurement_clock_unverified'))
    intervals = [capture_interval(row) for row in timeline]
    if any(interval is None for interval in intervals):
        return dict(result, reason='missing_or_invalid_capture_interval')
    start_lo, start_hi = window['start_bounds_ns']
    end_lo, end_hi = window['end_bounds_ns']
    before = [i for i in indices if intervals[i][1] <= start_lo]
    after = [i for i in indices if intervals[i][0] >= end_hi]
    left, right = before[-1] if before else None, after[0] if after else None
    result.update(left_sample_index=left, right_sample_index=right,
                  left_capture_bounds_ns=list(intervals[left]) if left is not None else None,
                  right_capture_bounds_ns=list(intervals[right]) if right is not None else None)
    if left is None or right is None:
        return dict(result, reason='missing_resource_capture_bracket')
    a, b = intervals[left], intervals[right]
    result.update(complete_bracket=True,
                  bracket_duration_bounds_ns=[b[0] - a[1], b[1] - a[0]],
                  start_slack_bounds_ns=[start_lo - a[1], start_hi - a[0]],
                  end_slack_bounds_ns=[b[0] - end_hi, b[1] - end_lo])
    return result


def measurement_window(phases, timeline):
    """Retained Linux CLOCK_MONOTONIC bounds, never the client's local epoch.

    Realtime is used only to check the existing wall-clock diagnostics. Permit
    1 ms read uncertainty and 1000 ppm slew, but reject observed clock steps.
    """
    invalid = dict(valid=False, reason='missing_or_invalid_common_clock')
    try:
        clock = phases['measurement_start_host_clock']
        lo, hi = clock['before_ns'], clock['after_ns']
        duration = phases['measurement_secs']
        if (clock['clock'] != 'CLOCK_MONOTONIC' or not natural(lo) or not natural(hi)
                or not 0 < lo <= hi <= lo + CLOCK_UNCERTAINTY_NS
                or type(duration) not in (int, float) or not math.isfinite(duration)
                or not 0 < duration <= 300):
            return invalid
        span = math.ceil(duration * 1e9)
        clocks = [row['clock'] for row in timeline]
        if len(clocks) < 2:
            return invalid
        for c in clocks:
            if (not all(natural(c[k]) for k in ('before_ns', 'after_ns', 'unix_ns'))
                    or not 0 < c['before_ns'] <= c['after_ns'] <= c['before_ns'] + CLOCK_UNCERTAINTY_NS):
                return invalid
        for a, b in zip(clocks, clocks[1:]):
            if b['before_ns'] <= a['after_ns']:
                return dict(valid=False, reason='nonmonotonic_capture_clock')
            slack = CLOCK_UNCERTAINTY_NS + (b['after_ns'] - a['before_ns']) // 1000
            if (b['unix_ns'] - b['after_ns'] > a['unix_ns'] - a['before_ns'] + slack
                    or a['unix_ns'] - a['after_ns'] > b['unix_ns'] - b['before_ns'] + slack):
                return dict(valid=False, reason='realtime_clock_jump')
        intervals = [capture_interval(row) for row in timeline]
        if any(interval is None for interval in intervals):
            return dict(valid=False, reason='missing_or_invalid_capture_interval')
        if any(b[0] < a[1] for a, b in zip(intervals, intervals[1:])):
            return dict(valid=False, reason='nonmonotonic_capture_interval')
        before = [i for i, (_, end) in enumerate(intervals) if end <= lo]
        after = [i for i, (start, _) in enumerate(intervals) if start >= hi + span]
        if not before or not after:
            return dict(valid=False, reason='missing_passive_capture_bracket')
        unix = phases['measurement_start_unix_secs']
        if type(unix) not in (int, float) or not math.isfinite(unix):
            return invalid
        anchor = clocks[before[-1]]
        slack = CLOCK_UNCERTAINTY_NS + (hi - anchor['before_ns']) // 1000
        if not (lo + anchor['unix_ns'] - anchor['after_ns'] - slack <= unix * 1e9
                <= hi + anchor['unix_ns'] - anchor['before_ns'] + slack):
            return dict(valid=False, reason='phase_realtime_clock_mismatch')
        window = dict(valid=True, clock='CLOCK_MONOTONIC', start_bounds_ns=[lo, hi],
                      end_bounds_ns=[lo + span, hi + span], uncertainty_ns=hi - lo,
                      realtime_check='1ms_read_uncertainty_plus_1000ppm_slew')
        window['passive_capture_bracket'] = passive_bracket(timeline, range(len(timeline)), window)
        return window
    except (KeyError, TypeError, ValueError, OverflowError):
        return invalid


def measurement_position(at_ns, window):
    if not window.get('valid') or not natural(at_ns):
        return 'unknown'
    lo, hi = window['start_bounds_ns']
    end_lo, end_hi = window['end_bounds_ns']
    if hi <= at_ns < end_lo:
        return 'measurement'
    if at_ns < lo or at_ns >= end_hi:
        return 'outside'
    return 'boundary_uncertain'


def provenance_issues(usage, window, time_namespace):
    issues = []
    if not window.get('valid'):
        issues.append('measurement_clock_unverified')
    # An untimed error could have occurred during measurement. A capture that
    # starts before measurement may also fail inside it, so retain its interval.
    errors = usage.get('errors', [])
    for row in usage.get('timeline', []):
        transport = row.get('transport')
        if not isinstance(transport, dict) or transport.get('errors') != []:
            errors = errors + [dict(at_ns=row.get('monotonic_ns'),
                                    end_ns=row.get('capture_end_ns'))]
    for error in errors:
        start, end = error.get('at_ns'), error.get('end_ns')
        if (not window.get('valid') or not natural(start) or not natural(end) or end < start
                or (start < window['end_bounds_ns'][1] and end >= window['start_bounds_ns'][0])):
            issues.append('process_provenance_incomplete')
            break
    if usage.get('capture_complete') is not True:
        issues.append('process_provenance_incomplete')
    owners = usage.get('owners', [])
    if (not time_namespace or not any(o.get('role') == 'client' for o in owners)
            or any(o.get('time_namespace') != time_namespace for o in owners)):
        issues.append('process_clock_namespace_unverified')
    return sorted(set(issues))


def validate_observer_record(row, family):
    """Reject malformed diagnostics before they can count as readiness/coverage."""
    if not isinstance(row, dict):
        raise ValueError('observer_record_not_object')
    phase = row.get('phase')
    fields = ()
    if phase == 'ready':
        status = row.get('status')
        if status == 'supported':
            fields = ('start_ns', 'netns', 'links')
            if row.get('family') != family or not all(natural(row.get(k)) and row[k] > 0 for k in fields):
                raise ValueError('invalid_observer_readiness')
        elif status not in ('unsupported', 'error') or not isinstance(row.get('reason'), str) or not row['reason']:
            raise ValueError('invalid_observer_outcome')
        elif not natural(row.get('errno')) or type(row.get('verifier_log_truncated')) is not bool:
            raise ValueError('invalid_observer_unavailability')
        return
    if phase in ('final', 'checkpoint', 'snapshot'):
        fields = ('start_ns', 'end_ns', 'map_read_failures', 'pending_tx', 'pending_rx',
                  'pending_selector', 'pending_detach', 'ring_drops')
        if not all(natural(row.get(k)) for k in fields):
            raise ValueError('invalid_observer_snapshot_diagnostic')
        if type(row.get('verifier_log_truncated')) is not bool:
            raise ValueError('invalid_observer_snapshot_log_diagnostic')
        losses = row.get('losses')
        if (not isinstance(losses, list) or len(losses) != len(LOSSES)
                or not all(natural(v) for v in losses) or not isinstance(row.get('rows'), list)):
            raise ValueError('invalid_observer_snapshot')
        for item in row['rows']:
            if (not isinstance(item, dict) or not all(natural(item.get(k)) for k in
                    ('cookie', 'peer_cookie', 'kind', 'count', 'first_ns', 'last_ns', 'length', 'segment', 'cpu'))
                    or item['kind'] not in KINDS or not item['cookie']
                    or type(item.get('result')) is not int):
                raise ValueError('invalid_observer_count_row')
            # Concurrent checkpoints can see a newly inserted zero-count row or
            # updates after their header timestamp. Only detached final is stable.
            if phase == 'final' and (not item['count'] or not
                    row['start_ns'] <= item['first_ns'] <= item['last_ns'] <= row['end_ns']):
                raise ValueError('invalid_observer_final_count_row')
    elif phase in ('lifecycle', 'witness'):
        fields = ('at_ns', 'cookie', 'kind', 'pid', 'tid', 'process_start_ns', 'thread_start_ns')
        if type(row.get('result')) is not int or row.get('kind') not in KINDS:
            raise ValueError('invalid_observer_event')
        fields += (('length', 'segment') if phase == 'witness' else
                   ('cgroup', 'netns', 'family', 'local_ipv4', 'local_port', 'peer_ipv4', 'peer_port',
                    'so_rcvbuf', 'so_sndbuf', 'drops', 'peer_cookie', 'attachment_generation',
                    'instruction_digest_fnv1a64', 'program_type', 'instruction_count', 'digest_valid'))
    elif phase == 'termination':
        fields = ('lifecycle_omitted', 'snapshot_failures', 'checkpoints_omitted')
        if any(type(row.get(k)) is not bool for k in ('requested_stop', 'signal', 'forced_or_parent_death')):
            raise ValueError('invalid_observer_termination')
    else:
        raise ValueError('unknown_observer_phase')
    if not all(natural(row.get(k)) for k in fields):
        raise ValueError('invalid_observer_numeric_diagnostic')
    if phase in ('lifecycle', 'witness') and (not row['at_ns'] or type(row['kind']) is not int):
        raise ValueError('invalid_observer_event_identity')
    if phase == 'lifecycle' and any(row[k] > 0xFFFFFFFF for k in ('local_ipv4', 'peer_ipv4')):
        raise ValueError('invalid_observer_endpoint')
    if phase in ('final', 'checkpoint', 'snapshot') and row['end_ns'] < row['start_ns']:
        raise ValueError('invalid_observer_snapshot_clock')


def observer_issues(results):
    issues = []
    if sorted(r.get('family', '') for r in results) != sorted(FAMILIES):
        issues.append('observer_family_inventory_incomplete')
    for r in results:
        family = r.get('family')
        try:
            validate_observer_record(r.get('ready'), family)
            if r['ready']['phase'] != 'ready':
                raise ValueError('missing_observer_readiness')
            if r.get('error') or r.get('returncode') != 0 or r.get('capture_complete') is not True:
                raise ValueError('observer_capture_failed')
            status = r['ready']['status']
            if status == 'error':
                raise ValueError('observer_implementation_error')
            if status == 'unsupported':
                continue
            final, stop = r.get('final'), r.get('termination')
            validate_observer_record(final, family)
            validate_observer_record(stop, family)
            if (final['phase'] != 'final' or stop['phase'] != 'termination'
                    or final['map_read_failures'] or stop['snapshot_failures']
                    or not stop['requested_stop'] or stop['signal'] or stop['forced_or_parent_death']):
                raise ValueError('observer_final_capture_failed')
            if final['verifier_log_truncated']:
                raise ValueError('observer_diagnostics_incomplete')
            if (stop['lifecycle_omitted'] or final['ring_drops']
                    or final['losses'][LOSSES.index('ring_full')]):
                raise ValueError('observer_lifecycle_incomplete')
        except (KeyError, TypeError, ValueError) as error:
            issues.append(f'{family}:{error}')
    return issues


def smoke_issues(evidence, results, arm):
    required = {'backend', 'client'} | (set() if arm == 'direct' else {'gateway_frontend', 'gateway_upstream'})
    # A capability gap is retained explicitly but cannot pass the live smoke.
    supported = {r['family'] for r in results if (r.get('ready') or {}).get('status') == 'supported'}
    issues = [f'smoke_required_family_unavailable:{f}' for f in ('tx', 'rx', 'lifetime', 'destroy') if f not in supported]
    coverage = evidence.get('operation_coverage', {})
    for role in sorted(required):
        if not ({1, 2} & set(coverage.get(role, []))) or not ({5, 6, 16} & set(coverage.get(role, []))):
            issues.append(f'smoke_missing_operation_role:{role}')
        cookies = {r['cookie'] for r in evidence.get('roles', []) if r['role'] == role}
        if not any(r['cookie'] in cookies and natural(r.get('birth_ns')) and natural(r.get('retirement_ns'))
                   and r['birth_ns'] < r['retirement_ns'] for r in evidence.get('socket_lifetimes', [])):
            issues.append(f'smoke_missing_lifecycle_role:{role}')
    return issues


def sample_admission_issues(record, issues):
    """Late observer/resource/artifact failures must reach calibration and RPS gating."""
    result = list(issues)
    if record.get('status') == 'error':
        result.append(record.get('reason', 'driver_error'))
    if record.get('observer_errors'):
        result.append('observer_capture_failed')
    result.extend(record.get('smoke_issues', []))
    if record.get('artifact_cap_exceeded'):
        result.append('artifact_cap_exceeded')
    return sorted(set(result))


def envoy_protocol_evidence(document):
    checks = {'upstream_cx_http1_total': 0, 'upstream_cx_http2_total': 0,
              'upstream_rq_retry': 0, 'upstream_rq_retry_success': 0, 'upstream_rq_timeout': 0}
    required = set(checks) | {'upstream_cx_http3_total'}
    if not isinstance(document, dict) or not isinstance(document.get('stats'), list):
        raise ValueError('invalid_envoy_stats_document')
    evidence = {}
    for row in document['stats']:
        if not isinstance(row, dict):
            raise ValueError('invalid_envoy_stats_row')
        name = row.get('name')
        if name is None and 'histograms' in row:
            continue
        if not isinstance(name, str) or 'value' not in row:
            raise ValueError('invalid_envoy_scalar_counter')
        key = name.removeprefix('cluster.backend_h3.')
        if name.startswith('cluster.backend_h3.') and key in required:
            if key in evidence or not natural(row['value']):
                raise ValueError('invalid_or_duplicate_envoy_protocol_counter')
            evidence[key] = row['value']
    if (evidence.keys() != required or any(evidence[k] != v for k, v in checks.items())
            or evidence['upstream_cx_http3_total'] <= 0):
        raise ValueError('envoy_protocol_retry_timeout_contract_incomplete')
    return evidence


def manifest(path):
    value = json.loads(Path(path).read_text())
    expected = dict(campaign="corrected-v1", arms=ARMS, payloads=PAYLOADS,
                    workers=[200, 200, 200, 100, 50], client_connections=[21, 21, 21, 11, 6],
                    measurement_seconds=30, pairs=4, main_samples=80,
                    downstream_stream_limit=100, upstream_stream_limits=[100, 4],
                    socket_buffer_bytes=4194304, envoy_image=ENVOY, pilots_per_arm=2,
                    socket_evidence_contract='socket-lifetime-v2',
                    upstream_identity=dict(connect_address='127.0.0.1:3445', sni='localhost',
                                           dns_san='localhost', verify_chain=True))
    if any(value.get(k) != v for k, v in expected.items()):
        raise ValueError("campaign differs from the approved finite contract")
    if value["calibration"] != dict(useful_rps_tolerance=0.02, p99_tolerance=0.05, confidence=0.95):
        raise ValueError("calibration tolerance changed")
    return value


def config_difference(left, right, path=()):
    if type(left) is not type(right):
        return [(path, left, right)]
    if isinstance(left, dict):
        if left.keys() != right.keys():
            return [(path, left, right)]
        return [diff for key in left for diff in config_difference(left[key], right[key], path + (key,))]
    if isinstance(left, list) and len(left) == len(right):
        return [diff for i, (a, b) in enumerate(zip(left, right)) for diff in config_difference(a, b, path + (i,))]
    return [] if left == right else [(path, left, right)]


def assert_upstream_only(left, right):
    expected = ("static_resources", "clusters", 0, "typed_extension_protocol_options",
                "envoy.extensions.upstreams.http.v3.HttpProtocolOptions", "explicit_http_config",
                "http3_protocol_options", "quic_protocol_options", "max_concurrent_streams", "value")
    differences = config_difference(left, right)
    if differences != [(expected, 100, 4)]:
        raise ValueError("only upstream admission may differ")
    listener = left["static_resources"]["listeners"][0]
    if listener["udp_listener_config"]["quic_options"]["quic_protocol_options"]["max_concurrent_streams"]["value"] != 100:
        raise ValueError("downstream admission changed")
    return differences


def calibration(pairs):
    """Two paired pilots, 95% t interval (df=1). Missing data never passes."""
    result = dict(resolved=False, active_main=False, intervals={}, reason="missing_or_invalid_pilots")
    if len(pairs) != 2 or any(a.get("traffic_issues") or b.get("traffic_issues") or not b.get("observer_ok", False) for a, b in pairs):
        return result
    try:
        for field in ("rps", "p99_us"):
            ratios = [math.log(b[field] / a[field]) for a, b in pairs]
            if not all(math.isfinite(r) for r in ratios):
                return result
            mean = statistics.mean(ratios)
            margin = 12.706204736 * statistics.stdev(ratios) / math.sqrt(2)
            result["intervals"][field] = [math.exp(mean - margin), math.exp(mean + margin)]
        rps, p99 = result["intervals"]["rps"], result["intervals"]["p99_us"]
        passed = rps[0] >= 0.98 and rps[1] <= 1.02 and p99[0] >= 0.95 and p99[1] <= 1.05
        exceeds = rps[1] < 0.98 or rps[0] > 1.02 or p99[0] > 1.05 or p99[1] < 0.95
        result.update(resolved=passed or exceeds, active_main=passed,
                      reason="within_tolerance" if passed else "exceeds_tolerance" if exceeds else "unresolved_uncertainty")
    except (KeyError, ValueError, TypeError, ZeroDivisionError, OverflowError):
        pass
    return result


def ipv4(value):
    return socket.inet_ntop(socket.AF_INET, struct.pack("=I", value))


def owned_role(event, owners, bound, backend_peers, frontend=("127.0.0.1", 8443)):
    """Full endpoint + known process generation, never a port-only inference."""
    owner = next((o for o in owners if o["pid"] == event["pid"] and o["cgroup_id"] == event["cgroup"]
                  and abs(o["start_ticks"] / o["ticks"] - event["process_start_ns"] / 1e9) <= 1 / o["ticks"]), None)
    if not owner or event["family"] != 2 or not event["cookie"]:
        return None
    local = (ipv4(event["local_ipv4"]), event["local_port"])
    peer = (ipv4(event["peer_ipv4"]), event["peer_port"])
    role = owner["role"]
    if role == "backend" and local == ("127.0.0.1", 3445):
        return "backend"
    if role == "client" and peer in (("127.0.0.1", 3445), ("127.0.0.1", 8443)):
        return "client"
    if role == "gateway":
        if (event["cookie"], local) in bound and local == frontend:
            return "gateway_frontend"
        # Quinn's unconnected send destination plus backend's actual connection peer.
        if peer == ("127.0.0.1", 3445) and ("127.0.0.1", local[1]) in backend_peers:
            return "gateway_upstream"
    return None


def group_history(events):
    """Observed membership operations only; never infer a group from equal ports."""
    membership, generations, history, gaps = {}, {}, [], []
    for e in sorted(events, key=lambda row: row['at_ns']):
        kind, cookie = e['kind'], e.get('cookie', 0)
        if e.get('result') != 0 or not cookie:
            continue
        if kind == 23:  # successful allocation can also mean an existing group
            if cookie not in membership:
                membership[cookie] = f"observed-{cookie}-{e['at_ns']}"
        elif kind == 24:
            peer = e.get('peer_cookie')
            if peer not in membership:
                gaps.append(dict(at_ns=e['at_ns'], reason='missing_peer_group', cookie=cookie))
                continue
            membership[cookie] = membership[peer]
        elif kind == 25:
            membership.pop(cookie, None)
        elif (kind == 14 and e.get('attachment_generation', 0)) or kind == 26:
            group = membership.get(cookie)
            if group is None:
                gaps.append(dict(at_ns=e['at_ns'], reason='attachment_without_group_history', cookie=cookie))
                continue
            generations[group] = generations.get(group, 0) + 1
            history.append(dict(at_ns=e['at_ns'], group=group, generation=generations[group],
                                kind=kind, cookie=cookie,
                                members=sorted(k for k, v in membership.items() if v == group),
                                instruction_digest_fnv1a64=e.get('instruction_digest_fnv1a64') if e.get('digest_valid') else None,
                                digest_is_cryptographic=False))
    return dict(history=history, gaps=gaps, complete=False,
                reason='site_readiness_and_event_loss_must_also_be_assessed')


def socket_lifetimes(events, boot, namespace_lifetime):
    records = {}
    for e in sorted(events, key=lambda row: row['at_ns']):
        cookie = e.get('cookie', 0)
        if not cookie or e['kind'] not in (18, 19, 20, 21): continue
        record = records.setdefault(cookie, dict(boot=boot, namespace_lifetime=namespace_lifetime,
            cookie=cookie, birth_ns=None, first_observed_ns=e['at_ns'], retirement_ns=None,
            final_drops=None, final_so_rcvbuf=None, final_so_sndbuf=None))
        if e['kind'] == 18:
            record['birth_ns'] = e['at_ns']
        elif e['kind'] == 20:
            record.update(retirement_ns=e['at_ns'], final_drops=e['drops'],
                          final_so_rcvbuf=e['so_rcvbuf'], final_so_sndbuf=e['so_sndbuf'])
    return list(records.values())
