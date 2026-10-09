"""Hosted regressions for clock correlation and fail-closed live admission."""
import copy
import socket
import struct
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import live
from evidence import LOSSES
from process_usage import IO_FIELDS, measurement_usage
from transport_diagnostics import bracket
from live_contract import (FAMILIES, calibration, measurement_window, measurement_position,
                           provenance_issues, observer_issues, smoke_issues,
                           sample_admission_issues, validate_observer_record, envoy_protocol_evidence)

NS = 1_000_000_000


class ObserverMemoryReservationTests(unittest.TestCase):
    def test_hosted_ubuntu_26_observations_fit_and_remain_recorded(self):
        # Run 37906469066: all four smoke arms and three idle fixtures exceeded
        # the former 32 MiB RSS reservation before their measurement bracket.
        for rss in (38965248, 38703104, 38739968, 38899712,
                    38875136, 38817792, 38981632):
            with self.subTest(rss=rss):
                record = {}
                live.observer_memory_checkpoint([SimpleNamespace(sample_cpu=lambda: rss)], record)
                self.assertEqual(record['observer_peak_combined_rss_bytes'], rss)
                reservation = record['observer_memory_reservation']
                self.assertEqual(reservation['kernel_maps_bytes'], 32 * 1024 * 1024)
                self.assertEqual(reservation['total_bytes'], 80 * 1024 * 1024)
                self.assertFalse(reservation['kernel_allocator_overhead_measured'])

    def test_combined_boundary_still_rejects_overflow_and_retains_peak(self):
        cap = 48 * 1024 * 1024
        record = {}
        live.observer_memory_checkpoint([SimpleNamespace(sample_cpu=lambda: cap)], record)
        with self.assertRaisesRegex(RuntimeError, 'observer_RSS_reservation_exceeded'):
            live.observer_memory_checkpoint([
                SimpleNamespace(sample_cpu=lambda: cap),
                SimpleNamespace(sample_cpu=lambda: 1)], record)
        self.assertEqual(record['observer_peak_combined_rss_bytes'], cap + 1)
        live.observer_memory_checkpoint([SimpleNamespace(sample_cpu=lambda: 1)], record)
        self.assertEqual(record['observer_peak_combined_rss_bytes'], cap + 1)


class PassiveBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.phases = dict(measurement_secs=30, measurement_elapsed_secs=30,
                           measurement_start_unix_secs=1_800_000_000,
                           measurement_start_host_clock=dict(clock='CLOCK_MONOTONIC',
                               before_ns=1000 * NS, after_ns=1000 * NS + 100),
                           client_usage=dict(pid=43, role='client', complete_bracket=True,
                                             cpu_seconds=2, peak_rss_bytes=4096))
        self.before = self.capture(999 * NS, 999 * NS + 1000, 1)
        self.cross_start = self.capture(1000 * NS - 10_000_000, 1000 * NS + 40_000_000, 2)
        self.middle = self.capture(1005 * NS, 1005 * NS + 1000, 3)
        self.cross_end = self.capture(1030 * NS - 10_000_000, 1030 * NS + 40_000_000, 4)
        self.after = self.capture(1031 * NS, 1031 * NS + 1000, 5)

    def capture(self, start, end, counter):
        owners = [dict(pid=42, start_ticks=7, role='backend', time_namespace=123),
                  dict(pid=43, start_ticks=8, role='client', time_namespace=123)]
        sockets = [dict(cookie=[p['pid'], 0], inode=p['pid'], family=socket.AF_INET,
                        local_address='127.0.0.1', local_port=3445 if p['role'] == 'backend' else 20000,
                        peer_address='127.0.0.1', peer_port=3445, owners=[dict(p)],
                        so_rcvbuf=4194304, so_sndbuf=4194304, socket_drops=counter * 10)
                   for p in owners]
        return dict(monotonic_ns=start, capture_end_ns=end, capture_ns=end - start,
                    unix_secs=1_800_000_000 + (start - 1000 * NS) / NS,
                    clock=dict(before_ns=start, after_ns=start + 100,
                               unix_ns=1_800_000_000 * NS + start - 1000 * NS),
                    processes=[dict(p, cpu_seconds=counter, rss_bytes=4096,
                                    io={key: counter * 100 for key in IO_FIELDS}) for p in owners],
                    transport=dict(errors=[], sockets=sockets))

    def assess(self, timeline):
        usage = dict(timeline=timeline, errors=[], capture_complete=True, available=True,
                     owners=copy.deepcopy(self.before['processes']),
                     processes=copy.deepcopy(self.before['processes']))
        raw = copy.deepcopy(usage)
        cpu = live.live_measurement_usage(usage, self.phases)
        budgets = live.passive_roles(usage, [], 'direct', self.phases)
        sample = dict(sample_schema=2, gateway='direct', duration_secs=30, phases=self.phases,
                      effective_concurrency=1, warmup_requests=1, total_errors=0, total_requests=3000,
                      payload_size=10240, total_bytes=3000 * 10240, rps=100, p99_us=100,
                      process_usage=dict(usage, measurement=cpu),
                      observed=dict(samples=1, workers_retired_before_deadline=0, workers_at_barrier=1,
                                    **{key: dict(min=1, max=1, mean=1) for key in
                                       ('active_workers', 'active_connections', 'active_streams', 'queued_requests')}))
        issues = live.sample_issues(sample)
        if not budgets['equal_socket_budget_verified']:
            issues.append('socket_budget_incomplete')
        issues.extend(provenance_issues(usage, measurement_window(self.phases, timeline), 123))
        issues = sample_admission_issues({}, issues)
        self.assertEqual(usage, raw)  # rejected/selected captures remain raw, never relabelled
        return cpu, budgets, issues

    def assert_rejected(self, timeline):
        cpu, budgets, issues = self.assess(timeline)
        self.assertFalse(cpu[0]['complete_bracket'])
        self.assertNotIn('cpu_seconds', cpu[0])
        self.assertNotIn('io', cpu[0])
        self.assertFalse(budgets['equal_socket_budget_verified'])
        self.assertTrue(budgets['sockets'])
        self.assertTrue(all(not row['complete_bracket'] for row in budgets['sockets']))
        self.assertTrue(all(row['drops'] is None for row in budgets['sockets']))
        self.assertIn('incomplete backend measurement bracket', issues)
        self.assertIn('socket_budget_incomplete', issues)
        off = dict(rps=100, p99_us=100, traffic_issues=[], observer_ok=True)
        on = dict(off, traffic_issues=issues)
        self.assertFalse(calibration([(off, on), (off, on)])['active_main'])

    def test_successful_start_crossing_with_narrow_clock_is_not_a_left_boundary(self):
        row = self.cross_start
        self.assertEqual(row['clock']['after_ns'] - row['clock']['before_ns'], 100)
        self.assertLess(row['unix_secs'], self.phases['measurement_start_unix_secs'])
        self.assertEqual(row['transport']['errors'], [])
        self.assert_rejected([row, self.middle, self.after])
        self.assertEqual(measurement_window(self.phases, [row, self.middle, self.after])['reason'],
                         'missing_passive_capture_bracket')

    def test_earlier_completed_capture_supplies_cpu_io_socket_and_drop_boundaries(self):
        older = self.capture(998 * NS, 998 * NS + 1000, 0)
        timeline = [older, self.before, self.cross_start, self.middle, self.cross_end, self.after]
        cpu, budgets, issues = self.assess(timeline)
        self.assertEqual(issues, [])
        self.assertTrue(cpu[0]['complete_bracket'])
        self.assertEqual(cpu[0]['cpu_seconds'], 4)
        self.assertEqual(cpu[0]['io'], {key: 400 for key in IO_FIELDS})
        self.assertEqual(cpu[0]['start_ticks'], 7)
        self.assertEqual(cpu[1], self.phases['client_usage'])
        self.assertTrue(budgets['equal_socket_budget_verified'])
        bounds = cpu[0]['capture_bracket']
        self.assertEqual(bounds['left_sample_index'], 1)
        self.assertEqual(bounds['right_sample_index'], 5)
        self.assertEqual(bounds['left_capture_bounds_ns'], [999 * NS, 999 * NS + 1000])
        self.assertEqual(bounds['right_capture_bounds_ns'], [1031 * NS, 1031 * NS + 1000])
        self.assertEqual(bounds['bracket_duration_bounds_ns'], [32 * NS - 1000, 32 * NS + 1000])
        self.assertEqual(bounds['start_slack_bounds_ns'], [NS - 1000, NS + 100])
        self.assertEqual(bounds['end_slack_bounds_ns'], [NS - 100, NS + 1000])
        for row in budgets['sockets']:
            self.assertEqual(row['capture_bracket'], bounds)
            self.assertEqual(row['drops'], {'socket_drops': 40})

    def test_end_crossing_capture_is_not_a_right_boundary(self):
        self.assert_rejected([self.before, self.middle, self.cross_end])
        # Even a start within the 100 ns end-boundary band is too early.
        end_band = self.capture(1030 * NS + 50, 1030 * NS + 1000, 4)
        self.assert_rejected([self.before, self.middle, end_band])

    def test_global_clock_bracket_cannot_substitute_for_resource_boundaries(self):
        for boundary in ('start', 'end'):
            with self.subTest(boundary=boundary):
                timeline = copy.deepcopy([self.before, self.cross_start, self.middle, self.cross_end, self.after])
                row = timeline[0 if boundary == 'start' else -1]
                row['processes'] = []
                row['transport']['sockets'] = []
                self.assertTrue(measurement_window(self.phases, timeline)['valid'])
                self.assert_rejected(timeline)

    def test_exact_outer_bounds_are_admitted_but_start_uncertainty_is_not(self):
        left = self.capture(999 * NS, 1000 * NS, 1)
        right = self.capture(1030 * NS + 100, 1030 * NS + 1000, 5)
        self.assertEqual(self.assess([left, self.middle, right])[2], [])
        left['capture_end_ns'] += 1
        left['capture_ns'] += 1
        self.assert_rejected([left, self.middle, right])

    def test_invalid_intervals_fail_closed_even_when_other_captures_bracket(self):
        mutations = [('capture_end_ns', None), ('capture_end_ns', 'bad'), ('capture_end_ns', True),
                     ('capture_end_ns', 1005 * NS - 1), ('capture_end_ns', 1005 * NS + 50),
                     ('monotonic_ns', None), ('monotonic_ns', 1005 * NS + 1),
                     ('capture_ns', -1), ('capture_ns', 1001)]
        for field, value in mutations:
            with self.subTest(field=field, value=value):
                middle = copy.deepcopy(self.middle)
                middle[field] = value
                self.assert_rejected([self.before, middle, self.after])
        for field in ('capture_end_ns', 'monotonic_ns'):
            with self.subTest(missing=field):
                middle = copy.deepcopy(self.middle)
                del middle[field]
                self.assert_rejected([self.before, middle, self.after])
        overlap = self.capture(999 * NS, 1006 * NS, 1)
        self.assert_rejected([overlap, self.middle, self.after])
        self.assertEqual(measurement_window(self.phases, [overlap, self.middle, self.after])['reason'],
                         'nonmonotonic_capture_interval')

    def test_overlapping_only_population_cannot_hide_as_pre_or_post_measurement(self):
        for only in (self.cross_start, self.cross_end):
            with self.subTest(start=only['monotonic_ns']):
                row = copy.deepcopy(only)
                row['processes'].append(dict(row['processes'][0], pid=99, start_ticks=10))
                row['transport']['sockets'].append(dict(row['transport']['sockets'][0], cookie=[99, 0]))
                cpu, budgets, issues = self.assess([self.before, row, self.after])
                extra = next(p for p in cpu if p['pid'] == 99)
                self.assertFalse(extra['complete_bracket'])
                extra_socket = next(sk for sk in budgets['sockets'] if sk['cookie'] == 99)
                self.assertFalse(extra_socket['complete_bracket'])
                self.assertNotIn(99, [sk['cookie'] for sk in budgets['probe_or_retired_outside_measurement']])
                self.assertIn('incomplete backend measurement bracket', issues)
                self.assertIn('socket_budget_incomplete', issues)

    def test_selected_endpoints_do_not_hide_missing_or_reused_population(self):
        for mode in ('missing', 'reused', 'duplicate'):
            with self.subTest(mode=mode):
                middle = copy.deepcopy(self.cross_start)
                if mode == 'missing':
                    middle['processes'] = []
                    middle['transport']['sockets'] = []
                elif mode == 'reused':
                    middle['processes'][0]['start_ticks'] += 1
                    middle['transport']['sockets'] = []
                else:
                    middle['processes'] += copy.deepcopy(middle['processes'])
                    middle['transport']['sockets'] += copy.deepcopy(middle['transport']['sockets'])
                self.assert_rejected([self.before, middle, self.after])

    def test_skipped_crossing_read_still_checks_buffers_and_io_counters(self):
        row = copy.deepcopy(self.cross_start)
        row['transport']['sockets'][0]['so_rcvbuf'] = 1024
        row['processes'][0]['io']['read_bytes'] = 9999
        cpu, budgets, issues = self.assess([self.before, row, self.after])
        self.assertTrue(cpu[0]['complete_bracket'])
        self.assertNotIn('io', cpu[0])
        self.assertIn('io_error', cpu[0])
        self.assertFalse(budgets['equal_socket_budget_verified'])
        self.assertIn('socket_budget_incomplete', issues)

    def test_historical_point_contract_is_unchanged_and_not_a_live_fallback(self):
        timeline = copy.deepcopy([self.before, self.middle, self.after])
        for row in timeline:
            for key in ('clock', 'monotonic_ns', 'capture_end_ns', 'capture_ns'):
                del row[key]
        self.assertTrue(measurement_usage(dict(timeline=timeline), self.phases)[0]['complete_bracket'])
        self.assertIsNotNone(bracket(timeline, self.phases['measurement_start_unix_secs'],
                                     self.phases['measurement_start_unix_secs'] + 30))
        self.assert_rejected(timeline)

    def test_passive_producer_retains_successful_delayed_capture_interval(self):
        monitor = live.Passive.__new__(live.Passive)
        monitor.timeline, monitor.owners, monitor.errors, monitor.transitions = [], {}, [], []
        monitor.arm = 'direct'
        monitor.stop = Mock()
        monitor.stop.is_set.side_effect = [False, True]
        monitor.scope = SimpleNamespace(rglob=lambda _: [SimpleNamespace(
            parent=SimpleNamespace(name='backend'), read_text=lambda: '42')])
        path = Mock()
        path.iterdir.return_value = [SimpleNamespace(name='7')]
        path.read_text.return_value = 'raw host diagnostic'
        owner = self.cross_start['processes'][0]
        read_times = []

        def read_process(*_):
            read_times.append(live.time.monotonic_ns())
            return dict(owner)

        with patch('live.Path', return_value=path), patch('live.owner', return_value=owner), \
                patch('live.capture', side_effect=read_process), patch('live.thread_snapshot', return_value=[]), \
                patch('live.os.readlink', return_value='socket:[42]'), \
                patch('live.snapshot', return_value=copy.deepcopy(self.cross_start['transport'])), \
                patch('live.time.time_ns', return_value=self.cross_start['clock']['unix_ns']), \
                patch('live.time.thread_time_ns', return_value=1), \
                patch('live.time.monotonic_ns', side_effect=[1000 * NS - 10_000_000,
                    1000 * NS - 10_000_000 + 100, 1000 * NS + 30_000_000, 1000 * NS + 40_000_000]):
            monitor.run()
        self.assertEqual(monitor.errors, [])
        self.assertEqual(read_times, [1000 * NS + 30_000_000])
        self.assertEqual(monitor.timeline[0]['capture_end_ns'], 1000 * NS + 40_000_000)
        self.assertEqual(monitor.timeline[0]['capture_ns'], 50_000_000)
        self.assertEqual(len(monitor.timeline[0]['transport']['sockets']), 1)
        self.assert_rejected(monitor.timeline + [self.middle, self.after])


def supported_results():
    return [dict(family=f, ready=dict(phase='ready', status='supported', family=f,
                 start_ns=1, netns=2, links=1), error=None, returncode=0, capture_complete=True,
                 final=dict(phase='final', start_ns=1, end_ns=50, rows=[], losses=[0] * len(LOSSES),
                            map_read_failures=0, pending_tx=0, pending_rx=0, pending_selector=0,
                            pending_detach=0, ring_drops=0, verifier_log_truncated=False),
                 termination=dict(phase='termination', requested_stop=True, signal=False,
                                  forced_or_parent_death=False, snapshot_failures=0,
                                  lifecycle_omitted=0, checkpoints_omitted=0)) for f in FAMILIES]


class LiveRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.phases = dict(measurement_start_monotonic_secs=3.0, measurement_secs=30,
                           measurement_start_unix_secs=1_800_000_000,
                           measurement_start_host_clock=dict(clock='CLOCK_MONOTONIC',
                               before_ns=1000 * NS, after_ns=1000 * NS + 100))
        self.timeline = [dict(monotonic_ns=at * NS, capture_end_ns=at * NS + 1000,
                             clock=dict(before_ns=at * NS, after_ns=at * NS + 100,
                                        unix_ns=(1_800_000_000 + at - 1000) * NS),
                             transport=dict(errors=[])) for at in (999, 1001, 1031)]
        self.usage = dict(timeline=self.timeline, errors=[], capture_complete=True,
                          owners=[dict(role='client', time_namespace=123)])

    def test_process_epoch_is_never_host_time(self):
        window = measurement_window(self.phases, self.timeline)
        self.assertTrue(window['valid'])
        self.assertEqual(measurement_position(1005 * NS, window), 'measurement')
        self.assertEqual(measurement_position(5 * NS, window), 'outside')
        del self.phases['measurement_start_host_clock']
        self.assertFalse(measurement_window(self.phases, self.timeline)['valid'])

    def test_boundary_uncertainty_is_not_positive_measurement_evidence(self):
        window = measurement_window(self.phases, self.timeline)
        for at, expected in [(1000 * NS - 1, 'outside'), (1000 * NS, 'boundary_uncertain'),
                             (1000 * NS + 100, 'measurement'),
                             (1030 * NS, 'boundary_uncertain'), (1030 * NS + 100, 'outside'),
                             (None, 'unknown')]:
            self.assertEqual(measurement_position(at, window), expected)

    def test_missing_wide_or_mismatched_clocks_fail_closed(self):
        for clock in (None, {}, dict(clock='process_local', before_ns=3 * NS, after_ns=3 * NS + 10),
                      dict(clock='CLOCK_MONOTONIC', before_ns=1000 * NS, after_ns=1000 * NS + 1_000_001),
                      dict(clock='CLOCK_MONOTONIC', before_ns=1000 * NS, after_ns=999 * NS)):
            with self.subTest(clock=clock):
                phases = dict(self.phases, measurement_start_host_clock=clock)
                self.assertFalse(measurement_window(phases, self.timeline)['valid'])
        self.assertFalse(measurement_window(self.phases, self.timeline[:-1])['valid'])
        for duration in (0, -1, None, float('nan'), float('inf'), True):
            self.assertFalse(measurement_window(dict(self.phases, measurement_secs=duration), self.timeline)['valid'])
        bad = dict(self.phases, measurement_start_unix_secs=1_800_000_030)
        self.assertFalse(measurement_window(bad, self.timeline)['valid'])

    def test_clock_jump_and_nonmonotonic_capture_fail_closed(self):
        for shift in (-NS, NS):
            timeline = copy.deepcopy(self.timeline)
            timeline[1]['clock']['unix_ns'] += shift
            self.assertEqual(measurement_window(self.phases, timeline)['reason'], 'realtime_clock_jump')
        timeline = copy.deepcopy(self.timeline)
        timeline[1]['clock'] = timeline[0]['clock']
        self.assertFalse(measurement_window(self.phases, timeline)['valid'])

    def test_error_intervals_and_untimed_errors_are_conservative(self):
        window = measurement_window(self.phases, self.timeline)
        self.assertEqual(provenance_issues(self.usage, window, 123), [])
        for error in ({'error': 'cap'}, dict(at_ns=1005 * NS, end_ns=1005 * NS),
                      dict(at_ns=999 * NS, end_ns=1000 * NS), dict(at_ns=1000 * NS + 50),
                      dict(at_ns=1005 * NS, end_ns=1004 * NS)):
            self.usage['errors'] = [error]
            self.assertIn('process_provenance_incomplete', provenance_issues(self.usage, window, 123))
        self.usage['errors'] = [dict(at_ns=998 * NS, end_ns=999 * NS)]
        self.assertEqual(provenance_issues(self.usage, window, 123), [])
        self.usage['timeline'][1]['transport']['errors'] = ['diagnostic dump failed']
        self.assertIn('process_provenance_incomplete', provenance_issues(self.usage, window, 123))
        self.assertIn('process_clock_namespace_unverified', provenance_issues(self.usage, window, 124))

    def test_real_proof_path_keeps_only_definite_measurement_witnesses(self):
        ip = struct.unpack('=I', socket.inet_aton('127.0.0.1'))[0]
        event = dict(phase='lifecycle', kind=21, cookie=7, pid=10, process_start_ns=NS,
                     cgroup=3, family=2, local_ipv4=ip, local_port=20000, peer_ipv4=ip,
                     peer_port=3445, at_ns=999 * NS, result=0)
        witness = dict(phase='witness', kind=1, cookie=7, pid=10, process_start_ns=NS,
                       at_ns=1005 * NS, result=4096, length=4096, segment=1024)
        observer = SimpleNamespace(family='tx', ready={'status': 'supported'}, error=None,
                                   rows=[event, witness, dict(witness, at_ns=1000 * NS),
                                         dict(witness, at_ns=5 * NS)])
        self.usage['owners'][0].update(pid=10, cgroup_id=3, start_ticks=100, ticks=100)
        args = ([observer], self.usage, [], dict(phases=self.phases),
                dict(boot_id='boot', time_namespace=123), {}, 'direct')
        proof = live.proof(*args)
        self.assertEqual([r['at_ns'] for r in proof['positive']], [1005 * NS])
        self.assertEqual(len(proof['uncorrelated_positive']), 1)
        self.assertFalse(proof['absence_claim_allowed'])
        self.phases['measurement_start_host_clock'] = None
        proof = live.proof(*args)
        self.assertEqual(proof['positive'], [])
        self.assertFalse(proof['measurement_clock']['valid'])
        self.assertFalse(proof['absence_claim_allowed'])

    def test_malformed_diagnostics_or_capture_errors_never_pass(self):
        results = supported_results()
        self.assertEqual(observer_issues(results), [])
        for field, value in [('ready', {}), ('final', {}), ('termination', None),
                             ('capture_complete', False), ('error', 'observer_artifact_cap'),
                             ('error', 'observer_resource_capture_failed'), ('returncode', 1)]:
            bad = copy.deepcopy(results)
            bad[0][field] = value
            self.assertTrue(observer_issues(bad), (field, value))
        self.assertTrue(observer_issues(results[:-1]))
        for field, value in [('losses', []), ('map_read_failures', 1), ('map_read_failures', None),
                             ('start_ns', 'bad'), ('pending_tx', False),
                             ('verifier_log_truncated', True), ('verifier_log_truncated', None),
                             ('verifier_log_truncated', 0)]:
            bad = copy.deepcopy(results)
            bad[0]['final'][field] = value
            self.assertTrue(observer_issues(bad), (field, value))
        for row in ([], {}, {'phase': 'unknown'}, dict(phase='ready', status='bogus')):
            with self.assertRaises(ValueError): validate_observer_record(row, 'tx')

    def test_attachment_load_error_survives_valid_schema_and_admission(self):
        results = supported_results()
        attachment = next(r for r in results if r['family'] == 'attach')
        for truncated in (False, True):
            attachment.update(ready=dict(phase='ready', status='error', reason='load',
                                        errno=28, verifier_log_truncated=truncated),
                              final=None, termination=None, returncode=1)
            validate_observer_record(attachment['ready'], 'attach')
            self.assertTrue(any(i.startswith('attach:') for i in observer_issues(results)))
            self.assertEqual(attachment['ready']['errno'], 28)

    def test_lifecycle_cap_loss_invalidates_otherwise_complete_role_proof(self):
        roles = ['backend', 'client', 'gateway_frontend', 'gateway_upstream']
        evidence = dict(operation_coverage={r: [2, 6] for r in roles},
                        roles=[dict(cookie=i + 1, role=r) for i, r in enumerate(roles)],
                        socket_lifetimes=[dict(cookie=i + 1, birth_ns=10, retirement_ns=20) for i in range(4)])
        for family in FAMILIES:
            for omitted in (1, 71701):  # one row is enough; latter is retained direct/destroy loss
                with self.subTest(family=family, omitted=omitted):
                    results = supported_results()
                    result = next(r for r in results if r['family'] == family)
                    result['termination']['lifecycle_omitted'] = omitted
                    self.assertEqual(smoke_issues(evidence, results, 'envoy'), [])
                    errors = observer_issues(results)
                    self.assertEqual(errors, [f'{family}:observer_lifecycle_incomplete'])
                    issues = sample_admission_issues(dict(observer_errors=errors), [])
                    off = dict(rps=100, p99_us=100, traffic_issues=[], observer_ok=True)
                    on = dict(off, traffic_issues=issues)
                    self.assertFalse(calibration([(off, on), (off, on)])['active_main'])
                    self.assertEqual(result['termination']['lifecycle_omitted'], omitted)

    def test_lifecycle_ring_loss_cannot_pass_before_output_cap(self):
        for family in FAMILIES:
            for field in ('ring_drops', 'losses'):
                with self.subTest(family=family, field=field):
                    results = supported_results()
                    result = next(r for r in results if r['family'] == family)
                    if field == 'losses':
                        result['final']['losses'][LOSSES.index('ring_full')] = 4021
                    else:
                        result['final']['ring_drops'] = 3941
                    self.assertEqual(result['termination']['lifecycle_omitted'], 0)
                    self.assertEqual(observer_issues(results), [f'{family}:observer_lifecycle_incomplete'])

    def test_missing_observer_resource_capture_is_an_error(self):
        observer = live.Observer.__new__(live.Observer)
        observer.process = SimpleNamespace(pid=123)
        observer.ready, observer.cpu, observer.error = {'status': 'supported'}, [], None
        with patch('live.capture', return_value=None):
            observer.sample_cpu()
        self.assertEqual(observer.error, 'observer_resource_capture_failed')

    def test_only_detached_final_rows_require_stable_counts_and_times(self):
        snapshot = supported_results()[0]['final']
        for count, last in [(0, 0), (1, 51)]:
            snapshot['rows'] = [dict(cookie=7, peer_cookie=0, kind=2, count=count,
                                    first_ns=20, last_ns=last, length=0, segment=0, cpu=0, result=0)]
            with self.assertRaises(ValueError): validate_observer_record(snapshot, 'tx')
            validate_observer_record(dict(snapshot, phase='checkpoint'), 'tx')

    def test_smoke_requires_each_role_operations_and_lifecycle(self):
        roles = ['backend', 'client', 'gateway_frontend', 'gateway_upstream']
        evidence = dict(operation_coverage={r: [2, 6] for r in roles},
                        roles=[dict(cookie=i + 1, role=r) for i, r in enumerate(roles)],
                        socket_lifetimes=[dict(cookie=i + 1, birth_ns=10, retirement_ns=20) for i in range(4)])
        results = supported_results()
        results[-1]['ready'] = dict(phase='ready', status='unsupported', errno=2,
                                   verifier_log_truncated=False, reason='missing_run_bpf_filter_execution_site')
        results[-1].update(final=None, termination=None)
        self.assertEqual(observer_issues(results), [])
        self.assertEqual(smoke_issues(evidence, results, 'envoy'), [])
        for i, role in enumerate(roles):
            bad = copy.deepcopy(evidence)
            del bad['operation_coverage'][role]
            self.assertIn(f'smoke_missing_operation_role:{role}', smoke_issues(bad, results, 'envoy'))
            bad = copy.deepcopy(evidence)
            bad['socket_lifetimes'][i]['retirement_ns'] = None
            self.assertIn(f'smoke_missing_lifecycle_role:{role}', smoke_issues(bad, results, 'envoy'))
        results[0]['ready'] = results[-1]['ready']
        self.assertIn('smoke_required_family_unavailable:tx', smoke_issues(evidence, results, 'envoy'))

    def test_late_failures_reach_calibration_and_traffic_validity(self):
        off = dict(rps=100, p99_us=100, traffic_issues=[], observer_ok=True)
        for record in (dict(status='error', reason='observer_RSS_reservation_exceeded'),
                       dict(artifact_cap_exceeded=True), dict(observer_errors=['malformed_final']),
                       dict(smoke_issues=['smoke_missing_lifecycle_role:client'])):
            issues = sample_admission_issues(record, [])
            self.assertTrue(issues)
            on = dict(off, traffic_issues=issues)
            self.assertFalse(calibration([(off, on), (off, on)])['active_main'])

    def test_malformed_envoy_counters_cannot_confirm_protocol_or_no_retries(self):
        counters = dict(upstream_cx_http1_total=0, upstream_cx_http2_total=0,
                        upstream_rq_retry=0, upstream_rq_retry_success=0,
                        upstream_rq_timeout=0, upstream_cx_http3_total=4)
        document = dict(stats=[dict(name='cluster.backend_h3.' + k, value=v) for k, v in counters.items()])
        self.assertEqual(envoy_protocol_evidence(document), counters)
        for key in (0, 5):
            for value in (None, True, False, float('nan'), float('inf'), -1, '0'):
                bad = copy.deepcopy(document)
                bad['stats'][key]['value'] = value
                with self.assertRaises(ValueError): envoy_protocol_evidence(bad)
        for stats in (document['stats'][:-1], document['stats'] + [document['stats'][0]], [], [None]):
            with self.assertRaises(ValueError): envoy_protocol_evidence(dict(stats=stats))
        document['stats'][0]['value'] = 1
        with self.assertRaises(ValueError): envoy_protocol_evidence(document)


if __name__ == '__main__':
    unittest.main()
