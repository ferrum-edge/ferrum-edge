"""Hosted semantic fixtures for independently classified socket evidence gaps."""
import copy
import socket
import struct
import unittest

import live
from live_contract import calibration
import test_live_runtime as fixtures

NS = fixtures.NS


class SocketCoverageTests(unittest.TestCase):
    def setUp(self):
        fixture = fixtures.PassiveBoundaryTests()
        fixture.setUp()
        self.phases = fixture.phases
        self.timeline = [fixture.capture(at * NS, at * NS + 1000, i + 1)
                         for i, at in enumerate((999, 1001, 1029, 1031))]
        for row in self.timeline:
            row.update(boot_id='boot-a', netns=2)
            for sk in row['transport']['sockets']:
                for owner in sk['owners']:
                    owner.update(ticks=100, cgroup_id=5, netns=2, cgroup='/h3live123.slice/backend')
        # Backend socket retires late in the window, client survives both bounds.
        self.timeline[-1]['transport']['sockets'] = self.timeline[-1]['transport']['sockets'][1:]
        self.usage = dict(timeline=self.timeline)
        birth = dict(phase='lifecycle', cookie=42, at_ns=998 * NS, kind=18,
                     pid=42, tid=42, process_start_ns=70_000_000, thread_start_ns=70_000_000,
                     cgroup=5, netns=2, family=int(socket.AF_INET), result=0,
                     local_ipv4=0, local_port=0, peer_ipv4=0, peer_port=0,
                     so_rcvbuf=4194304, so_sndbuf=4194304, drops=0,
                     peer_cookie=0, attachment_generation=0, instruction_digest_fnv1a64=0,
                     program_type=0, instruction_count=0, digest_valid=0)
        ip = struct.unpack('=I', socket.inet_aton('127.0.0.1'))[0]
        retire = dict(birth, kind=20, at_ns=1029 * NS + 10000, drops=37,
                      local_ipv4=ip, local_port=3445, peer_ipv4=ip, peer_port=3445)
        streams = [r for r in fixtures.supported_results() if r['family'] in ('lifetime', 'destroy')]
        for stream in streams:
            stream.update(invocation='h3live123.slice', events=[birth if stream['family'] == 'lifetime' else retire])
            stream['final']['end_ns'] = 1040 * NS
        self.context = dict(invocation='h3live123.slice', boot_id='boot-a', netns=2, observers=streams,
                            namespace_lifetime=dict(inode=2, opened_ns=990 * NS, closed_ns=1041 * NS))

    def assess(self, context=True):
        return live.passive_roles(self.usage, [], 'direct', self.phases, self.context if context else None)

    def assert_failure(self, reason):
        result = self.assess()
        self.assertFalse(result['equal_socket_budget_verified'])
        self.assertIn(reason, result['socket_evidence_issues'])
        row = next(r for r in result['sockets'] if r['cookie'] == 42)
        self.assertIsNone(row['drops'])
        return result

    def test_actual_final_drop_completes_retirement_without_full_passive_bracket(self):
        result = self.assess()
        self.assertTrue(result['equal_socket_budget_verified'])
        self.assertTrue(result['observed_buffer_equality_verified'])
        row = result['sockets'][0]
        self.assertFalse(row['complete_bracket'])
        self.assertTrue(row['lifetime_covered'])
        self.assertEqual(row['lifetime_status'], 'witnessed_retirement_with_final_drop')
        self.assertEqual(row['drops'], {'socket_drops': 27})

    def test_untraced_unknown_cannot_be_filled_from_clean_client_or_repeat(self):
        result = self.assess(context=False)
        self.assertTrue(result['observed_buffer_equality_verified'])
        self.assertFalse(result['observed_lifetime_drop_coverage_verified'])
        self.assertIn('unobserved_disappearance', result['socket_evidence_issues'])
        self.assertIn('missing_final_drop', result['socket_evidence_issues'])
        self.assertIsNone(result['sockets'][0]['drops'])
        off = dict(rps=100, p99_us=100, traffic_issues=result['socket_evidence_issues'])
        on = dict(rps=100, p99_us=100, traffic_issues=[], observer_ok=True)
        self.assertFalse(calibration([(off, on), (off, on)])['active_main'])

    def test_unrelated_owned_backend_udp_sockets_still_reject_population(self):
        original = copy.deepcopy(self.usage)
        for port in (3005, 3006, 3999):
            for arm in ('direct', 'ferrum', 'envoy', 'envoy-limit-4'):
                with self.subTest(port=port, arm=arm):
                    self.usage = copy.deepcopy(original)
                    # A clean H3 lifetime cannot authorize a second owned socket,
                    # even with equal buffers and no drops. Include an unknown port
                    # so this cannot become an exception list for UDP/DTLS.
                    sockets = self.usage['timeline'][1]['transport']['sockets']
                    extra = copy.deepcopy(sockets[0])
                    extra.update(cookie=[99, 0], inode=99, local_port=port, peer_port=0, socket_drops=0)
                    sockets.append(extra)
                    result = live.passive_roles(self.usage, [], arm, self.phases, self.context)
                    self.assertIn('unassigned_owned_socket', result['socket_evidence_issues'])
                    self.assertFalse(result['equal_socket_budget_verified'])
                    self.assertFalse(result['observed_lifetime_drop_coverage_verified'])

    def test_missing_initial_boundary_is_not_excused_by_birth(self):
        self.timeline[0]['transport']['sockets'] = self.timeline[0]['transport']['sockets'][1:]
        self.assert_failure('missing_initial_boundary')

    def test_missing_middle_capture_is_not_excused_by_later_retirement(self):
        self.timeline[1]['transport']['sockets'] = self.timeline[1]['transport']['sockets'][1:]
        self.assert_failure('missing_capture')

    def test_wrong_observed_buffer_is_distinct_from_lifetime(self):
        self.timeline[1]['transport']['sockets'][0]['so_rcvbuf'] = 1024
        result = self.assess()
        self.assertFalse(result['observed_buffer_equality_verified'])
        self.assertTrue(result['observed_lifetime_drop_coverage_verified'])
        self.assertIn('wrong_buffer', result['socket_evidence_issues'])

    def test_missing_final_drop_never_becomes_zero(self):
        self.context['observers'][1]['events'][0]['drops'] = None
        result = self.assert_failure('missing_final_drop')
        self.assertTrue(result['observed_buffer_equality_verified'])

    def test_reused_cookie_namespace_boot_owner_and_foreign_repeat_fail(self):
        original = copy.deepcopy((self.usage, self.context))
        for case in ('inode', 'namespace', 'boot', 'owner', 'repeat', 'duplicate_birth'):
            with self.subTest(case=case):
                self.usage, self.context = copy.deepcopy(original)
                row = self.usage['timeline'][1]
                reason = 'cookie_or_owner_reuse'
                if case == 'inode': row['transport']['sockets'][0]['inode'] += 1
                elif case == 'namespace': row['netns'] += 1; reason = 'boot_or_namespace_changed'
                elif case == 'boot': row['boot_id'] = 'another-boot'; reason = 'boot_or_namespace_changed'
                elif case == 'owner': row['transport']['sockets'][0]['owners'][0]['start_ticks'] += 100
                elif case == 'repeat':
                    self.context['observers'][1]['invocation'] = 'other'; reason = 'retirement_capture_incomplete'
                else:
                    self.context['observers'][0]['events'] *= 2
                self.assert_failure(reason)

    def test_loss_and_mismatched_end_identity_never_authorize_retirement(self):
        self.context['observers'][1]['final']['ring_drops'] = 1
        self.assert_failure('retirement_capture_incomplete')
        self.context['observers'][1]['final']['ring_drops'] = 0
        self.context['observers'][1]['events'][0]['pid'] += 1
        self.assert_failure('retirement_identity_mismatch')

    def test_missing_role_has_its_own_reason(self):
        for row in self.timeline:
            row['transport']['sockets'] = [sk for sk in row['transport']['sockets'] if sk['cookie'][0] != 43]
        result = self.assess()
        self.assertEqual(result['missing_roles'], ['client'])
        self.assertIn('missing_role:client', result['socket_evidence_issues'])

    def test_retirement_cannot_skip_an_unobserved_tail_or_a_counter_reset(self):
        end = self.context['observers'][1]['events'][0]
        end['at_ns'] = 1032 * NS
        self.assert_failure('unobserved_disappearance')
        end['at_ns'] = 1029 * NS + 10000
        end['drops'] = 0
        self.assert_failure('drop_counter_decreased')

    def test_role_coverage_cannot_discard_a_traced_only_socket(self):
        base = self.context['observers'][1]['events'][0]
        self.context['observers'][1]['events'].append(dict(base, cookie=99))
        self.usage['owners'] = [dict(self.timeline[0]['transport']['sockets'][0]['owners'][0], role='backend')]
        result = self.assess()
        self.assertIn('lifetime_without_passive_identity', result['socket_evidence_issues'])
        self.assertFalse(result['observed_lifetime_drop_coverage_verified'])
        self.assertFalse(result['equal_socket_budget_verified'])


if __name__ == '__main__':
    unittest.main()
