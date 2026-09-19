"""Hosted semantic tests. No gateway or observer is launched by these tests."""
import copy
import json
from pathlib import Path
import socket
import struct
import sys
import unittest

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from h3_experiment import envoy_config
from live_contract import (assert_upstream_only, calibration, group_history, manifest,
                           owned_role, socket_lifetimes)
from transport_diagnostics import envoy_counter_provenance

HERE = Path(__file__).resolve().parent


class LiveContracts(unittest.TestCase):
    def test_manifest_is_finite_and_ordinary_experiment_stays_disabled(self):
        plan = manifest(HERE / 'live_campaign.json')
        self.assertEqual(len(plan['payloads']) * len(plan['arms']) * plan['pairs'], 80)
        self.assertEqual(plan['workers'], [200, 200, 200, 100, 50])
        self.assertEqual(plan['client_connections'], [21, 21, 21, 11, 6])
        self.assertFalse(json.loads((HERE.parent / 'experiment.json').read_text())['enabled'])

    def test_real_envoy_config_diff_only_changes_upstream_limit(self):
        source = (HERE.parent / 'configs/envoy/http3.yaml').read_text()
        a = yaml.safe_load(envoy_config(source, 100, 4194304, upstream_only=True))
        b = yaml.safe_load(envoy_config(source, 4, 4194304, upstream_only=True))
        self.assertEqual(len(assert_upstream_only(a, b)), 1)
        text = envoy_config(source, 4, 4194304, upstream_only=True)
        self.assertIn('sni: localhost', text)
        self.assertIn('filename: CA_PATH', text)
        self.assertNotIn('retry_policy:', text)
        self.assertIn('timeout: 0s', text)
        self.assertEqual(text.count('int_value: 2097152'), 4)
        tls = a['static_resources']['clusters'][0]['transport_socket']['typed_config']['upstream_tls_context']
        self.assertEqual(tls['sni'], 'localhost')
        self.assertEqual(tls['common_tls_context']['validation_context'],
                         dict(trusted_ca=dict(filename='CA_PATH'),
                              match_typed_subject_alt_names=[dict(san_type='DNS', matcher=dict(exact='localhost'))]))
        broken = copy.deepcopy(b)
        broken['static_resources']['listeners'][0]['per_connection_buffer_limit_bytes'] = 1
        with self.assertRaises(ValueError): assert_upstream_only(a, broken)
        historical = yaml.safe_load(envoy_config(source, 4, 4194304))
        with self.assertRaises(ValueError): assert_upstream_only(a, historical)

    def test_ferrum_existing_identity_override_keeps_one_numeric_target(self):
        config = yaml.safe_load((HERE.parent / 'configs/http3_perf.yaml').read_text())
        proxy = next(p for p in config['proxies'] if p['id'] == 'h3-echo')
        upstream = next(u for u in config['upstreams'] if u['id'] == proxy['upstream_id'])
        self.assertEqual(upstream['targets'], [dict(host='127.0.0.1', port=3445, weight=1)])
        self.assertEqual(upstream['backend_tls_sni'], 'localhost')
        self.assertIs(upstream['backend_tls_verify_server_cert'], True)
        self.assertEqual(upstream['backend_tls_server_ca_cert_path'], 'CA_PATH')
        self.assertNotIn('retry', proxy)
        # Structural contract supplements the actual hosted positive/negative
        # handshakes. It cannot establish TLS behavior by itself.

    def test_calibration_never_passes_missing_or_uncertain_data(self):
        off = dict(rps=100, p99_us=100, traffic_issues=[], observer_ok=True)
        self.assertFalse(calibration([])['active_main'])
        self.assertFalse(calibration([(off, off)])['active_main'])
        self.assertTrue(calibration([(off, off), (off, off)])['active_main'])
        uncertain = [(off, dict(off, rps=99)), (off, dict(off, rps=101))]
        self.assertEqual(calibration(uncertain)['reason'], 'unresolved_uncertainty')
        bad = dict(off, traffic_issues=['missing_role'])
        self.assertFalse(calibration([(off, bad), (off, off)])['active_main'])
        missing = dict(off, observer_ok=False)
        self.assertFalse(calibration([(off, missing), (off, off)])['active_main'])
        high = dict(off, p99_us=110)
        self.assertEqual(calibration([(off, high), (off, high)])['reason'], 'exceeds_tolerance')

    def test_port_only_or_reused_pid_cannot_assign_gateway_role(self):
        ip = lambda value: struct.unpack('=I', socket.inet_aton(value))[0]
        event = dict(pid=10, cgroup=7, process_start_ns=1000000000, family=2,
                     cookie=123, local_ipv4=ip('127.0.0.1'), local_port=8443,
                     peer_ipv4=0, peer_port=0)
        owners = [dict(pid=10, cgroup_id=7, start_ticks=100, ticks=100, role='gateway')]
        self.assertIsNone(owned_role(event, owners, set(), set()))
        bound = {(123, ('127.0.0.1', 8443))}
        self.assertEqual(owned_role(event, owners, bound, set()), 'gateway_frontend')
        self.assertIsNone(owned_role(dict(event, process_start_ns=2000000000), owners, bound, set()))
        self.assertIsNone(owned_role(dict(event, cgroup=8), owners, bound, set()))
        self.assertIsNone(owned_role(dict(event, cookie=124), owners, bound, set()))
        upstream = dict(event, local_port=30000, peer_ipv4=ip('127.0.0.1'), peer_port=3445)
        self.assertIsNone(owned_role(upstream, owners, bound, set()))
        self.assertEqual(owned_role(upstream, owners, bound, {('127.0.0.1', 30000)}), 'gateway_upstream')

    def test_retirement_requires_kernel_event(self):
        row = dict(cookie=1, at_ns=10, kind=21)
        lifetime = socket_lifetimes([row], 'boot', {'inode': 123})[0]
        self.assertIsNone(lifetime['birth_ns'])
        self.assertIsNone(lifetime['retirement_ns'])
        self.assertIsNone(lifetime['final_drops'])
        retired = dict(row, kind=20, at_ns=20, drops=3, so_rcvbuf=4194304, so_sndbuf=4194304)
        lifetime = socket_lifetimes([row, retired], 'boot', {'inode': 123})[0]
        self.assertEqual(lifetime['retirement_ns'], 20)
        self.assertEqual(lifetime['final_drops'], 3)

    def test_membership_comes_from_successful_kernel_operations(self):
        events = [dict(cookie=1, kind=23, result=0, at_ns=1),
                  dict(cookie=2, peer_cookie=1, kind=24, result=0, at_ns=2),
                  dict(cookie=1, kind=14, result=0, at_ns=3, attachment_generation=1),
                  dict(cookie=2, kind=25, result=0, at_ns=4),
                  dict(cookie=1, kind=14, result=0, at_ns=5, attachment_generation=2)]
        history = group_history(events)['history']
        self.assertEqual(history[0]['members'], [1, 2])
        self.assertEqual(history[1]['members'], [1])
        self.assertEqual(history[1]['generation'], 2)
        broken = copy.deepcopy(events)
        broken[1]['result'] = -12
        self.assertEqual(group_history(broken)['history'][0]['members'], [1])

    def test_corrected_counter_provenance_does_not_relabel_history(self):
        plan = manifest(HERE / 'live_campaign.json')
        corrected = envoy_counter_provenance(plan['envoy_image'])
        self.assertEqual(corrected['source'], plan['envoy_source'])
        self.assertFalse(corrected['exact_kernel_loss_claim'])
        self.assertIn('inflated', envoy_counter_provenance('envoy:v1.33.5')['semantics'])
        self.assertEqual(envoy_counter_provenance()['semantics'], 'unverified_image_source')


if __name__ == '__main__':
    unittest.main()
