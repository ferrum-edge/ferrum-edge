import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from benchmark_validity import sample_issues
from h2_cpu_profile import ENVIRONMENT, fixture, report, stamp, validate_runtime


class H2CPUAdmissionTests(unittest.TestCase):
    def runtime(self, protocol='http2', gateway='ferrum'):
        config = fixture(protocol, gateway)
        runtime = dict(protocol=protocol, gateway=gateway, pair=1, network_mode='host',
                       running=True, image_id='sha256:' + 'a' * 64, user='65532:65532',
                       cap_drop=['ALL'], config_sha256=hashlib.sha256(config).hexdigest())
        if gateway == 'ferrum':
            runtime['environment'] = dict(zip(ENVIRONMENT,
                ('file', '8443', '0', 'false', '8388608', '33554432')))
        return config, runtime

    def test_fixed_ferrum_and_envoy_fixtures_admit_both_protocols(self):
        for protocol in ('http2', 'grpcs'):
            for gateway in ('ferrum', 'envoy'):
                with self.subTest(protocol=protocol, gateway=gateway):
                    config, runtime = self.runtime(protocol, gateway)
                    validate_runtime(dict(arm=gateway, pair=1), runtime, config, protocol)

    def test_wrong_workload_container_policy_or_config_is_rejected(self):
        for field, value in [('protocol', 'http3'), ('gateway', 'direct'), ('pair', 2),
                             ('network_mode', 'bridge'), ('running', False),
                             ('image_id', 'mutable-tag'), ('user', '0'), ('cap_drop', [])]:
            with self.subTest(field=field):
                config, runtime = self.runtime()
                runtime[field] = value
                with self.assertRaises(ValueError):
                    validate_runtime(dict(arm='ferrum', pair=1), runtime, config, 'http2')
        config, runtime = self.runtime()
        with self.assertRaises(ValueError):
            validate_runtime(dict(arm='ferrum', pair=1), runtime, config + b'\n', 'http2')
        runtime['environment']['FERRUM_POOL_HTTP2_ADAPTIVE_WINDOW'] = 'true'
        with self.assertRaises(ValueError):
            validate_runtime(dict(arm='ferrum', pair=1), runtime, config, 'http2')

    def test_cpu_and_counter_controls_cannot_enter_ordinary_scoreboards(self):
        for mode in ('off', 'counters', 'cpu'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'sample.json'
                path.write_text('{"rps":100}')
                stamp(path, mode)
                sample = json.loads(path.read_text())
                self.assertEqual(sample['h2_cpu_profile']['mode'], mode)
                self.assertIn('H2 CPU profiling campaign: diagnostic only', sample_issues(sample))

    def test_missing_campaign_is_retained_as_incomplete_not_an_empty_success(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(report(directory), 1)
            result = json.loads((Path(directory) / 'h2-cpu-report.json').read_text())
            self.assertFalse(result['complete'])
            self.assertEqual(len(result['observations']), 24)
            self.assertTrue(all(row['issues'] for row in result['observations']))
            self.assertTrue(all(not row['comparable'] for row in result['calibration']))


    def campaign(self, directory):
        root = Path(directory)
        for campaign, mode in (('control-before', 'off'), ('counters', 'counters'),
                               ('cpu', 'cpu'), ('control-after', 'off')):
            for pair in (1, 2):
                folder = root / campaign / 'pairs' / f'pair_{pair:03d}'
                (folder / 'diagnostics').mkdir(parents=True)
                for gateway in ('direct', 'ferrum', 'envoy'):
                    roles = ['backend', 'client'] + (['gateway'] if gateway != 'direct' else [])
                    usage = [dict(role=role, pid=index + 1, complete_bracket=True,
                                  cpu_seconds=5, user_cpu_seconds=4, system_cpu_seconds=1,
                                  bracket_secs=15, voluntary_ctxt_switches=7, nonvoluntary_ctxt_switches=3,
                                  context_switches=dict(scope='all process threads',
                                      voluntary_ctxt_switches=7, nonvoluntary_ctxt_switches=3))
                             for index, role in enumerate(roles)]
                    sample = dict(sample_schema=2, gateway=gateway, pair=pair, host_id='one-runner',
                                  protocol='http2', payload_size=10240, duration_secs=15,
                                  effective_concurrency=200, warmup_requests=200,
                                  total_requests=1500, total_errors=0, total_bytes=1500 * 10240, rps=100,
                                  phases=dict(measurement_secs=15, measurement_elapsed_secs=15.01, timed_out=False),
                                  observed=dict(samples=20, workers_at_barrier=200,
                                                workers_retired_before_deadline=0),
                                  process_usage=dict(processes=usage, measurement=usage))
                    for name in ('active_workers', 'active_connections', 'active_streams', 'queued_requests'):
                        sample['observed'][name] = dict(min=0, max=200, mean=100)
                    path = folder / f'{gateway}_http2_10240.json'
                    path.write_text(json.dumps(sample))
                    stamp(path, mode)
                    if gateway != 'direct':
                        config, runtime = self.runtime(gateway=gateway)
                        runtime['pair'] = pair
                        (folder / 'diagnostics' / f'{gateway}_runtime.json').write_text(json.dumps(runtime))
                        (folder / 'diagnostics' / f'{gateway}_config.yaml').write_bytes(config)
                        if mode == 'cpu':
                            trace = folder / 'traces' / f'{gateway}_10240'
                            trace.mkdir(parents=True)
                            (trace / 'trace-manifest.json').write_text(json.dumps(dict(
                                capture_complete=True, mode='cpu', cpu=dict(samples=100),
                                binding=dict(arm=gateway, pair=pair, payload=10240, h2_protocol='http2'))))
        return root / 'counters/pairs/pair_001/ferrum_http2_10240.json'

    def test_complete_campaign_calibrates_all_roles_and_preserves_controls(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.campaign(directory)
            self.assertEqual(report(directory), 0)
            result = json.loads((Path(directory) / 'h2-cpu-report.json').read_text())
            self.assertTrue(result['complete'])
            self.assertEqual(len(result['observations']), 24)
            self.assertTrue(all(row['comparable'] for row in result['calibration']))
            self.assertTrue(all(row['median_rps_overhead_percent'] == 0 for row in result['calibration']))
            self.assertTrue(json.loads(path.read_text())['h2_cpu_profile']['diagnostic_only'])

    def test_inconsistent_corrupt_or_incomplete_evidence_keeps_a_failed_report(self):
        for fault in ('json', 'not-object', 'duplicate-role', 'negative-counter', 'missing-scope',
                      'nonfinite-cpu', 'wrong-pair', 'wrong-gateway', 'mixed-image', 'wrong-capture'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                path = self.campaign(directory)
                sample = json.loads(path.read_text())
                if fault == 'duplicate-role':
                    sample['process_usage']['measurement'].append(sample['process_usage']['measurement'][0])
                elif fault == 'negative-counter':
                    sample['process_usage']['measurement'][0]['context_switches']['voluntary_ctxt_switches'] = -1
                elif fault == 'missing-scope':
                    del sample['process_usage']['measurement'][0]['context_switches']['scope']
                elif fault == 'nonfinite-cpu':
                    sample['process_usage']['measurement'][0]['user_cpu_seconds'] = float('nan')
                elif fault == 'wrong-pair':
                    sample['pair'] = 2
                elif fault == 'wrong-gateway':
                    sample['gateway'] = 'envoy'
                elif fault == 'mixed-image':
                    runtime_path = path.parent / 'diagnostics/ferrum_runtime.json'
                    runtime = json.loads(runtime_path.read_text())
                    runtime['image_id'] = 'sha256:' + 'b' * 64
                    runtime_path.write_text(json.dumps(runtime))
                elif fault == 'wrong-capture':
                    capture_path = Path(directory) / 'cpu/pairs/pair_001/traces/ferrum_10240/trace-manifest.json'
                    capture = json.loads(capture_path.read_text())
                    capture['binding']['arm'] = 'envoy'
                    capture_path.write_text(json.dumps(capture))
                path.write_text('{' if fault == 'json' else '[]' if fault == 'not-object' else json.dumps(sample))
                self.assertEqual(report(directory), 1)
                result = json.loads((Path(directory) / 'h2-cpu-report.json').read_text())
                self.assertFalse(result['complete'])

    def test_h2_binding_admits_envoy_only_with_the_fixed_protocol_opt_in(self):
        from h1_trace import write_binding
        for protocol in ('http2', 'grpcs'):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                data = dict(runtime=str(root / 'runtime.json'), config=str(root / 'config.yaml'),
                            sample=str(root / 'sample.json'), raw_sample=str(root / 'raw.json'),
                            client_exit=str(root / 'exit'), arm='envoy', pair=2, payload=71680)
                with self.assertRaises(ValueError):
                    write_binding(str(root), **data)
                for key, value in (('arm', 'direct'), ('pair', 3), ('payload', 1048576)):
                    with self.assertRaises(ValueError):
                        write_binding(str(root), **dict(data, **{key: value}), h2_protocol=protocol)
                write_binding(str(root), **data, h2_protocol=protocol)
                self.assertEqual(json.loads((root / 'bind.json').read_text()), dict(data, h2_protocol=protocol))


if __name__ == '__main__':
    unittest.main()
