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


if __name__ == '__main__':
    unittest.main()
