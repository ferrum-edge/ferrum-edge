"""Cheap selection/qualification contracts; no Cargo, sudo or kernel operations."""
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / '.github/scripts'))
import mesh_gap_checks as checks


class TelemetryCheckContracts(unittest.TestCase):
    def artifact(self, **changes):
        item = dict(reason='compiler-artifact', profile=dict(test=True),
                    target=dict(name='functional_tests', kind=['test']),
                    executable='/owned/source/target/debug/deps/functional_tests-0123')
        item.update(changes)
        return json.dumps(item)

    def test_selects_exact_cargo_functional_executable_amid_diagnostics(self):
        log = 'Compiling ferrum-edge\n' + self.artifact() + '\nFinished test profile\n'
        self.assertEqual(checks.functional_test_executable(log),
                         Path('/owned/source/target/debug/deps/functional_tests-0123'))
        non_test = self.artifact(profile=dict(test=False))
        self.assertEqual(checks.functional_test_executable(non_test + '\n' + self.artifact()),
                         Path('/owned/source/target/debug/deps/functional_tests-0123'))

    def test_missing_duplicate_wrong_target_or_relative_binary_fails(self):
        for text in ('', self.artifact() + '\n' + self.artifact(), self.artifact(executable=None),
                     self.artifact(executable='target/debug/deps/functional_tests-x'),
                     self.artifact(target=dict(name='unit_tests', kind=['test'])),
                     self.artifact(target=dict(name='functional_tests', kind=['bin'])),
                     self.artifact(profile=dict(test=1))):
            with self.subTest(text=text), self.assertRaises(ValueError):
                checks.functional_test_executable(text)

    def test_privilege_is_confined_to_prebuilt_required_live_binary(self):
        command = checks.source_capture_command(Path('/owned/test-binary'))
        self.assertEqual(command, ['sudo', '-n', 'env', 'FERRUM_LIVE_TESTS_REQUIRED=1',
            'FERRUM_SKIP_GATEWAY_BUILD=1', 'timeout', '--signal=KILL', '240s', '/owned/test-binary',
            'functional_mesh_live_source_capture', '--ignored', '--nocapture', '--test-threads=1'])
        self.assertNotIn('cargo', command)
        self.assertTrue({'unshare', 'nsenter', 'setpriv', 'ip', 'iptables', 'iptables-save'}.issubset(checks.LIVE_SOURCE_PREREQUISITES))

    def test_live_suite_requires_one_summary_exactly_two_passes_and_no_skips(self):
        green = 'test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 999 filtered out;\n'
        self.assertTrue(checks.live_source_qualification(0, green)['valid'])
        for code, text in ((1, green), (True, green), (0, ''), (0, green + green),
            (0, green.replace('2 passed', '0 passed')), (0, green.replace('2 passed', '3 passed')),
            (0, green.replace('0 ignored', '1 ignored')), (0, 'SKIP: missing capability\n' + green),
            (0, 'test capture ... SKIP: missing capability\n' + green)):
            with self.subTest(code=code, text=text):
                self.assertFalse(checks.live_source_qualification(code, text)['valid'])

    def test_root_cannot_start_any_telemetry_cargo_or_live_commands(self):
        with mock.patch.object(checks.os, 'geteuid', return_value=0), mock.patch.object(checks, 'run_command') as run:
            with self.assertRaises(ValueError):
                checks.require_nonroot_telemetry_runner()
            with self.assertRaises(ValueError):
                checks.telemetry_source_capture(Path('/owned/source'), Path('/owned/output'))
            run.assert_not_called()
        with mock.patch.object(checks.os, 'geteuid', return_value=1001):
            checks.require_nonroot_telemetry_runner()

    def test_metric_and_trigger_tests_preserve_manifest_default_features(self):
        commands = checks.telemetry_unit_commands()
        self.assertEqual({command[-1] for command in commands}, {
            'unit::plugins::mesh_telemetry_metric_families_tests::',
            'unit::plugins::plugin_trigger_gate_tests::',
            'unit::plugins::prometheus_metrics_tests::'})
        self.assertTrue(all(command[:6] == ['cargo', 'test', '--locked', '--test', 'unit_plugins_b_tests', command[-1]] for command in commands))
        self.assertTrue(all('--features' not in command and '--no-default-features' not in command for command in commands))


if __name__ == '__main__':
    unittest.main()
