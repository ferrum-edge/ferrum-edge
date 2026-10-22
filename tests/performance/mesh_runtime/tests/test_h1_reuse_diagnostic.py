import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[4]
SPEC = importlib.util.spec_from_file_location('h1_reuse', ROOT / '.github/scripts/mesh_h1_reuse_diagnostic.py')
diagnostic = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(diagnostic)


class ReuseDiagnosticContracts(unittest.TestCase):
    def row(self):
        return dict(state='completed', expected_tests=11, exit_code=0, timed_out=False,
                    log_limit_exceeded=False, counts=dict(status='ok', passed=11, failed=0, ignored=0))

    def test_plan_keeps_two_balanced_modes_and_all_positions(self):
        plan = diagnostic.planned()
        self.assertEqual([r['index'] for r in plan], list(range(8)))
        for offset, mode in ((0, 'module'), (4, 'singleton')):
            self.assertEqual([r['arm'] for r in plan[offset:offset + 4]], list(diagnostic.ORDER))
            self.assertTrue(all(r['mode'] == mode for r in plan[offset:offset + 4]))
        self.assertEqual(sum(r['expected_tests'] for r in plan), 48)

    def test_failed_summary_retains_partial_passes_and_failure(self):
        counts = diagnostic.test_counts('test result: FAILED. 10 passed; 1 failed; 0 ignored; 0 measured;')
        row = self.row()
        row.update(counts=counts, exit_code=101)
        self.assertEqual(counts['passed'], 10)
        self.assertEqual(counts['failed'], 1)
        self.assertEqual(diagnostic.execution_errors(row), ['original correctness assertion failed'])

    def test_no_zero_match_or_ignored_population_can_pass(self):
        for counts in (None, dict(status='ok', passed=0, failed=0, ignored=0),
                       dict(status='ok', passed=10, failed=0, ignored=1),
                       dict(status='ok', passed=True, failed=10, ignored=0)):
            row = self.row()
            row['counts'] = counts
            self.assertTrue(diagnostic.execution_errors(row))

    def test_pending_timeout_and_log_limit_never_pass(self):
        for delta in ({'state': 'pending'}, {'timed_out': True}, {'log_limit_exceeded': True}, {'exit_code': False}):
            row = self.row()
            row.update(delta)
            self.assertTrue(diagnostic.execution_errors(row))
        self.assertEqual(diagnostic.execution_errors(self.row()), [])

    def test_multiple_summaries_fail_closed(self):
        summary = 'test result: ok. 11 passed; 0 failed; 0 ignored;'
        self.assertIsNone(diagnostic.test_counts(summary + '\n' + summary))

    def test_environment_removes_inherited_binary_and_runtime_overrides(self):
        with patch.dict(os.environ, {'FERRUM_EDGE_TEST_BIN': '/wrong', 'FERRUM_POOL_WARMUP_ENABLED': 'true',
                                     'CARGO_BIN_EXE_ferrum-edge': '/wrong', 'CARGO_TARGET_DIR': '/shared',
                                     'RUSTFLAGS': '-C opt-level=3'}, clear=True):
            env = diagnostic.environment()
        self.assertFalse(any(key.startswith('FERRUM_') for key in env))
        self.assertNotIn('CARGO_TARGET_DIR', env)
        self.assertNotIn('CARGO_BIN_EXE_ferrum-edge', env)
        self.assertNotIn('RUSTFLAGS', env)
        self.assertEqual(env['CARGO_PROFILE_TEST_DEBUG'], '0')

    def test_cargo_artifact_must_be_unique_test_executable(self):
        event = dict(reason='compiler-artifact', target=dict(name='functional_tests'),
                     profile=dict(test=True), executable='/owned/target/debug/tests')
        self.assertEqual(diagnostic.functional_executable(json.dumps(event)), Path(event['executable']))
        other = dict(event, executable='/another/tests')
        for text in ('warning only', json.dumps(event) + '\n' + json.dumps(other), 'null'):
            with self.assertRaises(ValueError):
                diagnostic.functional_executable(text)

    def test_fast_command_cannot_export_oversized_output(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(diagnostic, 'OUTPUT', Path(directory)), patch.object(diagnostic, 'MAX_LOG_BYTES', 16):
                result = diagnostic.command([sys.executable, '-c', "print('x'*128)"], Path(directory),
                                            os.environ.copy(), 'bounded', 5)
            self.assertTrue(result['log_limit_exceeded'])
            self.assertEqual((Path(directory) / 'bounded.log').stat().st_size, 16)

    def test_owned_group_cleanup_is_attempted_after_direct_child_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(diagnostic, 'OUTPUT', Path(directory)), patch.object(diagnostic, 'stop_owned_group') as stop:
                result = diagnostic.command([sys.executable, '-c', 'pass'], Path(directory),
                                            os.environ.copy(), 'finished', 5)
            self.assertEqual(result['exit_code'], 0)
            self.assertTrue(stop.called)


if __name__ == '__main__':
    unittest.main()
