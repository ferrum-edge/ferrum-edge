"""Cheap input/classification contracts: never launches Rust, Docker or sockets."""
import copy
import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / '.github/scripts'))
from mesh_gap_candidate import (BASELINE, ORIGINAL_BASELINE, MAINTENANCE_EVIDENCE, PERFORMANCE_KINDS,
                                cargo_tests, expected_telemetry_red, validate_inputs, validate_maintenance_evidence)

CANDIDATE = 'a' * 40


class GapContracts(unittest.TestCase):
    def test_exact_candidate_input(self):
        for bad in ('main', CANDIDATE[:12], 'A' * 40, CANDIDATE + ';id', '$(id)', BASELINE, None):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                validate_inputs(bad, 'h2-handoff', 'gap-checks')
        self.assertEqual(validate_inputs(CANDIDATE, 'h2-handoff', 'gap-checks')['baseline_sha'], BASELINE)

    def test_telemetry_cannot_enter_performance_or_preflight(self):
        for kind, phase in (('telemetry-reproduce', 'gap-compare'), ('telemetry-reproduce', 'gap-checks'), ('telemetry-verify', 'gap-compare'), ('telemetry-verify', 'gap-telemetry-reproduce'), ('header-boundary', 'gap-vendor-preflight'), ('h2-handoff', 'gap-telemetry-reproduce'), ('arbitrary', 'gap-checks')):
            with self.subTest(kind=kind, phase=phase), self.assertRaises(ValueError):
                validate_inputs(CANDIDATE, kind, phase)

    def test_performance_and_diagnostic_baselines_remain_separate(self):
        for kind in PERFORMANCE_KINDS:
            self.assertEqual(validate_inputs(CANDIDATE, kind, 'gap-compare')['baseline_sha'], BASELINE)
        for variant in ('reproduce', 'verify'):
            kind = 'telemetry-' + variant
            phase = 'gap-telemetry-' + variant
            self.assertEqual(validate_inputs(CANDIDATE, kind, phase)['baseline_sha'], ORIGINAL_BASELINE)
            with self.assertRaises(ValueError):
                validate_inputs(ORIGINAL_BASELINE, kind, phase)
        import mesh_gap_profile_campaign as campaign
        import mesh_gap_profile_prepare as prepare
        self.assertEqual(campaign.BASELINE, ORIGINAL_BASELINE)
        self.assertEqual(prepare.capture.SOURCE, ORIGINAL_BASELINE)
        self.assertNotEqual(BASELINE, ORIGINAL_BASELINE)

    def test_maintenance_attestation_rejects_missing_or_changed_identity(self):
        validate_maintenance_evidence(copy.deepcopy(MAINTENANCE_EVIDENCE))
        for key in MAINTENANCE_EVIDENCE:
            with self.subTest(key=key):
                altered = copy.deepcopy(MAINTENANCE_EVIDENCE)
                altered[key] = ['src/secrets/azure.rs', 'src/proxy/http.rs'] if key == 'changed_paths' else 'different'
                with self.assertRaises(ValueError):
                    validate_maintenance_evidence(altered)
        for absent in (None, {}, dict(MAINTENANCE_EVIDENCE, unverified=True)):
            with self.assertRaises(ValueError):
                validate_maintenance_evidence(absent)

    def test_performance_checks_include_common_azure_semantics(self):
        expected = ['cargo', 'test', '--locked', '--features', 'cloud-secrets', '--test',
                    'unit_tests', 'unit::secrets::azure_tests::']
        for kind in PERFORMANCE_KINDS:
            with self.subTest(kind=kind):
                self.assertEqual(cargo_tests(kind).count(expected), 1)

    def test_reproducer_requires_runtime_failure_and_exact_assertion(self):
        assertion = 'configured builtin prometheus_metrics must observe real captured start'
        red = assertion + '\ntest result: FAILED. 0 passed; 1 failed; 0 ignored;'
        self.assertTrue(expected_telemetry_red(101, red))
        for code, text in ((0, red), (101, assertion + '\nerror: could not compile'), (101, 'test result: FAILED. 0 passed; 1 failed;'), (101, assertion + '\ntest result: FAILED. 0 passed; 2 failed;')):
            self.assertFalse(expected_telemetry_red(code, text))

    def test_header_plan_contains_new_semantic_suite(self):
        filters = {command[-1] for command in cargo_tests('header-boundary')}
        self.assertTrue({'header_merge_reconciliation_tests::', 'consumer_assertion_namespace_tests::', 'request_context_tests::', 'mesh_grpc_transport_tests::'}.issubset(filters))

    def test_interner_plan_preserves_policy_and_cardinality_coverage(self):
        filters = {command[-1] for command in cargo_tests('label-interner')}
        self.assertTrue({'mesh_label_interner_tests', 'mesh_label_cache_', 'mesh_telemetry_tag_cel_tests',
                         'mesh_telemetry_metric_families_tests', 'admin_mesh_service_graph_tests',
                         'mesh_telemetry_tracing_tests'}.issubset(filters))
        selected = validate_inputs(CANDIDATE, 'telemetry-verify', 'gap-telemetry-verify')
        self.assertEqual(selected['phase'], 'gap-telemetry-verify')

    def test_hyper_plan_contains_cancellation_and_hbone(self):
        filters = {command[-1] for command in cargo_tests('h2-handoff')}
        self.assertTrue({'vendor_integrity', 'http2_pool_tests::', 'mesh_hbone_tests::', 'mesh_grpc_transport_tests::', 'gateway_mesh_trust_retirement_tests::'}.issubset(filters))
        with self.assertRaises(ValueError):
            cargo_tests('arbitrary')


if __name__ == '__main__':
    unittest.main()
