import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / '.github/scripts'))
import mesh_header_ladder_campaign as campaign
import test_production as original_contracts


class HeaderCampaignContracts(unittest.TestCase):
    def fixture(self, directory, arm='ferrum', errors=0):
        cell = next(c for c in campaign.cells() if c['arm'] == arm)
        original = original_contracts.ProductionContracts()
        load = original.error_load(cell, errors) if errors else original.valid_load(cell)
        receipt = campaign.header_issues.__globals__['header_metadata'](0, 32)
        load['diagnostic_headers'] = dict(receipt, validated_receipt=receipt['expected_receipt'],
            validated_exchanges=load['warmup_requests'] + load['cohort_requests'])
        resource = original.valid_resource(cell)
        images = dict(ferrum='sha256:ferrum', envoy='sha256:envoy', tools='sha256:tools')
        identities = [dict(name=f'proxy-{i}', pid=10+i, image_id=images[arm],
            worker_environment=['FERRUM_WORKER_THREADS=4'] if arm == 'ferrum' else [],
            network_mode='host', cpu_limit_nanos=0, cpu_quota=0) for i in range(0 if arm == 'direct' else 2)]
        auxiliary = [dict(pid=20+i, image_id=images['tools']) for i in range(2)]
        resource.update(containers=identities, production=dict(proxy_containers=copy.deepcopy(identities),
            auxiliary_containers=auxiliary), rss_samples=3, proxy_rss_bytes_mean=1000,
            proxy_rss_bytes_peak=2000, host_cpu_steal_percent=0, auxiliary_cpu=[{}, {}])
        for phase in ('begin', 'end'):
            resource[phase].update(processes=[dict(pid=c['pid'], starttime=42) for c in identities],
                auxiliary=[dict(pid=c['pid'], starttime=42) for c in auxiliary])
        (directory / 'logs').mkdir(parents=True)
        (directory / 'logs/auth_probes.log').write_text('\n'.join('[auth-probe] ok: ' + proof for proof in (
            'plaintext refused', 'valid client certificate handshake', 'no-client-cert refused',
            'rogue-CA client certificate refused')))
        return cell, load, resource, dict(image_ids=images)

    def evaluate(self, directory, cell, load, resource, source, status=0):
        stem = f"{cell['arm']}_http1_1024"
        (directory / (stem + '.json')).write_text(json.dumps(load))
        (directory / (stem + '.resources.json')).write_text(json.dumps(resource))
        return campaign.observation(cell, directory, source, status)

    def test_conserved_errors_are_observations_and_fail_separate_capacity(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            cell, load, resource, source = self.fixture(directory, errors=1)
            row = self.evaluate(directory, cell, load, resource, source, status=1)
            self.assertTrue(row['measurement_valid'], row)
            self.assertFalse(row['capacity_qualified'])
            self.assertEqual(row['metrics']['total_errors'], 1)
            self.assertEqual(row['metrics']['goodput_rps'], 5999 / 30)
            row = self.evaluate(directory, cell, load, resource, source, status=124)
            self.assertFalse(row['measurement_valid'])

    def test_direct_has_no_invented_proxy_cpu_cost(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            cell, load, resource, source = self.fixture(directory, 'direct')
            row = self.evaluate(directory, cell, load, resource, source)
            self.assertTrue(row['capacity_qualified'], row)
            self.assertIsNone(row['metrics']['cpu_us_per_completion'])

    def test_identity_receipt_interval_and_accounting_fail_closed(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            cell, load, resource, source = self.fixture(directory)
            self.assertTrue(self.evaluate(directory, cell, load, resource, source)['capacity_qualified'])
            for mutate in (
                lambda l, r: r['containers'][0].update(image_id='other'),
                lambda l, r: r['production']['proxy_containers'][0].update(pid=99),
                lambda l, r: r['end']['processes'][0].update(starttime=43),
                lambda l, r: r['end']['auxiliary'][0].update(pid=99),
                lambda l, r: r['production']['auxiliary_containers'][0].update(image_id='other'),
                lambda l, r: l['diagnostic_headers'].update(validated_exchanges=0),
                lambda l, r: l.update(cohort_requests=0),
                lambda l, r: r.update(rss_samples=0),
                lambda l, r: r.update(elapsed_seconds=0),
            ):
                left, right = copy.deepcopy(load), copy.deepcopy(resource)
                mutate(left, right)
                self.assertFalse(self.evaluate(directory, cell, left, right, source)['measurement_valid'])
            for bad in (None, [], 3):
                self.assertFalse(self.evaluate(directory, cell, load, bad, source)['measurement_valid'])

    def test_missing_and_malformed_positions_remain_in_complete_plan(self):
        with tempfile.TemporaryDirectory() as raw, patch.object(campaign, 'OUTPUT', Path(raw)):
            path = Path(raw) / campaign.cells()[0]['directory'] / 'observation.json'
            path.parent.mkdir(parents=True)
            path.write_text('{trunc')
            report = campaign.summarize()
            self.assertEqual(len(report['mesh']), 30)
            self.assertEqual(len(report['smoke']), 6)
            self.assertEqual(report['measured_valid_cells'], 0)
            self.assertFalse(report['complete_valid_observations'])
            self.assertFalse(report['performance_eligible'])

    def test_workflow_has_single_explicit_job_and_correct_remote_checks(self):
        text = (ROOT / '.github/workflows/mesh-runtime-benchmark.yml').read_text()
        self.assertIn("inputs.phase != 'header-ladder-diagnostic'", text)
        self.assertEqual(text.count("if: inputs.phase == 'header-ladder-diagnostic'"), 1)
        self.assertIn("baseline['Config']['User']=='65532'", (ROOT/'.github/scripts/mesh_header_ladder_campaign.py').read_text())
        self.assertIn('cargo fmt --manifest-path tests/performance/mesh_runtime/Cargo.toml -- --check', text)
        self.assertIn('cargo clippy --locked --manifest-path tests/performance/mesh_runtime/Cargo.toml --all-targets -- -D warnings', text)


if __name__ == '__main__':
    unittest.main()
