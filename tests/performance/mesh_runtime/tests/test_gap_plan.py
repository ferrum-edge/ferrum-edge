"""Contract checks for plans, receipt binding and error-inclusive observations."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / '.github/scripts'))
import mesh_gap_campaign as campaign
from mesh_gap_build import checked_receipt
from mesh_gap_plan import ARMS, comparisons, gateway_blocks, mesh_cells, screen, summary
import test_production as fixtures


class GapPlanContracts(unittest.TestCase):
    def test_exact80_distinct_cells_and_balanced_blocks(self):
        mesh, gateway = mesh_cells(), gateway_blocks()
        self.assertEqual(len(mesh), 48)
        self.assertEqual(sum(len(block['members']) for block in gateway), 32)
        self.assertEqual(len({row['directory'] for row in mesh}), 48)
        for payload in (1024, 1048576):
            for load in ('saturated', 'fixed'):
                orders = [[c['arm'] for c in mesh if c['payload'] == payload and c['load'] == load and c['repetition'] == r] for r in range(1, 5)]
                self.assertEqual(orders[0], list(reversed(orders[1])))
                self.assertEqual(orders[2], list(reversed(orders[3])))
        # AA/AB order is independent of the two-arm CR/RC/RC/CR order.
        self.assertEqual([b['phase'] for b in gateway if b['scenario'] == 'http2'], ['aa', 'ab', 'ab', 'aa', 'aa', 'ab', 'ab', 'aa'])
        self.assertTrue(all(m['image_role'] == 'baseline' for b in gateway if b['phase'] == 'aa' for m in b['members']))

    def test_missing_positions_are_never_filtered(self):
        row = summary([1.1, None, 1.2, 1.3])
        self.assertIsNone(row['median'])
        self.assertEqual(row['all'], [1.1, None, 1.2, 1.3])
        paired = comparisons([], [])
        self.assertEqual(len(paired), 48)
        self.assertTrue(all(row['candidate']['all'] == [None] * 4 for row in paired))
        self.assertFalse(screen(paired, False, False)['review_eligible'])

    def test_noise_and_adverse_signals_block_promotion(self):
        row = dict(surface='mesh', scenario='1024/saturated', metric='goodput_rps',
                   aa=summary([1, 1.06, 1, 1]), candidate=summary([1.04] * 4))
        self.assertFalse(screen([row], True, True)['review_eligible'])
        row.update(surface='gateway', scenario='http2', metric='completion_p99_us',
                   aa=summary([1] * 4), candidate=summary([1.05] * 4))
        self.assertFalse(screen([row], True, True)['review_eligible'])

    def test_modified_preflight_receipt_never_builds_images(self):
        selected = {'candidate_sha': 'a' * 40}
        receipt = dict(selection=selected, complete=True, passed=True, performance_eligible=True,
                       modified_checkout=False, final_tracked_diff=[], errors=[])
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'receipt.json'
            path.write_text(json.dumps(receipt))
            self.assertEqual(checked_receipt(selected, path), receipt)
            for key, value in (('modified_checkout', True), ('performance_eligible', False), ('final_tracked_diff', ['vendor/VENDOR_INTEGRITY.sha256']), ('selection', {})):
                path.write_text(json.dumps(dict(receipt, **{key: value})))
                with self.assertRaises(ValueError):
                    checked_receipt(selected, path)

    def make_cell(self, directory, errors=0):
        cell = mesh_cells()[0]
        normalized = dict(cell, arm='ferrum')
        factory = fixtures.ProductionContracts()
        load = factory.error_load(normalized, errors) if errors else factory.valid_load(normalized)
        resource = factory.valid_resource(normalized)
        image, tools = 'sha256:' + 'a' * 64, 'sha256:' + 'b' * 64
        identities = [dict(name='proxy-' + ('client', 'server')[i], pid=i + 10, image_id=image) for i in range(2)]
        resource.update(containers=identities, clock_ticks_per_second=100, rss_samples=3,
            proxy_rss_bytes_mean=100, proxy_rss_bytes_peak=110, host_cpu_steal_percent=0,
            auxiliary_cpu=[dict(name='backend', cpu_seconds=1), dict(name='loadgen', cpu_seconds=1)],
            production=dict(proxy_containers=[dict(c, worker_environment=['FERRUM_WORKER_THREADS=4'], network_mode='host', cpu_limit_nanos=0, cpu_quota=0) for c in identities],
                            auxiliary_containers=[dict(image_id=tools)] * 2))
        for phase, ticks in (('begin', 100), ('end', 150)):
            resource[phase]['processes'] = [dict(pid=i + 10, starttime=1, cpu_ticks=ticks) for i in range(2)]
        (directory / 'logs').mkdir()
        (directory / 'logs/auth_probes.log').write_text('\n'.join('[auth-probe] ok: ' + text for text in ('plaintext refused', 'valid client certificate handshake', 'no-client-cert refused', 'rogue-CA client certificate refused')))
        for phase in ('before', 'after'):
            for role in (0, 1):
                (directory / f'{phase}-{role}-metrics.json').write_text(json.dumps(dict(returncode=0, body='metric 1')))
        (directory / 'ferrum_http1_1024.json').write_text(json.dumps(load))
        (directory / 'ferrum_http1_1024.resources.json').write_text(json.dumps(resource))
        source = dict(image_ids=dict(baseline=image, candidate=image, tools=tools))
        return cell, source, resource

    def test_conserved_error_is_retained_and_capacity_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            cell, source, _ = self.make_cell(directory, errors=1)
            row = campaign.mesh_observation(cell, directory, source, 1)
            self.assertTrue(row['measurement_valid'], row['issues'])
            self.assertFalse(row['capacity_qualified'])
            self.assertEqual(row['metrics']['total_errors'], 1)
            self.assertEqual(row['load']['admitted_errors'], 1)

    def test_image_and_marker_mismatch_stop_without_relabeling_product_error(self):
        for mutation in ('image', 'marker', 'auth'):
            with tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                cell, source, resource = self.make_cell(directory)
                if mutation == 'image':
                    resource['containers'][0]['image_id'] = 'sha256:' + 'c' * 64
                elif mutation == 'marker':
                    resource['end']['monotonic'] = 41
                else:
                    (directory / 'logs/auth_probes.log').write_text('unqualified')
                (directory / 'ferrum_http1_1024.resources.json').write_text(json.dumps(resource))
                row = campaign.mesh_observation(cell, directory, source, 0)
                self.assertFalse(row['measurement_valid'])
                self.assertEqual(row['metrics'], {})


if __name__ == '__main__':
    unittest.main()
