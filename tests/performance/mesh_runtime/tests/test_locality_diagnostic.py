import copy
from pathlib import Path
import sys
import unittest

SCRIPTS = Path(__file__).resolve().parents[4] / '.github/scripts'
sys.path.insert(0, str(SCRIPTS))
import mesh_locality_diagnostic as diagnostic


class LocalityContracts(unittest.TestCase):
    def test_complete_balanced_plan_has_no_duplicate_cells(self):
        cells = diagnostic.plan()
        self.assertEqual(len(cells), 16)
        identity = lambda cell: tuple(cell[key] for key in ('arm', 'workers', 'payload', 'repetition'))
        self.assertEqual(len(set(map(identity, cells))), 16)
        self.assertEqual([(c['arm'], c['workers'], c['payload']) for c in cells[:8]],
                         list(reversed([(c['arm'], c['workers'], c['payload']) for c in cells[8:]])))
        self.assertTrue(all(c['duration'] == 30 and c['rate'] == 0 for c in cells))

    def receipt(self, arm='ferrum', workers=4):
        processes = [dict(name='mesh-source-client', pid=7, image_id='sha256:example', cpu_limit_nanos=4_000_000_000),
                     dict(name='mesh-destination-server', pid=8, image_id='sha256:example', cpu_limit_nanos=4_000_000_000)]
        details = [dict(**p, network_mode='host', cpuset='', memory_limit_bytes=0,
                        worker_environment=[f'FERRUM_WORKER_THREADS={workers}'] if arm == 'ferrum' else [],
                        args=['-c', '/fixture.yaml', '--concurrency', str(workers)]) for p in processes]
        return dict(arm=arm, workers=workers), dict(containers=processes, production=dict(proxy_containers=details),
            begin=dict(processes=[dict(pid=7), dict(pid=8)]), end=dict(processes=[dict(pid=7), dict(pid=8)]))

    def test_both_real_role_shapes_validate(self):
        for arm in ('ferrum', 'envoy'):
            for workers in (1, 4):
                cell, resource = self.receipt(arm, workers)
                self.assertEqual(diagnostic.validate_workers(cell, resource, 'sha256:example'), [])

    def test_wrong_worker_quota_image_or_placement_fails(self):
        changes = [('worker_environment', ['FERRUM_WORKER_THREADS=1']),
                   ('cpu_limit_nanos', 0), ('image_id', 'sha256:other'),
                   ('network_mode', 'bridge'), ('pid', 99), ('cpuset', '0'), ('memory_limit_bytes', 1024)]
        for key, value in changes:
            cell, resource = self.receipt()
            resource['production']['proxy_containers'][1][key] = value
            self.assertTrue(diagnostic.validate_workers(cell, resource, 'sha256:example'), key)

    def test_envoy_missing_duplicate_or_wrong_concurrency_fails(self):
        for args in ([], ['--concurrency'], ['--concurrency', '1'],
                     ['--concurrency', '4', '--concurrency', '4']):
            cell, resource = self.receipt('envoy')
            resource['production']['proxy_containers'][0]['args'] = args
            self.assertTrue(diagnostic.validate_workers(cell, resource, 'sha256:example'))

    def test_duplicated_role_or_wrong_cpu_pid_fails(self):
        cell, resource = self.receipt()
        resource['production']['proxy_containers'][1] = copy.deepcopy(resource['production']['proxy_containers'][0])
        resource['containers'][1] = copy.deepcopy(resource['containers'][0])
        self.assertTrue(diagnostic.validate_workers(cell, resource, 'sha256:example'))
        cell, resource = self.receipt()
        resource['end']['processes'][0]['pid'] = 99
        self.assertTrue(diagnostic.validate_workers(cell, resource, 'sha256:example'))

    def test_malformed_nested_receipts_return_errors(self):
        for field, value in [('production', None), ('production', []), ('containers', None), ('begin', None)]:
            cell, resource = self.receipt()
            resource[field] = value
            self.assertTrue(diagnostic.validate_workers(cell, resource, 'sha256:example'))
        for value in (None, {}, [None, None]):
            cell, resource = self.receipt()
            resource['production']['proxy_containers'] = value
            self.assertTrue(diagnostic.validate_workers(cell, resource, 'sha256:example'))
        cell, resource = self.receipt('envoy')
        resource['production']['proxy_containers'][0]['args'] = None
        self.assertTrue(diagnostic.validate_workers(cell, resource, 'sha256:example'))

    def test_missing_role_receipts_fail(self):
        cell, resource = self.receipt()
        resource['production']['proxy_containers'].pop()
        self.assertTrue(diagnostic.validate_workers(cell, resource, 'sha256:example'))
        self.assertTrue(diagnostic.validate_workers(cell, None, 'sha256:example'))


if __name__ == '__main__':
    unittest.main()
