import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[4]
SPEC = importlib.util.spec_from_file_location('mesh_gap_export', ROOT / '.github/scripts/mesh_gap_export.py')
export = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(export)


class PublicExportTests(unittest.TestCase):
    def fixture(self, root, payload='resource'):
        campaign, images = root / 'campaign', root / 'images'
        campaign.mkdir()
        images.mkdir()
        directory = 'mesh/candidate/saturated/run_1/payload_1024'
        observed = dict(cell=dict(directory=directory), measurement_valid=False, capacity_qualified=False,
                        issues=['retained failure'], metrics=dict(goodput_rps=0, cpu_us_per_completion=None),
                        load=dict(total_errors=1, drained_requests=2), resources=dict(payload=payload))
        path = campaign / directory / 'observation.json'
        path.parent.mkdir(parents=True)
        path.write_bytes(export.encoded(observed))
        (campaign / 'raw.resources.json').write_bytes(export.encoded(dict(payload=payload)))
        (images / 'receipt.json').write_bytes(export.encoded(dict(complete=True)))
        pending = dict(cell=dict(directory='mesh/pending'), measurement_valid=False, issues=['not measured'])
        report = dict(planned_cells=80, complete_valid_observations=False, all_capacity_qualified=False,
                      screen=dict(review_eligible=False), comparisons=[], mesh=[observed, pending], gateway=[])
        (campaign / 'report.json').write_bytes(export.encoded(report))
        return campaign, images, report

    def test_round_trip_preserves_failed_pending_and_undefined_positions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            campaign, images, original = self.fixture(root)
            before = {str(p): p.read_bytes() for p in campaign.rglob('*') if p.is_file()}
            destination = root / 'public'
            manifest = export.export_public(campaign, images, destination)
            compact = export.decoded((destination / 'campaign/report.json').read_bytes())
            hydrated = export.hydrate_report(compact, lambda name: (destination / name).read_bytes())
            self.assertEqual(export.encoded(hydrated), export.encoded(original))
            self.assertEqual(compact['mesh'][1], original['mesh'][1])
            self.assertEqual(manifest['complete'], True)
            for name, content in before.items():
                self.assertEqual(Path(name).read_bytes(), content)
                if not name.endswith('/report.json'):
                    self.assertEqual((destination / 'campaign' / Path(name).relative_to(campaign)).read_bytes(), content)

    def test_hydration_rejects_corrupt_missing_or_escaping_references(self):
        with tempfile.TemporaryDirectory() as directory:
            campaign, images, _ = self.fixture(Path(directory))
            entries = export.inventory((('campaign', campaign), ('images', images)))
            compact = export.decoded(entries['campaign/report.json']['content'])
            for delta in (dict(path='../outside'), dict(path='/outside'), dict(sha256='0' * 64), dict(bytes=True)):
                bad = copy.deepcopy(compact)
                bad['mesh'][0][export.REFERENCE].update(delta)
                with self.assertRaises(ValueError):
                    export.hydrate_report(bad, lambda name: entries[name]['source'].read_bytes())
            with self.assertRaises(KeyError):
                export.hydrate_report(compact, lambda name: {}[name])

    def test_full_preflight_includes_manifest_at_exact_byte_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            campaign, images, _ = self.fixture(root)
            export.export_public(campaign, images, root / 'first')
            total = sum(p.stat().st_size for p in (root / 'first').rglob('*') if p.is_file())
            self.assertTrue(export.export_public(campaign, images, root / 'exact', limit=total)['complete'])
            with self.assertRaises(ValueError):
                export.export_public(campaign, images, root / 'over', limit=total - 1)
            self.assertEqual([p.name for p in (root / 'over').iterdir()], ['export.json'])
            self.assertFalse(export.decoded((root / 'over/export.json').read_bytes())['complete'])

    def test_outer_duplication_is_removed_without_discarding_raw_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            campaign, images, original = self.fixture(root, payload='x' * 100000)
            source = (campaign / 'report.json').read_bytes()
            export.export_public(campaign, images, root / 'public')
            compact_bytes = (root / 'public/campaign/report.json').read_bytes()
            self.assertLess(len(compact_bytes), len(source) / 10)
            self.assertEqual((root / 'public/campaign/raw.resources.json').read_bytes(),
                             (campaign / 'raw.resources.json').read_bytes())
            self.assertEqual(export.hydrate_report(export.decoded(compact_bytes),
                             lambda name: (root / 'public' / name).read_bytes()), original)

    def test_canonical_observation_mismatch_fails_without_successful_prefix(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            campaign, images, _ = self.fixture(root)
            path = next(campaign.rglob('observation.json'))
            path.write_bytes(export.encoded(dict(changed=True)))
            with self.assertRaises(ValueError):
                export.export_public(campaign, images, root / 'public')
            self.assertEqual([p.name for p in (root / 'public').iterdir()], ['export.json'])

    def test_private_material_and_symlink_inputs_are_not_exported(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            campaign, images, _ = self.fixture(root)
            outside = root / 'outside.json'
            outside.write_text('not public')
            (campaign / 'linked.json').symlink_to(outside)
            export.export_public(campaign, images, root / 'public')
            self.assertFalse((root / 'public/campaign/linked.json').exists())
            (campaign / 'private.txt').write_text('-----BEGIN PRIVATE KEY-----')
            with self.assertRaises(ValueError):
                export.export_public(campaign, images, root / 'blocked')
            self.assertFalse(export.decoded((root / 'blocked/export.json').read_bytes())['complete'])


if __name__ == '__main__':
    unittest.main()
