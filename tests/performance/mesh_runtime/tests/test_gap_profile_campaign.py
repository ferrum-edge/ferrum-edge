"""Synthetic profile qualification and public-export safety; no runtime work."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / '.github/scripts'))
import mesh_gap_profile_campaign as campaign


class ProfileCampaignTests(unittest.TestCase):
    def sample(self):
        image = 'sha256:' + 'a' * 64
        prep = dict(qualified=True, ready_for_dwarf_capture=True, source=campaign.BASELINE, builder=campaign.BUILDER,
            runtime_flags_changed=False, shipping_attribution_allowed=False, runtime_image=dict(Id=image),
            own_pair=dict(qualified=True, shipping_build_id='aaa', diagnostic_build_id='aaa'),
            unwind_preflight=dict(qualified_for_one_dwarf_attempt=True))
        snapshot = dict(user_cpu_ticks=100, system_cpu_ticks=20, cpu_ticks=120)
        rows = [dict(cell=dict(phase=phase), measurement_valid=True, capacity_qualified=True,
                     resources=dict(containers=[dict(image_id=image)] * 2, clock_ticks_per_second=100,
                                    begin=dict(processes=[snapshot.copy(), snapshot.copy()]),
                                    end=dict(processes=[snapshot.copy(), snapshot.copy()])),
                     metrics=dict(goodput_rps=100, cpu_us_per_completion=100)) for phase in campaign.PHASES]
        profile = dict(valid=True, roles=[dict(role=role, valid=True, raw_trace_cleanup=dict(raw_deleted=True))
                                         for role in campaign.ROLES])
        return rows, profile, prep, dict(complete=True, raw=[], stopped_recorders=[])

    def test_complete_exact_image_bracket(self):
        result = campaign.qualify(*self.sample())
        self.assertTrue(result['valid'], result['errors'])
        self.assertEqual(list(result['controls'].values()), [1, 1, 1, 1])
        self.assertIn('synchronous', result['scope'])

    def test_each_gate_blocks_without_dropping_a_cell(self):
        mutations = [lambda r, c, p, x: r[1].update(capacity_qualified=False),
            lambda r, c, p, x: r[2]['resources']['containers'][0].update(image_id='other'),
            lambda r, c, p, x: c['roles'][0]['raw_trace_cleanup'].update(raw_deleted=False),
            lambda r, c, p, x: p['own_pair'].update(diagnostic_build_id='different'),
            lambda r, c, p, x: x['raw'].append(dict(loss_denominator=None)),
            lambda r, c, p, x: p.update(runtime_flags_changed=True),
            lambda r, c, p, x: r[0]['resources']['begin']['processes'][0].update(cpu_ticks=121)]
        for mutate in mutations:
            args = self.sample()
            mutate(*args)
            result = campaign.qualify(*args)
            self.assertFalse(result['valid'])
            self.assertEqual(len(result['cells']), 3)

    def test_drift_and_undefined_ratios_are_retained(self):
        args = self.sample()
        args[0][1]['metrics']['goodput_rps'] = 90
        result = campaign.qualify(*args)
        self.assertFalse(result['valid'])
        self.assertEqual(result['controls']['profiled_control_rps_ratio'], .9)
        args[0][2]['metrics']['goodput_rps'] = None
        result = campaign.qualify(*args)
        self.assertIsNone(result['controls']['profiled_control_rps_ratio'])
        self.assertFalse(result['valid'])

    def test_failed_profile_keeps_conserved_descriptive_ratios(self):
        load = {key: 0 for key in campaign.production.COUNT_KEYS}
        load.update({key: 0 for key in campaign.production.TAIL_KEYS})
        load.update(mesh='ferrum', protocol='http1', payload_size=1024, duration_secs=30,
                    rate=0, concurrency=100, rps=100, total_requests=3000, cohort_requests=3000,
                    admitted_requests=3000, total_bytes=3072000, admission_delay_p99_us=0,
                    admission_delay_max_us=0, first_missed_slot=None, last_missed_slot=None)
        resource = dict(valid=False, errors=['leaf profile failed identity, loss, or coverage qualification'],
                        proxy_cpu_seconds=.3, elapsed_seconds=30, begin=dict(monotonic=1), end=dict(monotonic=31))
        description = campaign.descriptive_controls(load, resource)
        self.assertEqual(description['validation_issues'], [])
        self.assertEqual(description['cpu_us_per_completion'], 100)
        args = self.sample()
        args[0][1].update(metrics={}, measurement_valid=False, capacity_qualified=False, descriptive_controls=description)
        result = campaign.qualify(*args)
        self.assertFalse(result['valid'])
        self.assertEqual(result['controls']['profiled_control_rps_ratio'], 1)
        self.assertEqual(result['controls']['profiled_control_cpu_ratio'], 1)
        resource['errors'].append('proxy PID changed during measurement')
        self.assertIsNone(campaign.descriptive_controls(load, resource)['goodput_rps'])
        load['admitted_requests'] += 1
        self.assertIsNone(campaign.descriptive_controls(load, resource)['goodput_rps'])

    def test_missing_phase_cannot_be_a_subset(self):
        rows, *rest = self.sample()
        result = campaign.qualify(rows[:2], *rest)
        self.assertFalse(result['valid'])
        self.assertTrue(result['cells'][2]['missing'])

    def test_collector_delta_is_exact_and_unique(self):
        literal = campaign.REPLACEMENT[0]
        self.assertEqual(campaign.transform_runner('a\n' + literal + '\nz'), 'a\n' + campaign.REPLACEMENT[1] + '\nz')
        for text in ('absent', literal + literal):
            with self.assertRaises(ValueError):
                campaign.transform_runner(text)

    def test_public_copy_refuses_binary_key_and_linked_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, public = root / 'source', root / 'public'
            with mock.patch.object(campaign, 'PUBLIC', public):
                for content in (b'\x7fELFbinary', b'PERFILE2stack', b'-----BEGIN PRIVATE KEY-----'):
                    source.write_bytes(content)
                    with self.assertRaises(ValueError):
                        campaign.public_copy(source, public / 'a', [])
                source.write_text('{}')
                linked = root / 'linked'
                linked.symlink_to(source)
                with self.assertRaises(ValueError):
                    campaign.public_copy(linked, public / 'a', [])
                manifest = []
                campaign.public_copy(source, public / 'a.json', manifest)
                self.assertEqual(manifest[0]['bytes'], 2)

    def test_recorder_discovery_is_exact_path_and_command(self):
        with tempfile.TemporaryDirectory() as directory:
            proc = Path(directory)
            private = proc / 'owned'
            def add(pid, argv):
                target = proc / str(pid)
                target.mkdir()
                (target / 'cmdline').write_bytes(b'\0'.join(part.encode() for part in argv) + b'\0')
                fields = ['S'] + ['0'] * 18 + ['123']
                (target / 'stat').write_text(str(pid) + ' (perf) ' + ' '.join(fields))
            exact = ['/usr/bin/perf', 'record', '-p', '55', '-o', str(private / 'source/perf.data')]
            add(100, exact)
            add(101, [*exact[:-1], str(proc / 'other/perf.data')])
            add(102, ['/usr/bin/other', *exact[1:]])
            original = Path.stat
            def root_stat(path, *args, **kwargs):
                result = original(path, *args, **kwargs)
                if path.parent == proc and path.name.isdigit():
                    return mock.Mock(st_uid=0)
                return result
            with mock.patch.object(Path, 'stat', root_stat):
                found = campaign.owned_recorders(private, proc)
            self.assertEqual([item['pid'] for item in found], [100])
            self.assertEqual(found[0]['starttime'], 123)


if __name__ == '__main__':
    unittest.main()
