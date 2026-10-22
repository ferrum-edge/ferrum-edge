#!/usr/bin/env python3
"""Static/synthetic profiling contract tests; never build or execute Rust/perf."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import mesh_gap_profile_capture as profile
import mesh_gap_profile_prepare as prepare

DSO = '/app/ferrum-edge'
ATTRS = ('cpu-clock:u: type: 1 (software), config: 0 (PERF_COUNT_SW_CPU_CLOCK), '
         '{ sample_period, sample_freq }: 19, sample_type: IP|TID|TIME|CPU|CALLCHAIN|REGS_USER|STACK_USER, '
         'freq: 1, inherit: 1, exclude_kernel: 1, use_clockid: 1, clockid: 1, sample_stack_user: 8192\n')


def sample(pid=101, when=15, frames=None, event='cpu-clock:u', header_leaf=False):
    frames = frames if frames is not None else ['app::work', 'app::route', 'app::serve',
        'tokio::runtime::scheduler::multi_thread::worker::run']
    rows = [f'proxy {pid}/{pid + 1} {when:.9f}: {event}:']
    if header_leaf:
        rows[0] += f' abcd {frames[0]} ({DSO})'
    rows += [f'        {0xabcd + i:x} {symbol} ({DSO})' for i, symbol in enumerate(frames)]
    return '\n'.join(rows) + '\n\n'


class ContractTests(unittest.TestCase):
    def decode(self, text):
        return profile.parse_callchains(text, 101, 10, 20, {DSO: {}})

    def test_unwind_union_clips_and_deduplicates(self):
        result = prepare.fde_coverage('FDE pc=0064..00b4\nFDE pc=0096..00fa\nFDE pc=00c8..012c', 100, 100)
        self.assertEqual(result['covered_text_bytes'], 100)
        self.assertEqual(result['covered_text_fraction'], 1)

    def test_no_unwind_fails_preflight(self):
        self.assertFalse(prepare.fde_coverage('no FDE', 100, 100)['qualified_for_one_dwarf_attempt'])

    def test_exact_preflight_boundary(self):
        self.assertTrue(prepare.fde_coverage('FDE pc=0064..00b4', 100, 100)['qualified_for_one_dwarf_attempt'])
        self.assertFalse(prepare.fde_coverage('FDE pc=0064..00b3', 100, 100)['qualified_for_one_dwarf_attempt'])

    def test_bad_unwind_range(self):
        with self.assertRaises(ValueError):
            prepare.fde_coverage('', 0, 0)

    def test_argv_preserves_original_and_adds_bounded_dwarf(self):
        original = profile.ORIGINAL_ARGV('/usr/bin/perf', 101, Path('/tmp/profile/source'))
        argv = profile.record_argv('/usr/bin/perf', 101, Path('/tmp/profile/source'))
        self.assertEqual(argv[:-2], original)
        self.assertEqual(argv[-2:], ['--call-graph', 'dwarf,8192'])
        self.assertIn('--strict-freq', argv)
        self.assertNotIn('--all-cpus', argv)

    def test_attributes_keep_exact_event_and_stack_contract(self):
        self.assertEqual(profile.validate_attributes(ATTRS), [])
        for before, after in [('19, sample_type', '49, sample_type'), ('8192', '16384'),
                              ('exclude_kernel: 1', 'exclude_kernel: 0'), ('STACK_USER', 'BRANCH_STACK')]:
            with self.subTest(after=after):
                self.assertTrue(profile.validate_attributes(ATTRS.replace(before, after)))

    def test_dummy_cannot_request_stacks(self):
        dummy = ('dummy:u: type: 1, config: 9, mmap: 1, comm: 1, task: 1, exclude_kernel: 1, '
                 'use_clockid: 1, clockid: 1, sample_type: IP|CALLCHAIN\n')
        self.assertTrue(profile.validate_attributes(ATTRS + dummy))

    def test_derived_samples_and_inclusive_denominator(self):
        decoded = self.decode(sample() + sample(when=25))
        self.assertEqual(decoded['all_capture_sample_count'], 2)
        self.assertEqual(decoded['outside_window_samples'], 1)
        self.assertEqual(len(decoded['all_derived_events']), 2)
        self.assertEqual(decoded['rooted_stack_fraction'], 1)
        self.assertEqual(decoded['known_frame_fraction'], 1)
        self.assertEqual(decoded['measurement_sample_count'], 1)
        self.assertEqual(sum(row['samples'] for row in decoded['inclusive_functions']), 4)

    def test_unknown_remains_in_denominator(self):
        decoded = self.decode(sample() + sample(frames=['[unknown]']))
        self.assertEqual(decoded['known_leaf_fraction'], 0.5)
        self.assertEqual(decoded['rooted_stack_fraction'], 0.5)
        self.assertEqual(decoded['unknown_leaves'], 1)
        self.assertEqual(decoded['measurement_sample_count'], 2)

    def test_foreign_and_unexpected_are_retained_and_counted(self):
        decoded = self.decode(sample(pid=202) + sample(event='cycles:u'))
        self.assertEqual(decoded['foreign_pid_samples'], 1)
        self.assertEqual(decoded['unexpected_event_samples'], 1)
        self.assertEqual(decoded['measurement_sample_count'], 2)
        self.assertEqual(decoded['known_leaf_fraction'], 0)

    def test_header_duplicate_is_not_recursion(self):
        decoded = self.decode(sample(header_leaf=True))
        self.assertEqual(decoded['events'][0]['stack_depth'], 4)
        recursive = self.decode(sample(frames=['app::work'] * 4))
        self.assertEqual(recursive['events'][0]['stack_depth'], 4)
        self.assertEqual(recursive['inclusive_functions'][0]['samples'], 1)

    def test_cap_and_malformed_do_not_disappear(self):
        decoded = self.decode(sample(frames=['app::work'] * 129) + 'malformed sample\n')
        self.assertEqual(decoded['stacks_at_decode_cap'], 1)
        self.assertEqual(decoded['rooted_stack_fraction'], 0)
        self.assertEqual(decoded['malformed_samples'], 1)

    def test_nonfinite_bracket_fails(self):
        with self.assertRaises(ValueError):
            profile.parse_callchains(sample(), 101, float('nan'), 20, {DSO: {}})

    def test_guarded_environment_preflight_starts_no_collector(self):
        with mock.patch.dict(profile.os.environ, {'GITHUB_ACTIONS': 'true'}, clear=True), \
             mock.patch.object(profile.platform, 'system', return_value='Linux'), \
             mock.patch.object(profile.platform, 'machine', return_value='x86_64'), \
             mock.patch.object(profile.os, 'geteuid', return_value=0), \
             mock.patch.object(profile.sys, 'argv', ['capture.py', '--environment-preflight']), \
             mock.patch.object(profile.importlib.util, 'spec_from_file_location') as load, \
             mock.patch.object(profile, 'DwarfCapture') as capture, mock.patch('builtins.print') as output:
            self.assertEqual(profile.main(), 0)
        load.assert_not_called()
        capture.assert_not_called()
        self.assertEqual(json.loads(output.call_args.args[0]), dict(mode='environment-preflight', github_actions='true',
                                                                  system='Linux', machine='x86_64', euid=0))

    def test_environment_preflight_keeps_remote_platform_and_privilege_guards(self):
        for actions, system, machine, euid in ((None, 'Linux', 'x86_64', 0), ('false', 'Linux', 'x86_64', 0),
                ('TRUE', 'Linux', 'x86_64', 0), ('true', 'Darwin', 'x86_64', 0),
                ('true', 'Linux', 'aarch64', 0), ('true', 'Linux', 'x86_64', 1000)):
            with self.subTest(actions=actions, system=system, machine=machine, euid=euid), \
                 mock.patch.dict(profile.os.environ, {} if actions is None else {'GITHUB_ACTIONS': actions}, clear=True), \
                 mock.patch.object(profile.platform, 'system', return_value=system), \
                 mock.patch.object(profile.platform, 'machine', return_value=machine), \
                 mock.patch.object(profile.os, 'geteuid', return_value=euid), \
                 mock.patch.object(profile.sys, 'argv', ['capture.py', '--environment-preflight']), \
                 mock.patch.object(profile.importlib.util, 'spec_from_file_location') as load:
                with self.assertRaises(ValueError):
                    profile.main()
                load.assert_not_called()

    def test_cpu_snapshot_retains_user_system_split(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = Path(tmp)
            (proc / '101').mkdir()
            fields = ['0'] * 22
            fields[11], fields[12], fields[19], fields[21] = '13', '5', '77', '3'
            (proc / '101/stat').write_text('101 (name with ) parentheses) ' + ' '.join(fields))
            got = profile.split_cpu_snapshot(101, proc)
            self.assertEqual((got['cpu_ticks'], got['user_cpu_ticks'], got['system_cpu_ticks']), (18, 13, 5))

    def test_private_trace_cleanup_only_owned_regular_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            (directory / 'perf.data').write_bytes(b'private synthetic stack')
            obj = object.__new__(profile.DwarfCapture)
            obj.roles = [dict(directory=directory, report={'all_capture_sample_count': 7})]
            obj.persist = lambda: None
            obj.delete_private_raw()
            self.assertFalse((directory / 'perf.data').exists())
            self.assertEqual(obj.roles[0]['report']['raw_trace_cleanup']['derived_all_sample_count'], 7)
            (directory / 'private').write_text('keep')
            (directory / 'perf.data').symlink_to(directory / 'private')
            with self.assertRaises(ValueError):
                obj.delete_private_raw()
            self.assertEqual((directory / 'private').read_text(), 'keep')


    def test_export_retains_failed_capture_and_derived_unknowns(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / 'private'
            (source / 'source').mkdir(parents=True)
            report = dict(valid=False, roles=[dict(role='source', errors=['unknown frames'],
                          raw_trace_cleanup=dict(raw_deleted=True))])
            (source / 'capture.json').write_text(json.dumps(report))
            (source / 'source/callchain-events-all.jsonl').write_text('{"known":false}\n')
            (source / 'source/secret-not-allowlisted').write_text('private')
            profile.export_derived(source, root / 'public')
            self.assertFalse((root / 'public/source/secret-not-allowlisted').exists())
            self.assertFalse(json.loads((root / 'public/capture.json').read_text())['valid'])
            self.assertTrue((root / 'public/source/callchain-events-all.jsonl').exists())

    def test_export_refuses_any_remaining_raw_trace(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / 'private'
            (source / 'source').mkdir(parents=True)
            (source / 'capture.json').write_text(json.dumps(dict(roles=[dict(role='source')])))
            (source / 'source/perf.data').write_bytes(b'private synthetic stack')
            with self.assertRaises(ValueError):
                profile.export_derived(source, root / 'public')
            self.assertFalse((root / 'public').exists())


if __name__ == '__main__':
    unittest.main()
