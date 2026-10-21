#!/usr/bin/env python3
"""Offline linker-shim contracts. Fake Python processes only; no compiler/Docker."""
import json
import os
from pathlib import Path
import re
import signal
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import mesh_production_profile_linker as M
from mesh_production_profile_symbols_test import elf

BUILD_ID = b"12345678".hex()
ASSIGN_ID = "-Wl,--build-id=0x" + BUILD_ID


class Arguments(unittest.TestCase):
    def test_response_round_trip_nested_and_exact_rewrite(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            args = ['object with space.o', 'quote"and\\slash.o', '-Wl,--gc-sections,--strip-all', '-o', 'original']
            (root / 'inner').write_text(M.gcc_response(args))
            (root / 'outer').write_text('@inner')
            expanded, receipts = M.expand_response_files(['@outer'], root)
            self.assertEqual(expanded, args)
            self.assertEqual(len(receipts), 2)
            changed = M.symbol_arguments(expanded, root / 'symbols', BUILD_ID)
            self.assertEqual(changed, args[:2] + ['-Wl,--gc-sections', '-o', str(root / 'symbols'), ASSIGN_ID])
            self.assertEqual(M.output_path(args, root), root / 'original')

    def test_all_supported_strip_spellings_and_output_form(self):
        for strip in (['-s'], ['--strip-all'], ['-Wl,--strip-all'], ['-Xlinker', '--strip-all']):
            self.assertEqual(M.symbol_arguments(['a.o', '-ooriginal', *strip], Path('/twin'), BUILD_ID),
                             ['a.o', '-o/twin', ASSIGN_ID])
        for args in (['-o', 'x'], ['-o', 'x', '-s', '--strip-all'], ['-o', 'x', '-s', '-S'],
                     ['-o', 'x', '-o', 'y', '-s'], ['-o']):
            with self.subTest(args=args), self.assertRaises(ValueError):
                M.symbol_arguments(args, Path('/twin'), BUILD_ID)

    def test_explicit_id_last_and_delta_exactly_describes_secondary_changes(self):
        args = ['input.o', '-o', 'original', '-Wl,--build-id=sha1', '-Xlinker', '--strip-all']
        delta = []
        changed = M.symbol_arguments(args, Path('/twin'), BUILD_ID, delta=delta)
        self.assertEqual(changed, ['input.o', '-o', '/twin', '-Wl,--build-id=sha1', ASSIGN_ID])
        reconstructed = args[:]
        for row in reversed(delta):
            self.assertEqual(row['original'], args[row['original_start']:row['original_end']])
            self.assertEqual(row['secondary'], changed[row['secondary_start']:row['secondary_end']])
            reconstructed[row['original_start']:row['original_end']] = row['secondary']
        self.assertEqual(reconstructed, changed)
        for bad in ('', '0', '0x01', 'AA', 'aa' * 65, 'aa,--other-option'):
            with self.subTest(bad=bad), self.assertRaisesRegex(ValueError, 'invalid assigned'):
                M.symbol_arguments(args, Path('/twin'), bad)

    def test_build_id_reader_rejects_malformed_missing_and_oversize_notes(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'elf'
            elf(path)
            self.assertEqual(M.elf_build_id(path), BUILD_ID)
            valid = path.read_bytes()
            mutations = [b'invalid', valid.replace(b'GNU\0', b'BAD\0'),
                         valid.replace(b'.note.gnu.build-id', b'.note.gnu.nope--id')]
            for offset, form, value in ((18, '<H', 183), (40, '<Q', 2**63), (60, '<H', 8193)):
                content = bytearray(valid)
                struct.pack_into(form, content, offset, value)
                mutations.append(content)
            for content in mutations:
                path.write_bytes(content)
                with self.assertRaises(ValueError):
                    M.elf_build_id(path)
            elf(path, identity=bytes(65))
            with self.assertRaisesRegex(ValueError, 'bounded GNU'):
                M.elf_build_id(path)
            elf(path)
            with patch.dict(M.LIMITS, elf_bytes=64), self.assertRaisesRegex(ValueError, 'oversize'):
                M.elf_build_id(path)

    def test_cycles_nesting_bytes_and_argument_bounds(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'cycle').write_text('@cycle')
            with self.assertRaisesRegex(ValueError, 'cycle'):
                M.expand_response_files(['@cycle'], root)
            (root / 'large').write_text('longargument')
            with patch.dict(M.LIMITS, response_bytes=2), self.assertRaisesRegex(ValueError, 'size bound'):
                M.expand_response_files(['@large'], root)
            with patch.dict(M.LIMITS, arguments=1), self.assertRaisesRegex(ValueError, 'argument bound'):
                M.expand_response_files(['one', 'two'], root)
            with self.assertRaisesRegex(ValueError, 'unsupported response argument'):
                M.gcc_response(['line\nbreak'])

    def test_selection_is_exact_real_binary_path(self):
        from mesh_production_profile_ferrum import shim_config
        config = shim_config('/build/src/main.rs', 'hash')
        self.assertTrue(M.selected(Path('/build/target/release/deps/ferrum_edge-0123456789abcdef'), config))
        for path in ('/build/target/debug/deps/ferrum_edge-0123456789abcdef',
                     '/build/target/release/deps/ferrum_cni-0123456789abcdef',
                     '/build/target/release/deps/libferrum_edge-0123456789abcdef.so'):
            self.assertFalse(M.selected(Path(path), config))


class OriginalLink(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.shim = self.root / 'shim'
        self.shim.mkdir()
        (self.shim / 'cc').write_bytes(Path(M.__file__).read_bytes())
        self.real = self.root / 'real-cc'
        elf(self.root / 'original-fixture')
        elf(self.root / 'symbols-fixture', symbols=True)
        self.original_bytes = (self.root / 'original-fixture').read_bytes()
        self.symbol_bytes = (self.root / 'symbols-fixture').read_bytes()
        self.real.write_text('#!' + sys.executable + '\n' + """
import json, os, pathlib, shlex, sys, time
args = sys.argv[1:]
second = bool(args and args[0].startswith('@'))
if second:
    args = shlex.split(pathlib.Path(args[0][1:]).read_text())
settings = json.loads(pathlib.Path(__file__).with_name('settings.json').read_text())
if second and settings.get('sleep'):
    time.sleep(5)
print('secondary stdout' if second else 'original stdout')
print('secondary stderr' if second else 'original stderr', file=sys.stderr)
if settings.get('signal') and not second:
    os.kill(os.getpid(), settings['signal'])
if settings.get('code') and not second:
    sys.exit(settings['code'])
if settings.get('secondary_code') and second:
    sys.exit(settings['secondary_code'])
output = args[args.index('-o') + 1]
fixture = pathlib.Path(__file__).with_name('symbols-fixture' if second else 'original-fixture')
pathlib.Path(output).write_bytes(fixture.read_bytes())
""")
        self.real.chmod(0o755)
        self.settings = self.root / 'settings.json'
        self.settings.write_text('{}')
        self.source = self.root / 'main.rs'
        self.source.write_text('real source')
        self.output = self.root / 'ferrum_edge-0123456789abcdef'
        self.config = dict(real_cc=str(self.real), source_file=str(self.source),
                           source_sha256=M.sha256_file(self.source), capture_dir=str(self.root / 'capture'),
                           output_pattern=re.escape(str(self.output)), minimum_elf_bytes=1)
        (self.shim / 'config.json').write_text(json.dumps(self.config))
        self.args = ['-o', str(self.output), 'input.o', '-Wl,--strip-all']

    def tearDown(self):
        self.temp.cleanup()

    def run_shim(self, args=None):
        return subprocess.run([sys.executable, str(self.shim / 'cc'), *(args or self.args)],
                              capture_output=True, text=True, timeout=10)

    def receipt(self):
        return json.loads((self.root / 'capture/ferrum-edge/receipt.json').read_text())

    def test_first_output_stdout_stderr_status_and_argv_remain_unchanged(self):
        result = self.run_shim()
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, 'original stdout\n', 'original stderr\n'))
        self.assertEqual(self.output.read_bytes(), self.original_bytes)
        receipt = self.receipt()
        self.assertEqual(receipt['original_argv'], self.args)
        self.assertTrue(receipt['captured'])
        self.assertEqual(receipt['original_sha256_before'], receipt['original_sha256_after'])
        self.assertEqual((self.root / 'capture/ferrum-edge/symbols').read_bytes(), self.symbol_bytes)

    def test_receipt_records_assignment_and_is_verified_against_both_elfs(self):
        from mesh_production_profile_ferrum import read_capture
        self.assertEqual(self.run_shim().returncode, 0)
        receipt = read_capture(self.root / 'capture', self.config['source_sha256'])
        self.assertTrue(receipt['symbol_companion_normalization'])
        self.assertFalse(receipt['natural_build_id_reproducibility_claim'])
        self.assertIsNone(receipt['unassigned_companion_build_id'])
        for key in ('original_auto_build_id', 'assigned_companion_build_id', 'observed_companion_build_id'):
            self.assertEqual(receipt[key], BUILD_ID)
        self.assertEqual(receipt['secondary_expanded_argv'][-1], ASSIGN_ID)
        self.assertEqual(receipt['secondary_argv_delta'][-1]['secondary'], [ASSIGN_ID])
        path = self.root / 'capture/ferrum-edge/receipt.json'
        for key, value in (('symbol_companion_normalization', False),
                           ('natural_build_id_reproducibility_claim', True),
                           ('assigned_companion_build_id', 'bad')):
            changed = dict(receipt, **{key: value})
            path.write_text(json.dumps(changed))
            with self.assertRaisesRegex(ValueError, 'assignment not verified'):
                read_capture(self.root / 'capture', self.config['source_sha256'])

    def test_wrong_companion_id_is_rejected_without_changing_original_success(self):
        elf(self.root / 'symbols-fixture', symbols=True, identity=b'87654321')
        self.assertEqual(self.run_shim().returncode, 0)
        self.assertEqual(self.output.read_bytes(), self.original_bytes)
        receipt = self.receipt()
        self.assertFalse(receipt['captured'])
        self.assertIn('assigned companion build ID not retained', receipt['failure']['reason'])

    def test_assigned_id_cannot_qualify_changed_companion_code(self):
        from mesh_production_profile_ferrum import qualify_chain
        elf(self.root / 'symbols-fixture', symbols=True, code=b'B' * 16)
        self.assertEqual(self.run_shim().returncode, 0)
        self.assertTrue(self.receipt()['captured'])
        slot = self.root / 'capture/ferrum-edge'
        result = qualify_chain(self.output, slot / 'stripped', slot / 'symbols', 1)
        self.assertTrue(result['matching_build_ids'])
        self.assertFalse(result['qualified'])
        self.assertFalse(result['symbols_may_be_applied_to_shipping'])
        self.assertIn('.text', result['fresh_to_symbols']['allocated_section_differences'])

    def test_original_failure_preserves_nonzero_status_without_second_link(self):
        self.settings.write_text('{"code":7}')
        result = self.run_shim()
        self.assertEqual(result.returncode, 7)
        self.assertFalse((self.root / 'capture').exists())

    def test_original_signal_status_is_preserved(self):
        for signum in (signal.SIGTERM, signal.SIGKILL):
            self.settings.write_text(json.dumps(dict(signal=signum)))
            self.assertEqual(self.run_shim().returncode, -signum)
            self.assertFalse((self.root / "capture").exists())

    def test_secondary_failure_does_not_replace_original_success(self):
        self.settings.write_text('{"secondary_code":9}')
        result = self.run_shim()
        self.assertEqual(result.returncode, 0)
        self.assertEqual(self.output.read_bytes(), self.original_bytes)
        self.assertFalse(self.receipt()['captured'])
        self.assertEqual(self.receipt()['secondary_returncode'], 9)

    def test_actual_response_file_preserved_for_first_link(self):
        response = self.root / 'original.rsp'
        response.write_text(M.gcc_response(self.args))
        # Our fake cc uses @ to distinguish a secondary call, so test preservation
        # with a mocked original process while exercising the real parser.
        with patch.object(M.subprocess, 'Popen') as popen, patch.object(M, 'capture'):
            popen.return_value.wait.return_value = 0
            M.run(['@' + str(response)], self.config, self.shim)
            self.assertEqual(popen.call_args.args[0], ['cc', '@' + str(response)])
            self.assertEqual(popen.call_args.kwargs['executable'], str(self.real))
        self.assertEqual(M.expand_response_files(['@' + str(response)], self.root)[0], self.args)

    def test_changed_real_source_and_duplicate_selected_link_fail_capture(self):
        self.source.write_text('dummy')
        self.assertEqual(self.run_shim().returncode, 0)
        self.assertFalse(self.receipt()['captured'])
        self.assertEqual(self.run_shim().returncode, 0)
        self.assertEqual(len(list((self.root / 'capture').glob('failure-*.json'))), 1)

    def test_secondary_deadline_reaps_owned_process_and_keeps_original(self):
        self.output.write_bytes(self.original_bytes)
        self.settings.write_text('{"sleep":true}')
        with patch.dict(M.LIMITS, secondary_seconds=0.05):
            M.capture(self.args, self.config, self.root, dict(os.environ))
        self.assertFalse(self.receipt()['captured'])
        self.assertIn('deadline', self.receipt()['failure']['reason'])
        self.assertIsNotNone(self.receipt()['secondary_returncode'])
        self.assertEqual(self.output.read_bytes(), self.original_bytes)


if __name__ == '__main__':
    unittest.main()
