#!/usr/bin/env python3
"""Offline linker-shim contracts. Fake Python processes only; no compiler/Docker."""
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import mesh_production_profile_linker as M


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
            changed = M.symbol_arguments(expanded, root / 'symbols')
            self.assertEqual(changed, args[:2] + ['-Wl,--gc-sections', '-o', str(root / 'symbols')])
            self.assertEqual(M.output_path(args, root), root / 'original')

    def test_all_supported_strip_spellings_and_output_form(self):
        for strip in (['-s'], ['--strip-all'], ['-Wl,--strip-all'], ['-Xlinker', '--strip-all']):
            self.assertEqual(M.symbol_arguments(['a.o', '-ooriginal', *strip], Path('/twin')),
                             ['a.o', '-o/twin'])
        for args in (['-o', 'x'], ['-o', 'x', '-s', '--strip-all'], ['-o', 'x', '-s', '-S'],
                     ['-o', 'x', '-o', 'y', '-s'], ['-o']):
            with self.subTest(args=args), self.assertRaises(ValueError):
                M.symbol_arguments(args, Path('/twin'))

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
pathlib.Path(output).write_bytes(b'symbol twin' if second else b'original binary')
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
        self.assertEqual(self.output.read_bytes(), b'original binary')
        receipt = self.receipt()
        self.assertEqual(receipt['original_argv'], self.args)
        self.assertTrue(receipt['captured'])
        self.assertEqual(receipt['original_sha256_before'], receipt['original_sha256_after'])
        self.assertEqual((self.root / 'capture/ferrum-edge/symbols').read_bytes(), b'symbol twin')

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
        self.assertEqual(self.output.read_bytes(), b'original binary')
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
        self.output.write_bytes(b'original binary')
        self.settings.write_text('{"sleep":true}')
        with patch.dict(M.LIMITS, secondary_seconds=0.05):
            M.capture(self.args, self.config, self.root, dict(os.environ))
        self.assertFalse(self.receipt()['captured'])
        self.assertIn('deadline', self.receipt()['failure']['reason'])
        self.assertIsNotNone(self.receipt()['secondary_returncode'])
        self.assertEqual(self.output.read_bytes(), b'original binary')


if __name__ == '__main__':
    unittest.main()
