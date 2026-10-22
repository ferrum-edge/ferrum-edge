"""Small Python-only parser/process fixtures; never execute readelf/Rust/perf."""
import hashlib
import io
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / '.github/scripts'))
import mesh_gap_profile_fde as fde
import mesh_gap_profile_prepare as prepare

HEADER = b'00000018 0000000000000024 0000001c FDE cie=00000000 pc=0000000000000064..00000000000000b4\n'
RAW = b'Contents of the .eh_frame section:\n\n' + HEADER + b'  DW_CFA_nop\n\n'


class FdeStreamTests(unittest.TestCase):
    def limits(self, **changes):
        # Tiny Python fixture processes on macOS reserve more virtual address
        # space than readelf on the remote Linux host; production stays 512 MiB.
        return dict(fde.LIMITS, child_address_space_bytes=2**42, **changes)

    def run_fixture(self, stdout=RAW, stderr=b'', code=0, timeout=2, delay=0, **limits):
        with tempfile.TemporaryDirectory() as directory:
            out, err = Path(directory) / 'ranges.stdout', Path(directory) / 'ranges.stderr'
            script = ('import os,time; '
                      f'os.write(1,{stdout!r}); os.write(2,{stderr!r}); '
                      f'time.sleep({delay!r}); raise SystemExit({code!r})')
            receipt = fde.capture_ranges([sys.executable, '-c', script], out, err,
                                         timeout=timeout, limits=self.limits(**limits))
            return receipt, out.read_bytes(), err.read_bytes()

    def test_complete_stream_keeps_ranges_and_hashes_every_verbose_byte(self):
        receipt, compact, errors = self.run_fixture()
        self.assertTrue(receipt['complete'], receipt['errors'])
        self.assertEqual(receipt['returncode'], 0)
        self.assertEqual(receipt['raw_streams']['stdout'], dict(bytes_observed=len(RAW),
            sha256_observed=hashlib.sha256(RAW).hexdigest(), complete=True))
        self.assertEqual(receipt['stdout_sha256'], hashlib.sha256(compact).hexdigest())
        self.assertEqual(receipt['extracted_ranges'], 1)
        self.assertLess(len(compact), len(RAW))
        self.assertEqual(errors, b'')
        self.assertEqual(prepare.fde_coverage(compact.decode(), 100, 100)['covered_text_fraction'], .8)

    def test_split_headers_and_all_complete_ranges_are_retained(self):
        output = io.BytesIO()
        parser = fde.RangeExtractor(output, self.limits())
        second = HEADER.replace(b'0064..00000000000000b4', b'00b4..00000000000000c8')
        for byte in RAW + second:
            parser.feed(bytes([byte]))
        parser.finish()
        self.assertEqual(parser.ranges, 2)
        self.assertEqual(prepare.fde_coverage(output.getvalue().decode(), 100, 100)['covered_text_fraction'], 1)

    def test_incomplete_final_line_is_not_qualified_even_with_exit_zero(self):
        receipt, _, _ = self.run_fixture(stdout=RAW + b'  DW_CFA_advance_loc:')
        self.assertEqual(receipt['returncode'], 0)
        self.assertTrue(receipt['raw_streams']['stdout']['complete'])
        self.assertFalse(receipt['complete'])
        self.assertIn('incomplete final', str(receipt['errors']))

    def test_malformed_empty_reversed_and_overwide_ranges_are_rejected(self):
        for raw in (HEADER.replace(b'cie=00000000', b'cie=invalid'),
                    HEADER.replace(b'0064..00000000000000b4', b'0064..0000000000000064'),
                    HEADER.replace(b'0064..00000000000000b4', b'00b4..0000000000000064'),
                    HEADER.replace(b'00b4', b'10000000000000000'), b'no FDE records\n', b'none\n'):
            with self.subTest(raw=raw):
                receipt, _, _ = self.run_fixture(stdout=raw)
                self.assertFalse(receipt['complete'])

    def test_nonzero_or_stderr_cannot_qualify_a_complete_prefix(self):
        for options in (dict(code=1), dict(stderr=b'readelf: warning: damaged section\n')):
            receipt, _, _ = self.run_fixture(**options)
            self.assertFalse(receipt['complete'])
            self.assertEqual(receipt['extracted_ranges'], 1)

    def test_raw_compact_range_and_line_caps_fail_closed(self):
        cases = [dict(raw_stdout_bytes=len(RAW)-1), dict(compact_bytes=10),
                 dict(line_bytes=8), dict(stdout=RAW + HEADER, ranges=1),
                 dict(stderr=b'oversize', stderr_bytes=2), dict(stdout=RAW + b'x'*90, line_bytes=89)]
        for options in cases:
            with self.subTest(options=options):
                receipt, compact, stderr = self.run_fixture(**options)
                self.assertFalse(receipt['complete'])
                self.assertTrue(receipt['errors'])
                self.assertLessEqual(len(compact), receipt['limits']['compact_bytes'])
                self.assertLessEqual(len(stderr), receipt['limits']['stderr_bytes'])

    def test_timeout_after_valid_range_reaps_child_and_keeps_failure(self):
        receipt, _, _ = self.run_fixture(delay=2, timeout=.2)
        self.assertFalse(receipt['complete'])
        self.assertIn('timeout', str(receipt['errors']).lower())
        self.assertIsNotNone(receipt['returncode'])
        self.assertLess(receipt['elapsed_seconds'], 2)
        self.assertEqual(receipt['extracted_ranges'], 1)
        self.assertFalse(receipt['raw_streams']['stdout']['complete'])

    def test_eof_without_successful_process_completion_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            out, err = Path(directory) / 'out', Path(directory) / 'err'
            script = f'import os,time; os.write(1,{RAW!r}); os.close(1); os.close(2); time.sleep(2)'
            receipt = fde.capture_ranges([sys.executable, '-c', script], out, err,
                                         timeout=.2, limits=self.limits())
            self.assertTrue(all(x['complete'] for x in receipt['raw_streams'].values()))
            self.assertFalse(receipt['complete'])
            self.assertIsNotNone(receipt['returncode'])
            self.assertNotEqual(receipt['returncode'], 0)

    def test_stream_reducer_memory_tracks_only_line_not_verbose_dump(self):
        output = io.BytesIO()
        parser = fde.RangeExtractor(output, self.limits())
        for _ in range(1024):
            parser.feed(b'  DW_CFA_nop\n' * 64)
            self.assertEqual(parser.pending, b'')
        parser.feed(HEADER)
        parser.finish()
        self.assertEqual(parser.ranges, 1)
        self.assertLess(output.tell(), 100)


if __name__ == '__main__':
    unittest.main()
