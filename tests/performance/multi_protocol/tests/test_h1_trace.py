"""Consumer regressions; the workflow separately exercises the real C producers."""
import copy
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
from h1_trace_contract import (COUNTERS, LOSSES, decode_cpu, fd_lifetimes,
                               load_trace, syscall_coverage, validate_record, nested_fixture_proof)
from h1_trace_preflight import reconcile
from h1_internal_profile import validate_selection
import h1_trace as trace
import h1_trace_preflight as preflight
from live_contract import measurement_window


def counter(**changes):
    row = {k: 0 for k in COUNTERS}
    row.update(id=1, attempts=2, exits=2, positive=1, errors=1,
               accepted_known=2, accepted_bytes=5, min_return=-11, max_return=5,
               offered_known=2, offered=24)
    row.update(changes)
    return row


def producer_records():
    return [dict(phase='ready', status='supported'),
            dict(phase='bound', pid=7, start_ticks=9, cgroup=42, netns=1, at_ns=90),
            dict(phase='final', before_ns=100, after_ns=110, pending=0, map_read_failures=0,
                 losses=[0] * len(LOSSES), totals=[counter()], census={'1': 2},
                 rows=[counter(attempts=0, pid=7, process_ns=90_000_000, cgroup=42,
                               cookie=55, netns=1, role=1, outcome=1, direction=1)]),
            dict(phase='termination', requested_stop=True, bound=True, at_ns=111, lifecycle_omitted=0,
                 checkpoints_omitted=0, snapshot_failures=0)]


class H1CPUAttributeTests(unittest.TestCase):
    # Verbatim cpu/perf-attributes.txt, hosted run 35422193763, artifact
    # 10577439767, head 61e5dbd46197c3dca06e46585d2ad19a1309569c.
    def setUp(self):
        self.raw = (HERE / 'tests/fixtures/h1-perf-evlist-6.8.0-139.txt').read_bytes()
        self.cpu, self.dummy = self.raw.decode('ascii').splitlines()

    def verify(self, raw=None, *, status_changes=None):
        raw = self.raw if raw is None else raw
        if isinstance(raw, str):
            raw = raw.encode('ascii')
        status = dict(returncode=0, forced=False, incomplete=None,
                      stdout_sha256=hashlib.sha256(raw).hexdigest())
        status.update(status_changes or {})
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'perf-attributes.txt'
            path.write_bytes(raw)
            result = trace.read_cpu_attributes(path, status)
            self.assertEqual(path.read_bytes(), raw)
            return result

    def rejected(self, raw, reason, **kwargs):
        result = self.verify(raw, **kwargs)
        self.assertFalse(result['verified'], result)
        self.assertIn(reason, '\n'.join(result['issues']))
        return result

    def test_retained_union_attributes_bind_one_event_in_either_order(self):
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(),
                         '98b167836e2d3c96c808a5291676c0e8ae6eae35e651a9dcea63e8c085b6f5db')
        for raw, line in [(self.raw, 1), (self.dummy + '\n' + self.cpu + '\n', 2),
                          (self.cpu + '\n', 1)]:
            with self.subTest(line=line, raw=raw):
                result = self.verify(raw)
                self.assertTrue(result['verified'], result)
                self.assertEqual(result['issues'], [])
                self.assertEqual(result['event'], 'cpu-clock:uS')
                self.assertEqual(result['line'], line)
                self.assertEqual(result['fields']['{ sample_period, sample_freq }'], '99')
                self.assertEqual(result['fields']['config'], '0 (PERF_COUNT_SW_CPU_CLOCK)')
                self.assertNotIn('mmap', result['fields'])

    def test_numeric_spellings_and_union_spacing_preserve_semantics(self):
        raw = self.cpu.replace('type: 1 (software)', 'type: 0x1')
        raw = raw.replace('config: 0 (PERF_COUNT_SW_CPU_CLOCK)', 'config: 0x0')
        raw = raw.replace('{ sample_period, sample_freq }: 99', '{sample_period,\tsample_freq}: 0x63')
        raw = raw.replace('sample_regs_user: 0xff0fff', 'sample_regs_user: 16715775')
        raw = raw.replace('sample_stack_user: 8192', 'sample_stack_user: 0x2000')
        self.assertTrue(self.verify(raw)['verified'])

    def test_missing_attributes_are_not_borrowed_from_dummy(self):
        fragments = {
            'type': 'type: 1 (software), ',
            'config': 'config: 0 (PERF_COUNT_SW_CPU_CLOCK), ',
            '{ sample_period, sample_freq }': '{ sample_period, sample_freq }: 99, ',
            'freq': 'freq: 1, ', 'inherit': 'inherit: 1, ',
            'exclude_kernel': 'exclude_kernel: 1, ', 'use_clockid': 'use_clockid: 1, ',
            'clockid': ', clockid: 1', 'sample_stack_user': 'sample_stack_user: 8192, ',
            'sample_regs_user': 'sample_regs_user: 0xff0fff, ',
            'sample_type': 'sample_type: IP|TID|TIME|ADDR|READ|CALLCHAIN|CPU|PERIOD|REGS_USER|STACK_USER|IDENTIFIER|DATA_SRC, ',
            'read_format': 'read_format: TOTAL_TIME_ENABLED|TOTAL_TIME_RUNNING|ID|LOST, ',
        }
        for key, fragment in fragments.items():
            with self.subTest(field=key):
                self.assertIn(fragment, self.cpu)
                bad = self.cpu.replace(fragment, '', 1)
                for donor in (self.dummy, self.cpu.replace('cpu-clock:uS:', 'task-clock:uS:', 1)):
                    for raw in (bad + '\n' + donor, donor + '\n' + bad):
                        self.rejected(raw, key)

    def test_wrong_values_and_period_mode_cannot_pass(self):
        cases = [
            ('type: 1 (software)', 'type: 0 (hardware)', 'type'),
            ('type: 1 (software)', 'type: 0 (software)', 'type'),
            ('config: 0 (PERF_COUNT_SW_CPU_CLOCK)', 'config: 0x9 (PERF_COUNT_SW_DUMMY)', 'config'),
            ('config: 0 (PERF_COUNT_SW_CPU_CLOCK)', 'config: 1 (PERF_COUNT_SW_CPU_CLOCK)', 'config'),
            ('{ sample_period, sample_freq }: 99', '{ sample_period, sample_freq }: 100', 'expected 99'),
            ('{ sample_period, sample_freq }: 99', '{ sample_period, sample_freq }: 990', 'expected 99'),
            ('{ sample_period, sample_freq }: 99', 'sample_period: 99', 'missing attribute { sample_period, sample_freq }'),
            ('freq: 1', 'freq: 0', 'freq: expected 1'),
            ('inherit: 1', 'inherit: 0', 'inherit: expected 1'),
            ('exclude_kernel: 1', 'exclude_kernel: 0', 'exclude_kernel: expected 1'),
            ('use_clockid: 1', 'use_clockid: 0', 'use_clockid: expected 1'),
            (', clockid: 1', ', clockid: 0', 'clockid: expected 1'),
            (', clockid: 1', ', clockid: 11', 'clockid: expected 1'),
            ('sample_stack_user: 8192', 'sample_stack_user: 4096', 'expected 8192'),
            ('sample_stack_user: 8192', 'sample_stack_user: 81920', 'expected 8192'),
            ('sample_stack_user: 8192', 'sample_stack_user: 8192junk', 'invalid numeric'),
            ('sample_regs_user: 0xff0fff', 'sample_regs_user: 0', 'empty register mask'),
            ('sample_regs_user: 0xff0fff', 'sample_regs_user: 0xgarbage', 'invalid numeric'),
            ('freq: 1', 'freq: -1', 'invalid numeric'),
            ('freq: 1', 'freq: 18446744073709551616', 'invalid numeric'),
        ]
        for before, after, reason in cases:
            with self.subTest(change=after):
                self.assertIn(before, self.cpu)
                self.rejected(self.cpu.replace(before, after, 1) + '\n' + self.dummy, reason)
        self.rejected(self.cpu + ', exclude_user: 1\n' + self.dummy, 'exclude_user')

    def test_required_bits_must_belong_to_the_correct_cpu_field(self):
        for bit in ('IP', 'TID', 'TIME', 'READ', 'REGS_USER', 'STACK_USER',
                    'TOTAL_TIME_ENABLED', 'TOTAL_TIME_RUNNING'):
            for replacement in ('', 'NOT_' + bit + '|'):
                with self.subTest(bit=bit, replacement=replacement):
                    cpu = self.cpu.replace(bit + '|', replacement, 1)
                    self.assertNotEqual(cpu, self.cpu)
                    self.rejected(cpu + '\n' + self.dummy, bit)
        self.rejected(self.cpu.replace('READ|', '', 1) + ', note: READ\n' + self.dummy, 'READ')
        self.rejected(self.cpu.replace('TOTAL_TIME_RUNNING|', '', 1) +
                      ', note: TOTAL_TIME_RUNNING\n' + self.dummy, 'TOTAL_TIME_RUNNING')

    def test_unrelated_and_duplicate_events_cannot_supply_cpu_evidence(self):
        for name in ('dummy:u', 'task-clock:uS', 'cycles:uS', 'cpu-clock:u', 'cpu-clock:kS'):
            with self.subTest(event=name):
                unrelated = self.cpu.replace('cpu-clock:uS:', name + ':', 1)
                self.rejected(unrelated + '\n' + self.dummy, 'found 0')
                # Even a completely valid unrelated row cannot repair one bad
                # field on the selected CPU event, in either physical order.
                bad = self.cpu.replace('freq: 1', 'freq: 0', 1)
                for raw in (bad + '\n' + unrelated, unrelated + '\n' + bad):
                    self.rejected(raw, 'freq: expected 1')
        self.rejected(self.raw + self.cpu.encode('ascii'), 'found 2')
        split = self.cpu.replace('sample_stack_user: 8192, ', '', 1)
        other = self.cpu.replace('freq: 1, ', '', 1)
        self.rejected(split + '\n' + other, 'found 2')

    def test_corrupt_empty_duplicate_and_oversized_records_fail(self):
        for raw, reason in [
                ('', 'found 0'), ('not perf attributes', 'malformed event'),
                (self.cpu.replace('{ sample_period, sample_freq }', '{ sample_period, BROKEN }'), 'malformed attribute'),
                (self.cpu.replace(', inherit:', ' inherit:', 1), 'malformed attribute'),
                (self.cpu + ', freq: 1', 'duplicate attribute freq'),
                (self.cpu + ', freq: 0', 'duplicate attribute freq'),
                (self.cpu + ', {sample_period,sample_freq}: 99', 'duplicate attribute'),
                (self.cpu + ', sample_freq: 100', 'unexpected standalone union attribute'),
                (self.cpu + ', sample_period: 100', 'unexpected standalone union attribute'),
                (self.cpu + ',', 'trailing field separator'),
                (self.cpu.replace(', sample_stack_user:', '\nsample_stack_user:', 1), 'malformed attribute'),
                (self.raw + b'\xff', 'unavailable/invalid'),
                (self.raw + b'\0', 'non-text control bytes'),
                (self.cpu.replace('READ|', 'READ||', 1), 'missing/invalid bit field'),
                (self.cpu.replace('sample_type: IP|', 'sample_type: 0x1|', 1), 'missing/invalid bit field'),
                (b'x' * (2 * 1024**2 + 1), '2 MiB metadata cap'),
                ('x' * 16385, 'event/line bound'),
                ((self.dummy + '\n') * 33, 'event/line bound')]:
            with self.subTest(reason=reason):
                self.rejected(raw, reason)

    def test_missing_file_command_failure_and_hash_mismatch_fail_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            result = trace.read_cpu_attributes(Path(folder) / 'absent.txt', {})
            self.assertFalse(result['verified'])
            self.assertIn('unavailable/invalid', '\n'.join(result['issues']))
        for changes in ({'returncode': 1}, {'returncode': None}, {'returncode': False},
                        {'forced': True}, {'incomplete': 'deadline_or_output_cap'}):
            with self.subTest(status=changes):
                self.rejected(self.raw, 'command failed/incomplete', status_changes=changes)
        for digest in (None, '0' * 64):
            self.rejected(self.raw, 'hash missing/mismatched', status_changes={'stdout_sha256': digest})

    def test_cpu_decode_retains_attribute_reasons_and_unknown_unwinding(self):
        stacks = ('fixture 7/8 12.000000000: cpu-clock:uS:\n'
                  '        1234 fixture_leaf (/fixture)\n'
                  '        2345 fixture_middle (/fixture)\n'
                  '        3456 fixture_outer (/fixture)\n'
                  '        4567 [unknown] (/fixture)\n\n')
        records = b'PERF_RECORD_SAMPLE\nPERF_RECORD_MMAP2\nPERF_RECORD_COMM\n'
        for valid in (True, False):
            with self.subTest(valid=valid), tempfile.TemporaryDirectory() as folder:
                out = Path(folder)
                raw = self.raw if valid else self.raw.replace(b'freq: 1', b'freq: 0', 1)

                def metadata(action, destination, **kwargs):
                    content = {'perf-script': stacks.encode('ascii'), 'perf-attributes': raw,
                               'perf-buildids': b'12345678 /fixture\n', 'perf-header': b'header\n'}[action]
                    destination.write_bytes(content)
                    return dict(returncode=0, forced=False, incomplete=None,
                                stdout_sha256=hashlib.sha256(content).hexdigest())

                process = Mock()
                process.poll.return_value = 0
                process.wait.return_value = 0
                dsos = dict(complete=False, dsos=[dict(path='/fixture', eh_frame=False,
                                                      build_id_lines=['Build ID: 12345678'])])
                with patch.object(trace, 'command', side_effect=metadata), \
                        patch.object(trace, 'launch', return_value=process), \
                        patch.object(trace.os, 'set_blocking'), \
                        patch.object(trace.os, 'read', side_effect=[records, b'']):
                    result = trace.cpu_decode(out, {7}, dsos)
                self.assertEqual(result['attributes_verified'], valid)
                self.assertEqual(result['attribute_validation']['verified'], valid)
                self.assertEqual((out / 'perf-attributes.txt').read_bytes(), raw)
                self.assertEqual(result['samples'], 1)
                self.assertTrue(nested_fixture_proof(result['callchains'])['proven'])
                self.assertFalse(result['unwind_complete'])
                self.assertFalse(result['samples_complete'])
                self.assertIn('missing matching ELF/build IDs/CFI', result['issues'])
                self.assertIn('partial unwinding/unresolved samples', result['issues'])
                saved = json.loads((out / 'cpu-coverage.json').read_text())
                self.assertEqual(saved['attribute_validation'], result['attribute_validation'])
                if valid:
                    self.assertEqual(len(result['issues']), 2)
                else:
                    self.assertIn('actual software sample attributes not verified', result['issues'])
                    self.assertIn('CPU attributes: cpu-clock:uS freq: expected 1, got 0', result['issues'])


class H1ArtifactTests(unittest.TestCase):
    def test_fixture_setup_failure_reaps_before_reporting(self):
        with tempfile.TemporaryDirectory() as folder, \
                patch.object(preflight, 'launch') as launched, \
                patch.object(preflight, 'reap') as reaped, \
                patch.object(preflight.Fixture, 'wait', side_effect=RuntimeError('fixture missing ready')):
            with self.assertRaisesRegex(RuntimeError, 'fixture missing ready'):
                preflight.Fixture(Path(folder), 'cpu')
            reaped.assert_called_once_with(launched.return_value)

    def test_cli_handoff_runs_without_forgiving_producer_or_retention_failures(self):
        for producer_status, retention_status in [(0, 0), (1, 0), (0, 1), (1, 1)]:
            with self.subTest(producer=producer_status, retention=retention_status), \
                    tempfile.TemporaryDirectory() as folder, \
                    patch.object(sys, 'argv', ['h1_trace.py', 'preflight', '--output', folder]), \
                    patch.dict(os.environ, GITHUB_ACTIONS='true', RUNNER_ENVIRONMENT='github-hosted'), \
                    patch.object(trace.platform, 'system', return_value='Linux'), \
                    patch.object(trace.platform, 'machine', return_value='x86_64'), \
                    patch.object(trace.os, 'geteuid', return_value=0), \
                    patch.object(trace, 'command'), \
                    patch.object(preflight, 'preflight', return_value=producer_status), \
                    patch.object(trace, 'prepare_artifacts', return_value=retention_status) as prepare:
                self.assertEqual(trace.main(), producer_status or retention_status)
                prepare.assert_called_once_with(folder)
        with tempfile.TemporaryDirectory() as folder, \
                patch.object(sys, 'argv', ['h1_trace.py', 'preflight', '--output', folder]), \
                patch.dict(os.environ, GITHUB_ACTIONS='true', RUNNER_ENVIRONMENT='github-hosted'), \
                patch.object(trace.platform, 'system', return_value='Linux'), \
                patch.object(trace.platform, 'machine', return_value='x86_64'), \
                patch.object(trace.os, 'geteuid', return_value=0), \
                patch.object(trace, 'command'), \
                patch.object(preflight, 'preflight', side_effect=RuntimeError('preflight failed')), \
                patch.object(trace, 'prepare_artifacts', return_value=0) as prepare, \
                contextlib.redirect_stdout(io.StringIO()) as log:
            self.assertEqual(trace.main(), 1)
            prepare.assert_called_once_with(folder)
            self.assertIn('preflight failed', log.getvalue())

    def test_cpu_setup_failure_removes_only_owned_control_fifos(self):
        with tempfile.TemporaryDirectory() as folder:
            out = Path(folder)
            raw = out / 'perf.data'
            raw.write_bytes(b'partial raw capture')
            with patch.object(trace, 'launch', side_effect=OSError('perf launch failed')):
                with self.assertRaisesRegex(OSError, 'perf launch failed'):
                    trace.CPU(out, dict(pid=123))
            self.assertFalse((out / 'perf.control').exists())
            self.assertFalse((out / 'perf.ack').exists())
            self.assertEqual(raw.read_bytes(), b'partial raw capture')
            # A stale regular control artifact must never be unlinked as a FIFO.
            (out / 'perf.ack').write_bytes(b'retained control receipt')
            with self.assertRaises(FileExistsError):
                trace.CPU(out, dict(pid=123))
            self.assertFalse((out / 'perf.control').exists())
            self.assertEqual((out / 'perf.ack').read_bytes(), b'retained control receipt')

    def test_cpu_supported_and_unsupported_cleanup_preserve_first_exit(self):
        for supported in (True, False):
            with self.subTest(supported=supported), tempfile.TemporaryDirectory() as folder:
                out = Path(folder)
                process = Mock()
                process.poll.return_value = None if supported else 1
                status = dict(returncode=0 if supported else -9, forced=not supported)
                with patch.object(trace, 'launch', return_value=process), \
                        patch.object(trace.os, 'read', return_value=b'ack\n'), \
                        patch.object(trace, 'reap', return_value=status) as reaped:
                    cpu = trace.CPU(out, dict(pid=123))
                    self.assertEqual(cpu.ready['status'], 'supported' if supported else 'unsupported')
                    self.assertEqual(cpu.finish(), status)
                    self.assertEqual(cpu.finish(), status)
                    reaped.assert_called_once_with(process)
                self.assertTrue(cpu.err.closed)
                self.assertIsNone(cpu.control)
                self.assertIsNone(cpu.ack)
                self.assertFalse((out / 'perf.control').exists())
                self.assertFalse((out / 'perf.ack').exists())

    def test_preflight_log_is_bounded_scrubbed_and_does_not_open_fifo(self):
        with tempfile.TemporaryDirectory() as folder:
            out = Path(folder)
            (out / 'loader.stderr').write_text('verifier rejected\n0xffffffff81234567\n')
            (out / 'perf.stderr').write_text('x' * 10000 + '\nperf attach failed\n')
            os.mkfifo(out / 'fixture.stderr')
            result = dict(status='error', errors=['fixture failed\n0xffffffff81234567'],
                          ready=dict(status='unsupported', reason='no perf enable acknowledgement'))
            original = copy.deepcopy(result)
            log = io.StringIO()
            with contextlib.redirect_stdout(log):
                preflight.print_result('cpu', out, result)
            output = log.getvalue()
            self.assertLessEqual(len(output), 4096)
            self.assertEqual(len(output.splitlines()), 1)
            self.assertIn('verifier rejected', output)
            self.assertIn('perf attach failed', output)
            self.assertIn('not a regular file', output)
            self.assertIn('[address-redacted]', output)
            self.assertNotIn('ffffffff81234567', output)
            self.assertEqual(result, original)
            result['errors'] = ['long error' * 10000]
            log = io.StringIO()
            with contextlib.redirect_stdout(log):
                preflight.print_result('cpu', out, result)
            self.assertLessEqual(len(log.getvalue()), 4096)
            self.assertIn('[truncated;', log.getvalue())

    def test_preflight_retains_failure_and_verdict_on_all_normal_outcomes(self):
        for status, expected in [('error', 1), ('unsupported', 0), ('supported', 0)]:
            with self.subTest(status=status), tempfile.TemporaryDirectory() as folder:
                def run(out, results):
                    results['cpu'] = dict(status=status, errors=['actual failure'] if expected else [])
                with patch.object(preflight, 'run_fixtures', side_effect=run), \
                        contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(preflight.preflight(Path(folder)), expected)
                report = json.loads((Path(folder) / 'preflight.json').read_text())
                self.assertEqual(report['results']['cpu']['status'], status)
                self.assertFalse(report['gateway_coverage'])
        with tempfile.TemporaryDirectory() as folder:
            log = io.StringIO()
            with patch.object(preflight, 'capabilities', side_effect=RuntimeError('capability collection failed')), \
                    contextlib.redirect_stdout(log):
                self.assertEqual(preflight.preflight(Path(folder)), 1)
            self.assertIn('capability collection failed', log.getvalue())
            report = json.loads((Path(folder) / 'preflight.json').read_text())
            self.assertEqual(report['status'], 'error')
            self.assertIn('capability collection failed', report['results']['preflight']['error'])

    def test_interrupted_preflight_never_records_success(self):
        with tempfile.TemporaryDirectory() as folder, \
                patch.object(preflight, 'run_fixtures', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                preflight.preflight(Path(folder))
            self.assertEqual(json.loads((Path(folder) / 'preflight.json').read_text())['status'], 'error')


@unittest.skipUnless(os.geteuid() == 0 and os.environ.get('GITHUB_ACTIONS') == 'true'
                     and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted',
                     'requires the dedicated hosted sudo artifact regression step')
class H1ArtifactOwnershipTests(unittest.TestCase):
    def test_root_owned_raw_and_control_artifacts_are_runner_readable(self):
        uid, gid = int(os.environ['SUDO_UID']), int(os.environ['SUDO_GID'])
        self.assertGreater(uid, 0)
        self.assertGreater(gid, 0)
        with tempfile.TemporaryDirectory() as folder:
            out = Path(folder)
            cpu = out / 'cpu'; cpu.mkdir(mode=0o700)
            raw = cpu / 'perf.data'
            payload = b'\x00raw perf\xff\n0xffffffff81234567\n'
            raw.write_bytes(payload); raw.chmod(0o600)
            self.assertEqual(raw.stat().st_uid, 0)
            before = trace.digest(raw)
            for name in ('perf.control', 'perf.ack'):
                os.mkfifo(cpu / name, 0o600)
            # Only FIFO controls are disposable; regular control evidence stays.
            regular = out / 'perf.control'; regular.write_bytes(b'control receipt')
            (cpu / 'loader.stderr').write_text('verifier failed\n0xffffffff81234567\n')
            (out / 'preflight.json').write_text('{"status":"error"}\n')
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(trace.prepare_artifacts(out), 0)
                self.assertEqual(trace.prepare_artifacts(out), 0)
            self.assertEqual(trace.digest(raw), before)
            self.assertEqual((raw.stat().st_uid, raw.stat().st_gid), (uid, gid))
            self.assertEqual(stat.S_IMODE(raw.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(cpu.stat().st_mode), 0o700)
            self.assertFalse((cpu / 'perf.control').exists())
            self.assertFalse((cpu / 'perf.ack').exists())
            self.assertEqual(regular.read_bytes(), b'control receipt')
            self.assertEqual((cpu / 'loader.stderr').read_text(), 'verifier failed\n[address-redacted]\n')
            # Exercise the uploader's actual ordinary identity, not root's access.
            child = os.fork()
            if child == 0:
                try:
                    os.setgroups([]); os.setgid(gid); os.setuid(uid)
                    assert raw.read_bytes() == payload
                    assert (out / 'preflight.json').read_text() == '{"status":"error"}\n'
                    assert regular.read_bytes() == b'control receipt'
                except BaseException:
                    os._exit(1)
                os._exit(0)
            self.assertEqual(os.waitpid(child, 0)[1], 0)

    def test_acquired_mapped_elf_handoff_is_readable_by_ordinary_runner(self):
        fixture = H1DSOAcquisitionTests()
        fixture.setUp(); self.addCleanup(fixture.doCleanups)
        record = fixture.acquire()
        retained = fixture.destination / 'usr/lib/libfixture.so'
        uid, gid = int(os.environ['SUDO_UID']), int(os.environ['SUDO_GID'])
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(trace.prepare_artifacts(Path(fixture.folder.name)), 0)
        self.assertEqual(trace.digest(retained), record['sha256'])
        self.assertEqual(retained.stat().st_uid, uid)
        child = os.fork()
        if child == 0:
            try:
                os.setgroups([]); os.setgid(gid); os.setuid(uid)
                assert retained.read_bytes() == fixture.payload
            except BaseException:
                os._exit(1)
            os._exit(0)
        self.assertEqual(os.waitpid(child, 0)[1], 0)

    def test_links_and_unknown_fifos_fail_without_touching_external_data(self):
        with tempfile.TemporaryDirectory() as folder:
            parent = Path(folder)
            out = parent / 'capture'; out.mkdir()
            external = parent / 'outside'; external.mkdir(mode=0o700)
            target = external / 'data'; target.write_bytes(b'private sibling data'); target.chmod(0o600)
            before = target.stat()
            (out / 'file-link').symlink_to(target)
            (out / 'directory-link').symlink_to(external, target_is_directory=True)
            os.link(target, out / 'hard-link')
            os.mkfifo(out / 'unknown-control')
            with contextlib.redirect_stdout(io.StringIO()) as log:
                self.assertEqual(trace.prepare_artifacts(out), 1)
            self.assertIn('"error_count": 4', log.getvalue())
            after = target.stat()
            self.assertEqual((after.st_uid, after.st_gid, after.st_mode),
                             (before.st_uid, before.st_gid, before.st_mode))
            self.assertEqual(target.read_bytes(), b'private sibling data')
            self.assertTrue(stat.S_ISFIFO((out / 'unknown-control').lstat().st_mode))
            link = parent / 'root-link'; link.symlink_to(out, target_is_directory=True)
            with self.assertRaises(OSError):
                trace.prepare_artifacts(link)


class H1TraceTests(unittest.TestCase):
    def assess(self, rows):
        return syscall_coverage(rows, dict(pid=7, start_ticks=9, cgroup_id=42, namespaces={'net': 1}),
                                dict(measurement={'valid': True}))

    def test_byte_returns_and_errors_stay_distinct(self):
        result = self.assess(producer_records())
        self.assertTrue(result['complete'])
        row = result['syscall_totals'][0]
        self.assertEqual((row['attempts'], row['positive'], row['errors'], row['accepted_bytes']), (2, 1, 1, 5))
        self.assertFalse(result['accepted_is_peer_delivery'])
        self.assertFalse(result['exact_lifetimes_complete'])

    def test_missing_loss_schema_and_signed_return_do_not_zero_fill(self):
        for field in ('losses', 'pending', 'map_read_failures'):
            rows = producer_records()
            del rows[2][field]
            self.assertFalse(self.assess(rows).get('complete'))
        rows = producer_records()
        rows[2]['totals'][0]['min_return'] = 2**64 - 11
        self.assertFalse(self.assess(rows).get('complete'))

    def test_abandoned_attempts_and_reset_remain_incomplete(self):
        rows = producer_records()
        rows[2]['totals'][0]['attempts'] = 3
        self.assertFalse(self.assess(rows)['complete'])
        rows = producer_records()
        earlier = copy.deepcopy(rows[2]); earlier['phase'] = 'snapshot'
        earlier['totals'][0]['accepted_bytes'] = 50
        rows.insert(2, earlier)
        self.assertTrue(self.assess(rows)['reset'])

    def test_witness_cap_not_conflated_with_aggregate_loss(self):
        rows = producer_records()
        rows[2]['losses'][LOSSES.index('witness_cap')] = 100
        result = self.assess(rows)
        self.assertTrue(result['complete'])
        self.assertFalse(result['witness_complete'])
        rows[2]['losses'][LOSSES.index('map_full')] = 1
        self.assertFalse(self.assess(rows)['complete'])

    def test_shared_read_failure_invalidates_whole_call_completeness(self):
        rows = producer_records()
        rows[1]['at_ns'] = 5
        prior = copy.deepcopy(rows[2])
        prior.update(phase='checkpoint', before_ns=10, after_ns=20, rows=[], census={})
        prior['totals'] = [counter(**dict.fromkeys(COUNTERS, 0), min_return=0, max_return=0)]
        final = rows[2]
        rows.insert(2, prior)
        owner = dict(pid=7, start_ticks=9, cgroup_id=42, namespaces={'net': 1})
        boundaries = dict(measurement=dict(valid=True, start_bounds_ns=[50, 51], end_bounds_ns=[90, 91]))
        self.assertTrue(syscall_coverage(rows, owner, boundaries)['measurement_complete'])
        final['losses'][LOSSES.index('read_failed')] = 1
        result = syscall_coverage(rows, owner, boundaries)
        for flag in ('complete', 'measurement_complete', 'offered_length_complete',
                     'successful_return_bytes_complete', 'lifecycle_stream_complete', 'witness_complete'):
            self.assertFalse(result[flag], flag)
        self.assertEqual(result['syscall_totals'], final['totals'])
        self.assertEqual(result['census'], {'1': 2})

    def test_lifecycle_requires_typed_complete_bound_termination(self):
        variants = []
        for key in ('requested_stop', 'bound', 'at_ns', 'lifecycle_omitted', 'checkpoints_omitted', 'snapshot_failures'):
            for value in (None, '0', False if key not in ('requested_stop', 'bound') else 1):
                rows = producer_records(); rows[-1][key] = value; variants.append(rows)
            rows = producer_records(); rows[-1].pop(key); variants.append(rows)
        rows = producer_records(); rows.pop(); variants.append(rows)
        rows = producer_records(); rows.append(copy.deepcopy(rows[-1])); variants.append(rows)
        for loss in ('map_full', 'read_failed', 'ring_full', 'nested', 'unmatched', 'abandoned', 'compat', 'generation', 'exec'):
            rows = producer_records(); rows[2]['losses'][LOSSES.index(loss)] = 1; variants.append(rows)
        for key in ('cgroup', 'netns', 'start_ticks'):
            rows = producer_records(); rows[1][key] += 1; variants.append(rows)
        for rows in variants:
            with self.subTest(rows=rows):
                result = self.assess(rows)
                self.assertFalse(result['lifecycle_stream_complete'])
                self.assertFalse(result['witness_complete'])
                self.assertEqual(result['syscall_totals'], rows[2]['totals'])
        valid = self.assess(producer_records())
        self.assertTrue(valid['lifecycle_stream_complete'])
        self.assertTrue(valid['witness_complete'])

    def test_truncated_terminal_stream_keeps_partial_counters_without_certification(self):
        with tempfile.TemporaryDirectory() as folder:
            out = Path(folder)
            (out / 'syscalls.jsonl').write_text('\n'.join(json.dumps(row) for row in producer_records()))
            observer = object.__new__(trace.Observer)
            observer.out, observer.offset, observer.pending, observer.rows = out, 0, b'', []
            observer.poll()
            self.assertTrue(observer.pending)
            result = self.assess(observer.rows)
            self.assertFalse(result['complete'])
            self.assertFalse(result['lifecycle_stream_complete'])
            self.assertFalse(result['witness_complete'])
            self.assertEqual(result['syscall_totals'], producer_records()[2]['totals'])

    def test_lifecycle_losses_in_earlier_snapshots_cannot_disappear(self):
        rows = producer_records()
        prior = copy.deepcopy(rows[2]); prior.update(phase='checkpoint', before_ns=95, after_ns=96)
        prior['losses'][LOSSES.index('read_failed')] = 1
        rows.insert(2, prior)
        result = self.assess(rows)
        self.assertTrue(result['reset'])
        self.assertFalse(result['complete'])
        self.assertFalse(result['lifecycle_stream_complete'])
        self.assertEqual(result['losses']['read_failed'], 0)
        self.assertEqual(result['observed_loss_maxima']['read_failed'], 1)

    def test_zero_cookie_and_foreign_generation_never_get_roles(self):
        rows = producer_records()
        rows[2]['rows'][0]['cookie'] = 0
        with self.assertRaises(ValueError):
            validate_record(rows[2])
        rows = producer_records()
        rows[2]['rows'][0]['process_ns'] += 10_000_000
        self.assertFalse(self.assess(rows)['complete'])

    def test_unavailable_does_not_certify_measurement(self):
        self.assertFalse(self.assess([dict(phase='ready', status='unsupported')])['complete'])
        rows = producer_records()
        rows[-1]['requested_stop'] = False
        self.assertFalse(self.assess(rows)['complete'])
        rows[2]['census']['425'] = 1
        self.assertFalse(self.assess(rows)['socket_roles_complete'])

    def test_reconcile_actual_fixture_contract_mmsg_returns_messages(self):
        call = dict(phase='call', label='batch', pid=1, tid=2, id=307, fd=8,
                    result=2, errno=0, offered=24)
        event = dict(call, phase='h1_event', kind=1, known=1, accepted_known=1, accepted=24)
        self.assertEqual(reconcile([call], [event])['errors'], [])
        event['accepted'] = 2
        self.assertIn('batch returned-prefix length mismatch', reconcile([call], [event])['errors'])
        call.update(result=-1, errno=14)
        event.update(result=-14, accepted=0, inner_bytes=12)
        self.assertEqual(reconcile([call], [event])['errors'], [])

    def test_fd_reuse_retains_intervals_without_guessing_cookie(self):
        base = dict(phase='h1_event', kind=2, pid=1, process_ns=20, tid=1,
                    entered_ns=10, exited_ns=11, arg1=0, arg2=0)
        events = [dict(base, id=41, fd=2, result=9), dict(base, id=3, fd=9, result=0),
                  dict(base, id=33, fd=8, result=9)]
        result = fd_lifetimes(events)
        self.assertEqual(result['intervals'][2]['alias_of'], 8)
        self.assertTrue(all(r['cookie'] is None for r in result['intervals']))
        self.assertFalse(result['exact_alias_join'])

    def test_cpu_names_without_actual_stack_samples_are_not_stacks(self):
        counts = decode_cpu('cpu-clock count 99999 fixture_outer fixture_leaf', '', {7})
        self.assertFalse(counts['stack_useful'])
        text = '''fixture 7/8 12.000000000: cpu-clock:u:
        1234 fixture_leaf (/fixture)
        2345 fixture_middle (/fixture)
        3456 fixture_outer (/fixture)

fixture 99/99 12.100000000: cpu-clock:u:
        7777 unrelated (/control)

'''
        result = decode_cpu(text, 'PERF_RECORD_SAMPLE\nPERF_RECORD_SAMPLE\nPERF_RECORD_LOST\nPERF_RECORD_THROTTLE', {7})
        self.assertEqual(result['samples'], 1)
        self.assertEqual(result['foreign_samples'], 1)
        self.assertEqual(result['multi_frame_samples'], 1)
        self.assertEqual(result['lost_records'], 1)
        self.assertFalse(result['complete'])

    def test_fixture_nested_proof_rejects_three_flat_samples_and_wrong_order(self):
        def decoded(groups):
            text = ''.join(f'fixture 7/{8 + i} 12.000000000: cpu-clock:u:\n' +
                           ''.join(f'        1234 {name} (/fixture)\n' for name in names) + '\n'
                           for i, names in enumerate(groups))
            return decode_cpu(text, '', {7})
        expected = ['fixture_leaf', 'fixture_middle', 'fixture_outer']
        flats = decoded([[name] for name in expected])
        self.assertFalse(nested_fixture_proof(flats['callchains'])['proven'])
        wrong = decoded([list(reversed(expected))])
        self.assertFalse(nested_fixture_proof(wrong['callchains'])['proven'])
        names = ['fixture_leaf.constprop.0+0x12', '[unknown]', 'inline_helper',
                 'fixture_middle.isra.1', 'fixture_outer']
        nested = decoded([names])
        proof = nested_fixture_proof(nested['callchains'])
        self.assertTrue(proof['proven'])
        self.assertEqual(proof['witnesses'][0]['matched_frame_indices'], [0, 3, 4])
        self.assertEqual(proof['witnesses'][0]['pid'], 7)
        self.assertEqual(proof['witnesses'][0]['tid'], 8)
        self.assertEqual(proof['witnesses'][0]['frames'], nested['callchains'][0]['frames'])
        self.assertEqual(nested['unresolved_samples'], 1)
        self.assertFalse(proof['complete_unwinding'])
        self.assertFalse(nested_fixture_proof(decoded([['fixture_leaf_fake'] + expected[1:]])['callchains'])['proven'])
        foreign = decode_cpu('fixture 99/99 12.0: cpu-clock:u:\n' +
                            ''.join(f'        1234 {name} (/fixture)\n' for name in expected), '', {7})
        self.assertFalse(nested_fixture_proof(foreign['callchains'])['proven'])
        self.assertEqual(foreign['foreign_samples'], 1)

    def test_external_calibration_is_separate_and_exact(self):
        validate_selection('trace-calibration', 'http1-tls', '4', '15', '200', 'ferrum', '5242880', 'same-image', '')
        with self.assertRaises(ValueError):
            validate_selection('trace-calibration', 'http1-tls', '4', '15', '100', 'ferrum', '5242880', 'same-image', '')
        with tempfile.TemporaryDirectory() as folder:
            self.assertFalse(load_trace(Path(folder) / 'missing.json')['complete'])


class H1AdmissionTests(unittest.TestCase):
    def test_actual_admission_binds_recorded_generation_and_container(self):
        runtime = dict(host_pid=7, start_ticks=9, container_id='a' * 64)
        owner = dict(pid=7, start_ticks=9, cgroup='/system.slice/docker-' + 'a' * 64 + '.scope',
                     cgroup_id=42, boot_id='boot', executable_sha256='b' * 64,
                     namespaces={name: 1 for name in ('pid', 'mnt', 'net', 'time', 'user')})
        with patch.object(trace, 'identity', return_value=owner), patch.object(trace, 'admit') as admit:
            self.assertEqual(trace.admit_runtime_target(runtime), owner)
            admit.assert_called_once_with(owner)
        for change in (dict(start_ticks=10), dict(cgroup='/docker/' + 'c' * 64),
                       dict(cgroup='/docker/prefix-' + 'a' * 64), dict(pid=True)):
            with self.subTest(change=change), patch.object(trace, 'identity', return_value=dict(owner, **change)), \
                    patch.object(trace, 'admit') as admit:
                with self.assertRaises(ValueError):
                    trace.admit_runtime_target(runtime)
                admit.assert_not_called()
        for key, value in (('cgroup_id', 43), ('executable_sha256', 'c' * 64),
                           ('namespaces', dict(owner['namespaces'], mnt=99))):
            with patch.object(trace, 'identity', return_value=dict(owner, **{key: value})), \
                    patch.object(trace, 'admit'):
                with self.assertRaisesRegex(ValueError, 'adjacent'):
                    trace.admit_runtime_target(runtime, owner)


class H1CommandBoundTests(unittest.TestCase):
    def test_already_exited_and_final_poll_output_are_rechecked_after_reap(self):
        for race in ('already_exited', 'final_poll', 'reaped_after_deadline'):
            with self.subTest(race=race), tempfile.TemporaryDirectory() as folder:
                out = Path(folder) / 'metadata.txt'
                process = Mock(returncode=0)
                process.wait.return_value = 0
                streams = {}
                def overflow():
                    for stream in streams.values():
                        stream.write(b'x' * 3000); stream.flush()
                    return 0
                def launched(action, *, stdout, stderr, **data):
                    self.assertEqual(data['file_limit'], 4096)
                    streams.update(stdout=stdout, stderr=stderr)
                    if race == 'already_exited':
                        overflow(); process.poll.return_value = 0
                    elif race == 'final_poll':
                        process.poll.side_effect = [None, 0]
                    else:
                        process.poll.return_value = None
                    return process
                def reaped(child):
                    overflow()
                    return dict(returncode=0, forced=False)
                with patch.object(trace, 'launch', side_effect=launched), \
                        patch.object(trace.time, 'sleep', side_effect=lambda _: overflow()), \
                        patch.object(trace, 'reap', side_effect=reaped):
                    result = trace.command('perf-header', out, limit=4096,
                                           timeout=0 if race == 'reaped_after_deadline' else 30)
                self.assertEqual(result['returncode'], 0)
                self.assertEqual(result['incomplete'], 'output_cap_after_reap')
                self.assertEqual(result['retained_bytes'], 6000)
                self.assertEqual(out.stat().st_size, 3000)
                self.assertEqual(json.loads(out.with_suffix('.txt.status.json').read_text()), result)


@unittest.skipUnless(sys.platform == 'linux', 'Linux pinned descriptor contract')
class H1DSOAcquisitionTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name) / 'root'; self.root.mkdir()
        self.destination = Path(self.folder.name) / 'symfs'; self.destination.mkdir()
        (self.root / 'usr/lib').mkdir(parents=True)
        self.source = self.root / 'usr/lib/libfixture.so'
        self.payload = b'\x7fELF' + b'a' * 131072
        self.source.write_bytes(self.payload)
        info = self.source.stat()
        self.mapping = dict(path='/usr/lib/libfixture.so', device_major=os.major(info.st_dev),
                            device_minor=os.minor(info.st_dev), inode=info.st_ino)
        self.decoder = patch.object(trace, 'command', side_effect=self.decode)
        self.command = self.decoder.start(); self.addCleanup(self.decoder.stop)

    def decode(self, action, destination, *, elf_fd, output_directory_fd, **kwargs):
        self.assertEqual(action, 'elf')
        self.assertEqual(os.pread(elf_fd, len(self.payload), 0), self.payload)
        fd = os.open(Path(destination).name, os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                     0o600, dir_fd=output_directory_fd)
        with os.fdopen(fd, 'w') as stream:
            stream.write('Build ID: abcdef\n.eh_frame\n')
        return dict(returncode=0, forced=False, incomplete=None)

    def acquire(self, **kwargs):
        budget = kwargs.pop('budget', dict(remaining=512 * 1024**2, package_remaining=512 * 1024**2))
        with trace.directory_fd(self.root) as root, trace.directory_fd(self.destination) as target:
            return trace.retain_mapped_elf(root, target, self.mapping, budget,
                                           kwargs.pop('deadline', trace.time.monotonic() + 30))

    def test_valid_mapped_elf_is_pinned_hashed_and_reused(self):
        for path in ('/usr/lib/libfixture.so', '//usr/lib/libfixture.so'):
            self.mapping['path'] = path
            result = self.acquire()
            self.assertEqual(result['sha256'], hashlib.sha256(self.payload).hexdigest())
            self.assertEqual(result['inode'], self.mapping['inode'])
            self.assertEqual(result['bytes'], len(self.payload))
            self.assertTrue(result['eh_frame'])
            self.assertEqual((self.destination / 'usr/lib/libfixture.so').read_bytes(), self.payload)

    def test_wrong_inode_regular_replacement_never_copies_unmapped_bytes(self):
        self.source.rename(self.source.with_suffix('.old'))
        self.source.write_bytes(b'\x7fELFprivate replacement')
        with self.assertRaisesRegex(ValueError, 'inode'):
            self.acquire()
        self.assertFalse((self.destination / 'usr').exists())
        self.command.assert_not_called()

    def test_source_links_and_nonregular_mappings_are_refused_before_read(self):
        self.source.unlink()
        outside = Path(self.folder.name) / 'private'; outside.write_bytes(self.payload)
        for kind in ('absolute_link', 'relative_escape', 'fifo', 'directory'):
            with self.subTest(kind=kind):
                if kind == 'absolute_link':
                    self.source.symlink_to(outside)
                elif kind == 'relative_escape':
                    self.source.symlink_to('../../../private')
                elif kind == 'fifo':
                    os.mkfifo(self.source)
                else:
                    self.source.mkdir()
                info = self.source.lstat()
                self.mapping.update(device_major=os.major(info.st_dev), device_minor=os.minor(info.st_dev), inode=info.st_ino)
                with self.assertRaises(ValueError):
                    self.acquire()
                if kind == 'directory':
                    self.source.rmdir()
                else:
                    self.source.unlink()
        self.assertFalse((self.destination / 'usr').exists())
        self.command.assert_not_called()

    def test_intermediate_source_link_and_destination_escape_are_refused(self):
        (self.root / 'usr').rename(self.root / 'real')
        (self.root / 'usr').symlink_to('real', target_is_directory=True)
        with self.assertRaises(OSError):
            self.acquire()
        (self.root / 'usr').unlink(); (self.root / 'real').rename(self.root / 'usr')
        outside = Path(self.folder.name) / 'outside'; outside.mkdir()
        (self.destination / 'usr').symlink_to(outside, target_is_directory=True)
        with self.assertRaises(OSError):
            self.acquire()
        self.assertEqual(list(outside.iterdir()), [])
        with self.assertRaises(ValueError):
            with trace.directory_fd(self.destination / '../outside', create=True):
                self.fail('parent traversal admitted')

    def test_growth_and_deadline_during_copy_preserve_only_bounded_partial_elf(self):
        original_read = os.read
        calls = 0
        def grow(fd, size):
            nonlocal calls
            chunk = original_read(fd, size)
            if size == 65536:
                calls += 1
                if calls == 2:
                    with self.source.open('ab') as stream:
                        stream.write(b'not admitted' * 10000)
            return chunk
        with patch.object(trace.os, 'read', side_effect=grow):
            with self.assertRaisesRegex(ValueError, 'changed'):
                self.acquire()
        retained = self.destination / 'usr/lib/libfixture.so'
        self.assertEqual(retained.read_bytes(), self.payload[:65536])
        self.command.assert_not_called()
        with self.assertRaisesRegex(ValueError, 'deadline'):
            self.acquire(deadline=0)
        with self.assertRaisesRegex(ValueError, 'cap'):
            self.acquire(budget=dict(remaining=8, package_remaining=512 * 1024**2))

    def test_deadline_is_checked_between_reads_and_destination_links_are_refused(self):
        now = [0]
        original_read = os.read
        def expire(fd, size):
            chunk = original_read(fd, size)
            if size == 65536:
                now[0] = 31
            return chunk
        with patch.object(trace.time, 'monotonic', side_effect=lambda: now[0]), \
                patch.object(trace.os, 'read', side_effect=expire):
            with self.assertRaisesRegex(ValueError, 'deadline'):
                self.acquire(deadline=30)
        retained = self.destination / 'usr/lib/libfixture.so'
        self.assertEqual(retained.read_bytes(), b'')
        retained.unlink()
        outside = Path(self.folder.name) / 'outside'; outside.write_bytes(self.payload)
        for kind in ('symlink', 'hardlink', 'fifo'):
            with self.subTest(kind=kind):
                if kind == 'symlink':
                    retained.symlink_to(outside)
                elif kind == 'hardlink':
                    os.link(outside, retained)
                else:
                    os.mkfifo(retained)
                with self.assertRaises(ValueError):
                    self.acquire()
                self.assertEqual(outside.read_bytes(), self.payload)
                retained.unlink()
        self.command.assert_not_called()

    def test_pinned_source_cannot_be_swapped_between_magic_copy_and_hash(self):
        original_read = os.read
        def replace_after_magic(fd, size):
            chunk = original_read(fd, size)
            if size == 4:
                self.source.unlink()
                self.source.write_bytes(b'\x7fELFunmapped private bytes')
            return chunk
        with patch.object(trace.os, 'read', side_effect=replace_after_magic):
            with self.assertRaisesRegex(ValueError, 'changed'):
                self.acquire()
        retained = self.destination / 'usr/lib/libfixture.so'
        self.assertEqual(retained.read_bytes(), b'')
        self.command.assert_not_called()


class H1TeardownTests(unittest.TestCase):
    """Use the real runner request and supervisor consumer with mocked processes."""
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.out = Path(self.folder.name)
        self.owner = dict(pid=7, start_ticks=9, cgroup_id=42, executable_sha256='elf',
                          boot_id='boot', namespaces={'time': 1, 'net': 2})
        self.binding = dict(sample=str(self.out / 'sample.json'), raw_sample=str(self.out / 'raw.json'),
                            client_exit=str(self.out / 'exit'), arm='ferrum', pair=1, payload=10240)
        phases = dict(timed_out=False, stalled_workers=[], transport_close_timed_out=False,
                      drain_secs=0.2, drain_start_monotonic_secs=30.0,
                      measurement_secs=1, measurement_elapsed_secs=1.001,
                      measurement_start_unix_secs=102,
                      measurement_start_host_clock=dict(clock='CLOCK_MONOTONIC', before_ns=2_000_000_000,
                                                        after_ns=2_000_000_001))
        self.raw = dict(phases=phases, protocol='HTTP/1.1+TLS', rps=123)
        self.sample = dict(self.raw, gateway='ferrum', pair=1, payload_size=10240)
        self.retain_client()
        trace.write(self.out / 'bind.json', self.binding)
        self.ready = dict(session='this-capture', binding_sha256=trace.digest(self.out / 'bind.json'),
                          at=self.at(1_000_000_000), owner=self.owner, deadline_monotonic=30)
        trace.write(self.out / 'ready.json', self.ready)
        self.cpu = Mock(ready={'status': 'supported'})
        self.cpu.process.pid = 101
        self.cpu.process.poll.return_value = None
        self.observer = Mock(ready={'status': 'supported'})
        self.observer.process.pid = 102
        self.observer.process.poll.return_value = None
        self.lifecycle = trace.CaptureLifecycle(self.out, self.owner, self.binding, self.ready,
                                                dict(cpu=self.cpu, observer=self.observer))
        self.now = 5_000_000_000
        self.clock = self.patch('clock', side_effect=self.tick)
        self.receipt = self.patch('clock_receipt', side_effect=self.tick)
        self.alive = self.patch('target_alive', return_value=True)
        self.identity = self.patch('identity', return_value=self.owner)
        self.monotonic = self.patch('time.monotonic', return_value=5)

    def patch(self, name, **kwargs):
        context = patch('h1_trace.' + name, **kwargs)
        value = context.start()
        self.addCleanup(context.stop)
        return value

    @staticmethod
    def at(ns):
        return dict(kind='clock_receipt', clock='CLOCK_MONOTONIC', boot_id='boot', time_namespace=1,
                    before_ns=ns, after_ns=ns + 1, unix_ns=100_000_000_000 + ns)

    def tick(self):
        self.now += 100
        return self.at(self.now)

    def retain_client(self):
        trace.write(self.out / 'raw.json', self.raw)
        trace.write(self.out / 'sample.json', self.sample)
        (self.out / 'exit').write_text('0\n')

    def request(self):
        request = dict(session=self.ready['session'], binding_sha256=self.ready['binding_sha256'],
                       owner=self.owner, evidence=trace.completion_evidence(self.binding), at=self.tick())
        trace.write(self.out / 'teardown-request.json', request)
        return request

    def test_real_runner_handshake_then_autoexit_before_stop(self):
        events = []
        def supervisor_tick(_):
            events.append('retained_client_request')
            self.lifecycle.authorize_teardown()
            events.append('live_supervisor_ack')
        self.patch('time.sleep', side_effect=supervisor_tick)
        # Read the receipt on the next loop; a broken ack reaches the deadline.
        self.monotonic.side_effect = [5, 5, 5, 30]
        trace.request_teardown(self.out)
        self.assertTrue((self.out / 'teardown-ready.json').exists())
        measurement = self.lifecycle.teardown['completion']['measurement']
        self.assertEqual(measurement['basis'], 'clock_receipts')
        self.assertEqual(measurement['start_bounds_ns'], [2_000_000_000, 2_000_000_001])
        self.assertEqual(measurement['end_bounds_ns'], [3_000_000_000, 3_000_000_001])
        self.assertNotIn('passive_capture_bracket', measurement)
        # Docker removal can take arbitrarily many supervisor polls. Its stop
        # marker has not been published when perf naturally exits.
        self.alive.return_value = False
        self.cpu.process.poll.return_value = 0
        events.append('target_removed_perf_autoexit')
        for _ in range(3):
            self.lifecycle.poll()
        self.assertFalse((self.out / 'stop').exists())
        end = self.lifecycle.observations['cpu']['exit']
        self.assertTrue(end['expected_target_teardown'])
        self.assertIsNone(end['exact_exit_ns'])
        self.assertLessEqual(end['bounds_ns'][0], end['bounds_ns'][1])
        self.assertEqual(events, ['retained_client_request', 'live_supervisor_ack', 'target_removed_perf_autoexit'])
        self.assertLess(self.lifecycle.coverage_end(self.now), end['bounds_ns'][1])
        self.lifecycle.verify_stop()

    def test_stop_marker_cannot_bypass_completion_removal_or_final_read(self):
        (self.out / 'stop').touch()
        with self.assertRaisesRegex(RuntimeError, 'stop without verified'):
            self.lifecycle.verify_stop()
        self.request(); self.lifecycle.authorize_teardown()
        with self.assertRaisesRegex(RuntimeError, 'before owned gateway removal'):
            self.lifecycle.verify_stop()
        self.alive.return_value = False
        self.lifecycle.poll()
        self.lifecycle.verify_stop()
        (self.out / 'raw.json').write_text('{')
        with self.assertRaises(ValueError):
            self.lifecycle.verify_stop()

    def test_target_exit_between_alive_read_and_collector_poll(self):
        self.request(); self.lifecycle.authorize_teardown()
        self.alive.side_effect = [True, False]
        self.cpu.process.poll.return_value = 0
        self.assertFalse(self.lifecycle.poll())
        self.assertIsNotNone(self.lifecycle.target_gone)

    def test_resource_read_exit_race_requires_verified_teardown(self):
        self.request(); self.lifecycle.authorize_teardown()
        self.alive.return_value = False
        def read_usage(pid, *_):
            if pid == self.cpu.process.pid:
                self.cpu.process.poll.return_value = 0
                return None
            return {'rss_bytes': 100}
        self.patch('capture', side_effect=read_usage)
        self.assertEqual(self.lifecycle.usage(), [{'rss_bytes': 100}])
        self.assertTrue(self.lifecycle.observations['cpu']['resource_read_exit_race']['usage_unknown'])

    def test_live_resource_read_failure_remains_an_error(self):
        self.request(); self.lifecycle.authorize_teardown()
        self.patch('capture', return_value=None)
        with self.assertRaisesRegex(RuntimeError, 'resource capture missing'):
            self.lifecycle.usage()

    def test_acknowledgement_wait_is_capped_by_capture_deadline(self):
        self.monotonic.side_effect = [29.95, 30]
        with self.assertRaisesRegex(RuntimeError, 'acknowledgement deadline'):
            trace.request_teardown(self.out)
        self.assertIsNone(self.lifecycle.teardown)

    def test_active_client_and_queued_completion_cannot_forgive_collector_loss(self):
        self.cpu.process.poll.return_value = 0
        with self.assertRaisesRegex(RuntimeError, 'collector exited'):
            self.lifecycle.poll()
        self.request()
        with self.assertRaisesRegex(RuntimeError, 'collector exited'):
            self.lifecycle.authorize_teardown()
        self.assertIsNone(self.lifecycle.teardown)
        self.assertFalse((self.out / 'teardown-ready.json').exists())

    def test_early_target_death_or_generation_change_cannot_authorize(self):
        self.request()
        self.alive.return_value = False
        with self.assertRaisesRegex(RuntimeError, 'gateway exited'):
            self.lifecycle.authorize_teardown()
        self.alive.return_value = True
        self.identity.return_value = dict(self.owner, start_ticks=10)
        with self.assertRaisesRegex(RuntimeError, 'generation changed'):
            self.lifecycle.authorize_teardown()

    def test_missing_stale_and_changed_completion_rejected(self):
        self.lifecycle.authorize_teardown()
        self.assertIsNone(self.lifecycle.teardown)
        request = self.request()
        for key, value in [('session', 'prior-capture'), ('binding_sha256', 'old'),
                           ('owner', dict(self.owner, boot_id='prior-boot')), ('at', self.at(1))]:
            with self.subTest(key=key):
                trace.write(self.out / 'teardown-request.json', dict(request, **{key: value}))
                with self.assertRaisesRegex(ValueError, 'stale/mismatched'):
                    self.lifecycle.authorize_teardown()
        trace.write(self.out / 'teardown-request.json', request)
        self.raw['rps'] = 999
        self.retain_client()
        with self.assertRaisesRegex(ValueError, 'changed after retention'):
            self.lifecycle.authorize_teardown()

    def test_old_client_measurement_cannot_authorize_fresh_capture(self):
        self.raw['phases']['measurement_start_host_clock']['before_ns'] = 1
        self.raw['phases']['measurement_start_host_clock']['after_ns'] = 2
        self.retain_client(); self.request()
        with self.assertRaisesRegex(ValueError, 'does not bracket'):
            self.lifecycle.authorize_teardown()

    def test_receipt_admission_preserves_resource_interval_requirement(self):
        receipts = [self.ready['at'], self.at(self.now)]
        timeline = [dict(clock=c) for c in receipts]
        window = trace.boundary_report(self.sample, timeline, 900_000_000, self.now, self.owner)['measurement']
        self.assertTrue(window['valid'])
        self.assertEqual(window['basis'], 'clock_receipts')
        self.assertNotIn('passive_capture_bracket', window)
        # The same receipts cannot certify passive resource reads, even though
        # they suffice for event placement and teardown's clock admission.
        self.assertEqual(measurement_window(self.raw['phases'], timeline)['reason'],
                         'missing_or_invalid_capture_interval')
        resources = [dict(row, monotonic_ns=row['clock']['before_ns'],
                          capture_end_ns=row['clock']['after_ns'] + 100) for row in timeline]
        self.assertTrue(measurement_window(self.raw['phases'], resources)['valid'])
        resources[0]['capture_end_ns'] = 2_000_000_001
        self.assertEqual(measurement_window(self.raw['phases'], resources)['reason'],
                         'missing_passive_capture_bracket')
        for start, end in [(2_000_000_001, self.now), (900_000_000, 3_000_000_000)]:
            with self.subTest(start=start, end=end):
                self.assertFalse(trace.boundary_report(self.sample, timeline, start, end, self.owner)
                                 ['measurement']['valid'])

    def test_missing_malformed_foreign_and_early_receipts_cannot_authorize(self):
        request = self.request()
        malformed = [None, [], {}, dict(request['at'], before_ns=True),
                     dict(request['at'], after_ns='later')]
        malformed += [dict(request['at'], **{key: value}) for key, value in (
            ('kind', 'passive_capture'), ('clock', 'CLOCK_BOOTTIME'), ('boot_id', 'prior-boot'),
            ('time_namespace', 2), ('time_namespace', True), ('unix_ns', None),
            ('unix_ns', request['at']['unix_ns'] + 1_000_000_000),
            ('unix_ns', request['at']['unix_ns'] - 1_000_000_000))]
        malformed += [{key: value for key, value in request['at'].items() if key != missing}
                      for missing in request['at']]
        # Preserve realtime/monotonic correspondence while breaking uncertainty
        # or the actual measurement end bracket.
        malformed += [dict(self.at(4_000_000_000), after_ns=4_002_000_000),
                      self.at(3_000_000_000)]
        for at in malformed:
            with self.subTest(at=at):
                trace.write(self.out / 'teardown-request.json', dict(request, at=at))
                with self.assertRaises(ValueError):
                    self.lifecycle.authorize_teardown()
                self.assertIsNone(self.lifecycle.teardown)
                self.assertFalse((self.out / 'teardown-ready.json').exists())
        trace.write(self.out / 'teardown-request.json', request)
        self.lifecycle.authorize_teardown()
        self.assertIsNotNone(self.lifecycle.teardown)

    def test_invalid_phase_clock_cannot_authorize(self):
        original = copy.deepcopy(self.raw['phases'])
        invalid_clocks = [None, {}, dict(clock='process_local', before_ns=1, after_ns=2),
                          dict(clock='CLOCK_MONOTONIC', before_ns=1, after_ns=2),
                          dict(clock='CLOCK_MONOTONIC', before_ns=True, after_ns=2),
                          dict(clock='CLOCK_MONOTONIC', before_ns=2_000_000_000,
                               after_ns=2_002_000_000)]
        changes = [('measurement_start_host_clock', c) for c in invalid_clocks]
        changes += [('measurement_start_unix_secs', v) for v in (None, True, float('nan'), 1, 103)]
        changes += [('measurement_secs', v) for v in (0, True, float('inf'), 301)]
        for key, value in changes:
            with self.subTest(key=key, value=value):
                phases = dict(copy.deepcopy(original), **{key: value})
                self.raw['phases'] = self.sample['phases'] = phases
                self.retain_client()
                try:
                    self.request()
                    self.lifecycle.authorize_teardown()
                except ValueError:
                    pass
                else:
                    self.fail('invalid client phase authorized teardown')
                self.assertIsNone(self.lifecycle.teardown)
                self.assertFalse((self.out / 'teardown-ready.json').exists())

    def test_boundary_receipts_reject_missing_unordered_or_foreign_clocks(self):
        a, b, c = self.ready['at'], self.at(2_500_000_000), self.at(self.now)
        for receipts in ([a], [a, None, c], [a, b, b, c], [a, c, b],
                         [a, dict(b, boot_id='other'), c],
                         [a, dict(b, time_namespace=2), c],
                         [dict(a, clock='CLOCK_BOOTTIME'), b, c],
                         [dict(a, boot_id='prior-boot'), b, c],
                         [a, dict(b, unix_ns=b['unix_ns'] + 1_000_000_000), c]):
            with self.subTest(receipts=receipts):
                timeline = [dict(clock=r) for r in receipts]
                self.assertFalse(trace.boundary_report(self.sample, timeline, 1, self.now, self.owner)
                                 ['measurement']['valid'])

    def test_nonzero_client_incomplete_drain_partial_json_and_failed_read(self):
        (self.out / 'exit').write_text('124\n')
        with self.assertRaisesRegex(ValueError, 'client exit'):
            trace.completion_evidence(self.binding)
        self.retain_client()
        for field, value in [('timed_out', True), ('stalled_workers', [2]),
                              ('transport_close_timed_out', True), ('drain_secs', None)]:
            with self.subTest(field=field):
                saved = self.raw['phases'][field]
                self.raw['phases'][field] = value
                self.retain_client()
                with self.assertRaises(ValueError):
                    trace.completion_evidence(self.binding)
                self.raw['phases'][field] = saved
        (self.out / 'raw.json').write_text('{"phases":')
        with self.assertRaises(ValueError):
            trace.completion_evidence(self.binding)
        (self.out / 'raw.json').unlink()
        with self.assertRaises(OSError):
            trace.completion_evidence(self.binding)

    def test_only_zero_perf_exit_after_target_removal_is_allowed(self):
        self.request(); self.lifecycle.authorize_teardown()
        self.cpu.process.poll.return_value = 0
        with self.assertRaisesRegex(RuntimeError, 'collector exited'):
            self.lifecycle.poll()  # acknowledged, but the target is still alive
        self.alive.return_value = False
        self.cpu.process.poll.return_value = 1
        with self.assertRaisesRegex(RuntimeError, 'collector exited'):
            self.lifecycle.poll()
        self.cpu.process.poll.return_value = None
        self.observer.process.poll.return_value = 0
        with self.assertRaisesRegex(RuntimeError, 'collector exited'):
            self.lifecycle.poll()  # syscall observer may not autoexit

    def test_failed_target_read_is_not_target_removal(self):
        self.request(); self.lifecycle.authorize_teardown()
        self.alive.side_effect = PermissionError('proc read denied')
        with self.assertRaises(OSError):
            self.lifecycle.poll()

    def test_runner_retains_and_acknowledges_before_removing_gateway(self):
        source = (HERE / 'run_gateway_protocol_bench.sh').read_text()
        run = source.split('run_bench() {', 1)[1].split('# ── Orchestration', 1)[0]
        self.assertLess(run.index('_client.raw.json'), run.index('request-teardown'))
        self.assertLess(run.index('benchmark_plan.py" stamp'), run.index('request-teardown'))
        main = source.split('for size in $PAYLOAD_SIZES; do', 1)[1]
        self.assertLess(main.index('run_bench'), main.index('stop_gateway'))
        stop = source.split('stop_gateway() {', 1)[1].split('# ── Bench runner', 1)[0]
        self.assertLess(stop.index('stop_container "$GATEWAY_CID"'), stop.index('h1_trace_stop'))
        # stop_container removes only the container this run recorded (#5702).
        helper = source.split('stop_container() {', 1)[1].split('\n}', 1)[0]
        self.assertIn('docker rm -f "$cid"', helper)


class H1BindingTests(unittest.TestCase):
    def test_fixed_binding_command_retains_exact_data_and_rejects_bad_operands(self):
        with tempfile.TemporaryDirectory() as folder:
            out = Path(folder)
            data = dict(runtime=str(out / 'runtime.json'), config=str(out / 'config.yaml'),
                        sample=str(out / 'sample.json'), raw_sample=str(out / 'raw.json'),
                        client_exit=str(out / 'exit'), arm='ferrum', pair=1, payload=10240)
            for key, value in [('arm', 'direct'), ('arm', 'envoy'), ('pair', 0), ('pair', 5),
                               ('pair', True), ('payload', 1), ('sample', 'relative.json'),
                               ('runtime', str(out / '..' / 'runtime.json'))]:
                with self.subTest(key=key, value=value):
                    with self.assertRaises(ValueError):
                        trace.write_binding(str(out), **dict(data, **{key: value}))
                    self.assertFalse((out / 'bind.json').exists())
            trace.write_binding(str(out), **data)
            self.assertEqual(json.loads((out / 'bind.json').read_text()), data)
            with self.assertRaisesRegex(ValueError, 'already exists'):
                trace.write_binding(str(out), **dict(data, pair=2))
            self.assertEqual(json.loads((out / 'bind.json').read_text()), data)
            for arm in ('ferrum-baseline', 'ferrum-exp-cutoff-one'):
                arm_out = out / arm
                arm_out.mkdir()
                selected = dict(data, arm=arm, pair=4, payload=5242880)
                trace.write_binding(str(arm_out), **selected)
                self.assertEqual(json.loads((arm_out / 'bind.json').read_text()), selected)
        source = (HERE / 'run_gateway_protocol_bench.sh').read_text()
        self.assertIn('python3 "$SCRIPT_DIR/h1_trace.py" bind --output "$h1_trace_output"', source)
        self.assertNotIn('PYTRACE', source)

    @unittest.skipUnless(Path('/proc/self/ns/time').exists(), 'Linux clock receipt producer')
    def test_clock_receipt_records_producer_namespace_and_boot(self):
        receipt = trace.clock_receipt()
        self.assertEqual(receipt['kind'], 'clock_receipt')
        self.assertEqual(receipt['clock'], 'CLOCK_MONOTONIC')
        self.assertEqual(receipt['time_namespace'], Path('/proc/self/ns/time').stat().st_ino)
        self.assertEqual(receipt['boot_id'], Path('/proc/sys/kernel/random/boot_id').read_text().strip())
        self.assertLessEqual(receipt['before_ns'], receipt['after_ns'])


if __name__ == '__main__':
    unittest.main()
