import hashlib
import json
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from benchmark_validity import sample_issues
from h2_cpu_profile import (ENVIRONMENT, ENVOY_DECODE_BYTES, ENVOY_DECODE_SECONDS, ENVOY_EXECUTABLE,
                            ENVOY_SYMBOLS, elf_identity, fixture, report, stamp, symbolize_envoy,
                            validate_runtime)


def tiny_elf(build_id, *, symtab=True, extra=(), property_segment=False):
    """Minimal ELF64: GNU build-ID notes, an optional 8-aligned GNU property
    note segment before them, and an optional .symtab."""
    segments = []
    if property_segment:
        # NT_GNU_PROPERTY_TYPE_0: 16-byte header+name, 16-byte descriptor.
        segments.append((8, struct.pack('<III', 4, 16, 5) + b'GNU\0' + bytes(16)))
    segments.append((4, b''.join(struct.pack('<III', 4, len(i), 3) + b'GNU\0' + i for i in (build_id, *extra))))
    phoff, data_at = 64, 64 + 56 * len(segments)
    programs, body = b'', b''
    for align, notes in segments:
        body += bytes(-(data_at + len(body)) % align)
        programs += struct.pack('<IIQQQQQQ', 4, 4, data_at + len(body), 0, 0, len(notes), len(notes), align)
        body += notes
    shoff = data_at + len(body)
    header = (b'\x7fELF\x02\x01\x01' + bytes(9) + struct.pack('<HHIQQQIHHHHHH',
              2, 62, 1, 0, phoff, shoff, 0, 64, 56, len(segments), 64, 2, 0))
    sections = bytes(64) + struct.pack('<IIQQQQIIQQ', 1, 2 if symtab else 3, 0, 0, 0, 24, 0, 0, 8, 24)
    return header + programs + body + sections


class H2CPUAdmissionTests(unittest.TestCase):
    def runtime(self, protocol='http2', gateway='ferrum'):
        config = fixture(protocol, gateway)
        runtime = dict(protocol=protocol, gateway=gateway, pair=1, network_mode='host',
                       running=True, image_id='sha256:' + 'a' * 64, user='65532:65532',
                       cap_drop=['ALL'], config_sha256=hashlib.sha256(config).hexdigest())
        if gateway == 'ferrum':
            runtime['environment'] = dict(zip(ENVIRONMENT,
                ('file', '8443', '0', 'false', '8388608', '33554432')))
        return config, runtime

    def test_fixed_ferrum_and_envoy_fixtures_admit_both_protocols(self):
        for protocol in ('http2', 'grpcs'):
            for gateway in ('ferrum', 'envoy'):
                with self.subTest(protocol=protocol, gateway=gateway):
                    config, runtime = self.runtime(protocol, gateway)
                    validate_runtime(dict(arm=gateway, pair=1), runtime, config, protocol)

    def test_wrong_workload_container_policy_or_config_is_rejected(self):
        for field, value in [('protocol', 'http3'), ('gateway', 'direct'), ('pair', 2),
                             ('network_mode', 'bridge'), ('running', False),
                             ('image_id', 'mutable-tag'), ('user', '0'), ('cap_drop', [])]:
            with self.subTest(field=field):
                config, runtime = self.runtime()
                runtime[field] = value
                with self.assertRaises(ValueError):
                    validate_runtime(dict(arm='ferrum', pair=1), runtime, config, 'http2')
        config, runtime = self.runtime()
        with self.assertRaises(ValueError):
            validate_runtime(dict(arm='ferrum', pair=1), runtime, config + b'\n', 'http2')
        runtime['environment']['FERRUM_POOL_HTTP2_ADAPTIVE_WINDOW'] = 'true'
        with self.assertRaises(ValueError):
            validate_runtime(dict(arm='ferrum', pair=1), runtime, config, 'http2')

    def test_cpu_and_counter_controls_cannot_enter_ordinary_scoreboards(self):
        for mode in ('off', 'counters', 'cpu'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'sample.json'
                path.write_text('{"rps":100}')
                stamp(path, mode)
                sample = json.loads(path.read_text())
                self.assertEqual(sample['h2_cpu_profile']['mode'], mode)
                self.assertIn('H2 CPU profiling campaign: diagnostic only', sample_issues(sample))

    def test_missing_campaign_is_retained_as_incomplete_not_an_empty_success(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(report(directory), 1)
            result = json.loads((Path(directory) / 'h2-cpu-report.json').read_text())
            self.assertFalse(result['complete'])
            self.assertEqual(len(result['observations']), 24)
            self.assertTrue(all(row['issues'] for row in result['observations']))
            self.assertTrue(all(not row['comparable'] for row in result['calibration']))


    def campaign(self, directory, protocol='http2'):
        root = Path(directory)
        for campaign, mode in (('control-before', 'off'), ('counters', 'counters'),
                               ('cpu', 'cpu'), ('control-after', 'off')):
            for pair in (1, 2):
                folder = root / campaign / 'pairs' / f'pair_{pair:03d}'
                (folder / 'diagnostics').mkdir(parents=True)
                for gateway in ('direct', 'ferrum', 'envoy'):
                    roles = ['backend', 'client'] + (['gateway'] if gateway != 'direct' else [])
                    usage = [dict(role=role, pid=index + 1, complete_bracket=True,
                                  cpu_seconds=5, user_cpu_seconds=4, system_cpu_seconds=1,
                                  bracket_secs=15, voluntary_ctxt_switches=7, nonvoluntary_ctxt_switches=3,
                                  context_switches=dict(scope='all process threads',
                                      voluntary_ctxt_switches=7, nonvoluntary_ctxt_switches=3))
                             for index, role in enumerate(roles)]
                    sample = dict(sample_schema=2, gateway=gateway, pair=pair, host_id='one-runner',
                                  protocol={'http2': 'HTTP/2', 'grpcs': 'gRPC'}[protocol],
                                  payload_size=10240, duration_secs=15,
                                  effective_concurrency=200, warmup_requests=200,
                                  total_requests=1500, total_errors=0, total_bytes=1500 * 10240, rps=100,
                                  phases=dict(measurement_secs=15, measurement_elapsed_secs=15.01, timed_out=False),
                                  observed=dict(samples=20, workers_at_barrier=200,
                                                workers_retired_before_deadline=0),
                                  process_usage=dict(processes=usage, measurement=usage))
                    for name in ('active_workers', 'active_connections', 'active_streams', 'queued_requests'):
                        sample['observed'][name] = dict(min=0, max=200, mean=100)
                    path = folder / f'{gateway}_{protocol}_10240.json'
                    path.write_text(json.dumps(sample))
                    stamp(path, mode)
                    if gateway != 'direct':
                        config, runtime = self.runtime(protocol=protocol, gateway=gateway)
                        runtime['pair'] = pair
                        (folder / 'diagnostics' / f'{gateway}_runtime.json').write_text(json.dumps(runtime))
                        (folder / 'diagnostics' / f'{gateway}_config.yaml').write_bytes(config)
                        if mode == 'cpu':
                            trace = folder / 'traces' / f'{gateway}_10240'
                            trace.mkdir(parents=True)
                            (trace / 'trace-manifest.json').write_text(json.dumps(dict(
                                capture_complete=True, mode='cpu', cpu=dict(samples=100),
                                binding=dict(arm=gateway, pair=pair, payload=10240, h2_protocol=protocol))))
        return root / f'counters/pairs/pair_001/ferrum_{protocol}_10240.json'

    def test_complete_campaign_calibrates_all_roles_and_preserves_controls(self):
        for protocol in ('http2', 'grpcs'):
            with self.subTest(protocol=protocol), tempfile.TemporaryDirectory() as directory:
                path = self.campaign(directory, protocol)
                self.assertEqual(report(directory), 0)
                result = json.loads((Path(directory) / 'h2-cpu-report.json').read_text())
                self.assertTrue(result['complete'])
                self.assertEqual(len(result['observations']), 24)
                self.assertTrue(all(row['protocol'] == protocol for row in result['observations']))
                self.assertTrue(all(row['comparable'] for row in result['calibration']))
                self.assertTrue(all(row['median_rps_overhead_percent'] == 0 for row in result['calibration']))
                self.assertTrue(json.loads(path.read_text())['h2_cpu_profile']['diagnostic_only'])

    def test_inconsistent_corrupt_or_incomplete_evidence_keeps_a_failed_report(self):
        for fault in ('json', 'not-object', 'duplicate-role', 'negative-counter', 'missing-scope',
                      'nonfinite-cpu', 'wrong-pair', 'wrong-gateway', 'mixed-image', 'wrong-capture',
                      'malformed-observation', 'malformed-protocol', 'cli-protocol'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                path = self.campaign(directory)
                sample = json.loads(path.read_text())
                if fault == 'duplicate-role':
                    sample['process_usage']['measurement'].append(sample['process_usage']['measurement'][0])
                elif fault == 'negative-counter':
                    sample['process_usage']['measurement'][0]['context_switches']['voluntary_ctxt_switches'] = -1
                elif fault == 'missing-scope':
                    del sample['process_usage']['measurement'][0]['context_switches']['scope']
                elif fault == 'nonfinite-cpu':
                    sample['process_usage']['measurement'][0]['user_cpu_seconds'] = float('nan')
                elif fault == 'wrong-pair':
                    sample['pair'] = 2
                elif fault == 'wrong-gateway':
                    sample['gateway'] = 'envoy'
                elif fault == 'malformed-observation':
                    sample['h2_observation'] = True
                elif fault == 'malformed-protocol':
                    sample['protocol'] = {}
                elif fault == 'cli-protocol':
                    sample['protocol'] = 'http2'
                elif fault == 'mixed-image':
                    runtime_path = path.parent / 'diagnostics/ferrum_runtime.json'
                    runtime = json.loads(runtime_path.read_text())
                    runtime['image_id'] = 'sha256:' + 'b' * 64
                    runtime_path.write_text(json.dumps(runtime))
                elif fault == 'wrong-capture':
                    capture_path = Path(directory) / 'cpu/pairs/pair_001/traces/ferrum_10240/trace-manifest.json'
                    capture = json.loads(capture_path.read_text())
                    capture['binding']['arm'] = 'envoy'
                    capture_path.write_text(json.dumps(capture))
                path.write_text('{' if fault == 'json' else '[]' if fault == 'not-object' else json.dumps(sample))
                self.assertEqual(report(directory), 1)
                result = json.loads((Path(directory) / 'h2-cpu-report.json').read_text())
                self.assertFalse(result['complete'])

    def test_h2_binding_admits_envoy_only_with_the_fixed_protocol_opt_in(self):
        from h1_trace import write_binding
        for protocol in ('http2', 'grpcs'):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                data = dict(runtime=str(root / 'runtime.json'), config=str(root / 'config.yaml'),
                            sample=str(root / 'sample.json'), raw_sample=str(root / 'raw.json'),
                            client_exit=str(root / 'exit'), arm='envoy', pair=2, payload=71680)
                with self.assertRaises(ValueError):
                    write_binding(str(root), **data)
                for key, value in (('arm', 'direct'), ('pair', 3), ('payload', 1048576)):
                    with self.assertRaises(ValueError):
                        write_binding(str(root), **dict(data, **{key: value}), h2_protocol=protocol)
                write_binding(str(root), **data, h2_protocol=protocol)
                self.assertEqual(json.loads((root / 'bind.json').read_text()), dict(data, h2_protocol=protocol))


    def test_elf_identity_reads_one_gnu_build_id_and_symtab(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'envoy'
            path.write_bytes(tiny_elf(bytes.fromhex('ab' * 20)))
            self.assertEqual(elf_identity(path), dict(build_id='ab' * 20, symtab=True))
            path.write_bytes(tiny_elf(bytes.fromhex('ab' * 20), symtab=False))
            self.assertEqual(elf_identity(path), dict(build_id='ab' * 20, symtab=False))
            good = tiny_elf(bytes.fromhex('ab' * 20))
            short_note = bytearray(good)
            struct.pack_into('<I', short_note, 120 + 4, 64)
            far_symtab = bytearray(good)
            struct.pack_into('<Q', far_symtab, len(good) - 64 + 24, len(good))
            # An 8-aligned GNU property segment is valid and carries no build ID.
            path.write_bytes(tiny_elf(bytes.fromhex('ab' * 20), property_segment=True))
            self.assertEqual(elf_identity(path), dict(build_id='ab' * 20, symtab=True))
            # An identical repeated build-ID note is the same identity.
            path.write_bytes(tiny_elf(bytes.fromhex('ab' * 20), extra=[bytes.fromhex('ab' * 20)]))
            self.assertEqual(elf_identity(path)['build_id'], 'ab' * 20)
            for data in (tiny_elf(bytes.fromhex('ab' * 20), extra=[bytes.fromhex('cd' * 20)]),
                         b'\x7fELF\x01\x01' + bytes(58),
                         b'#!/bin/sh\n', good[:100], good[:-10], bytes(short_note), bytes(far_symtab)):
                path.write_bytes(data)
                with self.assertRaises(ValueError):
                    elf_identity(path)

    def test_workflow_fetches_exactly_the_pinned_symbol_layer(self):
        workflow = (Path(__file__).resolve().parents[4] / '.github/workflows/h2-cpu-profile.yml').read_text()
        self.assertIn('ENVOY_SYMBOL_LAYER: ' + ENVOY_SYMBOLS['layer'] + '\n', workflow)
        self.assertIn('envoyproxy/envoy:v1.39.1\n', workflow)
        self.assertIn('"$symbols/layer" --no-same-owner ' + ENVOY_SYMBOLS['member'] + '\n', workflow)
        self.assertIn('--debug-elf "$symbols/layer/' + ENVOY_SYMBOLS['member'] + '"', workflow)
        self.assertEqual(ENVOY_SYMBOLS['release_image'], 'envoyproxy/envoy:v1.39.1')

    STRIPPED = ('envoy 7/8 10.000000000: cpu-clock:uS:\n'
                '\t    5000 [unknown] (/usr/local/bin/envoy)\n'
                '\t    6000 __libc_start_main+0x80 (/usr/lib/x86_64-linux-gnu/libc.so.6)\n\n'
                'envoy 7/9 11.000000000: cpu-clock:uS:\n'
                '\t    5100 [unknown] (/usr/local/bin/envoy)\n'
                '\t    6000 __libc_start_main+0x80 (/usr/lib/x86_64-linux-gnu/libc.so.6)\n\n'
                'envoy 7/9 30.000000000: cpu-clock:uS:\n'
                '\t    5200 [unknown] (/usr/local/bin/envoy)\n'
                '\t    6000 __libc_start_main+0x80 (/usr/lib/x86_64-linux-gnu/libc.so.6)\n\n')

    def envoy_symbols(self, directory, fault=None):
        """Retained Envoy CPU captures plus a build-ID twin; returns symbolize_envoy's inputs."""
        from h1_trace_contract import decode_cpu
        root = Path(directory) / 'evidence'
        root.mkdir()
        self.campaign(root)
        build_id = bytes.fromhex('cd' * 20)
        release = tiny_elf(build_id, symtab=False)
        libc = b'\x7fELF libc'
        debug = Path(directory) / 'debug-envoy'
        debug.write_bytes(tiny_elf(bytes.fromhex('ee' * 20)) if fault == 'debug-build-id' else tiny_elf(build_id))
        pins = dict(ENVOY_SYMBOLS, release_sha256=hashlib.sha256(
                        b'other' if fault == 'release-sha' else release).hexdigest(),
                    sha256=hashlib.sha256(b'other' if fault == 'debug-sha' else debug.read_bytes()).hexdigest(),
                    bytes=debug.stat().st_size, build_id=build_id.hex())
        package = root / 'builds/envoy/symfs'
        (package / 'usr/local/bin').mkdir(parents=True)
        (package / 'usr/lib/x86_64-linux-gnu').mkdir(parents=True)
        (package / 'usr/local/bin/envoy').write_bytes(release)
        (package / 'usr/lib/x86_64-linux-gnu/libc.so.6').write_bytes(b'tampered' if fault == 'retained-dso' else libc)
        for pair in (1, 2):
            trace = root / f'cpu/pairs/pair_{pair:03d}/traces/envoy_10240'
            perf_data = b'raw perf %d' % pair
            (trace / 'perf.data').write_bytes(perf_data)
            (trace / 'stacks.txt').write_text(self.STRIPPED.replace('(/usr/local/bin/envoy)', '(/usr/lib/other.so)')
                                              if fault == 'no-executable-leaves' else self.STRIPPED)
            recorded = ('ff' * 20 if fault == 'recorded-build-id' or (fault == 'first-refused' and pair == 1)
                        else build_id.hex())
            (trace / 'perf-buildids.txt').write_text(f'{recorded} {ENVOY_EXECUTABLE}\n')
            (trace / 'build-mappings.json').write_text(json.dumps(dict(complete=True, dsos=[
                dict(path=ENVOY_EXECUTABLE, sha256=hashlib.sha256(release).hexdigest(),
                     build_id_lines=['Build ID: ' + build_id.hex()]),
                dict(path='/usr/lib/x86_64-linux-gnu/../../../etc/libc.so.6' if fault == 'unsafe-dso-path'
                     else '/usr/lib/x86_64-linux-gnu/libc.so.6', sha256=hashlib.sha256(libc).hexdigest(),
                     build_id_lines=['Build ID: ' + '12' * 20])])))
            manifest = json.loads((trace / 'trace-manifest.json').read_text())
            receipts = {name: dict(sha256=hashlib.sha256((trace / name).read_bytes()).hexdigest(),
                                   bytes=(trace / name).stat().st_size)
                        for name in ('perf.data', 'stacks.txt', 'perf-buildids.txt', 'build-mappings.json')}
            if fault == 'perf-data':
                receipts['perf.data']['sha256'] = hashlib.sha256(b'other').hexdigest()
            if fault == 'stacks-receipt':
                (trace / 'stacks.txt').write_text(self.STRIPPED.replace('5000', '5001'))
            manifest['cpu']['decoder_status'] = dict(incomplete='deadline_or_output_cap' if fault == 'truncated-original'
                                                     else None)
            manifest.update(identity=dict(pid=7), artifacts=receipts,
                symbol_package=str(root / 'builds/ferrum/symfs') if fault == 'symbol-package' else str(package.resolve()),
                boundaries={} if fault == 'window' else dict(measurement=dict(valid=True, start_bounds_ns=[9_000_000_000, 9_500_000_000],
                                                 end_bounds_ns=[20_000_000_000, 20_500_000_000])))
            (trace / 'trace-manifest.json').write_text(json.dumps(manifest))
        calls = []

        def decode(out, owners, dsos, *, symfs):
            self.assertEqual(owners, {7})
            self.assertEqual((symfs / ENVOY_EXECUTABLE.lstrip('/')).resolve(), debug.resolve())
            self.assertEqual((symfs / 'usr/lib/x86_64-linux-gnu/libc.so.6').read_bytes(), libc)
            if fault == 'decoder-timeout' or (fault == 'mixed' and '002' in str(out)):
                raise subprocess.TimeoutExpired('perf-script', 3)
            text = self.STRIPPED.replace('5000 [unknown]', 'abcd [unknown]' if fault == 'leaf-pc' else
                                         '5000 Envoy::Http::CodecHelper::dispatch+0x10')
            if fault == 'caller-pc':
                text = text.replace('6000 __libc_start_main', '6001 __libc_start_main', 1)
            text = text.replace('5100 [unknown]', '5100 Envoy::Http::CodecHelper::dispatch+0x20')
            if fault in ('no-op', 'no-executable-leaves'):
                text = self.STRIPPED
                if fault == 'no-executable-leaves':
                    text = text.replace('(/usr/local/bin/envoy)', '(/usr/lib/other.so)')
            decoded = decode_cpu(text, '', owners)
            (out / 'cpu-coverage.json').write_text('{}')
            (out / 'stacks.folded').write_text('folded 1\n')
            (out / 'stacks.txt.stderr').write_text('perf diagnostics\n')
            (out / 'stacks.txt.status.json').write_text('{"returncode": 0}\n')
            calls.append(out)
            issues = ['partial unwinding/unresolved samples']
            if fault == 'blocking-decoder':
                issues.append('lost or throttled samples')
            return dict(decoded, issues=issues, inline_expansion=False, decoder_status=dict(returncode=0))
        return root, debug, Path(directory) / 'scratch', pins, decode, calls

    def test_envoy_symbols_rename_only_the_retained_samples(self):
        with tempfile.TemporaryDirectory() as directory:
            root, debug, scratch, pins, decode, calls = self.envoy_symbols(directory)
            self.assertEqual(symbolize_envoy(root, debug, scratch, pins=pins, decode=decode), 0)
            self.assertEqual(len(calls), 2)
            result = json.loads((root / 'envoy-symbols.json').read_text())
            self.assertTrue(result['complete'])
            for row in result['captures']:
                self.assertEqual(row['issues'], [])
                # Only in-window samples count; the 30 s sample is outside.
                self.assertEqual(row['stripped']['window_samples'], 2)
                self.assertEqual(row['stripped']['known_leaf_samples'], 0)
                self.assertEqual(row['symbolized']['known_leaf_samples'], 2)
                self.assertEqual(row['symbolized']['top_leaves'],
                                 [dict(symbol='Envoy::Http::CodecHelper::dispatch', dso=ENVOY_EXECUTABLE,
                                       samples=2, fraction=1.0)])
                self.assertEqual(row['symbolized']['executable_known_leaf_samples'], 2)
            for pair in (1, 2):
                published = root / f'cpu/pairs/pair_{pair:03d}/traces/envoy_10240/envoy-symbols'
                self.assertEqual(sorted(p.name for p in published.iterdir()),
                                 ['cpu-coverage.json', 'stacks.folded', 'stacks.txt.status.json',
                                  'stacks.txt.stderr', 'summary.json'])
                self.assertEqual((published / 'stacks.txt.stderr').read_text(), 'perf diagnostics\n')
            # The symbol twin and overlay stay in scratch, never in evidence.
            debug_bytes = debug.read_bytes()
            self.assertFalse([p for p in root.rglob('*') if p.is_symlink() or
                              (p.is_file() and p.read_bytes() == debug_bytes)])
            self.assertFalse(list(root.rglob('.envoy-symbols.partial')))
            self.assertEqual(report(root), 0)
            self.assertTrue(json.loads((root / 'h2-cpu-report.json').read_text())['envoy_symbols']['complete'])
            # A rerun on symbolized evidence refuses rather than overwriting.
            self.assertEqual(symbolize_envoy(root, debug, Path(directory) / 'again', pins=pins, decode=decode), 1)
            rerun = json.loads((root / 'envoy-symbols.json').read_text())
            self.assertTrue(all('already has Envoy symbols' in row['issues'][0] for row in rerun['captures']))

    def test_unmatched_envoy_symbols_are_reported_without_hiding_the_capture(self):
        expected = {
            'debug-build-id': 'lacks the pinned build ID',
            'debug-sha': 'does not match the pinned image layer member',
            'release-sha': 'not the pinned release build',
            'recorded-build-id': 'recorded Envoy build ID does not match',
            'retained-dso': 'retained DSO does not match',
            'perf-data': 'perf.data does not match its manifest receipt hash',
            'stacks-receipt': 'stacks.txt does not match its manifest receipt hash',
            'truncated-original': 'original decode was incomplete',
            'leaf-pc': 'leaf PCs differ',
            'caller-pc': 'caller PCs differ',
            'no-op': 'resolved no additional Envoy executable leaves',
            'decoder-timeout': 'TimeoutExpired',
            'no-executable-leaves': 'no Envoy executable leaves in the measurement window',
            'unsafe-dso-path': 'unsafe mapped DSO path',
            'blocking-decoder': 'decoder: lost or throttled samples',
            'symbol-package': 'does not use the retained Envoy symbol package',
            'window': "KeyError: 'measurement'",
        }
        for fault, issue in expected.items():
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                root, debug, scratch, pins, decode, _ = self.envoy_symbols(directory, fault)
                self.assertEqual(symbolize_envoy(root, debug, scratch, pins=pins, decode=decode), 1)
                result = json.loads((root / 'envoy-symbols.json').read_text())
                self.assertFalse(result['complete'])
                issues = [i for row in result['captures'] for i in row['issues']] or result['issues']
                self.assertTrue(issues and all(issue in i for i in issues), issues)
                # Post-decode mismatches publish their diagnostics; earlier refusals publish nothing.
                self.assertFalse(list(root.rglob('envoy-symbols')) and fault not in (
                    'leaf-pc', 'caller-pc', 'no-op', 'blocking-decoder', 'no-executable-leaves'))
                # Capture evidence and calibration stay as they were.
                self.assertEqual(report(root), 0)
                self.assertFalse(json.loads((root / 'h2-cpu-report.json').read_text())['envoy_symbols']['complete'])

    def test_one_failed_capture_keeps_its_neighbour_and_fails_the_aggregate(self):
        with tempfile.TemporaryDirectory() as directory:
            root, debug, scratch, pins, decode, _ = self.envoy_symbols(directory, 'mixed')
            self.assertEqual(symbolize_envoy(root, debug, scratch, pins=pins, decode=decode), 1)
            result = json.loads((root / 'envoy-symbols.json').read_text())
            first, second = result['captures']
            self.assertEqual(first['issues'], [])
            self.assertTrue(second['issues'][0].startswith('TimeoutExpired'))
            self.assertEqual(result['issues'], ['stopped after an unreaped decoder'])
            self.assertTrue((root / 'cpu/pairs/pair_001/traces/envoy_10240/envoy-symbols/summary.json').is_file())
            self.assertFalse((root / 'cpu/pairs/pair_002/traces/envoy_10240/envoy-symbols').exists())

    def test_an_ordinary_refusal_does_not_stop_the_next_capture(self):
        with tempfile.TemporaryDirectory() as directory:
            root, debug, scratch, pins, decode, calls = self.envoy_symbols(directory, 'first-refused')
            self.assertEqual(symbolize_envoy(root, debug, scratch, pins=pins, decode=decode), 1)
            first, second = json.loads((root / 'envoy-symbols.json').read_text())['captures']
            self.assertIn('recorded Envoy build ID does not match', first['issues'][0])
            self.assertEqual(second['issues'], [])
            self.assertEqual(len(calls), 1)
            self.assertTrue((root / 'cpu/pairs/pair_002/traces/envoy_10240/envoy-symbols/summary.json').is_file())

    def test_workflow_symbolizes_after_hand_back_and_before_report_in_runner_scratch(self):
        workflow = (Path(__file__).resolve().parents[4] / '.github/workflows/h2-cpu-profile.yml').read_text()
        order = [workflow.index(name) for name in (
            '- name: Hand back bounded root-owned trace artifacts',
            '- name: Symbolize Envoy CPU stacks offline',
            '- name: Retain a report even when a campaign stops early',
            '- name: Retain raw profiles, coverage limits, counters and controls')]
        self.assertEqual(order, sorted(order))
        self.assertIn('symbols="$RUNNER_TEMP/envoy-symbols"', workflow)
        self.assertIn('--scratch "$symbols/decode"', workflow)

    def test_intermediate_records_never_claim_completeness(self):
        with tempfile.TemporaryDirectory() as directory:
            root, debug, scratch, pins, decode, calls = self.envoy_symbols(directory)
            seen = []

            def observing(out, owners, dsos, *, symfs):
                if calls:
                    # The first capture already succeeded and was recorded.
                    seen.append(json.loads((root / 'envoy-symbols.json').read_text()))
                return decode(out, owners, dsos, symfs=symfs)
            self.assertEqual(symbolize_envoy(root, debug, scratch, pins=pins, decode=observing), 0)
            self.assertEqual(len(seen), 1)
            self.assertEqual((len(seen[0]['captures']), seen[0]['expected_captures']), (1, 2))
            self.assertFalse(seen[0]['complete'])
            self.assertTrue(json.loads((root / 'envoy-symbols.json').read_text())['complete'])

    def test_scratch_overlapping_evidence_is_refused_before_any_capture_work(self):
        with tempfile.TemporaryDirectory() as directory:
            root, debug, _, pins, decode, calls = self.envoy_symbols(directory)
            for scratch in (root, root / 'cpu', root.parent):
                with self.subTest(scratch=scratch):
                    self.assertEqual(symbolize_envoy(root, debug, scratch, pins=pins, decode=decode), 1)
                    result = json.loads((root / 'envoy-symbols.json').read_text())
                    self.assertEqual(result['issues'], ['ValueError: scratch directory overlaps the evidence root'])
            self.assertEqual(calls, [])
            self.assertTrue((root / 'cpu/pairs/pair_001/traces/envoy_10240/perf.data').is_file())

    def test_an_unreaped_decoder_stops_later_captures(self):
        with tempfile.TemporaryDirectory() as directory:
            root, debug, scratch, pins, decode, calls = self.envoy_symbols(directory, 'decoder-timeout')
            self.assertEqual(symbolize_envoy(root, debug, scratch, pins=pins, decode=decode), 1)
            result = json.loads((root / 'envoy-symbols.json').read_text())
            self.assertEqual(len(result['captures']), 1)

    def test_retry_clears_stale_partial_and_scratch_from_an_interrupted_attempt(self):
        with tempfile.TemporaryDirectory() as directory:
            root, debug, scratch, pins, decode, _ = self.envoy_symbols(directory)
            for pair in (1, 2):
                (root / f'cpu/pairs/pair_{pair:03d}/traces/envoy_10240/.envoy-symbols.partial').mkdir()
                (scratch / f'cpu/pairs/pair_{pair:03d}/traces/envoy_10240/symfs').mkdir(parents=True)
            self.assertEqual(symbolize_envoy(root, debug, scratch, pins=pins, decode=decode), 0)
            self.assertFalse(list(root.rglob('.envoy-symbols.partial')))

    def test_report_withholds_a_malformed_symbolization_record(self):
        for text, issue in (('[]', 'malformed Envoy symbolization'), ('{', 'unreadable Envoy symbolization')):
            with self.subTest(text=text), tempfile.TemporaryDirectory() as directory:
                self.campaign(directory)
                (Path(directory) / 'envoy-symbols.json').write_text(text)
                self.assertEqual(report(directory), 0)
                symbols = json.loads((Path(directory) / 'h2-cpu-report.json').read_text())['envoy_symbols']
                self.assertEqual(symbols, dict(complete=False, issues=[issue]))

    def test_default_decoder_uses_the_offline_bounds_within_the_launch_ceiling(self):
        from h1_trace_contract import BOUNDS
        self.assertLessEqual(ENVOY_DECODE_BYTES, BOUNDS['raw_perf_bytes'])
        with tempfile.TemporaryDirectory() as directory:
            root, debug, scratch, pins, decode, _ = self.envoy_symbols(directory)
            seen = []

            def cpu_decode(out, owners, dsos, **bounds):
                seen.append(bounds)
                return decode(out, owners, dsos, symfs=bounds['symfs'])
            with mock.patch('h1_trace.cpu_decode', cpu_decode):
                self.assertEqual(symbolize_envoy(root, debug, scratch, pins=pins), 0)
            self.assertEqual(len(seen), 2)
            for bounds in seen:
                self.assertEqual((bounds['script_timeout'], bounds['script_limit']),
                                 (ENVOY_DECODE_SECONDS, ENVOY_DECODE_BYTES))

    def test_report_marks_missing_envoy_symbols_without_failing_the_capture(self):
        with tempfile.TemporaryDirectory() as directory:
            self.campaign(directory)
            self.assertEqual(report(directory), 0)
            symbols = json.loads((Path(directory) / 'h2-cpu-report.json').read_text())['envoy_symbols']
            self.assertEqual(symbols, dict(complete=False, issues=['Envoy symbolization not run']))


if __name__ == '__main__':
    unittest.main()
