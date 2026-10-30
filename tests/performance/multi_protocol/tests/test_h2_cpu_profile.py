import hashlib
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from benchmark_validity import sample_issues
from h2_cpu_profile import (ENVIRONMENT, ENVOY_EXECUTABLE, ENVOY_SYMBOLS, elf_identity, fixture,
                            report, stamp, symbolize_envoy, validate_runtime)


def tiny_elf(build_id, *, symtab=True, notes=1):
    """Minimal ELF64 with PT_NOTE GNU build-ID notes and optional .symtab."""
    note = struct.pack('<III', 4, len(build_id), 3) + b'GNU\0' + build_id
    body = note * notes
    phoff, notes_at = 64, 64 + 56
    shoff = notes_at + len(body)
    header = (b'\x7fELF\x02\x01\x01' + bytes(9) + struct.pack('<HHIQQQIHHHHHH',
              2, 62, 1, 0, phoff, shoff, 0, 64, 56, 1, 64, 2, 0))
    program = struct.pack('<IIQQQQQQ', 4, 4, notes_at, 0, 0, len(body), len(body), 4)
    sections = bytes(64) + struct.pack('<IIQQQQIIQQ', 1, 2 if symtab else 3, 0, 0, 0, 24, 0, 0, 8, 24)
    return header + program + body + sections


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
            for data in (tiny_elf(bytes.fromhex('ab' * 20), notes=2), b'\x7fELF\x01\x01' + bytes(58), b'#!/bin/sh\n'):
                path.write_bytes(data)
                with self.assertRaises(ValueError):
                    elf_identity(path)

    def test_workflow_fetches_exactly_the_pinned_symbol_layer(self):
        workflow = (Path(__file__).resolve().parents[4] / '.github/workflows/h2-cpu-profile.yml').read_text()
        self.assertIn('ENVOY_SYMBOL_LAYER: ' + ENVOY_SYMBOLS['layer'] + '\n', workflow)
        self.assertIn('envoyproxy/envoy:v1.39.1\n', workflow)
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
        pins = dict(ENVOY_SYMBOLS, release_sha256=hashlib.sha256(release).hexdigest(),
                    sha256=hashlib.sha256(debug.read_bytes()).hexdigest(), bytes=debug.stat().st_size,
                    build_id=build_id.hex())
        package = root / 'builds/envoy/symfs'
        (package / 'usr/local/bin').mkdir(parents=True)
        (package / 'usr/lib/x86_64-linux-gnu').mkdir(parents=True)
        (package / 'usr/local/bin/envoy').write_bytes(release)
        (package / 'usr/lib/x86_64-linux-gnu/libc.so.6').write_bytes(b'tampered' if fault == 'retained-dso' else libc)
        for pair in (1, 2):
            trace = root / f'cpu/pairs/pair_{pair:03d}/traces/envoy_10240'
            perf_data = b'raw perf %d' % pair
            (trace / 'perf.data').write_bytes(perf_data)
            (trace / 'stacks.txt').write_text(self.STRIPPED)
            recorded = 'ff' * 20 if fault == 'recorded-build-id' else build_id.hex()
            (trace / 'perf-buildids.txt').write_text(f'{recorded} {ENVOY_EXECUTABLE}\n')
            (trace / 'build-mappings.json').write_text(json.dumps(dict(complete=True, dsos=[
                dict(path=ENVOY_EXECUTABLE, sha256=hashlib.sha256(release).hexdigest(),
                     build_id_lines=['Build ID: ' + build_id.hex()]),
                dict(path='/usr/lib/x86_64-linux-gnu/libc.so.6', sha256=hashlib.sha256(libc).hexdigest(),
                     build_id_lines=['Build ID: ' + '12' * 20])])))
            manifest = json.loads((trace / 'trace-manifest.json').read_text())
            manifest.update(identity=dict(pid=7), symbol_package=str(package.resolve()),
                artifacts={'perf.data': dict(sha256=hashlib.sha256(
                    b'other' if fault == 'perf-data' else perf_data).hexdigest())},
                boundaries=dict(measurement=dict(valid=True, start_bounds_ns=[9_000_000_000, 9_500_000_000],
                                                 end_bounds_ns=[20_000_000_000, 20_500_000_000])))
            (trace / 'trace-manifest.json').write_text(json.dumps(manifest))
        calls = []

        def decode(out, owners, dsos, *, symfs):
            self.assertEqual(owners, {7})
            self.assertEqual((symfs / ENVOY_EXECUTABLE.lstrip('/')).resolve(), debug.resolve())
            self.assertEqual((symfs / 'usr/lib/x86_64-linux-gnu/libc.so.6').read_bytes(), libc)
            text = self.STRIPPED.replace('5000 [unknown]', 'abcd [unknown]' if fault == 'leaf-pc' else
                                         '5000 Envoy::Http::CodecHelper::dispatch+0x10')
            text = text.replace('5100 [unknown]', '5100 Envoy::Http::CodecHelper::dispatch+0x20')
            decoded = decode_cpu(text, '', owners)
            (out / 'cpu-coverage.json').write_text('{}')
            (out / 'stacks.folded').write_text('folded 1\n')
            calls.append(out)
            return dict(decoded, issues=['partial unwinding/unresolved samples'], inline_expansion=False,
                        decoder_status=dict(returncode=0))
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
                self.assertTrue(row['identical_unwound_pcs'])
                # Only in-window samples count; the 30 s sample is outside.
                self.assertEqual(row['stripped']['window_samples'], 2)
                self.assertEqual(row['stripped']['known_leaf_samples'], 0)
                self.assertEqual(row['symbolized']['known_leaf_samples'], 2)
                self.assertEqual(row['symbolized']['top_leaves'],
                                 [dict(symbol='Envoy::Http::CodecHelper::dispatch', samples=2, fraction=1.0)])
            self.assertTrue((root / 'cpu/pairs/pair_001/traces/envoy_10240/envoy-symbols/summary.json').is_file())
            self.assertFalse(any((root / 'cpu').rglob('perf.data.symfs')))
            self.assertEqual(report(root), 0)
            self.assertTrue(json.loads((root / 'h2-cpu-report.json').read_text())['envoy_symbols']['complete'])

    def test_unmatched_envoy_symbols_are_reported_without_hiding_the_capture(self):
        for fault in ('debug-build-id', 'recorded-build-id', 'retained-dso', 'perf-data', 'leaf-pc'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                root, debug, scratch, pins, decode, _ = self.envoy_symbols(directory, fault)
                self.assertEqual(symbolize_envoy(root, debug, scratch, pins=pins, decode=decode), 1)
                result = json.loads((root / 'envoy-symbols.json').read_text())
                self.assertFalse(result['complete'])
                self.assertTrue(result['issues'] or any(row['issues'] for row in result['captures']))
                # Capture evidence and calibration stay as they were.
                self.assertEqual(report(root), 0)
                self.assertFalse(json.loads((root / 'h2-cpu-report.json').read_text())['envoy_symbols']['complete'])

    def test_report_marks_missing_envoy_symbols_without_failing_the_capture(self):
        with tempfile.TemporaryDirectory() as directory:
            self.campaign(directory)
            self.assertEqual(report(directory), 0)
            symbols = json.loads((Path(directory) / 'h2-cpu-report.json').read_text())['envoy_symbols']
            self.assertEqual(symbols, dict(complete=False, issues=['Envoy symbolization not run']))


if __name__ == '__main__':
    unittest.main()
