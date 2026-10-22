"""Pure producer-schema tests and optional replay of immutable retained AA files."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / '.github/scripts'))
sys.path.insert(0, str(ROOT / 'tests/performance/multi_protocol'))
import mesh_gap_gateway_rss as rss

PRODUCER = ROOT / 'tests/performance/multi_protocol/process_usage.py'
SPEC = importlib.util.spec_from_file_location('gap_rss_frozen_producer', PRODUCER)
producer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(producer)
IMAGE = 'sha256:' + 'a' * 64


class GatewayRssTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.diag = self.root / 'protocol/pairs/pair_001/diagnostics'
        self.diag.mkdir(parents=True)
        self.usage_path = self.diag / 'ferrum_1048576_process_usage.json'
        self.runtime_path = self.diag / 'ferrum_runtime.json'
        phases = dict(measurement_start_unix_secs=100.0, measurement_secs=30.0,
                      client_usage=dict(pid=30, role='client', complete_bracket=True,
                                        cpu_seconds=3.0, bracket_secs=30.0, boundary_slack_secs=0.0))
        timeline = []
        for timestamp, value in ((99.9, 9999), (100.0, 100), (110.0, 200),
                                 (120.0, 300), (130.0, 400), (130.1, 8888)):
            timeline.append(dict(unix_secs=timestamp, processes=[
                dict(pid=10, start_ticks=10, role='gateway', rss_bytes=value, cpu_seconds=timestamp),
                dict(pid=20, start_ticks=20, role='backend', rss_bytes=80, cpu_seconds=timestamp / 2)]))
        self.usage = dict(capture_complete=True, timeline=timeline,
                          processes=[dict(pid=10, role='gateway'), dict(pid=20, role='backend')])
        self.raw = dict(gateway='ferrum', pair=1, payload_size=1048576, duration_secs=30,
                        sample_schema=2, phases=phases,
                        process_usage=dict(measurement=producer.measurement_usage(self.usage, phases)))
        self.runtime = [dict(Image=IMAGE, State=dict(Pid=10, Running=True))]
        self.store()

    def store(self, usage=None, runtime=None):
        self.usage_path.write_text(json.dumps(self.usage if usage is None else usage))
        self.runtime_path.write_text(json.dumps(self.runtime if runtime is None else runtime))

    def observe(self, raw=None, **kwargs):
        return rss.gateway_rss(self.raw if raw is None else raw, self.root,
                               arm=kwargs.get('arm', 'ferrum'), image_id=kwargs.get('image_id', IMAGE),
                               measurement_usage=producer.measurement_usage)

    def test_uses_exact_frozen_producer_source(self):
        # Blob at gateway helper766a3947;235 carries the identical producer.
        data = PRODUCER.read_bytes()
        blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
        self.assertEqual(blob, '4c44ab43df6dd9b0957235a33e071c8999b00a64')

    def test_external_timeline_without_inline_series_preserves_measurement_and_raw_bytes(self):
        before = {p: p.read_bytes() for p in (self.usage_path, self.runtime_path)}
        raw = copy.deepcopy(self.raw)
        result = self.observe()
        self.assertNotIn('timeline', self.raw['process_usage'])
        self.assertEqual(result['rss_samples'], 4)
        self.assertEqual(result['proxy_rss_bytes_mean'], 250.0)
        self.assertEqual(result['proxy_rss_bytes_peak'], 400)
        self.assertEqual((result['gateway_pid'], result['gateway_start_ticks']), (10, 10))
        self.assertEqual(self.raw, raw)
        for path, data in before.items():
            self.assertEqual(path.read_bytes(), data)
            self.assertEqual(result['evidence_sha256'][path.relative_to(self.root).as_posix()],
                             hashlib.sha256(data).hexdigest())

    def test_missing_external_files_and_symlink_fail(self):
        for path in (self.usage_path, self.runtime_path):
            data = path.read_bytes()
            path.unlink()
            with self.assertRaises(OSError):
                self.observe()
            path.write_bytes(data)
        copy_path = self.diag / 'copy.json'
        copy_path.write_bytes(self.usage_path.read_bytes())
        self.usage_path.unlink()
        self.usage_path.symlink_to(copy_path)
        with self.assertRaisesRegex(ValueError, 'symlink'):
            self.observe()

    def test_rejects_malformed_or_incomplete_capture(self):
        for value in (None, [], {}, dict(self.usage, capture_complete=False),
                      dict(self.usage, capture_complete=1), dict(self.usage, timeline=[]),
                      dict(self.usage, timeline=None), dict(self.usage, processes=[])):
            with self.subTest(value=value):
                self.store(usage=value)
                # None means default in store(), so write that malformed case explicitly.
                if value is None:
                    self.usage_path.write_text('null')
                with self.assertRaises(ValueError):
                    self.observe()

    def test_rejects_wrong_runtime_image_pid_and_duplicate_receipt(self):
        for value in ([], self.runtime * 2, [dict(Image='sha256:' + 'b' * 64, State=dict(Pid=10, Running=True))],
                      [dict(Image=IMAGE, State=dict(Pid=11, Running=True))],
                      [dict(Image=IMAGE, State=dict(Pid=True, Running=True))],
                      [dict(Image=IMAGE, State=dict(Pid=10, Running=False))]):
            with self.subTest(value=value):
                self.store(runtime=value)
                with self.assertRaises(ValueError):
                    self.observe()

    def test_rejects_missing_duplicate_wrong_pid_or_reused_generation(self):
        def mutate(mode):
            usage = copy.deepcopy(self.usage)
            row = usage['timeline'][2]
            if mode == 'missing':
                row['processes'].pop(0)
            elif mode == 'duplicate':
                row['processes'].append(copy.deepcopy(row['processes'][0]))
            elif mode == 'wrong-pid':
                row['processes'][0]['pid'] = 11
            elif mode == 'reuse':
                row['processes'][0]['start_ticks'] += 1
            else:
                usage['processes'][0]['pid'] = 11
            return usage
        for mode in ('missing', 'duplicate', 'wrong-pid', 'reuse', 'aggregate'):
            with self.subTest(mode=mode):
                self.store(usage=mutate(mode))
                with self.assertRaises(ValueError):
                    self.observe()

    def test_rejects_nonpositive_bool_noninteger_and_nonfinite_rss(self):
        for value in (0, -1, True, False, 1.5, float('nan'), float('inf'), 10**400, None, '400'):
            with self.subTest(value=value):
                usage = copy.deepcopy(self.usage)
                usage['timeline'][2]['processes'][0]['rss_bytes'] = value
                self.store(usage=usage)
                with self.assertRaises(ValueError):
                    self.observe()

    def test_rejects_unbracketed_empty_reordered_or_invalid_timeline(self):
        for mode in ('before', 'after', 'no-window', 'reorder', 'nan', 'bool'):
            usage = copy.deepcopy(self.usage)
            if mode == 'before':
                usage['timeline'] = usage['timeline'][2:]
            elif mode == 'after':
                usage['timeline'] = usage['timeline'][:4]
            elif mode == 'no-window':
                usage['timeline'] = [usage['timeline'][0], usage['timeline'][-1]]
            elif mode == 'reorder':
                usage['timeline'].reverse()
            else:
                usage['timeline'][2]['unix_secs'] = float('nan') if mode == 'nan' else True
            with self.subTest(mode=mode):
                self.store(usage=usage)
                with self.assertRaises(ValueError):
                    self.observe()

    def test_rejects_stamped_summary_or_phase_mismatch(self):
        variants = []
        raw = copy.deepcopy(self.raw)
        raw['process_usage']['measurement'][0]['cpu_seconds'] += 1
        variants.append(raw)
        raw = copy.deepcopy(self.raw)
        raw['process_usage']['measurement'][0]['complete_bracket'] = 1
        variants.append(raw)
        for value in (True, 0, -1, float('inf'), 31):
            raw = copy.deepcopy(self.raw)
            raw['phases']['measurement_secs'] = value
            variants.append(raw)
        for raw in variants:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                self.observe(raw)

    def test_rejects_wide_bracket_even_with_matching_producer_summary(self):
        usage = copy.deepcopy(self.usage)
        usage['timeline'] = [usage['timeline'][0], usage['timeline'][2],
                             usage['timeline'][3], usage['timeline'][-1]]
        usage['timeline'][0]['unix_secs'] = 95.0
        usage['timeline'][-1]['unix_secs'] = 135.0
        raw = copy.deepcopy(self.raw)
        raw['process_usage']['measurement'] = producer.measurement_usage(usage, raw['phases'])
        self.store(usage=usage)
        with self.assertRaisesRegex(ValueError, 'bracket mismatch'):
            self.observe(raw)

    def test_rejects_wrong_lane_or_arm(self):
        for key, value in (('pair', True), ('pair', 0), ('payload_size', 1024),
                           ('duration_secs', 31), ('sample_schema', True), ('gateway', 'ferrum-baseline')):
            raw = dict(self.raw, **{key: value})
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                self.observe(raw)
        with self.assertRaises(ValueError):
            self.observe(arm='../ferrum')

    def test_rejects_duplicate_json_keys_and_oversized_file(self):
        self.usage_path.write_text('{"capture_complete":true,"capture_complete":false}')
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            self.observe()
        self.store()
        from unittest.mock import patch
        with patch.object(rss, 'MAX_JSON_BYTES', 16), self.assertRaisesRegex(ValueError, 'byte bound'):
            self.observe()


class RetainedGatewayRssReplay(unittest.TestCase):
    @unittest.skipUnless(os.environ.get('MESH_GAP_RSS_REPLAY_ROOT'), 'retained AA evidence not selected')
    def test_original_aa_files_replay_without_changes(self):
        root = Path(os.environ['MESH_GAP_RSS_REPLAY_ROOT'])
        pair = root / 'protocol/pairs/pair_001'
        image = json.loads((root / 'identity.json').read_text())['image_ids']['baseline']
        expected = {
            'ferrum': (80984, 238850, 135438404.26666668,
                       'c476bd5046d663049af16438056d7282b17883163e1d5e1b499924ec727a0fb7'),
            'ferrum-baseline': (81245, 242196, 135534182.4,
                                '2bcfecef37a9ba07dc0213a218d2d120792585d1e8a31f2d8adfac173408daab')}
        for arm, (pid, generation, mean, usage_hash) in expected.items():
            raw_path = pair / f'{arm}_http1-tls_1048576.json'
            paths = (raw_path, pair / 'diagnostics' / f'{arm}_1048576_process_usage.json',
                     pair / 'diagnostics' / f'{arm}_runtime.json')
            before = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}
            raw = json.loads(raw_path.read_text())
            result = rss.gateway_rss(raw, root, arm=arm, image_id=image,
                                     measurement_usage=producer.measurement_usage)
            with self.subTest(arm=arm):
                self.assertEqual(result['rss_samples'], 60)
                self.assertEqual((result['gateway_pid'], result['gateway_start_ticks']), (pid, generation))
                self.assertEqual(result['proxy_rss_bytes_mean'], mean)
                self.assertEqual(result['proxy_rss_bytes_peak'], 144625664)
                self.assertIn(usage_hash, result['evidence_sha256'].values())
                self.assertEqual(before, {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in paths})


if __name__ == '__main__':
    unittest.main()
