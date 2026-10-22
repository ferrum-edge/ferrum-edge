"""Offline gateway receipt checks; no Rust, Docker, sockets or workloads."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / '.github/scripts'))
import audit_mesh_gap_gateway_identity as audit
from mesh_gap_plan import gateway_blocks


class GatewayIdentityAuditTests(unittest.TestCase):
    def fixture(self, block=None, cell=None):
        block = block or gateway_blocks()[0]
        cell = cell or block['members'][0]
        image = 'sha256:' + 'b' * 64
        images = dict(baseline=image, candidate='sha256:' + 'c' * 64)
        identity = dict(block, candidate_sha='a' * 40, members=[dict(member, image_id=images[member['image_role']],
            runtime_source_sha=audit.BASELINE if member['image_role'] == 'baseline' else 'a' * 40) for member in block['members']])
        manifest = dict(gateways=['ferrum', 'ferrum-baseline'], pairs=1, tail_confirm_pair=block['pair'], duration=30,
            payload_sizes=[1048576], host_id='host', baseline_image=image, h2_window='default', h2_observation_enabled=False)
        status = dict(state='completed', exit_code=0, cleanup_errors=[])
        runtime = [dict(Image=images[cell['image_role']], State=dict(Running=True, Pid=100), Config=dict(User='65532:65532'),
            HostConfig=dict(GroupAdd=['65532']))]
        raw = dict(gateway=cell['arm'], pair=block['pair'], host_id='host', sample_schema=2, protocol='HTTP/1.1+TLS' if block['scenario'] == 'http1-tls' else 'HTTP/2',
            concurrency=50, effective_concurrency=50, payload_size=1048576, duration_secs=30, order_position=block['members'].index(cell) + 1,
            gateway_order=[member['arm'] for member in block['members']], target='https://127.0.0.1:8443/echo',
            phases=dict(measurement_start_unix_secs=10, measurement_secs=30, measurement_elapsed_secs=30.1, timed_out=False),
            total_requests=60, total_bytes=60*1048576, total_errors=0, drain_requests=3, drain_bytes=3*1048576,
            warmup_requests=50, rps=2.0, p50_us=1, p95_us=2, p99_us=3,
            process_usage=dict(available=True, measurement=[dict(role='gateway', pid=100, complete_bracket=True,
                cpu_seconds=3, bracket_secs=30, boundary_slack_secs=0)], timeline=[
                dict(unix_secs=at, processes=[dict(role='gateway', pid=100, start_ticks=20,
                    cpu_seconds=cpu, rss_bytes=1000)]) for at, cpu in ((10, 1), (25, 2), (40, 4))]))
        return block, cell, identity, manifest, status, raw, runtime, images, 'host'

    def test_valid_binding_and_errorful_observation(self):
        args = self.fixture()
        self.assertEqual(audit.validate_cell(*args)['runtime_pid'], 100)
        args[5]['total_errors'] = 7
        result = audit.validate_cell(*args)
        self.assertEqual(result['total_errors'], 7)
        self.assertFalse(result['zero_error_capacity'])

    def test_wrong_pid_image_or_generation_is_rejected(self):
        for kind in ('pid', 'image', 'timeline_pid', 'generation', 'cpu', 'rss'):
            with self.subTest(kind=kind):
                args = self.fixture()
                if kind == 'pid': args[5]['process_usage']['measurement'][0]['pid'] = 101
                elif kind == 'image': args[6][0]['Image'] = 'sha256:' + 'd' * 64
                elif kind == 'timeline_pid': args[5]['process_usage']['timeline'][1]['processes'][0]['pid'] = 101
                elif kind == 'generation': args[5]['process_usage']['timeline'][1]['processes'][0]['start_ticks'] = 21
                elif kind == 'cpu': args[5]['process_usage']['measurement'][0]['cpu_seconds'] = 2
                else: args[5]['process_usage']['timeline'][1]['processes'][0]['rss_bytes'] = -1
                with self.assertRaises(ValueError): audit.validate_cell(*args)

    def test_count_latency_and_bracket_faults_are_rejected(self):
        for kind in ('bytes', 'drain', 'rps', 'error_count', 'quantile', 'bracket', 'missing_after', 'status'):
            with self.subTest(kind=kind):
                args = self.fixture()
                raw = args[5]
                if kind == 'bytes': raw['total_bytes'] -= 1
                elif kind == 'drain': raw['drain_bytes'] -= 1
                elif kind == 'rps': raw['rps'] = 3
                elif kind == 'error_count': raw['total_errors'] = True
                elif kind == 'quantile': raw['p99_us'] = 1
                elif kind == 'bracket': raw['process_usage']['measurement'][0]['complete_bracket'] = False
                elif kind == 'missing_after': raw['process_usage']['timeline'].pop()
                else: args[4]['cleanup_errors'] = ['leak']
                with self.assertRaises(ValueError): audit.validate_cell(*args)

    def test_named_runtime_diagnostic_is_readable_and_symlink_is_not(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            relative = Path('gateway/run_1/http2/aa/protocol/pairs/pair_001/diagnostics/ferrum_runtime.json')
            target = root / relative
            target.parent.mkdir(parents=True)
            target.write_text('[{}]')
            reader = audit.Evidence(root)
            self.assertEqual(reader.read(relative), [{}])
            self.assertIn(str(relative), reader.hashes)
            target.unlink()
            target.symlink_to(root / 'missing')
            with self.assertRaises(ValueError): reader.read(relative)

    def test_complete_export_binds_every_cell_and_one_pid_fault_invalidates_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            chosen = dict(baseline_sha=audit.BASELINE, candidate_sha='a' * 40, harness_sha='d' * 40, phase='gap-compare')
            images = dict(baseline='sha256:' + 'b' * 64, candidate='sha256:' + 'c' * 64)
            source = dict(selection=chosen, image_ids=images, builds={
                role: dict(selection=chosen, source_sha=audit.BASELINE if role == 'baseline' else 'a' * 40,
                    image_id=image, complete=True, errors=[]) for role, image in images.items()})
            plan = dict(selection=chosen, source=source, gateway=gateway_blocks(), state='completed', errors=[],
                cleanup_complete=True, host_id='host')
            def save(relative, value):
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(value))
            save('plan.json', plan)
            save('provenance.json', source)
            for block in gateway_blocks():
                for cell in block['members']:
                    args = self.fixture(block, cell)
                    prefix = Path(block['directory'])
                    pair = prefix / 'protocol/pairs' / f"pair_{block['pair']:03d}"
                    save(prefix / 'identity.json', args[2])
                    save(prefix / 'protocol/manifest.json', args[3])
                    save(prefix / 'protocol/status.json', args[4])
                    last_raw = pair / f"{cell['arm']}_{block['scenario']}_1048576.json"
                    save(last_raw, args[5])
                    save(pair / 'diagnostics' / f"{cell['arm']}_runtime.json", args[6])
            report = audit.audit(root, 'a' * 40, 'd' * 40)
            self.assertTrue(report['audit_valid'], report)
            self.assertEqual(report['valid_gateway_cells'], 32)
            bad = json.loads((root / last_raw).read_text())
            bad['process_usage']['measurement'][0]['pid'] = 999
            save(last_raw, bad)
            report = audit.audit(root, 'a' * 40, 'd' * 40)
            self.assertFalse(report['audit_valid'])
            self.assertEqual(report['valid_gateway_cells'], 31)

    def test_incomplete_artifact_never_certifies_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = audit.audit(temporary, 'a' * 40, 'b' * 40)
            self.assertFalse(report['audit_valid'])
            self.assertEqual(report['valid_gateway_cells'], 0)
            self.assertTrue(report['issues'])


if __name__ == '__main__':
    unittest.main()
