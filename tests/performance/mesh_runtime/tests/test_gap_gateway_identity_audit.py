"""Offline gateway receipt checks; no Rust, Docker, sockets or workloads."""
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / '.github/scripts'))
import audit_mesh_gap_gateway_identity as audit
from mesh_gap_plan import gateway_blocks
import test_gap_baseline_reuse as reuse_fixtures


class GatewayIdentityAuditTests(unittest.TestCase):
    def fixture(self, block=None, cell=None, images=None):
        block = block or gateway_blocks()[0]
        cell = cell or block['members'][0]
        images = images or dict(baseline='sha256:' + 'b' * 64, candidate='sha256:' + 'c' * 64)
        image = images['baseline']
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

    def save(self, root, relative, value):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value))

    def export_fixture(self, root, source=None):
        chosen = dict(baseline_sha=audit.BASELINE, candidate_sha='a' * 40, harness_sha='d' * 40, phase='gap-compare')
        images = dict(baseline='sha256:' + 'b' * 64, candidate='sha256:' + 'c' * 64)
        source = source or dict(selection=chosen, image_ids=images, builds={
            role: dict(selection=chosen, source_sha=audit.BASELINE if role == 'baseline' else 'a' * 40,
                image_id=image, complete=True, errors=[]) for role, image in images.items()})
        plan = dict(selection=source['selection'], source=source, gateway=gateway_blocks(), state='completed', errors=[],
            cleanup_complete=True, host_id='host')
        self.save(root, 'plan.json', plan)
        self.save(root, 'provenance.json', source)
        for block in gateway_blocks():
            for cell in block['members']:
                args = self.fixture(block, cell, source['image_ids'])
                prefix = Path(block['directory'])
                pair = prefix / 'protocol/pairs' / f"pair_{block['pair']:03d}"
                self.save(root, prefix / 'identity.json', args[2])
                self.save(root, prefix / 'protocol/manifest.json', args[3])
                self.save(root, prefix / 'protocol/status.json', args[4])
                last_raw = pair / f"{cell['arm']}_{block['scenario']}_1048576.json"
                self.save(root, last_raw, args[5])
                self.save(root, pair / 'diagnostics' / f"{cell['arm']}_runtime.json", args[6])
        return last_raw

    def test_complete_export_binds_every_cell_and_one_pid_fault_invalidates_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            last_raw = self.export_fixture(root)
            report = audit.audit(root, 'a' * 40, 'd' * 40)
            self.assertTrue(report['audit_valid'], report)
            self.assertEqual(report['valid_gateway_cells'], 32)
            bad = json.loads((root / last_raw).read_text())
            bad['process_usage']['measurement'][0]['pid'] = 999
            self.save(root, last_raw, bad)
            report = audit.audit(root, 'a' * 40, 'd' * 40)
            self.assertFalse(report['audit_valid'])
            self.assertEqual(report['valid_gateway_cells'], 31)

    def reuse_fixture(self, root):
        directory = root.parent / 'images/baseline'
        directory.mkdir(parents=True)
        request, chosen, checks, inputs, helper = reuse_fixtures.BaselineReuseTests().fixture(directory)
        chosen.update(candidate_sha='a' * 40, phase='gap-compare')
        original = json.loads((directory / 'receipt.json').read_text())
        original['selection']['candidate_sha'] = '9' * 40
        self.save(directory, 'receipt.json', original)
        current_checks = json.loads(checks.read_text())
        current_checks['selection'] = chosen
        checks = root.parent / 'checks/receipt.json'
        self.save(checks.parent, checks.name, current_checks)
        wrapper = json.loads((directory / 'baseline-reuse.json').read_text())
        wrapper.update(schema=1, current_selection=chosen, current_checks_receipt_sha256=audit.reuse.digest(checks),
                       original_receipt_sha256=audit.reuse.digest(directory / 'receipt.json'))
        self.save(directory, 'baseline-reuse.json', wrapper)
        self.save(directory, 'image.json', dict(Id=original['image_id'], Config=dict(Labels={
            'org.opencontainers.image.revision': audit.BASELINE, 'io.ferrum.benchmark.profile': 'release',
            'io.ferrum.benchmark.features': 'cloud-secrets'})))
        source = dict(selection=chosen, image_ids=dict(baseline=original['image_id'], candidate='sha256:' + 'c' * 64),
            baseline_reuse=wrapper, checks_receipt_sha256=audit.reuse.digest(checks), builds=dict(baseline=original,
            candidate=dict(selection=chosen, source_sha='a' * 40, image_id='sha256:' + 'c' * 64, complete=True, errors=[])))
        self.export_fixture(root, source)
        context = dict(run_id=999, attempt=3, repository='o/r', repository_id=8)
        environment = dict(GITHUB_SHA=chosen['harness_sha'], GITHUB_RUN_ID='999', GITHUB_RUN_ATTEMPT='3',
            GITHUB_REPOSITORY='o/r', GITHUB_REPOSITORY_ID='8', GAP_BASELINE_RUN_ID='123',
            GAP_BASELINE_RUN_ATTEMPT='2', BENCH_PHASE='gap-compare')
        return directory, checks, inputs, helper, context, environment

    def mint_reuse(self, root, fixture):
        directory, checks, inputs, helper, context, environment = fixture
        with mock.patch.object(audit.reuse, 'require_remote'), mock.patch.dict(os.environ, environment), \
             mock.patch.object(audit.reuse, 'fixed_input_hashes', return_value=inputs), \
             mock.patch.object(audit.reuse.subprocess, 'check_output', return_value=helper), \
             mock.patch.object(audit.reuse, 'validate_reuse', wraps=audit.reuse.validate_reuse) as full:
            record = audit.verify_reuse(root, 'a' * 40, 'e' * 40, checks)
            full.assert_called_once()
        return record

    def test_public_reuse_requires_full_remote_receipt_without_private_image_transfer(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'campaign'
            fixture = self.reuse_fixture(root)
            original = (fixture[0] / 'receipt.json').read_bytes()
            record = self.mint_reuse(root, fixture)
            for name in ('image.tar', 'Dockerfile.source'):
                (fixture[0] / name).unlink()
            with mock.patch.object(audit.reuse, 'validate_reuse', side_effect=AssertionError('no private archive in public audit')):
                report = audit.audit(root, 'a' * 40, 'e' * 40, checks=fixture[1], context=fixture[4])
            self.assertTrue(report['audit_valid'], report)
            self.assertEqual(report['valid_gateway_cells'], 32)
            self.assertEqual(report['baseline_reuse_verification'], record)
            self.assertEqual((fixture[0] / 'receipt.json').read_bytes(), original)
            self.assertEqual(json.loads((fixture[0] / 'baseline-reuse.json').read_text())['origin']['run']['conclusion'], 'failure')

    def test_public_reuse_rejects_missing_context_checks_and_tampered_chain(self):
        kinds = ('proof', 'proof_run', 'proof_schema', 'proof_archive', 'run', 'attempt', 'repository', 'repository_id', 'candidate',
                 'harness', 'checks', 'checks_selection', 'checks_bytes', 'origin', 'origin_run', 'origin_attempt',
                 'digest', 'receipt_bytes', 'wrapper', 'compiler', 'image', 'candidate_selection', 'current_selection')
        for kind in kinds:
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / 'campaign'
                fixture = self.reuse_fixture(root)
                self.mint_reuse(root, fixture)
                directory, checks, _, _, context, _ = fixture
                context = copy.deepcopy(context)
                candidate, harness = 'a' * 40, 'e' * 40
                proof = root / audit.REUSE_VERIFICATION
                if kind == 'proof': proof.unlink()
                elif kind.startswith('proof_'):
                    value = json.loads(proof.read_text())
                    if kind == 'proof_run': value['current_run']['run_id'] = 998
                    elif kind == 'proof_schema': value['schema'] = True
                    else: value['verified_private_inputs']['image_archive_sha256'] = '0' * 64
                    self.save(root, proof.name, value)
                elif kind in ('run', 'attempt', 'repository', 'repository_id'):
                    key = 'run_id' if kind == 'run' else kind
                    context[key] = 'elsewhere/r' if kind == 'repository' else 998
                elif kind == 'candidate': candidate = '8' * 40
                elif kind == 'harness': harness = '8' * 40
                elif kind == 'checks': checks = None
                elif kind in ('checks_selection', 'checks_bytes'):
                    if kind == 'checks_bytes': checks.write_text(checks.read_text() + ' ')
                    else:
                        value = json.loads(checks.read_text()); value['selection']['candidate_sha'] = '8' * 40
                        self.save(checks.parent, checks.name, value)
                elif kind == 'receipt_bytes':
                    with (directory / 'receipt.json').open('a') as stream: stream.write(' ')
                elif kind == 'compiler': (directory / 'compiler-native-packages.log').write_text('changed')
                elif kind == 'image':
                    value = json.loads((directory / 'image.json').read_text()); value['Id'] = 'sha256:' + '0' * 64
                    self.save(directory, 'image.json', value)
                elif kind == 'candidate_selection':
                    value = json.loads((root / 'provenance.json').read_text())
                    value['builds']['candidate']['selection'] = value['builds']['baseline']['selection']
                    self.save(root, 'provenance.json', value)
                    plan = json.loads((root / 'plan.json').read_text()); plan['source'] = value
                    self.save(root, 'plan.json', plan)
                else:
                    wrapper = json.loads((directory / 'baseline-reuse.json').read_text())
                    if kind == 'origin': wrapper['origin']['run']['head_repository']['id'] = 9
                    elif kind == 'origin_run': wrapper['origin']['run']['id'] = 124
                    elif kind == 'origin_attempt': wrapper['origin']['run']['run_attempt'] = 1
                    elif kind == 'digest': wrapper['downloaded_artifact_sha256'] = '0' * 64
                    elif kind == 'current_selection': wrapper['current_selection']['candidate_sha'] = '8' * 40
                    else: wrapper['rebuilt'] = True
                    self.save(directory, 'baseline-reuse.json', wrapper)
                    source = json.loads((root / 'provenance.json').read_text()); source['baseline_reuse'] = wrapper
                    self.save(root, 'provenance.json', source)
                    plan = json.loads((root / 'plan.json').read_text()); plan['source'] = source
                    self.save(root, 'plan.json', plan)
                report = audit.audit(root, candidate, harness, checks=checks, context=context)
                self.assertFalse(report['audit_valid'], report)
                self.assertTrue(report['issues'], report)

    def test_remote_reuse_rejects_private_tamper_and_failed_build_step(self):
        for kind in ('archive', 'recipe', 'inputs', 'helper', 'build_step', 'request', 'current_commit'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / 'campaign'
                fixture = list(self.reuse_fixture(root))
                directory, checks, inputs, helper, context, environment = fixture
                if kind == 'archive': (directory / 'image.tar').write_bytes(b'other image')
                elif kind == 'recipe': (directory / 'Dockerfile.source').write_bytes(b'other recipe')
                elif kind == 'inputs': inputs['Cargo.lock'] = '0' * 64
                elif kind == 'helper': fixture[3] = b'changed executor'
                elif kind in ('request', 'current_commit'):
                    environment['GAP_BASELINE_RUN_ATTEMPT' if kind == 'request' else 'GITHUB_SHA'] = '1' if kind == 'request' else '0' * 40
                else:
                    wrapper = json.loads((directory / 'baseline-reuse.json').read_text())
                    wrapper['origin']['jobs'][0]['steps'][0]['conclusion'] = 'skipped'
                    self.save(directory, 'baseline-reuse.json', wrapper)
                    source = json.loads((root / 'provenance.json').read_text()); source['baseline_reuse'] = wrapper
                    self.save(root, 'provenance.json', source)
                with self.assertRaises(ValueError): self.mint_reuse(root, fixture)
                self.assertFalse((root / audit.REUSE_VERIFICATION).exists())

    def test_fresh_build_selection_remains_strict_and_remote_gate_is_required(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.export_fixture(root)
            source = json.loads((root / 'provenance.json').read_text())
            source['builds']['baseline']['selection'] = dict(source['selection'], candidate_sha='9' * 40)
            self.save(root, 'provenance.json', source)
            plan = json.loads((root / 'plan.json').read_text()); plan['source'] = source
            self.save(root, 'plan.json', plan)
            self.assertFalse(audit.audit(root, 'a' * 40, 'd' * 40)['audit_valid'])
            with mock.patch.object(audit.reuse, 'require_remote', side_effect=ValueError('remote only')):
                with self.assertRaisesRegex(ValueError, 'remote only'):
                    audit.verify_reuse(root, 'a' * 40, 'd' * 40, None)

    def test_incomplete_artifact_never_certifies_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = audit.audit(temporary, 'a' * 40, 'b' * 40)
            self.assertFalse(report['audit_valid'])
            self.assertEqual(report['valid_gateway_cells'], 0)
            self.assertTrue(report['issues'])


if __name__ == '__main__':
    unittest.main()
