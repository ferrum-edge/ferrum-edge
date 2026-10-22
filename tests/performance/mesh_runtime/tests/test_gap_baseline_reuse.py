"""Synthetic exact-origin reuse gates; no network, Docker or Rust execution."""
import copy
import hashlib
import json
import io
import urllib.error
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock
import warnings
import zipfile

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / '.github/scripts'))
import mesh_gap_baseline_reuse as reuse


class BaselineReuseTests(unittest.TestCase):
    def origin(self):
        request = reuse.inputs('123', '2', 'gap-compare', '999')
        run = dict(id=123, run_attempt=2, repository=dict(full_name='o/r', id=8), head_repository=dict(id=8),
                   event='workflow_dispatch', path='.github/workflows/mesh-runtime-benchmark.yml', head_sha='a' * 40,
                   status='completed', conclusion='failure')
        job = dict(name='Matched release image (baseline)', run_id=123, head_sha='a' * 40,
                   status='completed', conclusion='success', steps=[dict(
                       name='Build exact submitted source with unchanged release recipe', conclusion='success')])
        artifact = dict(id=456, name=request['artifact_name'], expired=False, digest='sha256:' + 'b' * 64,
                        size_in_bytes=3, workflow_run=dict(id=123, head_sha='a' * 40, repository_id=8, head_repository_id=8))
        return request, run, [job], artifact

    def test_default_off_and_strict_inputs(self):
        self.assertIsNone(reuse.inputs('', '', 'gap-compare'))
        for run, attempt, phase in [('123', '', 'gap-compare'), ('', '1', 'gap-compare'), ('01', '1', 'gap-compare'),
                                    ('$(id)', '1', 'gap-compare'), ('123', '2;id', 'gap-compare'), ('123', '2', 'gap-checks')]:
            with self.subTest(run=run, attempt=attempt), self.assertRaises(ValueError):
                reuse.inputs(run, attempt, phase)
        with self.assertRaises(ValueError):
            reuse.inputs('123', '2', 'gap-compare', '123')

    def test_whole_run_performance_conclusion_is_not_an_origin_gate(self):
        request, run, jobs, artifact = self.origin()
        for conclusion in ('failure', 'cancelled', None, 'success'):
            run['conclusion'] = conclusion
            self.assertEqual(reuse.validate_origin(request, 'o/r', 8, run, jobs, artifact), jobs[0])

    def test_bad_origin_job_attempt_repository_and_artifact_rejected(self):
        mutations = [lambda q, r, j, a: r.update(run_attempt=1),
            lambda q, r, j, a: r['head_repository'].update(id=9),
            lambda q, r, j, a: r['repository'].update(full_name='elsewhere/r'),
            lambda q, r, j, a: j[0].update(conclusion='failure'),
            lambda q, r, j, a: j[0]['steps'][0].update(conclusion='skipped'),
            lambda q, r, j, a: j.append(copy.deepcopy(j[0])),
            lambda q, r, j, a: a.update(expired=True),
            lambda q, r, j, a: a.update(digest=None),
            lambda q, r, j, a: a['workflow_run'].update(id=124),
            lambda q, r, j, a: a.update(name='mesh-gap-image-baseline-123-1')]
        for mutate in mutations:
            args = self.origin()
            mutate(*args)
            with self.subTest(mutation=mutate), self.assertRaises(ValueError):
                reuse.validate_origin(args[0], 'o/r', 8, *args[1:])

    def fixture(self, directory):
        request, run, jobs, artifact = self.origin()
        inputs = {'Cargo.toml': 'c' * 64, 'Cargo.lock': 'd' * 64}
        for name, content in (('image.tar', b'image'), ('compiler-native-packages.log', b'compiler'), ('Dockerfile.source', b'recipe')):
            (directory / name).write_bytes(content)
        chosen = dict(baseline_sha=reuse.BASELINE, profile='release', features='cloud-secrets', allocation_instrumentation=False,
                      builder_image=reuse.BUILDER, dockerfile_sha256=reuse.digest(directory / 'Dockerfile.source'), harness_sha='e' * 40)
        receipt = dict(role='baseline', source_sha=reuse.BASELINE, complete=True, errors=[],
            selection=dict(chosen, harness_sha=run['head_sha'], phase='gap-compare'), source_file_sha256=inputs,
            recipe_scope='unchanged source Dockerfile; no linker wrapper or instrumentation',
            dockerfile_sha256=chosen['dockerfile_sha256'], image_id='sha256:' + 'f' * 64, binary_sha256='1' * 64,
            checks_receipt_sha256='2' * 64, image_archive_sha256=reuse.digest(directory / 'image.tar'),
            compiler_native_packages_sha256=reuse.digest(directory / 'compiler-native-packages.log'))
        reuse.write(directory / 'receipt.json', receipt)
        checks = directory / 'checks.json'
        reuse.write(checks, dict(selection=chosen, complete=True, passed=True, performance_eligible=True,
                                modified_checkout=False, final_tracked_diff=[], errors=[]))
        helper = (ROOT / '.github/scripts/mesh_gap_build.py').read_bytes()
        wrapper = dict(complete=True, rebuilt=False, errors=[], request=request, current_selection=chosen,
            current_checks_receipt_sha256=reuse.digest(checks), origin=dict(run=run, jobs=jobs, artifact=artifact),
            downloaded_artifact_sha256='b' * 64, downloaded_artifact_bytes=3,
            original_receipt_sha256=reuse.digest(directory / 'receipt.json'),
            original_build_helper_sha256=hashlib.sha256(helper).hexdigest())
        reuse.write(directory / 'baseline-reuse.json', wrapper)
        return request, chosen, checks, inputs, helper

    def test_receipt_binding_rejects_tamper_stale_checks_and_recipe_changes(self):
        for mutation in ('none', 'receipt', 'archive', 'compiler', 'wrapper_digest', 'checks', 'recipe', 'helper', 'no_request'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temp:
                directory = Path(temp)
                request, chosen, checks, inputs, helper = self.fixture(directory)
                if mutation in ('receipt', 'archive', 'compiler'):
                    name = {'receipt': 'receipt.json', 'archive': 'image.tar', 'compiler': 'compiler-native-packages.log'}[mutation]
                    with (directory / name).open('ab') as stream:
                        stream.write(b' ')
                elif mutation == 'checks':
                    data = json.loads(checks.read_text())
                    data['passed'] = False
                    reuse.write(checks, data)
                elif mutation == 'wrapper_digest':
                    data = json.loads((directory / 'baseline-reuse.json').read_text())
                    data['downloaded_artifact_sha256'] = '0' * 64
                    reuse.write(directory / 'baseline-reuse.json', data)
                elif mutation == 'recipe':
                    inputs['Cargo.lock'] = '0' * 64
                elif mutation == 'helper':
                    helper = b'other executor'
                elif mutation == 'no_request':
                    request = None
                with mock.patch.object(reuse, 'fixed_input_hashes', return_value=inputs), \
                     mock.patch.object(reuse.subprocess, 'check_output', return_value=helper):
                    call = lambda: reuse.validate_reuse(directory, chosen, checks, request, 'o/r', 8)
                    if mutation == 'none':
                        self.assertTrue(call()['complete'])
                    else:
                        with self.assertRaises(ValueError):
                            call()

    def test_download_digest_must_match_and_token_is_not_forwarded(self):
        for valid in (True, False):
            with self.subTest(valid=valid), tempfile.TemporaryDirectory() as temp:
                data = b'immutable zip bytes'
                artifact = dict(size_in_bytes=len(data), digest='sha256:' +
                                (hashlib.sha256(data).hexdigest() if valid else '0' * 64))
                redirect = urllib.error.HTTPError('https://api.github.com/safe', 302, 'redirect',
                                                 {'Location': 'https://storage.example/artifact?signature=private'}, None)
                opener = mock.Mock()
                opener.open.side_effect = redirect
                with mock.patch.object(reuse.urllib.request, 'build_opener', return_value=opener), \
                     mock.patch.object(reuse.urllib.request, 'urlopen', return_value=io.BytesIO(data)) as storage:
                    call = lambda: reuse.download('/repos/o/r/actions/artifacts/1/zip', 'private-token',
                                                  Path(temp) / 'artifact.zip', artifact)
                    if valid:
                        self.assertEqual(call()['downloaded_artifact_bytes'], len(data))
                    else:
                        with self.assertRaises(ValueError):
                            call()
                    self.assertIsInstance(storage.call_args.args[0], str)
                    self.assertNotIn('private-token', str(storage.call_args))
                    self.assertEqual(opener.open.call_args.args[0].get_header('Authorization'), 'Bearer private-token')

    def test_extract_refuses_paths_links_duplicates_and_chained_reuse(self):
        for extra in ('../image', 'baseline-reuse.json', 'image.tar', 'symlink'):
            with self.subTest(extra=extra), tempfile.TemporaryDirectory() as temp:
                archive, destination = Path(temp) / 'a.zip', Path(temp) / 'out'
                with warnings.catch_warnings(), zipfile.ZipFile(archive, 'w') as output:
                    warnings.simplefilter('ignore', UserWarning)
                    for name in ('receipt.json', 'image.json', 'image.tar', 'Dockerfile.source', 'compiler-native-packages.log'):
                        if extra == 'symlink' and name == 'image.tar':
                            info = zipfile.ZipInfo(name)
                            info.external_attr = (stat.S_IFLNK | 0o777) << 16
                            output.writestr(info, 'elsewhere')
                        else:
                            output.writestr(name, '{}')
                    if extra != 'symlink':
                        output.writestr(extra, 'bad')
                with self.assertRaises(ValueError):
                    reuse.extract(archive, destination)
                self.assertFalse(destination.exists())


if __name__ == '__main__':
    unittest.main()
