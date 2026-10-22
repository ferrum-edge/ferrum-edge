#!/usr/bin/env python3
"""Optional exact-origin baseline reuse; no build, performance selection or fallback.

Remote download is read-only. Verify GitHub's ZIP digest before extracting the
fixed flat build-artifact allowlist. Preserve the original receipt unchanged;
a separate wrapper binds it to fresh current candidate checks and its origin.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

from mesh_gap_candidate import BASELINE, BUILDER, IMAGE, ROOT, SHA, digest, require_remote, selection, validate_maintenance_evidence, write
from mesh_gap_build import checked_receipt

HEX = re.compile(r'[0-9a-f]{64}')
DECIMAL = re.compile(r'[1-9][0-9]{0,19}')
ARTIFACT_LIMIT = 2 * 1024**3
METADATA_LIMIT = 8 * 1024**2
COMMANDS = ('build-builder', 'compiler-native-packages', 'build-runtime', 'identity-create', 'identity-copy',
            'binary-notes', 'binary-sections', 'runtime-version', 'export-image')
FILES = {'receipt.json', 'image.json', 'image.tar', 'Dockerfile.source'} | {
    name + suffix for name in COMMANDS for suffix in ('.log', '.command.json')}
RECIPE_KEYS = ('baseline_sha', 'profile', 'features', 'allocation_instrumentation', 'builder_image', 'dockerfile_sha256', 'maintenance_origin')


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def inputs(run, attempt, phase, current_run=''):
    if run == '' and attempt == '':
        return None
    require(phase == 'gap-compare', 'baseline reuse is only available for gap-compare')
    require(isinstance(run, str) and DECIMAL.fullmatch(run) is not None
            and isinstance(attempt, str) and DECIMAL.fullmatch(attempt) is not None,
            'baseline run and attempt must both be exact positive decimal IDs')
    require(run != current_run, 'baseline origin must be a distinct prior run')
    return dict(run_id=int(run), attempt=int(attempt), artifact_name=f'mesh-gap-image-baseline-{run}-{attempt}')


def requested():
    return inputs(os.environ.get('GAP_BASELINE_RUN_ID', ''), os.environ.get('GAP_BASELINE_RUN_ATTEMPT', ''),
                  os.environ.get('BENCH_PHASE', ''), os.environ.get('GITHUB_RUN_ID', ''))


def validate_origin(request, repository, repository_id, run, jobs, artifact):
    require(run.get('id') == request['run_id'] and run.get('run_attempt') == request['attempt'], 'origin run/attempt mismatch')
    require(run.get('repository', {}).get('full_name') == repository
            and run.get('repository', {}).get('id') == repository_id
            and run.get('head_repository', {}).get('id') == repository_id, 'origin must be the same repository, not a fork')
    require(run.get('event') == 'workflow_dispatch'
            and str(run.get('path', '')).split('@', 1)[0] == '.github/workflows/mesh-runtime-benchmark.yml'
            and SHA.fullmatch(str(run.get('head_sha'))) is not None, 'origin workflow identity mismatch')
    matches = [job for job in jobs if job.get('name') == 'Matched release image (baseline)']
    require(len(matches) == 1, 'origin baseline job missing or ambiguous')
    job = matches[0]
    require(job.get('run_id') == request['run_id'] and job.get('head_sha') == run['head_sha']
            and job.get('status') == 'completed' and job.get('conclusion') == 'success', 'original baseline build job did not succeed')
    build_steps = [step for step in job.get('steps', []) if step.get('name') == 'Build exact submitted source with unchanged release recipe']
    require(len(build_steps) == 1 and build_steps[0].get('conclusion') == 'success', 'origin must contain an actual successful build, not chained reuse')
    linked = artifact.get('workflow_run', {})
    require(artifact.get('name') == request['artifact_name'] and artifact.get('expired') is False
            and type(artifact.get('id')) is int and artifact['id'] > 0
            and type(artifact.get('size_in_bytes')) is int and 0 < artifact['size_in_bytes'] <= ARTIFACT_LIMIT
            and IMAGE.fullmatch(str(artifact.get('digest'))) is not None, 'origin artifact identity, digest or size invalid')
    require(linked.get('id') == request['run_id'] and linked.get('head_sha') == run['head_sha']
            and linked.get('repository_id') == repository_id and linked.get('head_repository_id') == repository_id,
            'artifact does not belong to the specified same-repository origin')
    # Deliberately no gate on the full run's conclusion or performance results.
    return job


def fixed_input_hashes():
    result = {}
    for name in ('Cargo.toml', 'Cargo.lock', '.dockerignore', 'rust-toolchain.toml'):
        data = subprocess.run(['git', 'show', BASELINE + ':' + name], cwd=ROOT, capture_output=True)
        if data.returncode == 0:
            result[name] = hashlib.sha256(data.stdout).hexdigest()
    return result


def validate_original(receipt, chosen, origin_head, expected_inputs):
    validate_maintenance_evidence(chosen.get('maintenance_origin'))
    require(receipt.get('role') == 'baseline' and receipt.get('source_sha') == BASELINE
            and receipt.get('complete') is True and receipt.get('errors') == [], 'original baseline receipt is incomplete')
    old = receipt.get('selection', {})
    require(old.get('harness_sha') == origin_head and old.get('phase') == 'gap-compare'
            and all(old.get(key) == chosen.get(key) for key in RECIPE_KEYS), 'origin source/build selection differs from current frozen recipe')
    require(old.get('baseline_sha') == BASELINE and old.get('profile') == 'release' and old.get('features') == 'cloud-secrets'
            and old.get('allocation_instrumentation') is False and old.get('builder_image') == BUILDER,
            'baseline must be the unchanged uninstrumented representative release recipe')
    require(receipt.get('recipe_scope') == 'unchanged source Dockerfile; no linker wrapper or instrumentation'
            and receipt.get('dockerfile_sha256') == chosen['dockerfile_sha256']
            and receipt.get('source_file_sha256') == expected_inputs, 'Docker/Cargo/source-input identity mismatch')
    require(IMAGE.fullmatch(str(receipt.get('image_id'))) is not None and all(HEX.fullmatch(str(receipt.get(key))) is not None
            for key in ('binary_sha256', 'image_archive_sha256', 'compiler_native_packages_sha256', 'checks_receipt_sha256')),
            'original binary/image/compiler/checks hashes missing')


def validate_reuse(directory, chosen, checks, request, repository, repository_id):
    checked_receipt(chosen, checks)
    directory = Path(directory)
    receipt = json.loads((directory / 'receipt.json').read_text())
    wrapper = json.loads((directory / 'baseline-reuse.json').read_text())
    require(request is not None and wrapper.get('request') == request and wrapper.get('current_selection') == chosen,
            'reuse was not explicitly selected for this exact comparison')
    require(wrapper.get('complete') is True and wrapper.get('rebuilt') is False and wrapper.get('errors') == []
            and wrapper.get('current_checks_receipt_sha256') == digest(checks), 'reuse lacks fresh current checks binding')
    origin = wrapper['origin']
    validate_origin(request, repository, repository_id, origin['run'], origin['jobs'], origin['artifact'])
    require(wrapper.get('downloaded_artifact_sha256') == origin['artifact']['digest'].removeprefix('sha256:')
            and wrapper.get('downloaded_artifact_bytes') == origin['artifact']['size_in_bytes'], 'artifact download digest/size mismatch')
    require(wrapper.get('original_receipt_sha256') == digest(directory / 'receipt.json'), 'original receipt changed')
    validate_original(receipt, chosen, origin['run']['head_sha'], fixed_input_hashes())
    helper = Path(__file__).with_name('mesh_gap_build.py')
    old_helper = subprocess.check_output(['git', 'show', origin['run']['head_sha'] + ':.github/scripts/mesh_gap_build.py'], cwd=ROOT)
    require(wrapper.get('original_build_helper_sha256') == hashlib.sha256(old_helper).hexdigest() == digest(helper),
            'original build helper differs from current pinned recipe executor')
    require(receipt['image_archive_sha256'] == digest(directory / 'image.tar')
            and receipt['compiler_native_packages_sha256'] == digest(directory / 'compiler-native-packages.log')
            and receipt['dockerfile_sha256'] == digest(directory / 'Dockerfile.source'), 'reused artifact contents changed')
    return wrapper


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        return None


def api_request(path, token):
    require(path.startswith('/repos/'), 'invalid API path')
    return urllib.request.Request('https://api.github.com' + path, headers={
        'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'ferrum-mesh-baseline-reuse'})


def api_json(path, token):
    with urllib.request.build_opener(NoRedirect).open(api_request(path, token), timeout=60) as response:
        data = response.read(METADATA_LIMIT + 1)
    require(len(data) <= METADATA_LIMIT, 'origin API metadata exceeds limit')
    return json.loads(data)


def download(path, token, target, artifact):
    try:
        urllib.request.build_opener(NoRedirect).open(api_request(path, token), timeout=60)
    except urllib.error.HTTPError as error:
        require(error.code == 302, 'artifact API did not provide a signed download redirect')
        location = error.headers.get('Location', '')
        error.close()
    else:
        raise ValueError('artifact API did not provide expected redirect')
    parsed = urllib.parse.urlsplit(location)
    require(parsed.scheme == 'https' and parsed.hostname and parsed.username is None and parsed.password is None,
            'artifact redirect must be HTTPS without embedded credentials')
    # Never carry the API Authorization header onto the signed storage URL.
    size, checksum, started = 0, hashlib.sha256(), time.monotonic()
    with urllib.request.urlopen(location, timeout=60) as source, target.open('xb') as output:
        while chunk := source.read(1024 * 1024):
            size += len(chunk)
            require(size <= ARTIFACT_LIMIT and time.monotonic() - started <= 600, 'artifact download exceeds bound')
            checksum.update(chunk)
            output.write(chunk)
    require(size == artifact['size_in_bytes'] and checksum.hexdigest() == artifact['digest'].removeprefix('sha256:'),
            'artifact ZIP differs from GitHub digest or size; no extraction allowed')
    return dict(downloaded_artifact_sha256=checksum.hexdigest(), downloaded_artifact_bytes=size)


def extract(archive, destination):
    with zipfile.ZipFile(archive) as source:
        entries = source.infolist()
        names = [entry.filename for entry in entries]
        require(len(entries) <= len(FILES) and len(set(names)) == len(names)
                and set(names) <= FILES and {'receipt.json', 'image.json', 'image.tar', 'Dockerfile.source',
                                            'compiler-native-packages.log'} <= set(names), 'artifact file allowlist or uniqueness failed')
        require(sum(entry.file_size for entry in entries) <= ARTIFACT_LIMIT, 'uncompressed artifact size exceeds bound')
        for entry in entries:
            mode = entry.external_attr >> 16
            require(not entry.is_dir() and stat.S_IFMT(mode) in (0, stat.S_IFREG)
                    and entry.file_size <= (ARTIFACT_LIMIT if entry.filename == 'image.tar' else 64 * 1024**2),
                    'artifact member type or size invalid')
        destination.mkdir(parents=True, exist_ok=False)
        for entry in entries:
            with source.open(entry) as incoming, (destination / entry.filename).open('xb') as outgoing:
                shutil.copyfileobj(incoming, outgoing, 1024 * 1024)


def reuse():
    require_remote()
    request = requested()
    require(request is not None and os.environ.get('GAP_BUILD_ROLE') == 'baseline', 'explicit baseline reuse selection required')
    chosen = selection()
    checks = ROOT / 'results/gap/checks/receipt.json'
    checked_receipt(chosen, checks)
    repository = os.environ['GITHUB_REPOSITORY']
    require(re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository) is not None, 'invalid repository name')
    repository_id = int(os.environ['GITHUB_REPOSITORY_ID'])
    token = os.environ['GITHUB_TOKEN']
    prefix = f'/repos/{repository}/actions'
    run = api_json(f'{prefix}/runs/{request["run_id"]}/attempts/{request["attempt"]}', token)
    job_listing = api_json(f'{prefix}/runs/{request["run_id"]}/attempts/{request["attempt"]}/jobs?per_page=100', token)
    artifacts = api_json(f'{prefix}/runs/{request["run_id"]}/artifacts?per_page=100', token)
    require(job_listing['total_count'] == len(job_listing['jobs']) <= 100
            and artifacts['total_count'] == len(artifacts['artifacts']) <= 100, 'origin list is incomplete; no pagination inference')
    matches = [item for item in artifacts['artifacts'] if item.get('name') == request['artifact_name']]
    require(len(matches) == 1, 'selected origin artifact missing or ambiguous')
    artifact = matches[0]
    job = validate_origin(request, repository, repository_id, run, job_listing['jobs'], artifact)
    original_helper = subprocess.check_output(['git', 'show', run['head_sha'] + ':.github/scripts/mesh_gap_build.py'], cwd=ROOT)
    require(hashlib.sha256(original_helper).hexdigest() == digest(Path(__file__).with_name('mesh_gap_build.py')),
            'original build executor changed; selected reuse is ineligible')
    # Keep only source/build provenance. Whole-run outcome is recorded but never
    # used to prefer successful performance observations or discard errors.
    origin = dict(run={key: run.get(key) for key in ('id', 'run_attempt', 'repository', 'head_repository', 'event', 'path',
                                                   'head_sha', 'status', 'conclusion', 'html_url')}, jobs=[job], artifact=artifact)
    output = ROOT / 'results/gap/images/baseline'
    with tempfile.TemporaryDirectory(prefix='mesh-gap-baseline-origin-', dir=os.environ['RUNNER_TEMP']) as owned:
        archive = Path(owned) / 'artifact.zip'
        downloaded = download(f'{prefix}/artifacts/{artifact["id"]}/zip', token, archive, artifact)
        extract(archive, output)
    receipt = json.loads((output / 'receipt.json').read_text())
    validate_original(receipt, chosen, run['head_sha'], fixed_input_hashes())
    wrapper = dict(schema=1, complete=True, rebuilt=False, errors=[], request=request, origin=origin,
        current_selection=chosen, current_checks_receipt_sha256=digest(checks), original_receipt_sha256=digest(output / 'receipt.json'),
        original_build_helper_sha256=digest(Path(__file__).with_name('mesh_gap_build.py')), **downloaded,
        scope='reused original baseline build; fresh current candidate checks; origin performance outcome is not an eligibility gate')
    write(output / 'baseline-reuse.json', wrapper)
    try:
        validate_reuse(output, chosen, checks, request, repository, repository_id)
    except Exception:
        wrapper.update(complete=False, errors=['downloaded origin failed current reuse validation'])
        write(output / 'baseline-reuse.json', wrapper)
        raise
    print(json.dumps(dict(reused=True, run_id=request['run_id'], attempt=request['attempt'], artifact_id=artifact['id'],
                         artifact_sha256=downloaded['downloaded_artifact_sha256'], image_id=receipt['image_id'])))


if __name__ == '__main__':
    try:
        if len(sys.argv) == 2 and sys.argv[1] == 'validate-inputs':
            print(json.dumps(requested()))
        elif len(sys.argv) == 2 and sys.argv[1] == 'reuse':
            reuse()
        else:
            raise ValueError('expected validate-inputs or reuse')
    except Exception as error:
        # Network exceptions can contain signed URL queries. Do not expose them.
        reason = ('artifact HTTP ' + str(error.code) if isinstance(error, urllib.error.HTTPError) else
                  str(error) if isinstance(error, ValueError) else type(error).__name__)
        if len(sys.argv) == 2 and sys.argv[1] == 'reuse' and os.environ.get('GITHUB_ACTIONS') == 'true':
            write(ROOT / 'results/gap/images/baseline/baseline-reuse-failure.json',
                  dict(complete=False, rebuilt=False, error=reason, fallback_attempted=False))
        print('baseline reuse failed without fallback: ' + reason, file=sys.stderr)
        raise SystemExit(1)
