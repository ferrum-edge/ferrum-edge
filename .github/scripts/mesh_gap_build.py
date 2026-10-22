#!/usr/bin/env python3
"""Remote exact-source release builds. This never edits the Docker recipe."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import uuid

from mesh_gap_candidate import BASELINE, IMAGE, ROOT, digest, git, require_remote, selection, write


def command(argv, output, name, *, cwd=ROOT, timeout=7500):
    started = time.monotonic()
    with (output / (name + '.log')).open('w') as stream:
        result = subprocess.run(argv, cwd=cwd, stdout=stream, stderr=subprocess.STDOUT, timeout=timeout)
    write(output / (name + '.command.json'), dict(argv=argv, exit_code=result.returncode,
                                                elapsed_seconds=time.monotonic() - started))
    if result.returncode:
        raise ValueError(name + ' failed; retained log is authoritative')


def checked_receipt(chosen, path):
    receipt = json.loads(Path(path).read_text())
    if (receipt.get('selection') != chosen or receipt.get('complete') is not True
            or receipt.get('passed') is not True or receipt.get('performance_eligible') is not True
            or receipt.get('modified_checkout') is not False or receipt.get('final_tracked_diff') != []
            or receipt.get('errors') != []):
        raise ValueError('same-run exact-head correctness receipt is not performance eligible')
    return receipt


def build():
    require_remote()
    chosen = selection()
    if chosen['phase'] != 'gap-compare':
        raise ValueError('only the explicitly selected comparison builds release images')
    role = os.environ.get('GAP_BUILD_ROLE')
    if role not in ('baseline', 'candidate'):
        raise ValueError('unknown image role')
    checks = ROOT / 'results/gap/checks/receipt.json'
    checked_receipt(chosen, checks)
    output = ROOT / 'results/gap/images' / role
    output.mkdir(parents=True, exist_ok=False)
    revision = BASELINE if role == 'baseline' else chosen['candidate_sha']
    result = dict(selection=chosen, role=role, source_sha=revision, checks_receipt_sha256=digest(checks),
                  complete=False, errors=[], recipe_scope='unchanged source Dockerfile; no linker wrapper or instrumentation')
    write(output / 'receipt.json', result)
    owned = Path(tempfile.mkdtemp(prefix='mesh-gap-build-', dir=os.environ['RUNNER_TEMP']))
    source = owned / 'source'
    token = uuid.uuid4().hex
    tag, builder = 'mesh-gap-' + role + ':' + token, 'mesh-gap-builder-' + role + ':' + token
    container = 'mesh-gap-identity-' + token
    try:
        subprocess.run(['git', 'worktree', 'add', '--detach', str(source), revision], cwd=ROOT, check=True)
        if git('rev-parse', 'HEAD', cwd=source) != revision or git('status', '--porcelain', cwd=source):
            raise ValueError('build source is not the clean exact submitted commit')
        if digest(source / 'Dockerfile') != chosen['dockerfile_sha256']:
            raise ValueError('Docker recipe differs from the fixed baseline')
        shutil.copy2(source / 'Dockerfile', output / 'Dockerfile.source')
        for filename in ('Cargo.toml', 'Cargo.lock', '.dockerignore', 'rust-toolchain.toml'):
            if (source / filename).is_file():
                result.setdefault('source_file_sha256', {})[filename] = digest(source / filename)
        common = ['docker', 'build', '--platform', 'linux/amd64', '--progress', 'plain',
                  '--build-arg', 'FEATURES=cloud-secrets', '--build-arg', 'CARGO_PROFILE=release',
                  '-f', str(source / 'Dockerfile')]
        command([*common, '--target', 'builder', '-t', builder, str(source)], output, 'build-builder')
        command(['docker', 'run', '--rm', '--entrypoint', '/bin/sh', builder, '-c',
                 'rustc -Vv; cargo -Vv; cc --version; ld --version; dpkg-query -W'], output, 'compiler-native-packages', timeout=60)
        command([*common, '--target', 'runtime', '--label', 'org.opencontainers.image.revision=' + revision,
                 '--label', 'io.ferrum.benchmark.profile=release', '--label', 'io.ferrum.benchmark.features=cloud-secrets',
                 '-t', tag, str(source)], output, 'build-runtime')
        inspect = json.loads(subprocess.check_output(['docker', 'image', 'inspect', tag], text=True))[0]
        image = inspect['Id']
        if IMAGE.fullmatch(image) is None or inspect['Architecture'] != 'amd64' or inspect['Os'] != 'linux':
            raise ValueError('unexpected immutable Linux/amd64 image identity')
        write(output / 'image.json', inspect)
        command(['docker', 'create', '--name', container, image], output, 'identity-create', timeout=30)
        binary = owned / 'ferrum-edge'
        command(['docker', 'cp', container + ':/app/ferrum-edge', str(binary)], output, 'identity-copy', timeout=30)
        command(['readelf', '-n', str(binary)], output, 'binary-notes', timeout=30)
        command(['readelf', '-S', str(binary)], output, 'binary-sections', timeout=30)
        command(['docker', 'run', '--rm', image, 'version', '--json'], output, 'runtime-version', timeout=30)
        command(['docker', 'save', '--output', str(output / 'image.tar'), image], output, 'export-image', timeout=180)
        if git('status', '--porcelain', cwd=source):
            raise ValueError('release build changed submitted source')
        result.update(complete=True, image_id=image, binary_sha256=digest(binary),
                      image_archive_sha256=digest(output / 'image.tar'),
                      compiler_native_packages_sha256=digest(output / 'compiler-native-packages.log'),
                      dockerfile_sha256=digest(source / 'Dockerfile'))
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        result['errors'].append(str(error))
    finally:
        subprocess.run(['docker', 'rm', '-f', container], capture_output=True, check=False)
        subprocess.run(['git', 'worktree', 'remove', '--force', str(source)], cwd=ROOT, capture_output=True, check=False)
        shutil.rmtree(owned, ignore_errors=True)
        write(output / 'receipt.json', result)
    print(json.dumps(result, indent=2))
    return 0 if result['complete'] and not result['errors'] else 1


if __name__ == '__main__':
    raise SystemExit(build())
