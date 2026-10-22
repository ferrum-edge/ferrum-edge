#!/usr/bin/env python3
"""Frozen inputs and literal command plans for remote gap experiments."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

BASELINE = '4a7be250e45a367314e3dec872ecbd512220558e'
GATEWAY_HARNESS = '766a3947caadc114cb62aa915a7209a43b94b03d'
BUILDER = 'rust:latest@sha256:e259494b14672950a909b4c54527e19d29cae6ebf980672114c8bb85e5594e4a'
PERFORMANCE_KINDS = ('h2-handoff', 'header-boundary')
KINDS = (*PERFORMANCE_KINDS, 'telemetry-reproduce')
PHASES = ('gap-vendor-preflight', 'gap-checks', 'gap-compare', 'gap-telemetry-reproduce')
SHA = re.compile(r'[0-9a-f]{40}')
IMAGE = re.compile(r'sha256:[0-9a-f]{64}')
ROOT = Path(__file__).resolve().parents[2]


def write(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, allow_nan=False) + '\n')


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def validate_inputs(candidate, kind, phase):
    if not isinstance(candidate, str) or SHA.fullmatch(candidate) is None:
        raise ValueError('candidate must be an exact lowercase 40-hex commit SHA')
    if candidate == BASELINE:
        raise ValueError('candidate must differ from the fixed baseline')
    if kind not in KINDS or phase not in PHASES:
        raise ValueError('unknown allowlisted candidate kind or phase')
    if (phase == 'gap-telemetry-reproduce') != (kind == 'telemetry-reproduce'):
        raise ValueError('telemetry reproduction is a separate checks-only phase')
    if phase == 'gap-vendor-preflight' and kind != 'h2-handoff':
        raise ValueError('vendor preflight only applies to the vendored Hyper candidate')
    return dict(baseline_sha=BASELINE, candidate_sha=candidate, candidate_kind=kind,
                phase=phase, profile='release', features='cloud-secrets',
                allocation_instrumentation=False, builder_image=BUILDER,
                gateway_harness_sha=GATEWAY_HARNESS)


def git(*args, cwd=ROOT):
    return subprocess.check_output(['git', *args], cwd=cwd, text=True).strip()


def selection():
    result = validate_inputs(os.environ.get('GAP_CANDIDATE_SHA', ''),
                             os.environ.get('GAP_CANDIDATE_KIND', ''),
                             os.environ.get('BENCH_PHASE', ''))
    for revision in (BASELINE, result['candidate_sha'], GATEWAY_HARNESS):
        if git('rev-parse', '--verify', revision + '^{commit}') != revision:
            raise ValueError('exact source commit is unavailable')
    subprocess.run(['git', 'merge-base', '--is-ancestor', BASELINE, result['candidate_sha']],
                   cwd=ROOT, check=True)
    result['harness_sha'] = git('rev-parse', 'HEAD')
    # Candidate work can change runtime source, tests and patch notes, but not
    # choose a different build recipe, dependency graph or compiler configuration.
    immutable = ['Dockerfile', 'Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml',
                 '.cargo', 'build.rs', 'build', 'custom_plugins', 'proto', 'ebpf']
    changed = git('diff', '--name-only', BASELINE, result['candidate_sha'], '--', *immutable)
    if changed:
        raise ValueError('candidate changes frozen build inputs: ' + changed)
    result['changed_paths'] = git('diff', '--name-only', BASELINE, result['candidate_sha']).splitlines()
    if not result['changed_paths']:
        raise ValueError('candidate has no source delta')
    result['dockerfile_sha256'] = hashlib.sha256(subprocess.check_output(
        ['git', 'show', BASELINE + ':Dockerfile'], cwd=ROOT)).hexdigest()
    result['selection_sha256'] = hashlib.sha256(json.dumps(result, sort_keys=True).encode()).hexdigest()
    return result


def require_remote():
    if os.environ.get('GITHUB_ACTIONS') != 'true' or os.uname().sysname != 'Linux' or os.uname().machine != 'x86_64':
        raise ValueError('execution is restricted to remote GitHub Actions Linux x64')


def cargo_tests(kind):
    common = [
        ['cargo', 'test', '--locked', '--features', 'cloud-secrets', '--test', 'integration_tests', 'vendor_integrity'],
        ['cargo', 'test', '--locked', '--features', 'cloud-secrets', '--test', 'integration_tests', 'mesh_retry_rotation_tests::'],
        ['cargo', 'test', '--locked', '--features', 'cloud-secrets', '--test', 'integration_tests', 'gateway_mesh_trust_retirement_tests::'],
        ['cargo', 'test', '--locked', '--features', 'cloud-secrets', '--test', 'integration_tests', 'mesh_grpc_transport_tests::'],
    ]
    if kind == 'h2-handoff':
        return common + [
            ['cargo', 'test', '--locked', '--features', 'cloud-secrets', '--test', 'integration_tests', 'http2_pool_tests::'],
            ['cargo', 'test', '--locked', '--features', 'cloud-secrets', '--test', 'integration_tests', 'mesh_hbone_tests::'],
        ]
    if kind == 'header-boundary':
        return common + [
            ['cargo', 'test', '--locked', '--features', 'cloud-secrets', '--lib', 'proxy::headers::tests::'],
            ['cargo', 'test', '--locked', '--features', 'cloud-secrets', '--test', 'unit_gateway_core_tests', 'grpc_proxy_tests::'],
            ['cargo', 'test', '--locked', '--features', 'cloud-secrets', '--test', 'unit_gateway_core_tests', 'header_merge_reconciliation_tests::'],
            ['cargo', 'test', '--locked', '--features', 'cloud-secrets', '--test', 'unit_gateway_core_tests', 'consumer_assertion_namespace_tests::'],
            ['cargo', 'test', '--locked', '--features', 'cloud-secrets', '--test', 'unit_gateway_core_tests', 'request_context_tests::'],
            ['cargo', 'test', '--locked', '--features', 'cloud-secrets', '--test', 'unit_gateway_core_tests', 'request_trailer_boundary_tests::'],
            ['cargo', 'test', '--locked', '--features', 'cloud-secrets', '--test', 'unit_gateway_core_tests', 'response_trailer_policy_tests::'],
            ['cargo', 'test', '--locked', '--features', 'cloud-secrets', '--test', 'unit_gateway_core_tests', 'response_representation_tests::'],
        ]
    raise ValueError('no performance check plan for this kind')


def expected_telemetry_red(exit_code, text):
    return (exit_code == 101 and
            'configured builtin prometheus_metrics must observe real captured start' in text and
            re.search(r'test result: FAILED\. 0 passed; 1 failed;', text) is not None)
