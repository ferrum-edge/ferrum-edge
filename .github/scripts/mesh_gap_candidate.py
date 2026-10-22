#!/usr/bin/env python3
"""Frozen inputs and literal command plans for remote gap experiments."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

ORIGINAL_BASELINE = '4a7be250e45a367314e3dec872ecbd512220558e'
BASELINE = '7bddb58ae8cf547c9bb875f597557dd842bcb786'
MAINTENANCE_EVIDENCE = dict(
    origin_sha=ORIGINAL_BASELINE, baseline_sha=BASELINE, parent_sha=ORIGINAL_BASELINE,
    changed_paths=['src/secrets/azure.rs'], path='src/secrets/azure.rs',
    old_blob='165508f980193f8883dee2f022ca648af5f49519',
    new_blob='63403bddeacd79a38e0b4879bbc9705af62f2276', old_mode='100644', new_mode='100644',
    old_sha256='0c7ab0d5e4cc0b4d0c91049d9d57a30117396af29ea3d50d79733bf6febec599',
    new_sha256='1e0ad38ed6f23a905778ddc6a81bb7bd8860adbdd48514ee8296acd723925451',
    scope='common Azure if-let-chain maintenance on both performance arms; exact committed source, no overlay or lint suppression')
GATEWAY_HARNESS = '766a3947caadc114cb62aa915a7209a43b94b03d'
BUILDER = 'rust:latest@sha256:e259494b14672950a909b4c54527e19d29cae6ebf980672114c8bb85e5594e4a'
PERFORMANCE_KINDS = ('h2-handoff', 'h2-response-groups', 'header-boundary', 'label-interner')
HYPER_KINDS = ('h2-handoff', 'h2-response-groups')
KINDS = (*PERFORMANCE_KINDS, 'telemetry-reproduce', 'telemetry-verify')
PHASES = ('gap-vendor-preflight', 'gap-checks', 'gap-compare', 'gap-telemetry-reproduce', 'gap-telemetry-verify')
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
    if kind not in KINDS or phase not in PHASES:
        raise ValueError('unknown allowlisted candidate kind or phase')
    baseline = BASELINE if kind in PERFORMANCE_KINDS else ORIGINAL_BASELINE
    if candidate == baseline:
        raise ValueError('candidate must differ from its fixed baseline')
    for telemetry in ('reproduce', 'verify'):
        if (phase == 'gap-telemetry-' + telemetry) != (kind == 'telemetry-' + telemetry):
            raise ValueError('telemetry reproduction/verification use separate checks-only phases')
    if phase == 'gap-vendor-preflight' and kind not in HYPER_KINDS:
        raise ValueError('vendor preflight only applies to the vendored Hyper candidate')
    return dict(baseline_sha=baseline, candidate_sha=candidate, candidate_kind=kind,
                phase=phase, profile='release', features='cloud-secrets',
                recipe_scope='intended performance image recipe only; correctness uses its recorded command, manifest feature defaults or explicit features, and test/dev profile environment',
                allocation_instrumentation=False, builder_image=BUILDER,
                gateway_harness_sha=GATEWAY_HARNESS)


def git(*args, cwd=ROOT):
    return subprocess.check_output(['git', *args], cwd=cwd, text=True).strip()


def validate_maintenance_evidence(evidence):
    if evidence != MAINTENANCE_EVIDENCE:
        raise ValueError('performance baseline must contain only the exact attested Azure maintenance change')


def maintenance_origin():
    path = MAINTENANCE_EVIDENCE['path']
    observed = dict(origin_sha=ORIGINAL_BASELINE, baseline_sha=BASELINE,
        parent_sha=git('show', '-s', '--format=%P', BASELINE),
        changed_paths=git('diff', '--no-ext-diff', '--no-renames', '--name-only', ORIGINAL_BASELINE, BASELINE).splitlines(),
        path=path, scope=MAINTENANCE_EVIDENCE['scope'])
    for side, revision in (('old', ORIGINAL_BASELINE), ('new', BASELINE)):
        observed[side + '_blob'] = git('rev-parse', revision + ':' + path)
        observed[side + '_mode'] = git('ls-tree', revision, '--', path).split()[0]
        observed[side + '_sha256'] = hashlib.sha256(subprocess.check_output(
            ['git', 'show', revision + ':' + path], cwd=ROOT)).hexdigest()
    validate_maintenance_evidence(observed)
    return observed


def selection():
    result = validate_inputs(os.environ.get('GAP_CANDIDATE_SHA', ''),
                             os.environ.get('GAP_CANDIDATE_KIND', ''),
                             os.environ.get('BENCH_PHASE', ''))
    baseline = result['baseline_sha']
    for revision in (baseline, result['candidate_sha'], GATEWAY_HARNESS):
        if git('rev-parse', '--verify', revision + '^{commit}') != revision:
            raise ValueError('exact source commit is unavailable')
    subprocess.run(['git', 'merge-base', '--is-ancestor', baseline, result['candidate_sha']],
                   cwd=ROOT, check=True)
    result['maintenance_origin'] = maintenance_origin() if result['candidate_kind'] in PERFORMANCE_KINDS else None
    result['harness_sha'] = git('rev-parse', 'HEAD')
    # Candidate work can change runtime source, tests and patch notes, but not
    # choose a different build recipe, dependency graph or compiler configuration.
    immutable = ['Dockerfile', '.dockerignore', 'Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml',
                 '.cargo', 'build.rs', 'build', 'custom_plugins', 'proto', 'ebpf']
    if result['candidate_kind'] in PERFORMANCE_KINDS:
        immutable.append(MAINTENANCE_EVIDENCE['path'])
    changed = git('diff', '--name-only', baseline, result['candidate_sha'], '--', *immutable)
    if changed:
        raise ValueError('candidate changes frozen build inputs: ' + changed)
    result['changed_paths'] = git('diff', '--name-only', baseline, result['candidate_sha']).splitlines()
    if not result['changed_paths']:
        raise ValueError('candidate has no source delta')
    result['dockerfile_sha256'] = hashlib.sha256(subprocess.check_output(
        ['git', 'show', baseline + ':Dockerfile'], cwd=ROOT)).hexdigest()
    result['selection_sha256'] = hashlib.sha256(json.dumps(result, sort_keys=True).encode()).hexdigest()
    return result


def require_remote():
    if os.environ.get('GITHUB_ACTIONS') != 'true' or os.uname().sysname != 'Linux' or os.uname().machine != 'x86_64':
        raise ValueError('execution is restricted to remote GitHub Actions Linux x64')


def cargo_tests(kind):
    common = [
        ['cargo', 'test', '--locked', '--features', 'cloud-secrets', '--test', 'unit_tests', 'unit::secrets::azure_tests::'],
        ['cargo', 'test', '--locked', '--features', 'cloud-secrets', '--test', 'integration_tests', 'vendor_integrity'],
        ['cargo', 'test', '--locked', '--features', 'cloud-secrets', '--test', 'integration_tests', 'mesh_retry_rotation_tests::'],
        ['cargo', 'test', '--locked', '--features', 'cloud-secrets', '--test', 'integration_tests', 'gateway_mesh_trust_retirement_tests::'],
        ['cargo', 'test', '--locked', '--features', 'cloud-secrets', '--test', 'integration_tests', 'mesh_grpc_transport_tests::'],
    ]
    if kind in HYPER_KINDS:
        return common + [
            ['cargo', 'test', '--locked', '--features', 'cloud-secrets', '--test', 'integration_tests', 'http2_pool_tests::'],
            ['cargo', 'test', '--locked', '--features', 'cloud-secrets', '--test', 'integration_tests', 'mesh_hbone_tests::'],
        ]
    if kind == 'header-boundary':
        return [
            ['cargo', 'test', '--locked', '--features', 'cloud-secrets', '--test', 'unit_gateway_core_tests', 'header_merge_reconciliation_tests::'],
            ['cargo', 'test', '--locked', '--features', 'cloud-secrets', '--lib', 'proxy::headers::tests::'],
            ['cargo', 'test', '--locked', '--features', 'cloud-secrets', '--test', 'unit_gateway_core_tests', 'grpc_proxy_tests::'],
            ['cargo', 'test', '--locked', '--features', 'cloud-secrets', '--test', 'unit_gateway_core_tests', 'consumer_assertion_namespace_tests::'],
            ['cargo', 'test', '--locked', '--features', 'cloud-secrets', '--test', 'unit_gateway_core_tests', 'request_context_tests::'],
            ['cargo', 'test', '--locked', '--features', 'cloud-secrets', '--test', 'unit_gateway_core_tests', 'request_trailer_boundary_tests::'],
            ['cargo', 'test', '--locked', '--features', 'cloud-secrets', '--test', 'unit_gateway_core_tests', 'response_trailer_policy_tests::'],
            ['cargo', 'test', '--locked', '--features', 'cloud-secrets', '--test', 'unit_gateway_core_tests', 'response_representation_tests::'],
        ] + common
    if kind == 'label-interner':
        unit_filters = ('mesh_label_interner_tests', 'mesh_label_cache_',
            'test_mesh_request_key_interns_repeated_label_values', 'prometheus_metrics_tests',
            'mesh_telemetry_metric_families_tests', 'mesh_telemetry_tag_cel_tests', 'mesh_plugins_tests')
        return [
            ['cargo', 'test', '--locked', '--features', 'cloud-secrets', '--test', 'unit_plugins_b_tests', test_filter]
            for test_filter in unit_filters
        ] + [
            ['cargo', 'test', '--locked', '--features', 'cloud-secrets', '--lib', test_filter]
            for test_filter in ('plugins::mesh::prometheus_helpers::tests', 'plugins::mesh::service_graph::tests')
        ] + [
            ['cargo', 'test', '--locked', '--features', 'cloud-secrets', '--test', 'integration_tests', test_filter]
            for test_filter in ('admin_mesh_service_graph_tests', 'deferred_log_tests', 'mesh_telemetry_tracing_tests')
        ] + common
    raise ValueError('no performance check plan for this kind')


def expected_telemetry_red(exit_code, text):
    return (exit_code == 101 and
            'configured builtin prometheus_metrics must observe real captured start' in text and
            re.search(r'test result: FAILED\. 0 passed; 1 failed;', text) is not None)
