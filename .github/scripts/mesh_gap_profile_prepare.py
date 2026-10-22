#!/usr/bin/env python3
"""One remote representative release build with its own original-link symbols.

No shipping-image reconstruction/comparison, runtime execution, pushes or retries.
The existing PATH shim preserves the primary linker call and executable; its
secondary companion link is explicitly a diagnostic build-recipe delta. This
image is separate from the unchanged-recipe baseline/candidate performance run.
"""
from __future__ import annotations

import argparse
import difflib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import time

import mesh_production_profile_ferrum as capture

FDE = re.compile(r"\bFDE\b.*\bpc=([0-9a-fA-F]+)\.\.([0-9a-fA-F]+)")
MINIMUM_FDE_TEXT_FRACTION = 0.80


def fde_coverage(text, address, size):
    """Union of FDE ranges clipped to .text; overlap never inflates coverage."""
    if type(address) is not int or type(size) is not int or address < 0 or size <= 0:
        raise ValueError("invalid .text range")
    spans = []
    for start, end in FDE.findall(text):
        start, end = max(address, int(start, 16)), min(address + size, int(end, 16))
        if start < end:
            spans.append((start, end))
    covered, right = 0, address
    for start, end in sorted(spans):
        covered += max(0, end - max(start, right))
        right = max(right, end)
    return dict(text_address=address, text_bytes=size, fde_ranges_intersecting_text=len(spans),
                covered_text_bytes=covered, covered_text_fraction=covered / size,
                minimum_required_fraction=MINIMUM_FDE_TEXT_FRACTION,
                qualified_for_one_dwarf_attempt=covered / size >= MINIMUM_FDE_TEXT_FRACTION,
                limitation="FDE byte coverage is a preflight, not proof of correct sample unwinding")


def prepare(args, output, commands, report):
    report['canary_prerequisite'] = capture.validate_canary(args.canary_report)
    source = capture.SOURCE
    observed, _ = commands.run(['git', 'rev-parse', '--verify', source + '^{commit}'], 'source-commit', cwd=args.repo)
    capture.require(observed.read_text().strip() == source, 'exact baseline commit unavailable')
    archive, _ = commands.run(['git', 'archive', '--format=tar', source], 'source-archive',
                              cwd=args.repo, cap=capture.LIMITS['source_bytes'])
    context = output / 'source'
    context.mkdir()
    report['source_archive'] = capture.unpack_source(archive, context)
    original = (context / 'Dockerfile').read_text()
    transformed = capture.diagnostic_dockerfile(original)
    (context / 'Dockerfile').write_text(transformed)
    (output / 'Dockerfile.original').write_text(original)
    (output / 'Dockerfile.diagnostic').write_text(transformed)
    (output / 'Dockerfile.diff').write_text(''.join(difflib.unified_diff(
        original.splitlines(True), transformed.splitlines(True), fromfile='original', tofile='diagnostic')))
    shim = context / '.mesh-profile'
    shim.mkdir()
    shutil.copyfile(capture.SHIM, shim / 'cc')
    source_hash = capture.sha256_file(context / 'src/main.rs')
    (shim / 'config.json').write_text(json.dumps(capture.shim_config('/build/src/main.rs', source_hash)))
    report['profile'] = capture.validate_profile((context / 'Cargo.toml').read_text())
    report['inputs'] = {name: capture.sha256_file(context / name)
                        for name in ('Dockerfile', 'Cargo.toml', 'Cargo.lock', 'build.rs', 'src/main.rs')}
    suffix = os.urandom(6).hex()
    runtime, builder = 'mesh-gap-profile-runtime:' + suffix, 'mesh-gap-profile-builder:' + suffix
    build = ['docker', 'build', '--platform', 'linux/amd64', '--progress', 'plain', '--build-arg',
             'CARGO_PROFILE=release', '--build-arg', 'FEATURES=cloud-secrets', '--label',
             'org.opencontainers.image.revision=' + source]
    commands.run(build + ['--target', 'runtime', '--tag', runtime, str(context)],
                 'representative-runtime-build', seconds=capture.LIMITS['build_seconds'], build=True)
    # Docker reuses the completed builder stage; this exports it without recompiling.
    commands.run(build + ['--target', 'builder', '--tag', builder, str(context)],
                 'representative-builder-export', seconds=300, build=True)
    report['runtime_image'] = capture.image_info(commands, runtime, 'runtime-image', source=True)
    report['builder_image'] = capture.image_info(commands, builder, 'builder-image')
    executable = output / 'runtime-ferrum-edge'
    capture.extract_binary(commands, report['runtime_image']['Id'], 'gap-runtime-' + suffix, executable)
    companion = output / 'capture'
    capture.extract_capture(commands, report['builder_image']['Id'], 'gap-symbols-' + suffix, companion)
    report['link_receipt'] = capture.read_capture(companion, source_hash)
    capture.require(capture.sha256_file(executable) == capture.sha256_file(companion / 'ferrum-edge/stripped'),
                    'runtime executable differs from captured original link')
    # qualify() checks code and allocated sections but intentionally excludes the
    # build-ID note. Require exact IDs separately for this own-image pair.
    report['own_pair'] = capture.qualify(executable, companion / 'ferrum-edge/symbols')
    capture.require(report['own_pair']['qualified'] and
                    report['own_pair']['shipping_build_id'] == report['own_pair']['diagnostic_build_id'],
                    'own-image executable/companion identity failed')
    elf = capture.Elf(companion / 'ferrum-edge/symbols')
    try:
        section = elf.sections.get('.text')
        capture.require(section is not None, 'missing .text')
        report['unwind_sections'] = {name: elf.sections[name][5]
                                    for name in ('.eh_frame', '.debug_frame', '.eh_frame_hdr') if name in elf.sections}
        frames, _ = commands.run(['readelf', '--debug-dump=frames', str(companion / 'ferrum-edge/symbols')],
                                  'unwind-frames', cap=64 * 1024**2, seconds=30)
        report['unwind_preflight'] = fde_coverage(frames.read_text(), section[3], section[5])
    finally:
        elf.close()
    report['qualified'] = True
    report['ready_for_dwarf_capture'] = report['unwind_preflight']['qualified_for_one_dwarf_attempt']
    report['next_action'] = ('one prespecified before/profile/after bracket on this image only'
                             if report['ready_for_dwarf_capture'] else
                             'stop; separately labeled frame-pointer diagnostic needs its own build and controls')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--canary-report', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    capture.require(os.environ.get('GITHUB_ACTIONS') == 'true' and platform.system() == 'Linux'
                    and platform.machine() == 'x86_64', 'remote GitHub Actions Linux x64 only')
    output = args.output.absolute()
    output.mkdir(mode=0o700, exist_ok=False)
    report = dict(schema=1, qualified=False, ready_for_dwarf_capture=False, source=capture.SOURCE,
                  scope='fresh representative release; own-image controls; no shipping attribution',
                  builder=capture.BUILDER, helpers=capture.helper_hashes(),
                  helper_sha256=capture.sha256_file(Path(__file__)), limits=capture.LIMITS,
                  runtime_flags_changed=False, shipping_attribution_allowed=False)
    commands = capture.Commands(output, report)
    def interrupted(signum, frame):
        raise RuntimeError('representative build interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    try:
        free = os.statvfs(output)
        capture.require(free.f_bavail * free.f_frsize >= capture.LIMITS['minimum_free_bytes'], 'build disk reserve')
        prepare(args, output, commands, report)
    except Exception as error:
        report.update(qualified=False, ready_for_dwarf_capture=False,
                      failure=dict(type=type(error).__name__, reason=str(error)[:1000]))
    finally:
        report['elapsed_seconds'] = time.monotonic() - commands.started
        (output / 'report.json').write_text(json.dumps(report, indent=2, allow_nan=False) + '\n')
    print(json.dumps({key: report.get(key) for key in ('qualified', 'ready_for_dwarf_capture', 'next_action', 'failure')}))
    return 0 if report['qualified'] and report['ready_for_dwarf_capture'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
