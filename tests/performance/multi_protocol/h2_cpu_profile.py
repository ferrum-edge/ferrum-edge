"""Fixed HTTP/2 and gRPC CPU campaign metadata; capture uses the H1 supervisor.

Only the workload admission differs. PID-generation, clock, collector lifetime,
software-event validation and bounded ELF retention are shared with H1.
"""
import argparse
import collections
import hashlib
import json
import math
import os
import re
import shutil
import statistics
import struct
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
FIXTURES = {
    ('http2', 'ferrum'): 'http2_perf.yaml',
    ('grpcs', 'ferrum'): 'grpcs_e2e_perf.yaml',
    ('http2', 'envoy'): 'envoy/http2_tls.yaml',
    ('grpcs', 'envoy'): 'envoy/grpcs.yaml',
}
ENVIRONMENT = ('FERRUM_MODE', 'FERRUM_PROXY_HTTPS_PORT',
               'FERRUM_RESPONSE_BUFFER_CUTOFF_BYTES', 'FERRUM_POOL_HTTP2_ADAPTIVE_WINDOW',
               'FERRUM_POOL_HTTP2_INITIAL_STREAM_WINDOW_SIZE',
               'FERRUM_POOL_HTTP2_INITIAL_CONNECTION_WINDOW_SIZE')


# Envoy's release image ships a stripped executable, so its CPU stacks resolve
# almost no functions. The debug image of the same release carries the same
# link output (identical GNU build ID) with .symtab. Captures still measure the
# pinned release binary; only the offline decoder reads this symbol twin. The
# layer is content-addressed and the workflow fetches it by this digest.
ENVOY_EXECUTABLE = '/usr/local/bin/envoy'
ENVOY_SYMBOLS = dict(
    release_image='envoyproxy/envoy:v1.39.1',
    release_sha256='002c6e1c69ed0fa0ea381887247cadadfaec9481375fa8d8d2b1731eeabf40b8',
    image='envoyproxy/envoy:debug-v1.39.1',
    layer='sha256:abf36d5364d09e89c2a086c4a2362a60729c0356c299cf98a87dc6ee01b3a00e',
    member='usr/local/bin/envoy',
    sha256='171445f45fc3bd6f9e7ba5c308399c1da35645efecdac6bd208feaffefd9ee04',
    bytes=881314688,
    build_id='b579d07d3ad7ee11d32b105e91a5a39ad24718d7')
# Offline decoding of an 881 MB symbol table needs wider, still finite, bounds
# than the live 30-second decoder; the output cap stays within the raw cap.
ENVOY_DECODE_SECONDS = 600
ENVOY_DECODE_BYTES = 64 * 1024**2


def fixture(protocol, gateway):
    text = (HERE / 'configs' / FIXTURES[protocol, gateway]).read_text()
    prefix = '/etc/ferrum/tls' if gateway == 'ferrum' else '/certs'
    for token, filename in [('CERT_PATH', 'cert.pem'), ('KEY_PATH', 'key.pem'), ('CA_PATH', 'ca.pem')]:
        text = text.replace(token, prefix + '/' + filename)
    return text.encode()


def validate_runtime(binding, runtime, config, protocol):
    gateway = binding['arm']
    if (gateway not in ('ferrum', 'envoy') or runtime.get('gateway') != gateway
            or runtime.get('protocol') != protocol or runtime.get('pair') != binding['pair']
            or runtime.get('network_mode') != 'host' or runtime.get('running') is not True
            or not re.fullmatch(r'sha256:[0-9a-f]{64}', runtime.get('image_id', ''))):
        raise ValueError('H2 profile runtime/workload identity mismatch')
    if config != fixture(protocol, gateway) or hashlib.sha256(config).hexdigest() != runtime['config_sha256']:
        raise ValueError('effective config does not match the fixed H2/gRPC fixture')
    if gateway == 'ferrum':
        expected = dict(zip(ENVIRONMENT, ('file', '8443', '0', 'false', '8388608', '33554432')))
        if runtime.get('environment') != expected:
            raise ValueError('H2 profile Ferrum environment mismatch')
    if runtime.get('user') != '65532:65532' or runtime.get('cap_drop') != ['ALL']:
        raise ValueError('CPU campaign requires an ordinary UID and dropped capabilities')


def retain_runtime(args, container):
    # Keep only fixed configuration and identity; raw inspect can contain secrets.
    pid = container['State']['Pid']
    if type(pid) is not int or pid <= 0:
        raise ValueError('running container PID missing')
    from process_usage import parse_stat
    stat = parse_stat(Path(f'/proc/{pid}/stat').read_text(), 100, 4096)
    environment = dict(entry.split('=', 1) for entry in container['Config'].get('Env', []))
    config = Path(args.config).read_bytes()
    result = dict(container_id=container['Id'], image_id=container['Image'], host_pid=pid,
                  start_ticks=stat['start_ticks'], started_at=container['State']['StartedAt'],
                  running=container['State']['Running'], network_mode=container['HostConfig']['NetworkMode'],
                  user=container['Config']['User'], cap_drop=container['HostConfig']['CapDrop'],
                  gateway=args.gateway, protocol=args.protocol, pair=args.pair,
                  config_sha256=hashlib.sha256(config).hexdigest(),
                  environment={key: environment.get(key) for key in ENVIRONMENT} if args.gateway == 'ferrum' else {})
    validate_runtime(dict(arm=args.gateway, pair=args.pair), result, config, args.protocol)
    Path(args.output).write_text(json.dumps(result, indent=2) + '\n')


def stamp(path, mode):
    path = Path(path)
    sample = json.loads(path.read_text())
    sample['h2_cpu_profile'] = dict(mode=mode, diagnostic_only=True,
        user_stacks_only=mode == 'cpu', scheduler_counters=mode != 'off')
    path.write_text(json.dumps(sample, indent=2) + '\n')


def nonnegative(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def positive(value):
    return nonnegative(value) and value > 0


def report(root):
    from benchmark_validity import sample_issues
    root = Path(root)
    result = dict(schema=1, diagnostic_only=True, complete=False, issues=[], observations=[], calibration=[])
    indexed = {}
    for campaign, mode in (('control-before', 'off'), ('counters', 'counters'),
                           ('cpu', 'cpu'), ('control-after', 'off')):
        for pair in (1, 2):
            folder = root / campaign / 'pairs' / f'pair_{pair:03d}'
            for gateway in ('direct', 'ferrum', 'envoy'):
                paths = list(folder.glob(f'{gateway}_*.json'))
                row = dict(campaign=campaign, pair=pair, gateway=gateway, issues=[])
                result['observations'].append(row)
                if len(paths) != 1:
                    row['issues'].append('missing or ambiguous sample')
                    continue
                try:
                    sample = json.loads(paths[0].read_text())
                    if not isinstance(sample, dict):
                        raise ValueError('sample must be an object')
                except (OSError, ValueError):
                    row['issues'].append('unreadable or malformed sample')
                    continue
                marker = sample.pop('h2_cpu_profile', {})
                if (not isinstance(marker, dict) or marker.get('mode') != mode
                        or marker.get('diagnostic_only') is not True
                        or marker.get('user_stacks_only') is not (mode == 'cpu')
                        or marker.get('scheduler_counters') is not (mode != 'off')):
                    row['issues'].append('missing/mismatched diagnostic marker')
                # The client serializes display labels; runtime and capture
                # bindings use the command-line protocol names.
                protocol = ({'HTTP/2': 'http2', 'gRPC': 'grpcs'}.get(sample.get('protocol'))
                            if isinstance(sample.get('protocol'), str) else None)
                if (sample.get('gateway') != gateway or sample.get('pair') != pair
                        or sample.get('sample_schema') != 2
                        or protocol is None
                        or sample.get('payload_size') not in (10240, 71680)
                        or sample.get('duration_secs') != 15
                        or sample.get('effective_concurrency') != 200):
                    row['issues'].append('sample does not match fixed campaign identity')
                # Diagnostic exclusion is for scoreboards. All underlying
                # traffic, error and completeness rules still apply here.
                try:
                    row['issues'].extend(sample_issues(sample))
                except (TypeError, ValueError, KeyError, AttributeError):
                    row['issues'].append('malformed benchmark evidence')
                row.update(rps=sample.get('rps'), payload=sample.get('payload_size'),
                           protocol=protocol, host_id=sample.get('host_id'))
                usage = sample.get('process_usage')
                usage = usage.get('measurement') if isinstance(usage, dict) else None
                row['usage'] = usage if isinstance(usage, list) else []
                expected_roles = {'backend', 'client'} | ({'gateway'} if gateway != 'direct' else set())
                roles = [p.get('role') for p in row['usage']
                         if isinstance(p, dict) and isinstance(p.get('role'), str)]
                if len(row['usage']) != len(expected_roles) or set(roles) != expected_roles:
                    row['issues'].append('missing/ambiguous process CPU roles')
                for process in row['usage']:
                    if not isinstance(process, dict):
                        row['issues'].append('malformed process CPU record')
                        continue
                    if (process.get('complete_bracket') is not True
                            or not positive(process.get('bracket_secs'))
                            or not all(nonnegative(process.get(key))
                                       for key in ('user_cpu_seconds', 'system_cpu_seconds'))):
                        row['issues'].append('incomplete user/kernel CPU bracket')
                    if mode != 'off':
                        counters = process if process.get('role') == 'client' else process.get('context_switches')
                        if (not isinstance(counters, dict)
                                or not all(type(counters.get(key)) is int and counters[key] >= 0
                                           for key in ('voluntary_ctxt_switches', 'nonvoluntary_ctxt_switches'))
                                or (process.get('role') != 'client'
                                    and counters.get('scope') != 'all process threads')):
                            row['issues'].append('incomplete all-thread scheduler bracket')
                if gateway != 'direct':
                    try:
                        runtime = json.loads((folder / 'diagnostics' / f'{gateway}_runtime.json').read_text())
                        config = (folder / 'diagnostics' / f'{gateway}_config.yaml').read_bytes()
                        validate_runtime(dict(arm=gateway, pair=pair), runtime, config, row['protocol'])
                        row['image_id'] = runtime['image_id']
                        row['config_sha256'] = runtime['config_sha256']
                    except (OSError, ValueError, KeyError, TypeError, AttributeError):
                        row['issues'].append('missing/mismatched retained gateway runtime')
                if mode == 'cpu' and gateway != 'direct':
                    trace = folder / 'traces' / f"{gateway}_{row['payload']}" / 'trace-manifest.json'
                    try:
                        capture = json.loads(trace.read_text())
                        if not isinstance(capture, dict):
                            raise ValueError('capture must be an object')
                        row['cpu'] = capture.get('cpu', {})
                        if (capture.get('mode') != 'cpu' or not isinstance(row['cpu'], dict)
                                or not positive(row['cpu'].get('samples'))):
                            row['issues'].append('missing CPU samples or wrong collector mode')
                        row['capture_complete'] = capture.get('capture_complete') is True
                        binding = capture.get('binding') or {}
                        if (not isinstance(binding, dict) or binding.get('arm') != gateway
                                or binding.get('pair') != pair or binding.get('payload') != row['payload']
                                or binding.get('h2_protocol') != row['protocol']):
                            row['issues'].append('CPU capture binding mismatch')
                        if not row['capture_complete']:
                            row['issues'].append('incomplete CPU capture')
                    except (OSError, ValueError):
                        row['issues'].append('missing CPU capture')
                indexed[campaign, pair, gateway] = row
    identities = {tuple(r.get(key) if type(r.get(key)) is kind else None
                        for key, kind in (('host_id', str), ('protocol', str), ('payload', int)))
                  for r in result['observations'] if 'rps' in r}
    if len(identities) != 1 or any(None in identity for identity in identities):
        result['issues'].append('mixed/missing host or workload identity')
    for gateway in ('ferrum', 'envoy'):
        runtimes = {(r.get('image_id'), r.get('config_sha256'))
                    for r in result['observations'] if r['gateway'] == gateway}
        if len(runtimes) != 1 or any(None in identity for identity in runtimes):
            result['issues'].append('mixed/missing runtime identity: ' + gateway)
    for gateway in ('direct', 'ferrum', 'envoy'):
        for campaign in ('counters', 'cpu'):
            values = []
            for pair in (1, 2):
                rows = [indexed.get((name, pair, gateway))
                        for name in ('control-before', campaign, 'control-after')]
                if any(row is None or row['issues'] or not row.get('rps') for row in rows):
                    continue
                before, observed, after = rows
                values.append(dict(pair=pair,
                    rps_overhead_percent=100 * (observed['rps'] / ((before['rps'] + after['rps']) / 2) - 1),
                    control_drift_percent=100 * (after['rps'] / before['rps'] - 1)))
            result['calibration'].append(dict(gateway=gateway, campaign=campaign, pairs=values,
                comparable=not result['issues'] and len(values) == 2 and all(abs(v['control_drift_percent']) <= 5 for v in values),
                median_rps_overhead_percent=statistics.median(v['rps_overhead_percent'] for v in values) if values else None))
    result['complete'] = not result['issues'] and all(not row['issues'] for row in result['observations'])
    # Offline Envoy symbols add names to retained stacks; they never change
    # capture completeness or calibration.
    try:
        symbols = json.loads((root / 'envoy-symbols.json').read_text())
        result['envoy_symbols'] = (symbols if isinstance(symbols, dict) else
                                   dict(complete=False, issues=['malformed Envoy symbolization']))
    except FileNotFoundError:
        result['envoy_symbols'] = dict(complete=False, issues=['Envoy symbolization not run'])
    except (OSError, ValueError):
        result['envoy_symbols'] = dict(complete=False, issues=['unreadable Envoy symbolization'])
    result['limits'] = ['Shared-runner calibration; two pairs are diagnostic, not a throughput claim.',
                        'User stacks only; kernel cost comes from process CPU counters.',
                        'Symbolized physical DWARF frames only; inline source frames are not expanded.',
                        'Unresolved/optimized-away/async frames remain explicit in CPU coverage.',
                        'Thread churn makes scheduler deltas unavailable instead of zero.',
                        'Envoy names come from an offline build-ID-matched debug twin of the measured stripped binary.']
    (root / 'h2-cpu-report.json').write_text(json.dumps(result, indent=2) + '\n')
    return 0 if result['complete'] else 1


def elf_identity(path):
    """GNU build ID and .symtab presence of a little-endian ELF64 file."""
    try:
        return _elf_identity(path)
    except (struct.error, OverflowError) as error:
        raise ValueError('malformed ELF64 tables or notes') from error


def _read_range(stream, size, offset, length):
    if offset + length > size:
        raise ValueError('ELF range beyond end of file')
    stream.seek(offset)
    return stream.read(length)


def _elf_identity(path):
    with open(path, 'rb') as stream:
        size = os.fstat(stream.fileno()).st_size
        header = stream.read(64)
        if len(header) != 64 or header[:4] != b'\x7fELF' or header[4:6] != b'\x02\x01':
            raise ValueError('not a little-endian ELF64 file')
        phoff, shoff = struct.unpack_from('<QQ', header, 0x20)
        phentsize, phnum, shentsize, shnum = struct.unpack_from('<HHHH', header, 0x36)
        if phentsize != 56 or (shnum and shentsize != 64):
            raise ValueError('unexpected ELF64 header table entry size')
        build_ids = []
        headers = _read_range(stream, size, phoff, phentsize * phnum)
        for index in range(phnum):
            kind, _, offset, _, _, note_size, _, align = struct.unpack_from('<IIQQQQQQ', headers, index * phentsize)
            if kind != 4:
                continue
            if note_size > 1024**2:
                raise ValueError('oversize ELF note segment')
            align = 8 if align == 8 else 4
            notes, cursor = _read_range(stream, size, offset, note_size), 0
            while cursor + 12 <= len(notes):
                name_size, desc_size, note_type = struct.unpack_from('<III', notes, cursor)
                name = notes[cursor + 12:cursor + 12 + name_size]
                # The descriptor follows the header plus name, aligned together.
                desc = cursor + -(-(12 + name_size) // align) * align
                if desc + desc_size > len(notes):
                    raise ValueError('truncated ELF note')
                if note_type == 3 and name == b'GNU\0':
                    build_ids.append(notes[desc:desc + desc_size].hex())
                cursor = desc + -(-desc_size // align) * align
        sections = _read_range(stream, size, shoff, shentsize * shnum)
        symtab = False
        for index in range(shnum):
            kind, = struct.unpack_from('<I', sections, index * shentsize + 4)
            offset, length = struct.unpack_from('<QQ', sections, index * shentsize + 24)
            if kind == 2 and length > 0:
                if offset + length > size:
                    raise ValueError('.symtab beyond end of file')
                symtab = True
    if len(set(build_ids)) != 1:
        raise ValueError('ELF must carry exactly one GNU build ID')
    return dict(build_id=build_ids[0], symtab=symtab)


def file_sha256(path):
    with open(path, 'rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def known_leaf(sample):
    frames = sample['frames']
    return bool(frames) and frames[0]['symbol'] not in ('[unknown]', '0x0') and frames[0]['dso'] != '[unknown]'


def leaf_summary(chains, window, *, top=0):
    """Measurement-window leaf coverage of admitted samples."""
    from h1_trace_contract import cpu_phases
    inside = [s for s in chains if cpu_phases([s], window)['samples'].get('measurement')]
    known = [s for s in inside if known_leaf(s)]
    executable = [s for s in inside if s['frames'] and s['frames'][0]['dso'] == ENVOY_EXECUTABLE]
    result = dict(window_samples=len(inside), known_leaf_samples=len(known),
                  known_leaf_fraction=len(known) / len(inside) if inside else None,
                  executable_leaf_samples=len(executable),
                  executable_known_leaf_samples=sum(known_leaf(s) for s in executable),
                  leaf_dsos=dict(collections.Counter(s['frames'][0]['dso'] if s['frames'] else '[none]'
                                                     for s in inside)))
    if top:
        leaves = collections.Counter((re.sub(r'\+0x[0-9a-fA-F]+$', '', s['frames'][0]['symbol']),
                                      s['frames'][0]['dso']) for s in known)
        result['top_leaves'] = [dict(symbol=name, dso=dso, samples=count, fraction=count / len(inside))
                                for (name, dso), count in leaves.most_common(top)]
    return result


def retained_bytes(folder, manifest, name, limit):
    """A capture file, only as its manifest receipt recorded it."""
    receipt = manifest['artifacts'][name]
    path = folder / name
    if path.is_symlink() or not path.is_file() or path.stat().st_size != receipt['bytes'] or receipt['bytes'] > limit:
        raise ValueError(f'retained {name} does not match its manifest receipt size or bound')
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != receipt['sha256']:
        raise ValueError(f'retained {name} does not match its manifest receipt hash')
    return data


def symbolize_capture(root, manifest_path, debug_elf, scratch, pins, decode):
    from h1_trace_contract import BOUNDS, decode_cpu
    folder = manifest_path.parent
    relative = folder.relative_to(root)
    row = dict(path=str(relative), issues=[])
    destination = folder / 'envoy-symbols'
    if destination.exists():
        raise ValueError('capture already has Envoy symbols; symbolize a fresh evidence copy')
    manifest = json.loads(manifest_path.read_text())
    if not isinstance(manifest.get('symbol_package'), str) or not manifest['symbol_package'].endswith('/builds/envoy/symfs'):
        raise ValueError('capture does not use the retained Envoy symbol package')
    if manifest['cpu']['decoder_status'].get('incomplete'):
        raise ValueError('original decode was incomplete, so its samples cannot anchor equivalence')
    pid = manifest['identity']['pid']
    mappings = json.loads(retained_bytes(folder, manifest, 'build-mappings.json', 16 * 1024**2))
    stripped = retained_bytes(folder, manifest, 'stacks.txt', BOUNDS['raw_perf_bytes']).decode(errors='replace')
    buildids = retained_bytes(folder, manifest, 'perf-buildids.txt', 2 * 1024**2).decode(errors='replace')
    executables = [d for d in mappings.get('dsos', []) if d.get('path') == ENVOY_EXECUTABLE]
    if (len(executables) != 1 or executables[0].get('sha256') != pins['release_sha256']
            or not any(line.lower().endswith(pins['build_id']) for line in executables[0].get('build_id_lines', []))):
        raise ValueError('mapped Envoy executable is not the pinned release build')
    recorded = {}
    for line in buildids.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2:
            recorded[parts[1].strip()] = parts[0].lower()
    if recorded.get(ENVOY_EXECUTABLE) != pins['build_id']:
        raise ValueError('recorded Envoy build ID does not match the symbol twin')
    # Overlay of the retained package: every mapped DSO is the verified
    # retained copy, except the release executable, whose build-ID twin
    # supplies .symtab. The equivalence checks below hold perf to that.
    package = (root / 'builds' / 'envoy' / 'symfs').resolve()
    out = scratch / relative
    overlay = out / 'symfs'
    overlay.mkdir(parents=True)
    for dso in mappings['dsos']:
        retained = (package / dso['path'].lstrip('/')).resolve()
        if not retained.is_relative_to(package) or file_sha256(retained) != dso['sha256']:
            raise ValueError('retained DSO does not match its acquisition record: ' + dso['path'])
        target = overlay / dso['path'].lstrip('/')
        target.parent.mkdir(parents=True, exist_ok=True)
        target.symlink_to(debug_elf if dso['path'] == ENVOY_EXECUTABLE else retained)
    (out / 'perf.data').write_bytes(retained_bytes(folder, manifest, 'perf.data', BOUNDS['raw_perf_bytes']))
    decoded = decode(out, {pid}, mappings, symfs=overlay)
    original = decode_cpu(stripped, '', {pid})
    # Same raw samples and the same unwound PCs: only names may differ. The
    # twin's extra sections must not change what the folded stacks attribute.
    def leaves(chains):
        return [(s['pid'], s['tid'], s['time_secs'], s['frames'][0]['ip'] if s['frames'] else None) for s in chains]
    def stacks(chains):
        return [[f['ip'] for f in s['frames']] for s in chains]
    if leaves(decoded['callchains']) != leaves(original['callchains']):
        row['issues'].append('symbolized samples or leaf PCs differ from the original decode')
    elif stacks(decoded['callchains']) != stacks(original['callchains']):
        row['issues'].append('symbolized caller PCs differ from the original decode')
    blocking = [i for i in decoded['issues'] if i not in (
        'missing matching ELF/build IDs/CFI', 'partial unwinding/unresolved samples')]
    row['issues'].extend('decoder: ' + issue for issue in blocking)
    window = manifest['boundaries']['measurement']
    before = leaf_summary(original['callchains'], window)
    after = leaf_summary(decoded['callchains'], window, top=40)
    # A decode that silently ignored the twin would reproduce the stripped names.
    if (before['executable_known_leaf_samples'] < before['executable_leaf_samples']
            and after['executable_known_leaf_samples'] <= before['executable_known_leaf_samples']):
        row['issues'].append('debug twin resolved no additional Envoy executable leaves')
    row.update(pair=manifest.get('binding', {}).get('pair'), samples=decoded['samples'],
               decoder_issues=decoded['issues'], inline_expansion=decoded.get('inline_expansion'),
               decoder_status=decoded.get('decoder_status'), stripped=before, symbolized=after)
    # Assemble beside the capture and publish whole, never a partial directory.
    partial = folder / '.envoy-symbols.partial'
    partial.mkdir()
    for name in ('cpu-coverage.json', 'stacks.folded', 'stacks.txt.stderr', 'stacks.txt.status.json'):
        if (out / name).is_file():
            shutil.copyfile(out / name, partial / name)
    (partial / 'summary.json').write_text(json.dumps(row, indent=2) + '\n')
    partial.rename(destination)
    return row


def symbolize_envoy(root, debug_elf, scratch, *, pins=ENVOY_SYMBOLS, decode=None):
    """Re-decode each retained Envoy CPU capture against the debug twin."""
    root, scratch, debug_elf = Path(root).resolve(), Path(scratch), Path(debug_elf).resolve()
    if decode is None:
        from h1_trace import cpu_decode
        def decode(out, owners, dsos, *, symfs):
            return cpu_decode(out, owners, dsos, symfs=symfs,
                              script_timeout=ENVOY_DECODE_SECONDS, script_limit=ENVOY_DECODE_BYTES)
    result = dict(schema=1, diagnostic_only=True, complete=False, source=dict(pins), captures=[], issues=[])
    try:
        if debug_elf.stat().st_size != pins['bytes'] or file_sha256(debug_elf) != pins['sha256']:
            raise ValueError('debug executable does not match the pinned image layer member')
        identity = elf_identity(debug_elf)
        if identity != dict(build_id=pins['build_id'], symtab=True):
            raise ValueError('debug executable lacks the pinned build ID or .symtab')
    except (OSError, ValueError) as error:
        result['issues'].append(f'{type(error).__name__}: {error}')
    else:
        manifests = sorted((root / 'cpu' / 'pairs').glob('pair_*/traces/envoy_*/trace-manifest.json'))
        if not manifests:
            result['issues'].append('no retained Envoy CPU captures')
        for path in manifests:
            try:
                result['captures'].append(symbolize_capture(root, path, debug_elf, scratch, pins, decode))
            except (OSError, ValueError, KeyError, TypeError, AttributeError, RuntimeError,
                    subprocess.TimeoutExpired) as error:
                # A decoder that outlives its reap bound must not lose the record.
                result['captures'].append(dict(path=str(path.parent.relative_to(root)),
                                               issues=[f'{type(error).__name__}: {error}']))
    result['complete'] = (not result['issues'] and bool(result['captures'])
                          and all(not row['issues'] for row in result['captures']))
    (root / 'envoy-symbols.json').write_text(json.dumps(result, indent=2) + '\n')
    return 0 if result['complete'] else 1


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest='action', required=True)
    runtime = sub.add_parser('runtime')
    runtime.add_argument('--protocol', choices=('http2', 'grpcs'), required=True)
    runtime.add_argument('--gateway', choices=('ferrum', 'envoy'), required=True)
    runtime.add_argument('--pair', type=int, required=True)
    runtime.add_argument('--config', required=True)
    runtime.add_argument('--output', required=True)
    mark = sub.add_parser('stamp')
    mark.add_argument('path')
    mark.add_argument('mode', choices=('off', 'counters', 'cpu'))
    summary = sub.add_parser('report')
    summary.add_argument('root')
    symbols = sub.add_parser('symbolize-envoy')
    symbols.add_argument('root')
    symbols.add_argument('--debug-elf', required=True)
    symbols.add_argument('--scratch', required=True)
    args = parser.parse_args()
    if args.action == 'runtime':
        retain_runtime(args, json.load(sys.stdin))
    elif args.action == 'stamp':
        stamp(args.path, args.mode)
    elif args.action == 'symbolize-envoy':
        return symbolize_envoy(args.root, args.debug_elf, args.scratch)
    else:
        return report(args.root)
    return 0


if __name__ == '__main__':
    sys.exit(main())
