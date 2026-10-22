#!/usr/bin/env python3
"""Remote-only bounded DWARF observer, reusing the reviewed leaf collector.

Use this executable in place of collect_resources.py in a disposable diagnostic
harness only; all ordinary collector arguments remain the same. The parent
campaign must use the same representative image in before/profile/after cells,
unchanged 5% goodput/CPU controls, and BENCH_PERF_LEAF only in the middle cell.
Export explicit derived *.json/*.jsonl/*.txt receipts; NEVER export perf.data,
ELF caches, or a recursive capture directory. Private raw stack/register data is
deleted in finally; derived records retain ALL samples, including outside-window,
foreign, unknown, malformed, and capped observations. No logical task/wake counts
or cross-task inclusive request CPU are claimed by synchronous callchains.
"""
from __future__ import annotations

from collections import Counter
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import sys

ROOT = Path(__file__).resolve().parents[2]
RUNTIME = ROOT / 'tests/performance/mesh_runtime'
sys.path.insert(0, str(RUNTIME))
import production_perf as base

ORIGINAL_ARGV = base.record_argv
ORIGINAL_ATTRIBUTES = base.validate_attributes
STACK_BYTES = 8192
MAX_FRAMES = 128
ROOT_FRAME = re.compile(r'(?:tokio::runtime::scheduler::multi_thread::worker::run|'
                        r'std::sys::pal::unix::thread::Thread::new|__libc_start_main|'
                        r'(?:^|::)clone3?(?:$|\+)|(?:^|::)start_thread(?:$|\+))')


def record_argv(perf, pid, directory):
    return ORIGINAL_ARGV(perf, pid, directory) + ['--call-graph', f'dwarf,{STACK_BYTES}']


def validate_attributes(text):
    # Keep all inherited event, frequency, inheritance and clock checks. Only
    # this explicit observer may request bounded user stack/register records.
    def leaf_bits(match):
        return 'sample_type: ' + '|'.join(bit for bit in match[1].split('|')
                                          if bit not in ('CALLCHAIN', 'STACK_USER', 'REGS_USER'))
    errors = ORIGINAL_ATTRIBUTES(re.sub(r'sample_type\s*:\s*([A-Z_|]+)', leaf_bits, text))
    primary = [line for line in text.splitlines() if line.strip().startswith('cpu-clock:u:')]
    if len(primary) != 1:
        return errors + ['missing unique DWARF sampling event']
    sample = re.search(r'sample_type\s*:\s*([A-Z_|]+)', primary[0])
    if not sample or not {'CALLCHAIN', 'STACK_USER', 'REGS_USER'} <= set(sample[1].split('|')):
        errors.append('missing DWARF callchain/user-stack/register sample fields')
    stack = re.search(r'\bsample_stack_user\s*:\s*(\d+)', primary[0])
    if not stack or int(stack[1]) != STACK_BYTES:
        errors.append('DWARF user stack size differs from prespecified 8192 bytes')
    for line in text.splitlines():
        if line.strip().startswith('dummy:u:') and re.search(r'\b(?:CALLCHAIN|STACK_USER|REGS_USER)\b', line):
            errors.append('metadata dummy requested stack/register fields')
    return errors


def parse_callchains(text, pid, begin, end, retained_paths):
    if not all(type(value) in (int, float) and math.isfinite(value) for value in (begin, end)) or not begin < end:
        raise ValueError('invalid finite measurement bracket')
    aliases = {}
    for path in retained_paths:
        aliases.setdefault(Path(path).name, set()).add(path)
    events, current, malformed = [], None, 0
    for line in text.splitlines():
        header = base.HEADER.match(line)
        if header:
            if current is not None:
                events.append(current)
            current = dict(pid=int(header[2]), tid=int(header[3]), monotonic=float(header[4]),
                           event=header[5], frames=[], raw_lines=[line], header_leaf_pending=bool(header[6]))
            payload = header[6]
        elif not line.strip():
            continue
        elif current is not None:
            current['raw_lines'].append(line)
            payload = line.strip()
        else:
            malformed += 1
            continue
        if not payload:
            continue
        leaf = base.LEAF.fullmatch(payload)
        if not leaf:
            malformed += 1
            current['malformed_frame_lines'] = current.get('malformed_frame_lines', 0) + 1
            continue
        ip, original, displayed = leaf.groups()
        candidates = {displayed} if displayed in retained_paths else aliases.get(Path(displayed).name, set())
        known = (len(candidates) == 1 and int(ip, 16) != 0
                 and original not in ('[unknown]', '[unknown]!', '0x0')
                 and re.fullmatch(r'(?:0x)?[0-9a-fA-F]+', original) is None)
        frame = dict(ip=ip, symbol=re.sub(r'\+0x[0-9a-fA-F]+$', '', original) if known else 'UNKNOWN',
                     dso=next(iter(candidates)) if known else 'UNKNOWN', known=known)
        # perf versions can put the leaf both on the header and first stack line.
        duplicate_header = (header is None and current.pop('header_leaf_pending', False)
                            and current['frames'] and current['frames'][0] == frame)
        if not duplicate_header:
            current['frames'].append(frame)
    if current is not None:
        events.append(current)
    counts, inclusive, lengths = Counter(), Counter(), Counter()
    window, raw_lines = [], []
    known_frames = all_frames = rooted = capped = unknown_leaf = 0
    for event in events:
        frames = event['frames']
        event.pop('header_leaf_pending', None)
        event.update(in_measurement_window=begin <= event['monotonic'] <= end,
                     foreign_pid=event['pid'] != pid, unexpected_event=base.CPU_EVENT.fullmatch(event['event']) is None,
                     stack_depth=len(frames), stack_at_decode_cap=len(frames) >= MAX_FRAMES,
                     reaches_thread_or_runtime_root=any(ROOT_FRAME.search(frame['symbol']) for frame in frames))
        if not event['in_measurement_window']:
            continue
        raw_lines.extend(event['raw_lines'])
        leaf = frames[0] if frames else dict(ip=None, symbol='UNKNOWN', dso='UNKNOWN', known=False)
        known = leaf['known'] and not event['foreign_pid'] and not event['unexpected_event']
        event.update(ip=leaf['ip'], symbol=leaf['symbol'] if known else 'UNKNOWN',
                     dso=leaf['dso'] if known else 'UNKNOWN', known=known)
        window.append(event)
        unknown_leaf += not known
        counts[(event['dso'], event['symbol'])] += 1
        lengths[len(frames)] += 1
        capped += event['stack_at_decode_cap']
        all_frames += len(frames)
        known_frames += sum(frame['known'] for frame in frames)
        rooted += len(frames) >= 4 and event['reaches_thread_or_runtime_root'] and not event['stack_at_decode_cap']
        for key in {(frame['dso'], frame['symbol']) for frame in frames}:
            inclusive[key] += 1  # one hit/sample even for recursion; rows overlap.
    total = len(window)
    def table(counter):
        return [dict(dso=dso, symbol=symbol, samples=count, fraction_all_measurement_samples=count / total if total else 0)
                for (dso, symbol), count in counter.most_common()]
    return dict(all_capture_sample_count=len(events), measurement_sample_count=total,
                outside_window_samples=sum(not event['in_measurement_window'] for event in events),
                foreign_pid_samples=sum(event['foreign_pid'] for event in events),
                unexpected_event_samples=sum(event['unexpected_event'] for event in events),
                dummy_event_samples=sum(event['event'] == 'dummy:u' for event in events), malformed_samples=malformed,
                unknown_leaves=unknown_leaf, known_leaves=total - unknown_leaf,
                known_leaf_fraction=(total - unknown_leaf) / total if total else 0,
                all_measurement_frames=all_frames, known_measurement_frames=known_frames,
                known_frame_fraction=known_frames / all_frames if all_frames else 0,
                rooted_stacks=rooted, rooted_stack_fraction=rooted / total if total else 0,
                stacks_at_decode_cap=capped, stack_depth_histogram=dict(sorted(lengths.items())),
                functions=table(counts), inclusive_functions=table(inclusive),
                inclusive_semantics='synchronous sampled stack only; overlapping rows; no async causality or wake counts',
                events=window, all_derived_events=events, raw_window_lines=raw_lines)


class DwarfCapture(base.PerfCapture):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.report.update(schema_version=2, scope=__doc__, callgraph='dwarf', user_stack_bytes=STACK_BYTES,
                           maximum_decoded_frames=MAX_FRAMES, minimum_rooted_stack_fraction=0.80,
                           raw_retention='private transient only; all derived samples retained before deletion')
        ACTIVE.append(self)

    def publish_artifacts(self):
        # Keep the whole capture private. The campaign exports explicit derived
        # files after checking raw deletion receipts, never this directory tree.
        return

    def command(self, role, name, arguments, **kwargs):
        if name == 'leaf-events-all.txt':
            arguments = [*arguments, '--max-stack', str(MAX_FRAMES + 1)]
        return super().command(role, name, arguments, **kwargs)

    def decode(self, begin, end):
        def parse(text, pid, start, finish, mappings):
            result = parse_callchains(text, pid, start, finish, mappings)
            role = next(role for role in self.roles if role['container']['pid'] == pid)
            with (role['directory'] / 'callchain-events-all.jsonl').open('w') as output:
                for event in result.pop('all_derived_events'):
                    event.pop('raw_lines', None)
                    output.write(json.dumps(event, allow_nan=False) + '\n')
            return result
        base.parse_leaves = parse
        result = super().decode(begin, end)
        for role in self.roles:
            report = role['report']
            if (report.get('rooted_stack_fraction', 0) < 0.80 or report.get('known_frame_fraction', 0) < 0.80
                    or report.get('stacks_at_decode_cap', 0)):
                report['errors'].append('inclusive stack coverage failed: require 80% rooted/known frames and zero capped stacks')
            report['valid'] = not report['errors']
        result['valid'] = len(self.roles) == 2 and not result['errors'] and all(role['report']['valid'] for role in self.roles)
        self.persist()
        return result

    def delete_private_raw(self):
        for role in self.roles:
            path = role['directory'] / 'perf.data'
            if not path.exists():
                continue
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid():
                raise ValueError('refusing raw cleanup of an unowned, linked or nonregular file')
            role['report']['raw_trace_cleanup'] = dict(bytes=info.st_size, sha256=base.sha256(path),
                derived_all_sample_count=role['report'].get('all_capture_sample_count'), raw_deleted=False)
            path.unlink()
            role['report']['raw_trace_cleanup']['raw_deleted'] = not path.exists()
        self.persist()


ACTIVE = []


def split_cpu_snapshot(pid, proc=Path('/proc')):
    fields = (proc / str(pid) / 'stat').read_text().rsplit(')', 1)[1].split()
    return dict(pid=pid, starttime=int(fields[19]), cpu_ticks=int(fields[11]) + int(fields[12]),
                user_cpu_ticks=int(fields[11]), system_cpu_ticks=int(fields[12]),
                rss_bytes=int(fields[21]) * os.sysconf('SC_PAGE_SIZE'))


def export_derived(source, destination):
    """Explicit allowlist only; failed qualifications remain exportable."""
    source, destination = Path(source), Path(destination)
    receipt = json.loads((source / 'capture.json').read_text())
    allowed = ['capture.json']
    names = ('attributes.txt', 'attributes.txt.stderr', 'record-types.txt', 'record-types.txt.stderr',
             'buildids.txt', 'buildids.txt.stderr', 'perf-record.stderr', 'leaf-events-all.txt',
             'leaf-events-all.txt.stderr', 'leaf-events-window.txt', 'leaf-events-window.jsonl',
             'callchain-events-all.jsonl')
    for role in receipt.get('roles', []):
        name = role.get('role')
        if name not in ('source', 'destination'):
            raise ValueError('unexpected export role')
        directory = source / name
        if any(directory.glob('perf.data*')):
            raise ValueError('raw stack/register trace still exists; export refused')
        if role.get('raw_trace_cleanup') and role['raw_trace_cleanup'].get('raw_deleted') is not True:
            raise ValueError('raw trace deletion not confirmed')
        allowed.extend(name + '/' + item for item in names)
    destination.mkdir(mode=0o755, exist_ok=False)
    total, manifest = 0, []
    for relative in allowed:
        path = source / relative
        if not path.exists():
            continue
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid():
            raise ValueError('unowned, linked or nonregular export input')
        total += info.st_size
        if info.st_size > base.RAW_BYTES or total > 256 * 1024**2:
            raise ValueError('derived export size bound')
        target = destination / relative
        target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        shutil.copyfile(path, target, follow_symlinks=False)
        target.chmod(0o644)
        manifest.append(dict(path=relative, bytes=info.st_size, sha256=base.sha256(target)))
    (destination / 'export-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    (destination / 'export-manifest.json').chmod(0o644)
    return 0


def main():
    if os.environ.get('GITHUB_ACTIONS') != 'true' or platform.system() != 'Linux' or platform.machine() != 'x86_64':
        raise ValueError('capture execution is restricted to remote GitHub Actions Linux x64')
    if sys.argv[1:] == ['--environment-preflight']:
        if os.geteuid() != 0:
            raise ValueError('privileged collector preflight requires root')
        print(json.dumps(dict(mode='environment-preflight', github_actions=os.environ['GITHUB_ACTIONS'],
                              system=platform.system(), machine=platform.machine(), euid=os.geteuid())))
        return 0
    if len(sys.argv) == 4 and sys.argv[1] == '--export':
        return export_derived(sys.argv[2], sys.argv[3])
    base.record_argv, base.validate_attributes, base.PerfCapture = record_argv, validate_attributes, DwarfCapture
    spec = importlib.util.spec_from_file_location('mesh_gap_profile_resources', RUNTIME / 'collect_resources.py')
    collector = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(collector)
    collector.process_snapshot = split_cpu_snapshot
    try:
        return collector.main()
    finally:
        for capture in ACTIVE:
            capture.stop()
            capture.delete_private_raw()


if __name__ == '__main__':
    raise SystemExit(main())
