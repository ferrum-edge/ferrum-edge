#!/usr/bin/env python3
"""Bounded readelf stream reduction. Partial output never qualifies coverage."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import resource
import selectors
import signal
import subprocess
import time

LIMITS = dict(raw_stdout_bytes=256 * 1024**2, stderr_bytes=64 * 1024,
              compact_bytes=8 * 1024**2, line_bytes=64 * 1024, ranges=200_000,
              child_address_space_bytes=512 * 1024**2, read_chunk_bytes=64 * 1024)
FDE = re.compile(rb'\s*[0-9a-fA-F]+\s+[0-9a-fA-F]+\s+[0-9a-fA-F]+\s+FDE\s+'
                 rb'cie=[0-9a-fA-F]+\s+pc=([0-9a-fA-F]+)\.\.([0-9a-fA-F]+)\s*')


class RangeExtractor:
    """Only one bounded pending line and counters are retained in memory."""
    def __init__(self, output, limits):
        self.output, self.limits = output, limits
        self.pending = b''
        self.ranges = self.compact_bytes = self.lines = 0

    def feed(self, chunk):
        parts = (self.pending + chunk).split(b'\n')
        self.pending = parts.pop()
        for line in parts:
            if len(line) > self.limits['line_bytes'] or b'\0' in line:
                raise ValueError('invalid or oversized readelf line')
            self.lines += 1
            if not re.search(rb'\bFDE\b', line):
                continue
            match = FDE.fullmatch(line)
            if not match:
                raise ValueError('malformed FDE range header')
            start, end = (int(value, 16) for value in match.groups())
            if not 0 <= start < end <= 2**64 - 1:
                raise ValueError('empty, reversed or oversized FDE range')
            compact = f'FDE pc={start:016x}..{end:016x}\n'.encode('ascii')
            if self.ranges >= self.limits['ranges'] or self.compact_bytes + len(compact) > self.limits['compact_bytes']:
                raise ValueError('FDE range count or compact output cap exceeded')
            self.output.write(compact)
            self.ranges += 1
            self.compact_bytes += len(compact)
        if len(self.pending) > self.limits['line_bytes']:
            raise ValueError('unterminated readelf line exceeds cap')

    def finish(self):
        if self.pending:
            raise ValueError('incomplete final readelf line')
        if not self.ranges:
            raise ValueError('no complete FDE ranges')


def stop_child(child):
    if child is None or child.poll() is not None:
        return
    try:
        os.killpg(child.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        child.wait(timeout=1)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait(timeout=1)


def capture_ranges(argv, stdout, stderr, *, timeout=30, limits=None, record=None):
    """Record compact stdout and bounded stderr; hash all observed raw bytes.

    Raw hashes describe the complete stream only when the corresponding EOF is
    observed. `complete` additionally requires successful process termination,
    no stderr, complete lines and all bounds. Failed prefixes remain evidence.
    """
    bounds = dict(LIMITS if limits is None else limits)
    if set(bounds) != set(LIMITS) or any(type(x) is not int or x <= 0 for x in bounds.values()):
        raise ValueError('invalid FDE extraction bounds')
    if type(timeout) not in (int, float) or not 0 < timeout <= 30:
        raise ValueError('invalid FDE extraction timeout')
    stdout, stderr = Path(stdout), Path(stderr)
    record = {} if record is None else record
    record.update(argv=list(argv), label='unwind-frames', stdout=stdout.name, stderr=stderr.name,
                  timeout_seconds=timeout, environment=dict(LC_ALL='C'), limits=bounds,
                  stdout_format='complete FDE address ranges only; verbose stream hashed without storage',
                  complete=False, errors=[])
    start, child = time.monotonic(), None
    count, hashes, eof = ({name: 0 for name in ('stdout', 'stderr')},
                         {name: hashlib.sha256() for name in ('stdout', 'stderr')},
                         {name: False for name in ('stdout', 'stderr')})
    def child_limits():
        resource.setrlimit(resource.RLIMIT_AS, (bounds['child_address_space_bytes'],) * 2)
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    with stdout.open('xb') as out, stderr.open('xb') as err, selectors.DefaultSelector() as selector:
        extractor = RangeExtractor(out, bounds)
        try:
            env = dict(os.environ, LC_ALL='C')
            child = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
                                     start_new_session=True, preexec_fn=child_limits)
            selector.register(child.stdout, selectors.EVENT_READ, 'stdout')
            selector.register(child.stderr, selectors.EVENT_READ, 'stderr')
            while selector.get_map():
                remaining = start + timeout - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('readelf stream timeout')
                for key, _ in selector.select(min(0.1, remaining)):
                    name = key.data
                    data = os.read(key.fd, bounds['read_chunk_bytes'])
                    if not data:
                        eof[name] = True
                        selector.unregister(key.fileobj)
                        continue
                    count[name] += len(data)
                    hashes[name].update(data)
                    cap = bounds['raw_stdout_bytes'] if name == 'stdout' else bounds['stderr_bytes']
                    if count[name] > cap:
                        raise ValueError(name + ' stream cap exceeded')
                    if name == 'stdout':
                        extractor.feed(data)
                    else:
                        err.write(data)
            remaining = start + timeout - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('readelf process completion timeout')
            code = child.wait(timeout=remaining)
            if code != 0:
                raise ValueError('readelf returned nonzero: ' + str(code))
            if count['stderr']:
                raise ValueError('readelf emitted stderr; range completeness unqualified')
            extractor.finish()
            record['complete'] = True
        except Exception as error:
            record['errors'].append(type(error).__name__ + ': ' + str(error))
        except BaseException:
            record['errors'].append('interrupted before complete FDE extraction')
            raise
        finally:
            stop_child(child)
            if child is not None:
                child.stdout.close()
                child.stderr.close()
            out.flush()
            err.flush()
            record.update(returncode=None if child is None else child.returncode,
                          elapsed_seconds=time.monotonic() - start, extracted_ranges=extractor.ranges,
                          parsed_lines=extractor.lines, compact_bytes=extractor.compact_bytes,
                          pending_line_bytes=len(extractor.pending),
                          raw_streams={name: dict(bytes_observed=count[name], sha256_observed=hashes[name].hexdigest(),
                                                 complete=eof[name]) for name in count},
                          stdout_sha256=hashlib.sha256(stdout.read_bytes()).hexdigest(),
                          stderr_sha256=hashlib.sha256(stderr.read_bytes()).hexdigest())
    return record
