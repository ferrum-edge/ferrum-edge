"""Fold `perf script` output into collapsed stacks (experiment only, not for merge).

Usage: perf script -i X | python3 perf_fold.py > folded.txt
Each output line is `frame;frame;...;leaf count`, root first, so the result can be
fed to flamegraph tools or summed for inclusive time per symbol.
"""

import collections
import re
import sys

counts = collections.Counter()
stack = []
comm = None


def flush():
    global stack, comm
    if comm is not None and stack:
        frames = [comm] + list(reversed(stack))
        counts[";".join(frames)] += 1
    stack = []
    comm = None


frame_re = re.compile(r"^\s+[0-9a-f]+\s+(.*?)\s+\((.*)\)\s*$")
for raw in sys.stdin:
    line = raw.rstrip("\n")
    if not line.strip():
        flush()
        continue
    if not line.startswith((" ", "\t")):
        flush()
        # Thread name: tokio workers all share one comm; keep it coarse.
        comm = line.split()[0]
        continue
    m = frame_re.match(line)
    if not m:
        continue
    sym, dso = m.group(1), m.group(2)
    sym = re.sub(r"\+0x[0-9a-f]+$", "", sym)
    if sym == "[unknown]":
        sym = "[" + dso.rsplit("/", 1)[-1] + "]"
    # Drop Rust hash suffixes and long generic noise to keep lines short.
    sym = re.sub(r"::h[0-9a-f]{16}$", "", sym)
    sym = sym.replace(";", ":")
    if len(sym) > 160:
        sym = sym[:160]
    stack.append(sym)
flush()

for frames, n in counts.most_common():
    print(f"{frames} {n}")
