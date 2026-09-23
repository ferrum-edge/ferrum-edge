#!/usr/bin/env python3
"""Compare stream-profile arms.

Reports the contrast that decides whether the aggregation window is safe to
enable by default: per-frame delivery latency on an idle proxy carrying a
low-rate stream. The window's whole cost shows up here, and nowhere in the
throughput benchmark.
"""
import json
import math
import statistics
import sys
from collections import defaultdict
from pathlib import Path

T95 = {1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447, 7: 2.365,
       8: 2.306, 9: 2.262, 10: 2.228, 12: 2.179, 15: 2.131, 20: 2.086, 30: 2.042}


def tcrit(df):
    for k in sorted(T95):
        if max(1, int(df)) <= k:
            return T95[k]
    return 1.96


def welch(a, b):
    """Absolute difference b-a with a 95% CI, in the input's units."""
    if len(a) < 2 or len(b) < 2:
        return None
    ma, mb = statistics.mean(a), statistics.mean(b)
    va, vb = statistics.variance(a), statistics.variance(b)
    se = math.sqrt(va / len(a) + vb / len(b))
    if se == 0:
        return dict(diff=mb - ma, lo=mb - ma, hi=mb - ma, ma=ma, mb=mb, sep=mb != ma)
    df = (va / len(a) + vb / len(b)) ** 2 / (
        (va / len(a)) ** 2 / (len(a) - 1) + (vb / len(b)) ** 2 / (len(b) - 1))
    t = tcrit(df)
    return dict(diff=mb - ma, lo=(mb - ma) - t * se, hi=(mb - ma) + t * se,
                ma=ma, mb=mb, sep=((mb - ma) - t * se) > 0 or ((mb - ma) + t * se) < 0)


def main(root):
    arms = defaultdict(list)
    for path in sorted(Path(root).glob("*_repeat*.json")):
        doc = json.loads(path.read_text())
        arms[path.name.split("_repeat")[0]].append(doc)
    if not arms:
        sys.exit(f"no stream-profile results under {root}")

    print(f"{'arm':10} {'n':>3} {'frames':>7} {'reads':>7} "
          f"{'delay p50':>10} {'delay p99':>10} {'ttfb p50':>9} {'failed':>7}")
    for arm, docs in arms.items():
        print(f"{arm:10} {len(docs):>3} "
              f"{statistics.mean(d['frames_received_mean'] for d in docs):>7.1f} "
              f"{statistics.mean(d['reads_mean'] for d in docs):>7.1f} "
              f"{statistics.mean(d['frame_delay_us']['p50'] for d in docs):>10.0f} "
              f"{statistics.mean(d['frame_delay_us']['p99'] for d in docs):>10.0f} "
              f"{statistics.mean(d['ttfb_us']['p50'] for d in docs):>9.0f} "
              f"{sum(d['requests_failed'] for d in docs):>7}")

    def series(arm, group, stat):
        return [d[group][stat] for d in arms.get(arm, [])]

    print("\n== plain -> window (the window is the only difference) ==")
    for group, stat in (("frame_delay_us", "p50"), ("frame_delay_us", "p99"),
                        ("ttfb_us", "p50"), ("inter_frame_us", "p50")):
        r = welch(series("plain", group, stat), series("window", group, stat))
        if not r:
            print(f"{group}.{stat:>4}: insufficient repeats")
            continue
        verdict = "SEPARATED" if r["sep"] else "overlaps 0"
        print(f"{group}.{stat:<4} {r['ma']:>9.0f}us -> {r['mb']:>9.0f}us  "
              f"{r['diff']:>+8.0f}us  [{r['lo']:+.0f}, {r['hi']:+.0f}]  {verdict}")

    r = welch(series("plain", "frame_delay_us", "p50"),
              series("window", "frame_delay_us", "p50"))
    if r:
        print("\nA window that holds every frame for its full length would move "
              "frame_delay p50 by about the window itself.")
        print(f"Observed shift: {r['diff']:+.0f}us")

    # Aggregation means one read carried more than one backend frame, so the
    # test is reads < frames WITHIN an arm. Comparing reads BETWEEN arms is
    # wrong: a gateway can deliver one frame split across two reads, and a
    # window that rejoins the halves drops the read count with nothing merged.
    print("\nBackend frames merged into one read (reads < frames within the arm):")
    for arm in ("plain", "window"):
        docs = arms.get(arm)
        if not docs:
            continue
        reads = statistics.mean(d["reads_mean"] for d in docs)
        frames = statistics.mean(d["frames_received_mean"] for d in docs)
        verdict = "merging" if reads < frames - 0.5 else "no merging"
        print(f"  {arm:7} reads {reads:.1f} / frames {frames:.1f}  ({verdict})")


main(sys.argv[1] if len(sys.argv) > 1 else ".")
