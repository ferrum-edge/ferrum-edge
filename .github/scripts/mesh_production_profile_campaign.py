#!/usr/bin/env python3
"""Complete three-cell observer qualification; no ranked performance claims."""
import importlib.util
import json
import math
import os
import shutil
from pathlib import Path
import sys

ROOT = Path('results')
ARM = os.environ.get('BENCH_PROFILE_ARM', 'envoy')
if ARM not in ('envoy', 'ferrum'):
    raise ValueError('unsupported profile arm')
spec = importlib.util.spec_from_file_location('production_campaign', Path(__file__).with_name('mesh_production_campaign.py'))
campaign = importlib.util.module_from_spec(spec)
spec.loader.exec_module(campaign)


def summarize():
    rows, errors = [], []
    for phase in ('before', 'profile', 'after'):
        path = ROOT/f'profile-{ARM}'/phase/'payload_1024'
        try:
            load = json.loads((path/f'{ARM}_http1_1024.json').read_text())
            resources = json.loads((path/f'{ARM}_http1_1024.resources.json').read_text())
            failures = campaign.validate(dict(arm=ARM, payload=1024, duration=30, rate=0), load, resources)
            row = dict(phase=phase, load=load, resources=resources, valid=not failures,
                       cpu_us_per_completion=resources.get('proxy_cpu_seconds', 0)*1e6/max(1, load.get('total_requests', 0)))
            if phase == 'profile':
                row['profile'] = json.loads((path/'perf-leaf/capture.json').read_text())
                if not row['profile'].get('valid'):
                    failures.append('profile failed independent identity/coverage/loss gate')
            if failures:
                errors.append(dict(phase=phase, errors=failures))
            row["valid"] = not failures
            rows.append(row)
        except (OSError, ValueError, TypeError, KeyError) as error:
            errors.append(dict(phase=phase, errors=[str(error)]))
    controls = None
    if not errors and len(rows) == 3:
        before, profiled, after = rows
        rps_ratio = after['load']['rps']/before['load']['rps']
        cpu_ratio = after['cpu_us_per_completion']/before['cpu_us_per_completion']
        profiled_rps_ratio = profiled['load']['rps']/math.sqrt(before['load']['rps']*after['load']['rps'])
        profiled_cpu_ratio = profiled['cpu_us_per_completion']/math.sqrt(before['cpu_us_per_completion']*after['cpu_us_per_completion'])
        controls = dict(after_before_rps_ratio=rps_ratio, after_before_cpu_ratio=cpu_ratio,
                        profiled_control_rps_ratio=profiled_rps_ratio, profiled_control_cpu_ratio=profiled_cpu_ratio)
        if any(not 1/1.05 <= value <= 1.05 for value in controls.values()):
            errors.append(dict(phase='controls', errors=['observer or bracket drift exceeds prespecified 5% qualification bound']))
    result = dict(arm=ARM, valid=not errors and len(rows)==3, errors=errors, cells=rows, controls=controls,
                  scope='User CPU leaf functions only; all process CPU/completion recorded separately. No callchain, async task wake, or source-line attribution.')
    (ROOT/'profile-qualification.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k != 'cells'}, indent=2))
    return 0 if result['valid'] else 1


def export_public():
    # Explicit paths avoid traversing private perf caches even when an artifact
    # glob implementation descends into directories excluded from its matches.
    destination = ROOT/'profile-public'
    destination.mkdir(exist_ok=False)
    patterns = ['*.json', '*.txt', 'images/*']
    for phase in ('before', 'profile', 'after'):
        base = f'profile-{ARM}/{phase}/payload_1024'
        patterns += [base+'/*.json', base+'/*.log', base+'/logs/*', base+'/perf-leaf/capture.json']
        for role in ('source', 'destination'):
            patterns += [base+f'/perf-leaf/{role}/*'+suffix for suffix in ('.txt', '.jsonl', '.stderr')]
            patterns.append(base+f'/perf-leaf/{role}/perf.data')
    total = 0
    for pattern in patterns:
        for source in ROOT.glob(pattern):
            if source.is_symlink() or not source.is_file():
                continue
            total += source.stat().st_size
            if total > 256*1024**2:
                raise ValueError('public profile artifact exceeds 256 MiB')
            target = destination/source.relative_to(ROOT)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
    return 0


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'export':
        raise SystemExit(export_public())
    if len(sys.argv) > 1 and sys.argv[1] == 'accept':
        raise SystemExit(0 if json.loads((ROOT/'profile-qualification.json').read_text())['valid'] else 1)
    raise SystemExit(summarize())
