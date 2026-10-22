"""Finite synthetic header diagnostic; never a ranking or performance candidate."""
from __future__ import annotations
import math

ARMS = ('ferrum', 'envoy', 'direct')
PROFILES = (('baseline_a', 0, 32), ('eight_short', 8, 32), ('thirtytwo_short', 32, 32),
            ('eight_long', 8, 256), ('baseline_b', 0, 32))
LIMITS = ('Single-host diagnostic, not production ranking or a runtime improvement.',
          'Header slopes also include parsing, HPACK, crypto and backend validation; not String-map attribution.',
          'Two reversed blocks are descriptive. All planned cells/errors/undefined ratios remain.',
          'Saturated successful-cohort latency includes drains; errors have no successful latency sample.',
          'Full identity-bound workload telemetry remains separately unqualified; native operational counters remain enabled.')


def header_metadata(count, value_bytes):
    if type(count) is not int or type(value_bytes) is not int or not 0 <= count <= 32 or not 0 <= value_bytes <= 256:
        raise ValueError('invalid synthetic header profile')
    return dict(count=count, value_bytes=value_bytes, added_request_wire_bytes=count * (20 + value_bytes),
                expected_receipt=f'{count:02x}-{value_bytes:04x}')


def cells(smoke=False):
    rows=[]
    for repetition in ((1,) if smoke else (1,2)):
        arms=ARMS if repetition % 2 else ARMS[::-1]
        profiles=(('smoke_zero',0,32),('smoke_bound',32,256)) if smoke else (PROFILES if repetition % 2 else PROFILES[::-1])
        for arm in arms:
            for profile,count,value_bytes in profiles:
                rows.append(dict(arm=arm,payload=1024,repetition=repetition,load='saturated',
                    duration=3 if smoke else 30,concurrency=100,warmup=1 if smoke else 3,rate=0,
                    profile=profile,header_count=count,header_value_bytes=value_bytes,
                    directory=f'{"smoke" if smoke else "measured"}/{arm}/run_{repetition}/{profile}'))
    return rows


def header_issues(cell, load):
    if not isinstance(load,dict): return ['missing load observation']
    actual=load.get('diagnostic_headers')
    if not isinstance(actual,dict): return ['missing enabled diagnostic header receipt']
    expected=header_metadata(cell['header_count'],cell['header_value_bytes'])
    issues=[]
    for key,value in expected.items():
        if type(actual.get(key)) is not type(value) or actual[key]!=value:
            issues.append('diagnostic workload metadata differs: '+key)
    if any(type(load.get(key)) is not int or load[key] < 0 for key in ('warmup_requests','cohort_requests')):
        return issues + ['invalid successful diagnostic population']
    successes=load['warmup_requests']+load['cohort_requests']
    if (type(actual.get('validated_exchanges')) is not int or actual['validated_exchanges']!=successes
            or actual.get('validated_receipt')!=(expected['expected_receipt'] if successes else None)):
        issues.append('successful header-validated population does not conserve warmup/cohort/drains')
    return issues


def ratio(a,b):
    return a/b if type(a) in (int,float) and type(b) in (int,float) and math.isfinite(a) and math.isfinite(b) and a>0 and b>0 else None


def comparisons(rows):
    """Preserve both paired positions, including absent/invalid cells."""
    by={(r['cell']['arm'],r['cell']['repetition'],r['cell']['profile']):r for r in rows}
    output=[]
    for arm in ARMS:
        for metric in ('goodput_rps','cpu_us_per_completion','cohort_p50_us','cohort_p95_us','cohort_p99_us'):
            aa=[];values={name:[] for name,_,_ in PROFILES if not name.startswith('baseline_')}
            for repetition in (1,2):
                def get(profile):
                    row=by.get((arm,repetition,profile),{})
                    return row.get('metrics',{}).get(metric) if row.get('measurement_valid') else None
                a,b=get('baseline_a'),get('baseline_b');aa.append(ratio(b,a))
                baseline=math.sqrt(a*b) if ratio(a,b) is not None else None
                for name in values: values[name].append(ratio(get(name),baseline))
            output.append(dict(arm=arm,metric=metric,identical_workload_aa=aa,profile_over_baseline=values))
    return output
