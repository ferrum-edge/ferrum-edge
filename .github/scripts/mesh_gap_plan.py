#!/usr/bin/env python3
"""Prespecified 80-cell design and conservative, descriptive review screen."""
from __future__ import annotations

import math
import statistics

ARMS = ('baseline_a', 'baseline_b', 'candidate')
MESH_METRICS = ('goodput_rps', 'cpu_us_per_completion', 'cohort_p50_us', 'cohort_p95_us', 'cohort_p99_us',
                'proxy_rss_bytes_mean', 'proxy_rss_bytes_peak')
GATEWAY_METRICS = ('goodput_rps', 'cpu_us_per_completion', 'completion_p50_us', 'completion_p95_us',
                   'completion_p99_us', 'proxy_rss_bytes_mean', 'proxy_rss_bytes_peak')
DECISION = dict(materiality_fraction=0.03, paired_repetitions=4,
    promotion='review only: all80 valid, all zero-error capacity gates, small saturated goodput and CPU each improve in all4 pairs; median improvement >=3% and beyond full AA log envelope; no adverse guard',
    adverse_guard='bulk, fixed, RSS and gateway medians outside max(3%, full same-scenario AA absolute-log envelope) block promotion',
    automatic_reruns=0, automatic_confirmation=0,
    limitations='n=4 descriptive screen, not statistical equivalence or attribution; any undefined planned ratio blocks conclusions')


def mesh_cells():
    cells = []
    for repetition in range(1, 5):
        for payload in ((1024, 1048576) if repetition % 2 else (1048576, 1024)):
            for load in (('saturated', 'fixed') if repetition <= 2 else ('fixed', 'saturated')):
                for position, arm in enumerate(ARMS if repetition % 2 else tuple(reversed(ARMS)), 1):
                    cells.append(dict(arm=arm, payload=payload, repetition=repetition, load=load, duration=30,
                        rate=(2000 if payload == 1024 else 200) if load == 'fixed' else 0,
                        order_position=position, directory=f'mesh/{arm}/{load}/run_{repetition}/payload_{payload}'))
    return cells


def gateway_blocks():
    blocks = []
    orders = (('ferrum', 'ferrum-baseline'), ('ferrum-baseline', 'ferrum'),
              ('ferrum-baseline', 'ferrum'), ('ferrum', 'ferrum-baseline'))
    for repetition in range(1, 5):
        for protocol in (('http1-tls', 'http2') if repetition % 2 else ('http2', 'http1-tls')):
            for phase in (('aa', 'ab') if repetition % 2 else ('ab', 'aa')):
                blocks.append(dict(pair=repetition, scenario=protocol, phase=phase,
                    directory=f'gateway/run_{repetition}/{protocol}/{phase}',
                    members=[dict(arm=arm, leg='comparison' if arm == 'ferrum' else 'reference',
                        image_role='candidate' if phase == 'ab' and arm == 'ferrum' else 'baseline')
                        for arm in orders[repetition - 1]]))
    return blocks


def ratio(numerator, denominator):
    if not all(type(v) in (int, float) and math.isfinite(v) and v > 0 for v in (numerator, denominator)):
        return None
    return numerator / denominator


def summary(values):
    complete = len(values) == 4 and all(type(v) in (int, float) and math.isfinite(v) and v > 0 for v in values)
    return dict(all=values, defined=sum(v is not None for v in values), median=statistics.median(values) if complete else None,
                min=min(values) if complete else None, max=max(values) if complete else None,
                geomean=math.exp(sum(map(math.log, values)) / 4) if complete else None)


def comparisons(mesh, gateway):
    results = []
    for payload in (1024, 1048576):
        for load in ('saturated', 'fixed'):
            metrics = (*MESH_METRICS, *(('cohort_scheduled_p50_us', 'cohort_scheduled_p95_us', 'cohort_scheduled_p99_us') if load == 'fixed' else ()))
            group = {(r['cell']['repetition'], r['cell']['arm']): r for r in mesh
                     if r['cell']['payload'] == payload and r['cell']['load'] == load}
            for metric in metrics:
                aa, ab = [], []
                for rep in range(1, 5):
                    values = [group.get((rep, arm), {}).get('metrics', {}).get(metric) for arm in ARMS]
                    a, b, c = values
                    aa.append(ratio(b, a))
                    denominator = math.sqrt(a * b) if ratio(a, b) is not None else None
                    ab.append(ratio(c, denominator))
                results.append(dict(surface='mesh', scenario=f'{payload}/{load}', metric=metric,
                    latency_scope='successful admitted cohort; service latency plus separately labeled scheduled latency for fixed load',
                    aa=summary(aa), candidate=summary(ab), candidate_denominator='geomean(baseline_a, baseline_b)'))
    for protocol in ('http1-tls', 'http2'):
        group = {(r['block']['pair'], r['block']['phase'], r['cell']['leg']): r for r in gateway if r['block']['scenario'] == protocol}
        for metric in GATEWAY_METRICS:
            paired = {}
            for phase in ('aa', 'ab'):
                paired[phase] = summary([ratio(group.get((rep, phase, 'comparison'), {}).get('metrics', {}).get(metric),
                    group.get((rep, phase, 'reference'), {}).get('metrics', {}).get(metric)) for rep in range(1, 5)])
            results.append(dict(surface='gateway', scenario=protocol, metric=metric,
                latency_scope='completion-window successes only; successful drains excluded; no admitted-cohort quantiles',
                aa=paired['aa'], candidate=paired['ab'], candidate_denominator='paired baseline reference'))
    return results


def screen(rows, complete, capacity):
    reasons, guards = [], []
    if not complete:
        reasons.append('incomplete or structurally invalid observations')
    if not capacity:
        reasons.append('one or more zero-error capacity gates failed')
    floor = math.log1p(DECISION['materiality_fraction'])
    for row in rows:
        aa, ab = row['aa'], row['candidate']
        if aa['median'] is None or ab['median'] is None:
            reasons.append(f"undefined planned ratios: {row['surface']}/{row['scenario']}/{row['metric']}")
            continue
        noise = max(abs(math.log(value)) for value in aa['all'])
        lower_is_better = row['metric'] != 'goodput_rps'
        median_log = math.log(ab['median'])
        if row['surface'] == 'mesh' and row['scenario'] == '1024/saturated' and row['metric'] in ('goodput_rps', 'cpu_us_per_completion'):
            improvement = -median_log if lower_is_better else median_log
            every = ab['max'] < 1 if lower_is_better else ab['min'] > 1
            required_gain = -math.log1p(-DECISION['materiality_fraction']) if lower_is_better else floor
            if not every or improvement < required_gain or improvement <= noise:
                reasons.append('small saturated ' + row['metric'] + ' is not repeatable/material beyond full AA envelope')
        adverse = median_log if lower_is_better else -median_log
        flag = adverse > max(floor, noise)
        guards.append(dict(surface=row['surface'], scenario=row['scenario'], metric=row['metric'],
                           aa_log_envelope=noise, allowed_log_departure=max(floor, noise), adverse=flag))
        if flag:
            reasons.append(f"adverse paired median: {row['surface']}/{row['scenario']}/{row['metric']}")
    return dict(review_eligible=not reasons, reasons=reasons, guards=guards,
                decision='eligible for independent review, not an automatic performance claim' if not reasons else 'do not promote from this campaign',
                automatic_reruns=0)
