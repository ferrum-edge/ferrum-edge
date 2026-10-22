"""Read the frozen gateway sampler's external timeline without changing evidence.

Call only after the frozen ``observed()`` gates. ``measurement_usage`` must be
the producer's function from the pinned gateway-helper checkout. The stamped
sample intentionally contains its derived summary, not the full timeline.
"""
from __future__ import annotations

import copy
import hashlib
import json
import math
from pathlib import Path
import re


MAX_JSON_BYTES = 8 * 1024**2
ARMS = ('ferrum', 'ferrum-baseline')


def _finite(value, *, positive=False):
    try:
        return (type(value) in (int, float) and math.isfinite(value)
                and (value > 0 if positive else value >= 0))
    except OverflowError:
        return False


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate gateway RSS JSON key')
        result[key] = value
    return result


def _constant(value):
    raise ValueError('nonfinite gateway RSS JSON constant: ' + value)


def _read(root, relative):
    path = root
    for part in relative.parts:
        path = path / part
        if path.is_symlink():
            raise ValueError('gateway RSS evidence must not contain symlinks')
    with path.open('rb') as stream:
        content = stream.read(MAX_JSON_BYTES + 1)
    if len(content) > MAX_JSON_BYTES:
        raise ValueError('gateway RSS evidence exceeds fixed byte bound')
    value = json.loads(content, parse_constant=_constant, object_pairs_hook=_object)
    return value, hashlib.sha256(content).hexdigest()


def _canonical(value):
    # JSON comparison distinguishes booleans from numbers, unlike Python ==.
    return json.dumps(value, sort_keys=True, allow_nan=False, separators=(',', ':'))


def gateway_rss(raw, directory, *, arm, image_id, measurement_usage):
    """Return in-window RSS metrics and hash-bound external evidence.

    ``directory`` is the existing gateway block directory. Only the current
    1 MiB/30 s lane is supported. This function reads two exact diagnostic files,
    calls the frozen pure summary function, and never writes or changes inputs.
    Missing or inconsistent proof raises OSError/ValueError; there is no fallback
    to the sampler-lifetime peak or to a different arm's process.
    """
    if (not isinstance(raw, dict) or arm not in ARMS or raw.get('gateway') != arm
            or type(raw.get('pair')) is not int or raw['pair'] <= 0
            or type(raw.get('payload_size')) is not int or raw['payload_size'] != 1048576
            or type(raw.get('duration_secs')) is not int or raw['duration_secs'] != 30
            or type(raw.get('sample_schema')) is not int or raw['sample_schema'] != 2
            or not isinstance(image_id, str) or re.fullmatch(r'sha256:[0-9a-f]{64}', image_id) is None
            or not callable(measurement_usage)):
        raise ValueError('gateway RSS lane or image identity mismatch')
    phases = raw.get('phases')
    if (not isinstance(phases, dict)
            or not _finite(phases.get('measurement_start_unix_secs'), positive=True)
            or not _finite(phases.get('measurement_secs'), positive=True)
            or phases['measurement_secs'] != 30):
        raise ValueError('invalid gateway RSS measurement phase')
    start, duration = phases['measurement_start_unix_secs'], phases['measurement_secs']
    end = start + duration
    if not _finite(end, positive=True):
        raise ValueError('invalid gateway RSS measurement end')

    directory = Path(directory)
    diagnostics = Path('protocol/pairs') / f"pair_{raw['pair']:03d}" / 'diagnostics'
    usage_path = diagnostics / f'{arm}_1048576_process_usage.json'
    runtime_path = diagnostics / f'{arm}_runtime.json'
    usage, usage_hash = _read(directory, usage_path)
    runtimes, runtime_hash = _read(directory, runtime_path)
    if (not isinstance(runtimes, list) or len(runtimes) != 1 or not isinstance(runtimes[0], dict)
            or runtimes[0].get('Image') != image_id):
        raise ValueError('gateway RSS runtime image receipt mismatch')
    state = runtimes[0].get('State')
    if (not isinstance(state, dict) or state.get('Running') is not True
            or type(state.get('Pid')) is not int or state['Pid'] <= 1):
        raise ValueError('gateway RSS runtime PID unavailable')
    pid = state['Pid']
    if (not isinstance(usage, dict) or usage.get('capture_complete') is not True
            or usage.get('error') or usage.get('available') is False
            or not isinstance(usage.get('timeline'), list) or not usage['timeline']
            or not isinstance(usage.get('processes'), list)
            or any(not isinstance(item, dict) for item in usage['processes'])):
        raise ValueError('gateway RSS capture incomplete or malformed')
    aggregate = [item for item in usage['processes'] if item.get('role') == 'gateway']
    if len(aggregate) != 1 or type(aggregate[0].get('pid')) is not int or aggregate[0]['pid'] != pid:
        raise ValueError('gateway RSS aggregate PID mismatch')

    previous, generation, samples = None, None, []
    for snapshot in usage['timeline']:
        if (not isinstance(snapshot, dict) or not _finite(snapshot.get('unix_secs'), positive=True)
                or previous is not None and snapshot['unix_secs'] <= previous
                or not isinstance(snapshot.get('processes'), list)
                or any(not isinstance(item, dict) for item in snapshot['processes'])):
            raise ValueError('invalid gateway RSS timeline snapshot')
        previous = timestamp = snapshot['unix_secs']
        processes = snapshot['processes']
        identities = [(item.get('pid'), item.get('start_ticks')) for item in processes]
        if (any(type(p) is not int or p <= 0 or type(t) is not int or t <= 0 for p, t in identities)
                or len({p for p, _ in identities}) != len(identities)):
            raise ValueError('duplicate or malformed gateway RSS process identity')
        gateways = [item for item in processes if item.get('role') == 'gateway']
        if (len(gateways) != 1 or gateways[0]['pid'] != pid
                or type(gateways[0].get('rss_bytes')) is not int
                or not _finite(gateways[0]['rss_bytes'], positive=True)):
            raise ValueError('gateway RSS sample missing, invalid or wrong PID')
        gateway = gateways[0]
        if generation is None:
            generation = gateway['start_ticks']
        if gateway['start_ticks'] != generation:
            raise ValueError('gateway RSS process generation changed')
        if start <= timestamp <= end:
            samples.append(gateway['rss_bytes'])
    if (usage['timeline'][0]['unix_secs'] > start or usage['timeline'][-1]['unix_secs'] < end
            or not samples):
        raise ValueError('gateway RSS measurement window is not bracketed')

    stamped = raw.get('process_usage')
    if not isinstance(stamped, dict) or not isinstance(stamped.get('measurement'), list):
        raise ValueError('gateway RSS stamped measurement summary unavailable')
    try:
        derived = measurement_usage(copy.deepcopy(usage), copy.deepcopy(phases))
        if _canonical(derived) != _canonical(stamped['measurement']):
            raise ValueError('gateway RSS external/stamped measurement summary mismatch')
        measured = [item for item in derived if item.get('role') == 'gateway']
        if (len(measured) != 1 or measured[0].get('pid') != pid
                or measured[0].get('complete_bracket') is not True
                or not _finite(measured[0].get('bracket_secs'), positive=True)
                or not duration <= measured[0]['bracket_secs'] <= duration * 1.05
                or not _finite(measured[0].get('boundary_slack_secs'))
                or not math.isclose(measured[0]['bracket_secs'] - duration,
                                    measured[0]['boundary_slack_secs'], abs_tol=0.001)):
            raise ValueError('gateway RSS measurement summary bracket mismatch')
        mean = sum(samples) / len(samples)
        if not _finite(mean, positive=True):
            raise ValueError('invalid gateway RSS sample mean')
    except (KeyError, TypeError, IndexError, ArithmeticError) as error:
        raise ValueError('malformed gateway RSS producer summary') from error

    return dict(proxy_rss_bytes_mean=mean, proxy_rss_bytes_peak=max(samples), rss_samples=len(samples),
                gateway_pid=pid, gateway_start_ticks=generation,
                measurement_start_unix_secs=start, measurement_secs=duration,
                evidence_sha256={usage_path.as_posix(): usage_hash, runtime_path.as_posix(): runtime_hash})
