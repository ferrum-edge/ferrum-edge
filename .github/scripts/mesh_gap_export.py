#!/usr/bin/env python3
"""Bounded public export with lossless report references and atomic publication.

Raw files and per-cell observations retain their original bytes. Only the
duplicated outer report is represented with hash-bound observation references.
Hydration must recover the original report bytes before export can succeed.
An incomplete campaign remains incomplete; export completeness is only an
inventory property. No measurement, validity or performance threshold changes.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import tempfile

SCHEMA = 'mesh_gap_report_refs.v1'
MARKER = '_public_observation_references'
REFERENCE = '$mesh_observation_ref'
LIMIT = 256 * 1024**2
SUFFIXES = ('.json', '.jsonl', '.log', '.txt', '.md', '.err')


def encoded(value):
    return (json.dumps(value, indent=2, allow_nan=False) + '\n').encode()


def decoded(data):
    return json.loads(data, parse_constant=lambda value: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def relative(value):
    if not isinstance(value, str):
        raise ValueError('reference path must be a string')
    path = Path(value)
    if path.is_absolute() or '..' in path.parts or not path.parts or path.parts[0] not in ('campaign', 'images'):
        raise ValueError('unsafe public reference path')
    return path


def sha(data):
    return hashlib.sha256(data).hexdigest()


def source_digest(path):
    marker, tail = b'PRIVATE KEY-----', b''
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024**2), b''):
            if marker in tail + chunk:
                raise ValueError('private key material in public allowlist')
            digest.update(chunk)
            tail = chunk[-len(marker):]
    return digest.hexdigest()


def observation_path(group, row):
    if not isinstance(row, dict):
        return None
    if group == 'mesh':
        directory = row.get('cell', {}).get('directory')
        if directory is None:
            return None
        return str(relative('campaign/' + directory + '/observation.json'))
    directory = row.get('block', {}).get('directory')
    leg = row.get('cell', {}).get('leg')
    if directory is None or leg is None:
        return None
    if leg not in ('comparison', 'reference'):
        raise ValueError('unexpected gateway observation leg')
    return str(relative('campaign/' + directory + '/' + leg + '-observation.json'))


def hydrate_report(compact, lookup):
    if not isinstance(compact, dict):
        raise ValueError('public report must be an object')
    meta = compact.get(MARKER)
    if not isinstance(meta, dict) or meta.get('schema') != SCHEMA:
        raise ValueError('unknown report reference schema')
    result = {key: value for key, value in compact.items() if key != MARKER}
    for group in ('mesh', 'gateway'):
        rows = result.get(group)
        if not isinstance(rows, list):
            raise ValueError('missing report observation positions')
        hydrated = []
        for row in rows:
            if isinstance(row, dict) and set(row) == {REFERENCE}:
                reference = row[REFERENCE]
                if not isinstance(reference, dict) or set(reference) != {'path', 'bytes', 'sha256'}:
                    raise ValueError('malformed observation reference')
                name = str(relative(reference['path']))
                content = lookup(name)
                if (type(reference['bytes']) is not int or reference['bytes'] < 0
                        or len(content) != reference['bytes'] or sha(content) != reference['sha256']):
                    raise ValueError('observation reference digest or size mismatch')
                hydrated.append(decoded(content))
            else:
                hydrated.append(row)
        result[group] = hydrated
    original = encoded(result)
    if len(original) != meta.get('source_bytes') or sha(original) != meta.get('source_sha256'):
        raise ValueError('report hydration does not recover exact original bytes')
    return result


def compact_report(content, entries):
    report = decoded(content)
    if not isinstance(report, dict) or MARKER in report:
        raise ValueError('unexpected source report schema')
    result = dict(report)
    for group in ('mesh', 'gateway'):
        rows = report.get(group)
        if not isinstance(rows, list):
            raise ValueError('missing source report observation positions')
        public = []
        for row in rows:
            name = observation_path(group, row)
            if name is None or name not in entries:
                public.append(row)  # Pending/absent positions remain verbatim.
                continue
            entry = entries[name]
            canonical = entry['source'].read_bytes()
            if sha(canonical) != entry['sha256'] or decoded(canonical) != row:
                raise ValueError('report row differs from its canonical observation')
            public.append({REFERENCE: dict(path=name, bytes=len(canonical), sha256=sha(canonical))})
        result[group] = public
    result[MARKER] = dict(schema=SCHEMA, source_bytes=len(content), source_sha256=sha(content))
    hydrate_report(result, lambda name: entries[name]['source'].read_bytes())
    return encoded(result)


def inventory(roots):
    entries = {}
    for label, root in roots:
        root = Path(root)
        for path in sorted(root.rglob('*')):
            item = path.relative_to(root)
            if (not path.is_file() or path.is_symlink() or path.suffix not in SUFFIXES
                    or any(part in ('runtime', 'target', 'fixture') for part in item.parts) or path.name == 'image.tar'):
                continue
            if not path.resolve().is_relative_to(root.resolve()):
                raise ValueError('allowlisted source escapes its root')
            name = str(relative(label + '/' + str(item)))
            entries[name] = dict(source=path, bytes=path.stat().st_size, sha256=source_digest(path))
    name = 'campaign/report.json'
    if name in entries:
        entry = entries[name]
        content = compact_report(entry['source'].read_bytes(), entries)
        entry.update(content=content, source_sha256=entry['sha256'], bytes=len(content), sha256=sha(content))
    return entries


def export_public(campaign, images, destination, limit=LIMIT):
    destination = Path(destination)
    if destination.exists():
        raise ValueError('public export destination already exists')
    entries, staging = {}, None
    try:
        entries = inventory((('campaign', Path(campaign)), ('images', Path(images))))
        files = {name: {key: entry[key] for key in ('bytes', 'sha256')} for name, entry in sorted(entries.items())}
        manifest = dict(schema=2, complete=True, bytes=sum(row['bytes'] for row in files.values()),
                        private_fixture_included=False, build_trees_included=False,
                        report_reference_schema=SCHEMA, files=files)
        payload = encoded(manifest)
        if manifest['bytes'] + len(payload) > limit:
            raise ValueError('complete public inventory exceeds fixed byte bound')
        destination.parent.mkdir(parents=True, exist_ok=True)
        staging = Path(tempfile.mkdtemp(prefix=destination.name + '.staging-', dir=destination.parent))
        for name, entry in sorted(entries.items()):
            target = staging / relative(name)
            target.parent.mkdir(parents=True, exist_ok=True)
            if 'content' in entry:
                if source_digest(entry['source']) != entry['source_sha256']:
                    raise ValueError('source report changed during export')
                target.write_bytes(entry['content'])
            else:
                shutil.copyfile(entry['source'], target)
            if target.stat().st_size != entry['bytes'] or source_digest(target) != entry['sha256']:
                raise ValueError('export source changed or copied bytes differ')
        (staging / 'export.json').write_bytes(payload)
        staging.rename(destination)
        staging = None
        return manifest
    except Exception as error:
        if staging is not None:
            shutil.rmtree(staging)
        destination.mkdir(parents=True, exist_ok=False)
        # A failure status is explicitly incomplete, never a successful prefix.
        (destination / 'export.json').write_bytes(encoded(dict(schema=2, complete=False, error=str(error),
            selected_paths=sorted(entries), private_fixture_included=False, build_trees_included=False)))
        raise
