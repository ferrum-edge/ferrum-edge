#!/usr/bin/env python3
"""Fail when a first-class Helm values.yaml key is missing from values.schema.json.

Walks object keys in each chart's values.yaml and requires a matching
``properties`` entry in the companion schema (resolving ``$ref``). Descent stops
under documented free-form maps (``additionalProperties`` not ``false``) and
under arrays, so extension-map entries and list item payloads are not treated
as schema-declared chart keys.

Requires PyYAML. Install the hash-pinned requirements next to this script::

    python3 -m pip install --require-hashes \\
      -r scripts/check_helm_values_schema_parity.requirements.txt

CI creates a temp venv and installs the same pin before invoking this script.
No subprocess helpers are used so Cross automation policy stays clean.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REQUIREMENTS = Path(__file__).with_name(
    "check_helm_values_schema_parity.requirements.txt"
)

CHARTS = (
    ROOT / "charts" / "ferrum-gateway",
    ROOT / "charts" / "ferrum-mesh",
)


def load_yaml(path: Path) -> Any:
    try:
        import yaml  # type: ignore
    except ImportError as exc:
        raise RuntimeError(
            "PyYAML is required to run check_helm_values_schema_parity.py; "
            "install the hash-pinned requirements with: "
            f"python3 -m pip install --require-hashes -r {REQUIREMENTS}"
        ) from exc

    with path.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def resolve_ref(schema_root: dict[str, Any], node: dict[str, Any]) -> dict[str, Any]:
    ref = node.get("$ref")
    if not isinstance(ref, str):
        return node
    if not ref.startswith("#/"):
        raise ValueError(f"unsupported $ref (local fragments only): {ref}")
    cur: Any = schema_root
    for part in ref[2:].split("/"):
        if not isinstance(cur, dict) or part not in cur:
            raise ValueError(f"unresolved $ref {ref}")
        cur = cur[part]
    if not isinstance(cur, dict):
        raise ValueError(f"$ref {ref} did not resolve to an object schema")
    # Merge sibling keywords onto the resolved target (draft-07 local style).
    merged = dict(cur)
    for key, value in node.items():
        if key != "$ref":
            merged[key] = value
    return merged


def schema_properties(schema_root: dict[str, Any], node: dict[str, Any]) -> dict[str, Any]:
    node = resolve_ref(schema_root, node)
    props = node.get("properties")
    if props is None:
        return {}
    if not isinstance(props, dict):
        raise ValueError("schema properties must be an object")
    return props


def is_open_map(schema_root: dict[str, Any], node: dict[str, Any]) -> bool:
    """True when additionalProperties permits undeclared child keys."""
    node = resolve_ref(schema_root, node)
    additional = node.get("additionalProperties", True)
    return additional is not False


def collect_missing(
    values: Any,
    schema_node: dict[str, Any],
    schema_root: dict[str, Any],
    prefix: str,
) -> list[str]:
    if not isinstance(values, dict):
        return []

    schema_node = resolve_ref(schema_root, schema_node)
    props = schema_properties(schema_root, schema_node)
    missing: list[str] = []

    for key, child in values.items():
        path = f"{prefix}.{key}" if prefix else str(key)
        if key not in props:
            missing.append(path)
            continue
        child_schema = resolve_ref(schema_root, props[key])
        if isinstance(child, dict):
            if is_open_map(schema_root, child_schema) and not schema_properties(
                schema_root, child_schema
            ):
                # Pure free-form map (annotations/env/passthrough): key is
                # declared; children are intentionally unconstrained.
                continue
            if is_open_map(schema_root, child_schema) and schema_properties(
                schema_root, child_schema
            ):
                # Structured object that also allows extras: still require
                # declared children that appear in values.yaml.
                missing.extend(
                    collect_missing(child, child_schema, schema_root, path)
                )
                continue
            missing.extend(collect_missing(child, child_schema, schema_root, path))
        # Arrays and scalars: presence of the parent key is enough.
    return missing


def check_chart(chart_dir: Path) -> list[str]:
    values_path = chart_dir / "values.yaml"
    schema_path = chart_dir / "values.schema.json"
    if not values_path.is_file():
        return [f"{chart_dir.name}: missing values.yaml"]
    if not schema_path.is_file():
        return [f"{chart_dir.name}: missing values.schema.json"]

    values = load_yaml(values_path)
    if values is None:
        values = {}
    if not isinstance(values, dict):
        return [f"{chart_dir.name}: values.yaml root must be a mapping"]

    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    if not isinstance(schema, dict):
        return [f"{chart_dir.name}: values.schema.json root must be an object"]

    if schema.get("additionalProperties") is not False:
        return [
            f"{chart_dir.name}: root additionalProperties must be false "
            f"(got {schema.get('additionalProperties')!r})"
        ]

    missing = collect_missing(values, schema, schema, "")
    return [f"{chart_dir.name}: missing schema property for values key `{path}`" for path in missing]


def main() -> int:
    failures: list[str] = []
    for chart_dir in CHARTS:
        failures.extend(check_chart(chart_dir))

    if failures:
        print("Helm values/schema parity check failed:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1

    for chart_dir in CHARTS:
        print(f"ok: {chart_dir.name} values.yaml keys are declared in values.schema.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
