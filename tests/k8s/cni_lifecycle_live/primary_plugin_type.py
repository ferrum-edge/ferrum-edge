#!/usr/bin/env python3
"""Print the first plugin type (or top-level type) from a CNI config JSON file."""

from __future__ import annotations

import json
import sys


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: primary_plugin_type.py <cni-config.json>", file=sys.stderr)
        return 2
    with open(sys.argv[1], encoding="utf-8") as handle:
        document = json.load(handle)
    plugins = document.get("plugins")
    if isinstance(plugins, list) and plugins:
        plugin_type = plugins[0].get("type")
    else:
        plugin_type = document.get("type")
    if not isinstance(plugin_type, str) or not plugin_type:
        print("primary CNI config has no plugin type", file=sys.stderr)
        return 1
    print(plugin_type)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
