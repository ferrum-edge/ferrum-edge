#!/usr/bin/env python3
"""Split a rendered CNI cleanup hook multi-doc YAML into DaemonSet and Job files."""

from __future__ import annotations

import re
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 4:
        print(
            "usage: split_cleanup_hook.py <hook.yaml> <daemonset.out> <job.out>",
            file=sys.stderr,
        )
        return 2
    source = Path(sys.argv[1])
    daemonset_out = Path(sys.argv[2])
    job_out = Path(sys.argv[3])
    documents = [
        document
        for document in re.split(r"(?m)^---\s*$", source.read_text(encoding="utf-8"))
        if document.strip()
    ]
    daemonsets = [document for document in documents if re.search(r"(?m)^kind:\s*DaemonSet\s*$", document)]
    jobs = [document for document in documents if re.search(r"(?m)^kind:\s*Job\s*$", document)]
    if len(daemonsets) != 1 or len(jobs) != 1:
        print(
            f"expected one DaemonSet and one Job, got {len(daemonsets)}/{len(jobs)}",
            file=sys.stderr,
        )
        return 1
    daemonset_out.write_text(daemonsets[0].lstrip("\n"), encoding="utf-8")
    job_out.write_text(jobs[0].lstrip("\n"), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
