#!/usr/bin/env python3
"""Install only the shared test suite in an isolated exact-base Hyper copy.

Never use the resulting copy for a production/ranking build. This does not run
Cargo, resolve dependencies, or alter a runtime statement. Use the control cfg
specified in README.md when compiling this test-only copy remotely.
"""
import argparse
import hashlib
import json
from pathlib import Path

BASE_SHA = "4a7be250e45a367314e3dec872ecbd512220558e"
BASE_FILES = {'src/client/dispatch.rs': 'd9a366571783230d186a96396c9974a59347e8a2d46f4587ec138dde84ed94e6', 'src/proto/h2/client.rs': '323d957facddb0f881515dbb162c22ddfce47eeb3042b85439f55629c8e6bd2b'}
HOOK = '\n#[cfg(test)]\n#[path = "client/ferrum_send_batch_tests.rs"]\nmod ferrum_send_batch_tests;\n'

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("hyper_root", type=Path)
    args = parser.parse_args()
    root = args.hyper_root.resolve()
    for name, expected in BASE_FILES.items():
        actual = hashlib.sha256((root / name).read_bytes()).hexdigest()
        if actual != expected:
            raise SystemExit(f"Refusing non-base source: {name}: {actual}")
    repo = Path(__file__).resolve().parents[3]
    source = repo / "vendor/hyper-1.10.0-ferrum-patched/src/proto/h2/client/ferrum_send_batch_tests.rs"
    target = root / "src/proto/h2/client/ferrum_send_batch_tests.rs"
    if target.exists():
        raise SystemExit("Refusing existing test target")
    target.parent.mkdir(exist_ok=True)
    target.write_bytes(source.read_bytes())
    client = root / "src/proto/h2/client.rs"
    client.write_bytes(client.read_bytes() + HOOK.encode())
    print(json.dumps({"kind": "test-only-baseline-overlay", "base": BASE_SHA,
        "checked_runtime_source_sha256": BASE_FILES,
        "test_sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
        "required_cfg": "ferrum_h2_batch_control"}, sort_keys=True))

if __name__ == "__main__":
    main()
