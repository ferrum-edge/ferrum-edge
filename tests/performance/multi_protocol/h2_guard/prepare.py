"""Hosted-only preparation of an isolated diagnostic build; never edits checkout."""
import argparse
import difflib
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tarfile
import urllib.request

ASSETS = Path(__file__).resolve().parent
ROOT = ASSETS.parents[3]
SHA256 = "ef8e5e5a340588f4452631496976cf8636d4a7ecf600239fdc27615d2530bc16"
REVISION = "d57d1b852fec9dda6d42d3454502006d52104da8"
URL = "https://static.crates.io/crates/h2/h2-0.4.19.crate"
VENDOR = "vendor/h2-0.4.19-observation"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def extract_source(data, destination):
    """Validate before extraction; refuse links, duplicates, traversal and bombs."""
    if len(data) > 2 * 1024 * 1024 or sha(data) != SHA256:
        raise ValueError("h2 source archive checksum/size mismatch")
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        members = archive.getmembers()
        names = set()
        if len(members) > 1000 or sum(m.size for m in members) > 8 * 1024 * 1024:
            raise ValueError("h2 expanded source exceeds bound")
        for member in members:
            path = PurePosixPath(member.name)
            if (path.is_absolute() or ".." in path.parts or not path.parts
                    or path.parts[0] != "h2-0.4.19" or member.name in names
                    or not (member.isfile() or member.isdir())):
                raise ValueError("invalid h2 archive member")
            names.add(member.name)
        for member in members:
            if member.isfile():
                path = destination.joinpath(*PurePosixPath(member.name).parts[1:])
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(archive.extractfile(member).read())
    vcs = json.loads((destination / ".cargo_vcs_info.json").read_text())
    if vcs["git"]["sha1"] != REVISION:
        raise ValueError("h2 immutable revision mismatch")


def patch_source(source, provenance):
    patch = (ASSETS / "h2-0.4.19.patch").read_bytes()
    if sha(patch) != provenance["patch_sha256"]:
        raise ValueError("patch identity mismatch")
    for name, hashes in provenance["files"].items():
        if sha((source / name).read_bytes()) != hashes["before"]:
            raise ValueError("h2 preimage mismatch: " + name)
    subprocess.run(["patch", "--batch", "--fuzz=0", "-p1"],
                   input=patch, cwd=source, check=True)
    for name, hashes in provenance["files"].items():
        if sha((source / name).read_bytes()) != hashes["after"]:
            raise ValueError("h2 postimage mismatch: " + name)
    for asset, target in (("observer.rs", "guard_observe.rs"), ("guard_tests.rs", "guard_tests.rs")):
        raw = (ASSETS / asset).read_bytes()
        if sha(raw) != provenance["assets"][asset]:
            raise ValueError("observer/test identity mismatch")
        destination = source / "src/proto/streams" / target
        if destination.exists():
            raise ValueError("unexpected injected-file collision")
        destination.write_bytes(raw)


def select_dependency(context, evidence, provenance):
    original = (context / "Cargo.toml").read_text()
    if original.count("[patch.crates-io]\n") != 1:
        raise ValueError("unexpected root patch table")
    modified = original.replace("[patch.crates-io]\n", '[patch.crates-io]\nh2 = { path = "' + VENDOR + '" }\n')
    (context / "Cargo.toml").write_text(modified)
    diff = "".join(difflib.unified_diff(original.splitlines(True), modified.splitlines(True),
                                       fromfile="a/Cargo.toml", tofile="b/Cargo.toml"))
    lock = (context / "Cargo.lock").read_text()
    pin = ('name = "h2"\nversion = "0.4.19"\n'
           'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
           f'checksum = "{SHA256}"\n')
    if lock.count(pin) != 1:
        raise ValueError("root lock no longer pins the approved h2 archive")
    selected = lock.replace(pin, 'name = "h2"\nversion = "0.4.19"\n')
    (context / "Cargo.lock").write_text(selected)
    diff += "".join(difflib.unified_diff(lock.splitlines(True), selected.splitlines(True),
                                        fromfile="a/Cargo.lock", tofile="b/Cargo.lock"))
    # Keep the existing Docker stages/features/profile. Lock both Cargo calls in
    # this generated copy; the ordinary Dockerfile is never rewritten.
    docker = (context / "Dockerfile").read_text()
    if docker.count('cargo build --features "${FEATURES}"') != 2:
        raise ValueError("Docker build recipe drift")
    locked = docker.replace('cargo build --features "${FEATURES}"',
                            'cargo build --locked --features "${FEATURES}"')
    (context / "Dockerfile").write_text(locked)
    diff += "".join(difflib.unified_diff(docker.splitlines(True), locked.splitlines(True),
                                        fromfile="a/Dockerfile", tofile="b/Dockerfile"))
    # No shipping route/API change: insert the narrow authenticated snapshot
    # trigger only in this disposable build, with exact context identities.
    hook = (ASSETS / "metrics-hook.txt").read_bytes()
    if sha(hook) != provenance["assets"]["metrics-hook.txt"]:
        raise ValueError("metrics hook identity mismatch")
    admin = context / "src/admin/mod.rs"
    before = admin.read_bytes()
    pin = provenance["context_files"]["src/admin/mod.rs"]
    anchor = b"        let mut metrics_output = registry.render();\n"
    if sha(before) != pin["before"] or before.count(anchor) != 1:
        raise ValueError("diagnostic metrics context drift")
    after = before.replace(anchor, anchor + hook)
    if sha(after) != pin["after"]:
        raise ValueError("diagnostic metrics postimage mismatch")
    admin.write_bytes(after)
    shutil.copy2(admin, evidence / "diagnostic-admin.rs")
    diff += "".join(difflib.unified_diff(before.decode().splitlines(True), after.decode().splitlines(True),
                                       fromfile="a/src/admin/mod.rs", tofile="b/src/admin/mod.rs"))
    (evidence / "selection.patch").write_text(diff)
    for name in ("Cargo.toml", "Cargo.lock", "Dockerfile", ".dockerignore"):
        shutil.copy2(context / name, evidence / name.lstrip("."))


def check_pins_only(provenance):
    """Check pinned source anchors and print replacement context hashes."""
    admin = (ROOT / "src/admin/mod.rs").read_bytes()
    anchor = b"        let mut metrics_output = registry.render();\n"
    if admin.count(anchor) != 1:
        raise SystemExit("pin check failed: src/admin/mod.rs metrics anchor must occur once")
    hook = (ASSETS / "metrics-hook.txt").read_bytes()
    after = admin.replace(anchor, anchor + hook)
    before_hash = sha(admin)
    after_hash = sha(after)

    lock = (ROOT / "Cargo.lock").read_text()
    lock_anchor = ('name = "h2"\nversion = "0.4.19"\n'
                   'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
                   f'checksum = "{SHA256}"\n')
    if lock.count(lock_anchor) != 1:
        raise SystemExit("pin check failed: approved h2 0.4.19 lock anchor must occur once")

    manifest = (ROOT / "Cargo.toml").read_text()
    patch_anchor = "[patch.crates-io]\n"
    if manifest.count(patch_anchor) != 1:
        raise SystemExit("pin check failed: Cargo.toml [patch.crates-io] anchor must occur once")

    docker = (ROOT / "Dockerfile").read_text()
    cargo_anchor = 'cargo build --features "${FEATURES}"'
    if docker.count(cargo_anchor) != 2:
        raise SystemExit("pin check failed: Dockerfile cargo build anchor must occur twice")

    expected = provenance["context_files"]["src/admin/mod.rs"]
    print("Computed source.json replacement values:")
    print('"context_files": {')
    print('  "src/admin/mod.rs": {')
    print(f'    "before": "{before_hash}",')
    print(f'    "after": "{after_hash}"')
    print("  }")
    print("}")
    if (before_hash, after_hash) != (expected["before"], expected["after"]):
        raise SystemExit("pin check failed: update source.json with the computed values above")
    print("H2 guard pins match source.json and all pinned input anchors are present.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check-pins-only", action="store_true")
    args = parser.parse_args()
    if args.check_pins_only:
        provenance = json.loads((ASSETS / "source.json").read_text())
        check_pins_only(provenance)
        return
    if args.output is None:
        parser.error("--output is required unless --check-pins-only is selected")
    if (os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
            or os.environ.get("RUNNER_OS") != "Linux"):
        raise SystemExit("preparation requires a GitHub-hosted Linux runner")
    output = args.output.resolve()
    if output.exists():
        raise SystemExit("output must be a new directory")
    provenance = json.loads((ASSETS / "source.json").read_text())
    if (provenance["url"], provenance["sha256"], provenance["revision"]) != (URL, SHA256, REVISION):
        raise ValueError("source provenance differs from immutable preparation pins")
    output.mkdir(parents=True)
    evidence = output / "evidence"
    shutil.copytree(ASSETS, evidence / "assets")
    with urllib.request.urlopen(URL, timeout=60) as response:
        raw = response.read(2 * 1024 * 1024 + 1)
    (evidence / "h2-0.4.19.crate").write_bytes(raw)
    context = output / "context"
    shutil.copytree(ROOT, context, ignore=shutil.ignore_patterns(".git", "target", ".cache", "__pycache__"))
    source = context / VENDOR
    source.mkdir()
    extract_source(raw, source)
    # Keep an unmodified copy of the verified archive for same-toolchain lint
    # comparison. Do not alter upstream code merely to silence newer Clippy.
    shutil.copytree(source, output / "upstream")
    patch_source(source, provenance)
    select_dependency(context, evidence, provenance)
    identity = dict(source=provenance, checkout=os.environ["GITHUB_SHA"],
                    run_id=os.environ["GITHUB_RUN_ID"], attempt=os.environ["GITHUB_RUN_ATTEMPT"],
                    features="cloud-secrets", profile="release", image_target="runtime",
                    ordinary_dependency_graph_changed=False,
                    files={str(p.relative_to(ASSETS)): sha(p.read_bytes())
                           for p in sorted(ASSETS.iterdir()) if p.is_file()})
    (evidence / "preparation.json").write_text(json.dumps(identity, indent=2) + "\n")
    print(source)


if __name__ == "__main__":
    main()
