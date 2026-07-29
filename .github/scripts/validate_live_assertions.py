#!/usr/bin/env python3
"""Validate an emitted `live-assertions.json` artifact against a live contract.

Live datapath suites (`tests/k8s/lib/live_assertions.sh`) emit one JSON
document per run:

    {
      "schema_version": 1,
      "suite": "...",
      "commit": "...",
      "platform_profile": "...",
      "created_at": "<ISO-8601, tz-aware>",
      "assertions": [{"id": ..., "status": pass|fail|skip, "timestamp": ...}]
    }

The fixture's own `ferrum_live_assertions_require_all_passed` call only proves
that the *fixture process* saw the required ids pass. It cannot prove that the
artifact the workflow published is the one that process wrote, that it belongs
to this commit, that it came from the expected platform profile, or that it is
not a stale document left behind by an earlier run. This validator closes that
gap: it reads the published artifact and fails closed on anything it cannot
positively confirm.

Standard library only, and deliberately free of any subprocess dispatch, so it
can run in a workflow job that must not introduce a build/toolchain surface.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

VALID_STATUSES = frozenset({"pass", "fail", "skip"})
DEFAULT_CLOCK_SKEW_SECONDS = 300
DEFAULT_MAX_AGE_SECONDS = 6 * 60 * 60


class ArtifactError(Exception):
    """A fail-closed rejection of a published live-assertion artifact."""


def _parse_timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ArtifactError(f"{label} must be a non-empty ISO-8601 string")
    text = value.strip()
    # `Z` is valid ISO-8601 but older interpreters reject it in fromisoformat.
    if text.endswith(("Z", "z")):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as error:
        raise ArtifactError(f"{label} is not a valid ISO-8601 timestamp: {error}")
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ArtifactError(
            f"{label} must carry a UTC offset; a naive timestamp cannot be "
            "aged against the validating clock"
        )
    return parsed.astimezone(timezone.utc)


def _require_string(payload: dict[str, Any], key: str) -> str:
    if key not in payload:
        raise ArtifactError(f"artifact is missing required field `{key}`")
    value = payload[key]
    if not isinstance(value, str) or not value.strip():
        raise ArtifactError(f"artifact field `{key}` must be a non-empty string")
    return value


def load_artifact(path: Path) -> dict[str, Any]:
    """Read the artifact as JSON, refusing anything but a regular file."""

    if path.is_symlink():
        raise ArtifactError(f"{path} must be a regular file, not a symlink")
    if not path.is_file():
        raise ArtifactError(
            f"{path} does not exist or is not a regular file; the live suite "
            "published no assertion artifact for this run"
        )
    raw = path.read_text(encoding="utf-8")
    if not raw.strip():
        raise ArtifactError(f"{path} is empty")
    try:
        payload = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ArtifactError(f"{path} is not valid JSON: {error}")
    if not isinstance(payload, dict):
        raise ArtifactError(f"{path} must contain a JSON object at the top level")
    return payload


def validate_artifact(
    payload: dict[str, Any],
    *,
    schema_version: int,
    suite: str,
    commit: str,
    platform_profile: str,
    required_ids: set[str],
    required_namespaces: tuple[str, ...] = (),
    max_age_seconds: int = DEFAULT_MAX_AGE_SECONDS,
    clock_skew_seconds: int = DEFAULT_CLOCK_SKEW_SECONDS,
    now: datetime | None = None,
) -> list[str]:
    """Return a summary, or raise `ArtifactError` on the first failure found."""

    reference = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)

    observed_version = payload.get("schema_version")
    if observed_version != schema_version:
        raise ArtifactError(
            f"artifact schema_version is {observed_version!r}, expected "
            f"{schema_version!r}"
        )

    observed_suite = _require_string(payload, "suite")
    if observed_suite != suite:
        raise ArtifactError(
            f"artifact suite is {observed_suite!r}, expected {suite!r}"
        )

    observed_commit = _require_string(payload, "commit")
    if observed_commit != commit:
        raise ArtifactError(
            f"artifact commit is {observed_commit!r}, expected the exact "
            f"validated commit {commit!r}"
        )

    observed_profile = _require_string(payload, "platform_profile")
    if observed_profile != platform_profile:
        raise ArtifactError(
            f"artifact platform_profile is {observed_profile!r}, expected "
            f"{platform_profile!r}"
        )

    created_at = _parse_timestamp(payload.get("created_at"), "created_at")
    if created_at > reference + timedelta(seconds=clock_skew_seconds):
        raise ArtifactError(
            f"artifact created_at {created_at.isoformat()} is in the future "
            "relative to the validating clock"
        )
    age = reference - created_at
    if age > timedelta(seconds=max_age_seconds):
        raise ArtifactError(
            f"artifact created_at {created_at.isoformat()} is "
            f"{int(age.total_seconds())}s old, beyond the {max_age_seconds}s "
            "freshness ceiling; this is not the artifact this run produced"
        )

    assertions = payload.get("assertions")
    if not isinstance(assertions, list):
        raise ArtifactError("artifact field `assertions` must be a list")
    if not assertions:
        raise ArtifactError("artifact recorded no assertions at all")

    observed: dict[str, str] = {}
    for index, entry in enumerate(assertions):
        label = f"assertions[{index}]"
        if not isinstance(entry, dict):
            raise ArtifactError(f"{label} must be a JSON object")
        assertion_id = entry.get("id")
        if not isinstance(assertion_id, str) or not assertion_id.strip():
            raise ArtifactError(f"{label} must carry a non-empty string `id`")
        status = entry.get("status")
        if status not in VALID_STATUSES:
            raise ArtifactError(
                f"{label} (`{assertion_id}`) has status {status!r}, which is "
                f"not one of {sorted(VALID_STATUSES)}"
            )
        stamped = _parse_timestamp(
            entry.get("timestamp"),
            f"{label} (`{assertion_id}`) timestamp",
        )
        if stamped > reference + timedelta(seconds=clock_skew_seconds):
            raise ArtifactError(
                f"{label} (`{assertion_id}`) timestamp {stamped.isoformat()} "
                "is in the future relative to the validating clock"
            )
        if reference - stamped > timedelta(seconds=max_age_seconds):
            raise ArtifactError(
                f"{label} (`{assertion_id}`) timestamp {stamped.isoformat()} "
                f"is beyond the {max_age_seconds}s freshness ceiling"
            )
        observed[assertion_id] = status

    duplicates = sorted(
        assertion_id
        for assertion_id, count in Counter(
            entry["id"] for entry in assertions
        ).items()
        if count > 1
    )
    if duplicates:
        raise ArtifactError(
            "artifact records duplicate assertion ids (a re-recorded id can "
            f"overwrite a failure with a later pass): {duplicates}"
        )

    missing = sorted(required_ids - set(observed))
    if missing:
        raise ArtifactError(
            f"artifact is missing required assertion ids: {missing}"
        )

    extra = sorted(
        assertion_id
        for assertion_id in observed
        if assertion_id not in required_ids
        and any(
            assertion_id.startswith(namespace)
            for namespace in required_namespaces
        )
    )
    if extra:
        raise ArtifactError(
            "artifact records assertion ids inside a governed namespace that "
            "the release contract does not require (add the contract row, or "
            f"rename the diagnostic assertion): {extra}"
        )

    not_passing = sorted(
        f"{assertion_id}={observed[assertion_id]}"
        for assertion_id in required_ids
        if observed[assertion_id] != "pass"
    )
    if not_passing:
        raise ArtifactError(
            "required assertions did not pass (a required `skip` is a failure "
            f"for a release gate): {not_passing}"
        )

    return [
        f"suite={observed_suite}",
        f"commit={observed_commit}",
        f"platform_profile={observed_profile}",
        f"schema_version={schema_version}",
        f"assertions={len(assertions)}",
        f"required={len(required_ids)} (all pass)",
        f"age={int(age.total_seconds())}s",
    ]


# ── self-test ────────────────────────────────────────────────────────────────

_BASE_TIME = datetime(2026, 7, 29, 12, 0, 0, tzinfo=timezone.utc)
_SELF_TEST_KWARGS: dict[str, Any] = {
    "schema_version": 1,
    "suite": "multicluster-federation",
    "commit": "0123456789abcdef0123456789abcdef01234567",
    "platform_profile": "kind-spire-multicluster-federation",
    "required_ids": {"suite.alpha", "suite.beta"},
    "required_namespaces": ("suite.",),
    "max_age_seconds": DEFAULT_MAX_AGE_SECONDS,
    "now": _BASE_TIME,
}


def _self_test_payload() -> dict[str, Any]:
    stamp = (_BASE_TIME - timedelta(minutes=5)).isoformat()
    return {
        "schema_version": 1,
        "suite": "multicluster-federation",
        "commit": "0123456789abcdef0123456789abcdef01234567",
        "platform_profile": "kind-spire-multicluster-federation",
        "created_at": (_BASE_TIME - timedelta(minutes=30)).isoformat(),
        "assertions": [
            {"id": "suite.alpha", "status": "pass", "timestamp": stamp},
            {"id": "suite.beta", "status": "pass", "timestamp": stamp},
            {"id": "diagnostic.note", "status": "skip", "timestamp": stamp},
        ],
    }


def _expect_rejection(payload: dict[str, Any], because: str) -> None:
    try:
        validate_artifact(payload, **_SELF_TEST_KWARGS)
    except ArtifactError:
        return
    raise AssertionError(f"validator accepted an artifact it must reject: {because}")


def run_self_test() -> None:
    """Prove the validator is fail-closed on every contract dimension."""

    accepted = validate_artifact(_self_test_payload(), **_SELF_TEST_KWARGS)
    assert any(item.startswith("required=2") for item in accepted), accepted

    stamp = (_BASE_TIME - timedelta(minutes=5)).isoformat()

    mutations: list[tuple[str, Any, Any]] = [
        ("schema_version", 2, "wrong schema version"),
        ("schema_version", "1", "string schema version"),
        ("suite", "mesh-e2e-sidecar", "wrong suite"),
        ("suite", "", "blank suite"),
        ("commit", "deadbeef", "wrong commit"),
        ("platform_profile", "kind-spire-sidecar", "wrong platform profile"),
        ("created_at", "not-a-timestamp", "malformed created_at"),
        ("created_at", "2026-07-29T11:30:00", "naive created_at"),
        (
            "created_at",
            (_BASE_TIME + timedelta(hours=1)).isoformat(),
            "future created_at",
        ),
        (
            "created_at",
            (_BASE_TIME - timedelta(hours=7)).isoformat(),
            "stale created_at",
        ),
        ("assertions", {}, "assertions is not a list"),
        ("assertions", [], "no assertions recorded"),
    ]
    for key, value, because in mutations:
        payload = _self_test_payload()
        payload[key] = value
        _expect_rejection(payload, because)

    for key in ("schema_version", "suite", "commit", "platform_profile", "created_at"):
        payload = _self_test_payload()
        del payload[key]
        _expect_rejection(payload, f"missing `{key}`")

    payload = _self_test_payload()
    payload["assertions"] = [
        entry for entry in payload["assertions"] if entry["id"] != "suite.beta"
    ]
    _expect_rejection(payload, "missing required id")

    payload = _self_test_payload()
    for entry in payload["assertions"]:
        if entry["id"] == "suite.beta":
            entry["status"] = "skip"
    _expect_rejection(payload, "required id skipped")

    payload = _self_test_payload()
    for entry in payload["assertions"]:
        if entry["id"] == "suite.beta":
            entry["status"] = "fail"
    _expect_rejection(payload, "required id failed")

    payload = _self_test_payload()
    for entry in payload["assertions"]:
        if entry["id"] == "suite.beta":
            entry["status"] = "passed"
    _expect_rejection(payload, "unknown status word")

    payload = _self_test_payload()
    payload["assertions"].append(
        {"id": "suite.alpha", "status": "pass", "timestamp": stamp}
    )
    _expect_rejection(payload, "duplicate assertion id")

    payload = _self_test_payload()
    payload["assertions"].append(
        {"id": "suite.gamma", "status": "pass", "timestamp": stamp}
    )
    _expect_rejection(payload, "extra id inside the governed namespace")

    payload = _self_test_payload()
    payload["assertions"].append("suite.delta")
    _expect_rejection(payload, "assertion entry is not an object")

    payload = _self_test_payload()
    payload["assertions"].append({"status": "pass", "timestamp": stamp})
    _expect_rejection(payload, "assertion entry has no id")

    payload = _self_test_payload()
    payload["assertions"][0]["timestamp"] = (
        _BASE_TIME + timedelta(hours=1)
    ).isoformat()
    _expect_rejection(payload, "future assertion timestamp")

    payload = _self_test_payload()
    payload["assertions"][0]["timestamp"] = (
        _BASE_TIME - timedelta(hours=9)
    ).isoformat()
    _expect_rejection(payload, "stale assertion timestamp")

    payload = _self_test_payload()
    del payload["assertions"][0]["timestamp"]
    _expect_rejection(payload, "assertion entry has no timestamp")

    # A `Z`-suffixed UTC stamp is valid ISO-8601 and must stay accepted.
    payload = _self_test_payload()
    payload["created_at"] = (
        (_BASE_TIME - timedelta(minutes=30))
        .replace(tzinfo=None)
        .isoformat()
        + "Z"
    )
    validate_artifact(payload, **_SELF_TEST_KWARGS)

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        absent = root / "live-assertions.json"
        for path, because in (
            (absent, "artifact file does not exist"),
            (root, "artifact path is a directory"),
        ):
            try:
                load_artifact(path)
            except ArtifactError:
                continue
            raise AssertionError(f"load_artifact accepted: {because}")

        malformed = root / "malformed.json"
        malformed.write_text("{not json", encoding="utf-8")
        try:
            load_artifact(malformed)
        except ArtifactError:
            pass
        else:
            raise AssertionError("load_artifact accepted malformed JSON")

        blank = root / "blank.json"
        blank.write_text("   \n", encoding="utf-8")
        try:
            load_artifact(blank)
        except ArtifactError:
            pass
        else:
            raise AssertionError("load_artifact accepted an empty artifact")

        scalar = root / "scalar.json"
        scalar.write_text("[]", encoding="utf-8")
        try:
            load_artifact(scalar)
        except ArtifactError:
            pass
        else:
            raise AssertionError("load_artifact accepted a non-object artifact")

        real = root / "real.json"
        real.write_text(json.dumps(_self_test_payload()), encoding="utf-8")
        link = root / "link.json"
        try:
            link.symlink_to(real)
        except (OSError, NotImplementedError):
            link = None
        if link is not None:
            try:
                load_artifact(link)
            except ArtifactError:
                pass
            else:
                raise AssertionError("load_artifact accepted a symlinked artifact")
        assert load_artifact(real)["suite"] == "multicluster-federation"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", type=Path)
    parser.add_argument("--schema-version", type=int, default=1)
    parser.add_argument("--suite")
    parser.add_argument("--commit")
    parser.add_argument("--platform-profile")
    parser.add_argument(
        "--require",
        action="append",
        default=[],
        metavar="ASSERTION_ID",
        help="an assertion id the release contract requires to be present and pass",
    )
    parser.add_argument(
        "--required-namespace",
        action="append",
        default=[],
        metavar="PREFIX",
        help=(
            "an id prefix the release contract owns completely; any recorded id "
            "under it that is not in --require is rejected"
        ),
    )
    parser.add_argument(
        "--max-age-seconds", type=int, default=DEFAULT_MAX_AGE_SECONDS
    )
    parser.add_argument(
        "--clock-skew-seconds", type=int, default=DEFAULT_CLOCK_SKEW_SECONDS
    )
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        run_self_test()
        print("validate_live_assertions self-test passed")
        return 0

    missing_options = [
        name
        for name, value in (
            ("--artifact", args.artifact),
            ("--suite", args.suite),
            ("--commit", args.commit),
            ("--platform-profile", args.platform_profile),
        )
        if not value
    ]
    if missing_options or not args.require:
        if not args.require:
            missing_options.append("--require")
        print(
            "::error::validate_live_assertions requires "
            + ", ".join(missing_options),
            file=sys.stderr,
        )
        return 2
    if args.max_age_seconds <= 0 or args.clock_skew_seconds < 0:
        print(
            "::error::validate_live_assertions freshness bounds must be positive",
            file=sys.stderr,
        )
        return 2

    required_ids = set(args.require)
    if len(required_ids) != len(args.require):
        print(
            "::error::--require lists the same assertion id more than once",
            file=sys.stderr,
        )
        return 2

    try:
        payload = load_artifact(args.artifact)
        summary = validate_artifact(
            payload,
            schema_version=args.schema_version,
            suite=args.suite,
            commit=args.commit,
            platform_profile=args.platform_profile,
            required_ids=required_ids,
            required_namespaces=tuple(args.required_namespace),
            max_age_seconds=args.max_age_seconds,
            clock_skew_seconds=args.clock_skew_seconds,
        )
    except ArtifactError as error:
        print(f"::error::live assertion artifact rejected: {error}", file=sys.stderr)
        return 1

    for line in summary:
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
