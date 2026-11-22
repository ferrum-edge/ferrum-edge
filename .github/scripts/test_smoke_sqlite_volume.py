#!/usr/bin/env python3
"""Unit tests and static contract checks for scripts/smoke_sqlite_volume.sh.

Executed by verify_required_ci.py in Tests. Stays free of process APIs so
trusted automation policy can statically audit this module.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import sqlite3
import tarfile
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SMOKE_SH = REPO_ROOT / "scripts" / "smoke_sqlite_volume.sh"
VERIFY_PY = REPO_ROOT / "scripts" / "smoke_sqlite_volume_verify.py"

_SPEC = importlib.util.spec_from_file_location("smoke_sqlite_volume_verify", VERIFY_PY)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError(f"unable to load {VERIFY_PY}")
verify = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(verify)

DISTROLESS_PASSWD = (
    "root:x:0:0:root:/root:/sbin/nologin\n"
    "nobody:x:65534:65534:nobody:/nonexistent:/sbin/nologin\n"
    "nonroot:x:65532:65532:nonroot:/home/nonroot:/sbin/nologin\n"
)
DISTROLESS_GROUP = (
    "root:x:0:\n"
    "tty:x:5:\n"
    "staff:x:50:\n"
    "nobody:x:65534:\n"
    "nonroot:x:65532:\n"
)
PROCESS_API_TOKENS = (
    "sub" + "process",
    "os." + "system",
    "os." + "popen",
    "os." + "execl",
    "os." + "execv",
    "os." + "spawn",
    "os." + "posix_spawn",
    "asyncio.create_sub" + "process",
)


def _write_single_file_tar(tar_path: Path, member_name: str, content: str) -> Path:
    data = content.encode("utf-8")
    with tarfile.open(tar_path, "w") as archive:
        info = tarfile.TarInfo(name=member_name)
        info.size = len(data)
        info.mode = 0o644
        archive.addfile(info, io.BytesIO(data))
    return tar_path


def _write_data_tar(
    tar_path: Path,
    *,
    dir_name: str = "data",
    dir_uid: int = 65532,
    dir_gid: int = 65532,
    dir_mode: int = 0o755,
    db_name: str | None = "data/ferrum.db",
    db_uid: int = 65532,
    db_gid: int = 65532,
    db_bytes: bytes = b"SQLite format 3\x00test-payload",
    db_symlink: bool = False,
    extra_files: list[tuple[str, int, int, bytes]] | None = None,
) -> Path:
    with tarfile.open(tar_path, "w") as archive:
        dir_info = tarfile.TarInfo(name=dir_name)
        dir_info.type = tarfile.DIRTYPE
        dir_info.uid = dir_uid
        dir_info.gid = dir_gid
        dir_info.mode = dir_mode
        archive.addfile(dir_info)

        if db_name is not None:
            db_info = tarfile.TarInfo(name=db_name)
            db_info.uid = db_uid
            db_info.gid = db_gid
            if db_symlink:
                db_info.type = tarfile.SYMTYPE
                db_info.linkname = "/tmp/other.db"
                archive.addfile(db_info)
            else:
                db_info.size = len(db_bytes)
                db_info.mode = 0o644
                archive.addfile(db_info, io.BytesIO(db_bytes))

        for name, uid, gid, payload in extra_files or []:
            info = tarfile.TarInfo(name=name)
            info.uid = uid
            info.gid = gid
            info.size = len(payload)
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(payload))
    return tar_path


def _write_migrations_db(db_path: Path, rows: list[tuple[int, str, str, str, int]]) -> Path:
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            "CREATE TABLE _ferrum_migrations ("
            "version INTEGER, name TEXT, applied_at TEXT, "
            "checksum TEXT, execution_time_ms INTEGER)"
        )
        conn.executemany(
            "INSERT INTO _ferrum_migrations VALUES (?, ?, ?, ?, ?)",
            rows,
        )
        conn.commit()
    finally:
        conn.close()
    return db_path


class SmokeSqliteVolumeTests(unittest.TestCase):
    def test_resolve_user_accepts_distroless_bare_uid_with_matching_primary_gid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            passwd_tar = _write_single_file_tar(root / "passwd.tar", "passwd", DISTROLESS_PASSWD)
            group_tar = _write_single_file_tar(root / "group.tar", "group", DISTROLESS_GROUP)
            for config_user in (
                "65532",
                "65532:",
                "65532:65532",
                "nonroot",
                "nonroot:nonroot",
                "65532:nonroot",
                "nonroot:65532",
            ):
                with self.subTest(config_user=config_user):
                    self.assertEqual(
                        verify.verify_configured_user(config_user, passwd_tar, group_tar),
                        (65532, 65532),
                    )

    def test_resolve_user_accepts_explicit_numeric_uid_gid_without_etc_files(self) -> None:
        self.assertEqual(
            verify.verify_configured_user("65532:65532", None, None),
            (65532, 65532),
        )

    def test_resolve_user_rejects_bare_uid_when_primary_gid_is_wrong_or_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            wrong_gid_passwd = _write_single_file_tar(
                root / "wrong-gid.tar",
                "passwd",
                "nonroot:x:65532:0:nonroot:/home/nonroot:/sbin/nologin\n",
            )
            other_gid_passwd = _write_single_file_tar(
                root / "other-gid.tar",
                "passwd",
                "nonroot:x:65532:1000:nonroot:/home/nonroot:/sbin/nologin\n",
            )
            no_nonroot_passwd = _write_single_file_tar(
                root / "no-nonroot.tar",
                "passwd",
                "root:x:0:0:root:/root:/sbin/nologin\n",
            )
            for label, passwd_tar in (
                ("gid 0 in /etc/passwd", wrong_gid_passwd),
                ("gid 1000 in /etc/passwd", other_gid_passwd),
                ("uid 65532 absent from /etc/passwd", no_nonroot_passwd),
                ("missing /etc/passwd", None),
            ):
                with self.subTest(label=label):
                    with self.assertRaisesRegex(ValueError, "expected default UID/GID 65532:65532"):
                        verify.verify_configured_user("65532", passwd_tar, None)

    def test_resolve_user_rejects_root_wrong_ids_and_malformed_specs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            passwd_tar = _write_single_file_tar(root / "passwd.tar", "passwd", DISTROLESS_PASSWD)
            group_tar = _write_single_file_tar(root / "group.tar", "group", DISTROLESS_GROUP)
            for bad_user in (
                "",
                "0",
                "0:0",
                "root",
                "root:root",
                "65532:0",
                "0:65532",
                "65532:root",
                "root:65532",
                ":65532",
                "1000",
                "1000:1000",
                "nonexistent",
                "65532:nonexistent",
                "65532:65532:65532",
                "-1:65532",
                " 65532",
            ):
                with self.subTest(config_user=bad_user):
                    with self.assertRaises(ValueError):
                        verify.verify_configured_user(bad_user, passwd_tar, group_tar)

    def test_resolve_user_rejects_spoofed_nonroot_or_numeric_username(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            spoofed_passwd = _write_single_file_tar(
                root / "spoofed.tar",
                "passwd",
                "nonroot:x:0:0:spoof:/root:/sbin/nologin\n"
                "65532:x:0:0:spoof:/root:/sbin/nologin\n"
                "real:x:65532:65532:real:/home/nonroot:/sbin/nologin\n",
            )
            spoofed_group = _write_single_file_tar(
                root / "spoofed-group.tar",
                "group",
                "nonroot:x:0:\n",
            )
            for config_user in ("nonroot", "nonroot:nonroot", "65532", "65532:nonroot"):
                with self.subTest(config_user=config_user):
                    with self.assertRaises(ValueError):
                        verify.verify_configured_user(config_user, spoofed_passwd, spoofed_group)

    def test_verify_data_tar_accepts_expected_owner_and_extracts_db(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            payload = b"SQLite format 3\x00hello"
            for dir_name, db_name in (("data", "data/ferrum.db"), ("./data/", "./data/ferrum.db")):
                with self.subTest(dir_name=dir_name):
                    tar_path = _write_data_tar(
                        root / "ok.tar",
                        dir_name=dir_name,
                        db_name=db_name,
                        db_bytes=payload,
                        extra_files=[("data/ferrum.db-wal", 65532, 65532, b"wal")],
                    )
                    out_db = root / "extracted.db"
                    self.assertEqual(
                        verify.verify_data_tar(tar_path, extract_db=out_db),
                        (65532, 65532),
                    )
                    self.assertEqual(out_db.read_bytes(), payload)

    def test_verify_data_tar_rejects_wrong_owner_setgid_or_invalid_db(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cases = [
                ("db owned by root", {"db_uid": 0, "db_gid": 0}),
                ("db has root gid", {"db_uid": 65532, "db_gid": 0}),
                ("db has root uid", {"db_uid": 0, "db_gid": 65532}),
                ("dir owned by root", {"dir_uid": 0, "dir_gid": 0}),
                ("dir has setgid bit", {"dir_mode": 0o2755}),
                ("db missing", {"db_name": None}),
                ("db empty", {"db_bytes": b""}),
                ("db symlink", {"db_symlink": True}),
                (
                    "sibling wal has wrong gid",
                    {"extra_files": [("data/ferrum.db-wal", 65532, 0, b"wal")]},
                ),
            ]
            for index, (label, kwargs) in enumerate(cases):
                with self.subTest(label=label):
                    tar_path = _write_data_tar(root / f"bad-{index}.tar", **kwargs)
                    with self.assertRaises(ValueError):
                        verify.verify_data_tar(tar_path)

    def test_verify_migrations_accepts_matching_and_rejects_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rows = [(1, "V001_baseline", "2026-11-22T00:00:00Z", "abc", 12)]
            db1 = _write_migrations_db(root / "m1.db", rows)
            db2 = _write_migrations_db(root / "m2.db", rows)
            db_diff = _write_migrations_db(
                root / "diff.db",
                [(1, "V001_baseline", "2026-11-22T00:00:01Z", "abc", 12)],
            )
            db_empty = _write_migrations_db(root / "empty.db", [])

            self.assertEqual(verify.verify_migrations(db1, db2), 1)
            with self.assertRaisesRegex(ValueError, "did not persist"):
                verify.verify_migrations(db1, db_diff)
            with self.assertRaisesRegex(ValueError, "No applied migrations"):
                verify.verify_migrations(db_empty, db_empty)

    def test_cli_entry_points_and_leading_dash_config_user(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            passwd_tar = _write_single_file_tar(root / "passwd.tar", "passwd", DISTROLESS_PASSWD)
            group_tar = _write_single_file_tar(root / "group.tar", "group", DISTROLESS_GROUP)
            out = io.StringIO()
            err = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                rc = verify.main(
                    [
                        "resolve-user",
                        "--config-user=65532",
                        f"--passwd-tar={passwd_tar}",
                        f"--group-tar={group_tar}",
                    ]
                )
            self.assertEqual(rc, 0, err.getvalue())
            self.assertEqual(out.getvalue().strip(), "65532:65532")

            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                rc = verify.main(["resolve-user", "--config-user=-1"])
            self.assertEqual(rc, 1)
            self.assertIn("SQLite volume smoke failed:", err.getvalue())

            rows = [(1, "V001_baseline", "2026-11-22T00:00:00Z", "abc", 12)]
            db1 = _write_migrations_db(root / "m1.db", rows)
            tar_path = _write_data_tar(root / "data.tar", db_bytes=db1.read_bytes())
            extracted = root / "extracted.db"
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rc = verify.main(
                    [
                        "verify-data-tar",
                        f"--tar={tar_path}",
                        f"--extract-db={extracted}",
                    ]
                )
            self.assertEqual(rc, 0)
            self.assertEqual(out.getvalue().strip(), "65532:65532")
            self.assertEqual(
                verify.main(
                    [
                        "verify-migrations",
                        f"--migrated={db1}",
                        f"--restarted={extracted}",
                    ]
                ),
                0,
            )

    def test_smoke_script_contract_and_policy_hygiene(self) -> None:
        shell_source = SMOKE_SH.read_text(encoding="utf-8")
        verify_source = VERIFY_PY.read_text(encoding="utf-8")

        for required in (
            "python3 -I scripts/smoke_sqlite_volume_verify.py resolve-user",
            "python3 -I scripts/smoke_sqlite_volume_verify.py verify-data-tar",
            "python3 -I scripts/smoke_sqlite_volume_verify.py verify-migrations",
            'docker cp -L "$migrate:/etc/passwd" -',
            'docker cp -L "$migrate:/etc/group" -',
            'docker cp "$migrate:/data" -',
            'docker cp "$gateway:/data" -',
        ):
            self.assertIn(required, shell_source)
        self.assertNotIn("65532|65532:65532|nonroot|nonroot:nonroot", shell_source)
        for token in PROCESS_API_TOKENS:
            self.assertNotIn(token, verify_source)


def run_self_test() -> list[str]:
    """Run SQLite volume smoke verifier regressions from verify_required_ci.py."""

    result = unittest.TestResult()
    unittest.defaultTestLoader.loadTestsFromTestCase(SmokeSqliteVolumeTests).run(result)
    return [trace for _, trace in result.failures + result.errors]


if __name__ == "__main__":
    unittest.main()
