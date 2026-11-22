#!/usr/bin/env python3
"""Pure-Python identity, volume-tar, and SQLite verifiers for smoke_sqlite_volume.sh.

Docker execution stays in scripts/smoke_sqlite_volume.sh so this module stays
free of process APIs and remains directly unit-testable in CI.
"""

from __future__ import annotations

import argparse
import contextlib
import shutil
import sqlite3
import sys
import tarfile
from pathlib import Path

MAX_ETC_FILE_BYTES = 1024 * 1024
SETGID_BIT = 0o2000


def _is_nonneg_int(value: str) -> bool:
    return bool(value) and value.isascii() and value.isdigit()


def normalize_tar_name(name: str) -> str:
    if name.startswith("/"):
        raise ValueError(f"unexpected absolute tar member path: {name!r}")
    while name.startswith("./"):
        name = name[2:]
    normalized = name.rstrip("/")
    if normalized == ".":
        return ""
    if ".." in normalized.split("/"):
        raise ValueError(f"unexpected parent-traversal tar member path: {name!r}")
    return normalized


def read_single_regular_file_from_tar(tar_path: Path, label: str) -> str:
    try:
        with tarfile.open(tar_path, "r:*") as archive:
            regular_members = [m for m in archive.getmembers() if m.isfile()]
            if len(regular_members) != 1:
                raise ValueError(
                    f"{label} tar must contain exactly one regular file, "
                    f"found {len(regular_members)}"
                )
            member = regular_members[0]
            if member.size > MAX_ETC_FILE_BYTES:
                raise ValueError(
                    f"{label} exceeds size limit ({member.size} > {MAX_ETC_FILE_BYTES})"
                )
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError(f"could not read {label} from tar archive")
            with stream:
                raw = stream.read(MAX_ETC_FILE_BYTES + 1)
    except (OSError, tarfile.TarError) as exc:
        raise ValueError(f"failed to read {label} tar archive: {exc}") from exc
    if len(raw) > MAX_ETC_FILE_BYTES:
        raise ValueError(f"{label} exceeds size limit ({MAX_ETC_FILE_BYTES} bytes)")
    return raw.decode("utf-8", errors="replace")


def parse_passwd(text: str) -> list[tuple[str, int, int]]:
    entries: list[tuple[str, int, int]] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split(":")
        if len(fields) < 4:
            continue
        name = fields[0]
        uid_str = fields[2].strip()
        gid_str = fields[3].strip()
        if not (_is_nonneg_int(uid_str) and _is_nonneg_int(gid_str)):
            continue
        entries.append((name, int(uid_str), int(gid_str)))
    return entries


def parse_group(text: str) -> list[tuple[str, int]]:
    entries: list[tuple[str, int]] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split(":")
        if len(fields) < 3:
            continue
        name = fields[0]
        gid_str = fields[2].strip()
        if not _is_nonneg_int(gid_str):
            continue
        entries.append((name, int(gid_str)))
    return entries


def resolve_oci_user(
    config_user: str,
    passwd_entries: list[tuple[str, int, int]],
    group_entries: list[tuple[str, int]],
) -> tuple[int, int]:
    """Resolve Docker/OCI Config.User to effective numeric (uid, gid).

    Matches runc/libcontainer/user.GetExecUser semantics:
    - Empty Config.User defaults to 0:0 (root).
    - A bare UID or username resolves its primary GID from container /etc/passwd;
      a numeric UID absent from /etc/passwd defaults to GID 0 (root).
    - An explicit group after ':' resolves via container /etc/group or numeric GID.
    """
    if config_user == "":
        return 0, 0
    if config_user.count(":") > 1:
        raise ValueError(f"malformed Config.User {config_user!r}")

    user_part, _has_colon, group_part = config_user.partition(":")

    if user_part == "":
        uid = 0
        gid = 0
    else:
        matched_user: tuple[str, int, int] | None = None
        for entry in passwd_entries:
            if entry[0] == user_part:
                matched_user = entry
                break
        if matched_user is None and _is_nonneg_int(user_part):
            wanted_uid = int(user_part)
            for entry in passwd_entries:
                if entry[1] == wanted_uid:
                    matched_user = entry
                    break

        if matched_user is not None:
            uid = matched_user[1]
            gid = matched_user[2]
        elif _is_nonneg_int(user_part):
            uid = int(user_part)
            gid = 0
        else:
            raise ValueError(
                f"user {user_part!r} in Config.User={config_user!r} "
                "not found in container /etc/passwd"
            )

    if group_part != "":
        matched_group: tuple[str, int] | None = None
        for entry in group_entries:
            if entry[0] == group_part:
                matched_group = entry
                break
        if matched_group is not None:
            gid = matched_group[1]
        elif _is_nonneg_int(group_part):
            gid = int(group_part)
        else:
            raise ValueError(
                f"group {group_part!r} in Config.User={config_user!r} "
                "not found in container /etc/group"
            )

    return uid, gid


def verify_configured_user(
    config_user: str,
    passwd_tar: Path | None,
    group_tar: Path | None,
    expected_uid: int = 65532,
    expected_gid: int = 65532,
) -> tuple[int, int]:
    passwd_entries = (
        parse_passwd(read_single_regular_file_from_tar(passwd_tar, "/etc/passwd"))
        if passwd_tar is not None
        else []
    )
    group_entries = (
        parse_group(read_single_regular_file_from_tar(group_tar, "/etc/group"))
        if group_tar is not None
        else []
    )
    uid, gid = resolve_oci_user(config_user, passwd_entries, group_entries)
    if (uid, gid) != (expected_uid, expected_gid):
        shown = config_user if config_user != "" else "<empty>"
        raise ValueError(
            f"expected default UID/GID {expected_uid}:{expected_gid}, "
            f"got {uid}:{gid} (Config.User={shown})"
        )
    return uid, gid


def verify_data_tar(
    tar_path: Path,
    expected_uid: int = 65532,
    expected_gid: int = 65532,
    extract_db: Path | None = None,
) -> tuple[int, int]:
    try:
        with tarfile.open(tar_path, "r:*") as archive:
            data_dir_member: tarfile.TarInfo | None = None
            db_member: tarfile.TarInfo | None = None
            for member in archive.getmembers():
                normalized = normalize_tar_name(member.name)
                if normalized == "":
                    continue
                if normalized == "data":
                    if data_dir_member is not None:
                        raise ValueError("duplicate /data entry in container archive")
                    if not member.isdir():
                        raise ValueError("/data is not a directory")
                    if (member.uid, member.gid) != (expected_uid, expected_gid):
                        raise ValueError(
                            f"expected /data owner {expected_uid}:{expected_gid}, "
                            f"got {member.uid}:{member.gid}"
                        )
                    if member.mode & SETGID_BIT:
                        raise ValueError(
                            f"/data has setgid bit set (mode {oct(member.mode)}); "
                            "cannot attribute /data/ferrum.db GID to the runtime process"
                        )
                    data_dir_member = member
                    continue

                if not normalized.startswith("data/"):
                    raise ValueError(
                        "unexpected entry outside /data in container archive: "
                        f"{normalized!r}"
                    )
                if (member.uid, member.gid) != (expected_uid, expected_gid):
                    raise ValueError(
                        f"expected /{normalized} owner {expected_uid}:{expected_gid}, "
                        f"got {member.uid}:{member.gid}"
                    )
                if normalized == "data/ferrum.db":
                    if db_member is not None:
                        raise ValueError(
                            "duplicate /data/ferrum.db entry in container archive"
                        )
                    if not member.isfile():
                        raise ValueError("/data/ferrum.db is not a regular file")
                    if member.size <= 0:
                        raise ValueError("/data/ferrum.db is empty")
                    db_member = member

            if data_dir_member is None:
                raise ValueError("container archive missing /data directory")
            if db_member is None:
                raise ValueError("migration did not create /data/ferrum.db")

            if extract_db is not None:
                source = archive.extractfile(db_member)
                if source is None:
                    raise ValueError("could not extract /data/ferrum.db from archive")
                extract_db.parent.mkdir(parents=True, exist_ok=True)
                with source, extract_db.open("wb") as target:
                    shutil.copyfileobj(source, target)

            return db_member.uid, db_member.gid
    except (OSError, tarfile.TarError) as exc:
        raise ValueError(f"failed to read /data tar archive: {exc}") from exc


def _migration_records(path: Path) -> list[tuple[object, ...]]:
    try:
        with contextlib.closing(
            sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)
        ) as db:
            if db.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
                raise ValueError(f"SQLite integrity check failed: {path}")
            rows = db.execute(
                "SELECT version, name, applied_at, checksum, execution_time_ms "
                "FROM _ferrum_migrations ORDER BY version"
            ).fetchall()
            if not rows:
                raise ValueError(f"No applied migrations in {path}")
            return rows
    except sqlite3.Error as exc:
        raise ValueError(f"SQLite verification failed for {path}: {exc}") from exc


def verify_migrations(migrated_path: Path, restarted_path: Path) -> int:
    migrated_rows = _migration_records(migrated_path)
    restarted_rows = _migration_records(restarted_path)
    if migrated_rows != restarted_rows:
        raise ValueError(
            "Original SQLite migration records did not persist across restart"
        )
    return len(migrated_rows)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    resolve_cmd = subparsers.add_parser("resolve-user")
    resolve_cmd.add_argument("--config-user", required=True)
    resolve_cmd.add_argument("--passwd-tar", default="")
    resolve_cmd.add_argument("--group-tar", default="")
    resolve_cmd.add_argument("--expected-uid", type=int, default=65532)
    resolve_cmd.add_argument("--expected-gid", type=int, default=65532)

    data_cmd = subparsers.add_parser("verify-data-tar")
    data_cmd.add_argument("--tar", required=True)
    data_cmd.add_argument("--extract-db", default="")
    data_cmd.add_argument("--expected-uid", type=int, default=65532)
    data_cmd.add_argument("--expected-gid", type=int, default=65532)

    mig_cmd = subparsers.add_parser("verify-migrations")
    mig_cmd.add_argument("--migrated", required=True)
    mig_cmd.add_argument("--restarted", required=True)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        if args.command == "resolve-user":
            uid, gid = verify_configured_user(
                config_user=args.config_user,
                passwd_tar=Path(args.passwd_tar) if args.passwd_tar else None,
                group_tar=Path(args.group_tar) if args.group_tar else None,
                expected_uid=args.expected_uid,
                expected_gid=args.expected_gid,
            )
            print(f"{uid}:{gid}")
            return 0
        if args.command == "verify-data-tar":
            uid, gid = verify_data_tar(
                tar_path=Path(args.tar),
                expected_uid=args.expected_uid,
                expected_gid=args.expected_gid,
                extract_db=Path(args.extract_db) if args.extract_db else None,
            )
            print(f"{uid}:{gid}")
            return 0
        if args.command == "verify-migrations":
            verify_migrations(Path(args.migrated), Path(args.restarted))
            return 0
        raise ValueError(f"unsupported command: {args.command}")
    except ValueError as exc:
        print(f"SQLite volume smoke failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
