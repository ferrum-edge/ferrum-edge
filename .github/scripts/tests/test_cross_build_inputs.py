#!/usr/bin/env python3
"""Hosted-only checks of the admitted protoc bytes and Cross shell ordering."""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import tempfile
import unittest
import urllib.request
from pathlib import Path

# This read-only candidate lane intentionally tests candidate policy. It cannot
# provide admission evidence or replace the trusted-base verifier.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from verify_cross_build_policy import (  # noqa: E402
    CROSS_PROTOC_SHA256_PIN,
    CROSS_PROTOC_URL,
    EXPECTED_PRE_BUILD_COMMANDS,
)


class ProtocIntegrityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        with urllib.request.urlopen(CROSS_PROTOC_URL, timeout=60) as response:
            cls.published_archive = response.read()
        # Compare the published bytes with a previously admitted checksum, never
        # create the expected checksum from this download.
        if hashlib.sha256(cls.published_archive).hexdigest() != CROSS_PROTOC_SHA256_PIN:
            raise AssertionError("published protoc archive does not match the admitted pin")

    def exercise_command(self, archive: bytes, should_extract: bool) -> None:
        with tempfile.TemporaryDirectory(prefix="cross-input-integrity-") as directory:
            root = Path(directory)
            tools = root / "tools"
            tools.mkdir()
            source = root / "source.zip"
            source.write_bytes(archive)
            marker = root / "extracted"
            permission_marker = root / "permissions"
            removal_marker = root / "removed"
            # Run a byte-identical production-command fixture and real sha256sum.
            # Stub network, extraction, chmod and rm; no protoc bytes are run.
            stubs = {
                "wget": 'cp "$PROTOC_TEST_SOURCE" "$2"\n',
                "unzip": 'touch "$PROTOC_TEST_EXTRACTED"\n',
                "chmod": 'touch "$PROTOC_TEST_PERMISSIONS"\n',
                "rm": 'touch "$PROTOC_TEST_REMOVED"\n',
            }
            for name, body in stubs.items():
                program = tools / name
                program.write_text("#!/bin/sh\nset -eu\n" + body, encoding="utf-8")
                program.chmod(0o755)
            fixture = Path(".github/scripts/tests/cross_protoc_command.sh")
            self.assertEqual(
                fixture.read_text(encoding="utf-8"),
                "#!/bin/sh\n" + EXPECTED_PRE_BUILD_COMMANDS[3] + "\n",
            )
            result = subprocess.run(
                ["/bin/sh", ".github/scripts/tests/cross_protoc_command.sh"],
                env={
                    "PATH": f"{tools}{os.pathsep}/usr/bin:/bin",
                    "PROTOC_TEST_SOURCE": str(source),
                    "PROTOC_TEST_EXTRACTED": str(marker),
                    "PROTOC_TEST_PERMISSIONS": str(permission_marker),
                    "PROTOC_TEST_REMOVED": str(removal_marker),
                },
                capture_output=True,
                text=True,
                check=False,
                timeout=15,
            )
            Path("/tmp/protoc.zip").unlink(missing_ok=True)
            self.assertEqual(result.returncode == 0, should_extract, result.stderr)
            self.assertEqual(marker.exists(), should_extract)
            self.assertEqual(permission_marker.exists(), should_extract)
            self.assertEqual(removal_marker.exists(), should_extract)

    def test_admitted_published_archive_reaches_extraction(self) -> None:
        self.exercise_command(self.published_archive, should_extract=True)

    def test_corrupt_archive_stops_before_extraction(self) -> None:
        self.exercise_command(b"untrusted or corrupted download", should_extract=False)


if __name__ == "__main__":
    unittest.main()
