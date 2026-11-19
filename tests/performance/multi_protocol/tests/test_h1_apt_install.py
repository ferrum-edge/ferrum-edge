"""H1 Internal Profile hosted apt install: canonical-mirror fallback and workflow wiring.

Scheduled runs failed when the runner's regional Ubuntu mirror throttled
downloads (run 44302253556) and when `apt-get install` did not read the same
Ubuntu-only source as `apt-get update` (run 43587602406).
"""
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest

HERE = Path(__file__).resolve().parents[1]
ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(HERE))
import h1_apt_sources as sources

SCRIPT = HERE / "h1_apt_install.sh"
WORKFLOW = ROOT / ".github/workflows/h1-internal-profile.yml"
KEYRING = "/usr/share/keyrings/ubuntu-archive-keyring.gpg"

DEB822 = textwrap.dedent(f"""\
    # Ubuntu sources have moved to /etc/apt/sources.list.d/ubuntu.sources
    Types: deb
    URIs: http://us-east-2.ec2.archive.ubuntu.com/ubuntu/
    Suites: resolute resolute-updates resolute-backports
    Components: main universe restricted multiverse
    Signed-By: {KEYRING}

    Types: deb
    URIs: http://security.ubuntu.com/ubuntu/
    Suites: resolute-security
    Components: main universe restricted multiverse
    Signed-By: {KEYRING}
    """)

ONE_LINE = textwrap.dedent(f"""\
    deb [signed-by={KEYRING}] http://azure.archive.ubuntu.com/ubuntu/ noble main restricted
    deb http://azure.archive.ubuntu.com/ubuntu noble-updates universe # updates
    deb-src http://security.ubuntu.com/ubuntu noble-security main
    # deb http://azure.archive.ubuntu.com/ubuntu/ noble-proposed main
    """)

TRACE_PACKAGES = ("clang-18 llvm-18 libbpf-dev libelf-dev zlib1g-dev gcc libc6-dev binutils "
                  "util-linux linux-perf linux-tools-generic linux-tools-common python3-yaml")


class SourceRewriteTests(unittest.TestCase):
    def test_deb822_rewrites_only_the_regional_mirror(self):
        self.assertEqual(sources.CANONICAL, "https://archive.ubuntu.com/ubuntu/")
        text, changed = sources.rewrite(DEB822, deb822=True)
        self.assertTrue(changed)
        self.assertEqual(text, DEB822.replace("http://us-east-2.ec2.archive.ubuntu.com/ubuntu/",
                                              sources.CANONICAL))
        self.assertIn("URIs: http://security.ubuntu.com/ubuntu/", text)
        self.assertEqual(text.count(f"Signed-By: {KEYRING}"), 2)
        self.assertIn("Suites: resolute resolute-updates resolute-backports", text)

    def test_https_sources_stay_https_on_fallback(self):
        for raw, deb822 in (
                (DEB822.replace("http://us-east-2.ec2", "https://us-east-2.ec2", 1), True),
                (DEB822.replace("http://us-east-2.ec2.archive.ubuntu.com/ubuntu/",
                                "mirror+https://mirrors.ubuntu.com/mirrors.txt", 1), True),
                (f"deb [signed-by={KEYRING}] https://azure.archive.ubuntu.com/ubuntu/ noble main\n", False),
                (f"deb [signed-by={KEYRING}] mirror+https://mirrors.ubuntu.com/mirrors.txt noble main\n", False)):
            with self.subTest(raw=raw):
                rewritten, changed = sources.rewrite(raw, deb822)
                self.assertTrue(changed)
                self.assertIn("https://archive.ubuntu.com/ubuntu/", rewritten)
                self.assertNotIn("http://archive.ubuntu.com/ubuntu/", rewritten)

    def test_mixed_http_canonical_and_regional_mirror_normalizes_active_entries_to_https(self):
        disabled_http = (
            "Types: deb\n"
            "Enabled: no\n"
            "URIs: http://archive.ubuntu.com/ubuntu/\n"
            "Suites: resolute-proposed\n"
            "Components: main\n"
            f"Signed-By: {KEYRING}\n"
        )
        mixed_deb822 = (
            "Types: deb\n"
            "URIs: http://archive.ubuntu.com/ubuntu/\n"
            "Suites: resolute\n"
            "Components: main\n"
            f"Signed-By: {KEYRING}\n\n"
            "Types: deb\n"
            "URIs: https://us-east-2.ec2.archive.ubuntu.com/ubuntu/\n"
            "Suites: resolute\n"
            "Components: universe\n"
            f"Signed-By: {KEYRING}\n\n"
            + disabled_http
        )
        rewritten_d, changed_d = sources.rewrite(mixed_deb822, deb822=True)
        self.assertTrue(changed_d)
        self.assertEqual(rewritten_d.count("URIs: https://archive.ubuntu.com/ubuntu/\n"), 2)
        self.assertTrue(rewritten_d.endswith(disabled_http), "disabled HTTP canonical stanza stays untouched")

        mixed_one_line = (
            f"deb [signed-by={KEYRING}] http://archive.ubuntu.com/ubuntu/ resolute main\n"
            f"deb [signed-by={KEYRING}] https://azure.archive.ubuntu.com/ubuntu/ resolute universe\n"
        )
        rewritten_o, changed_o = sources.rewrite(mixed_one_line, deb822=False)
        self.assertTrue(changed_o)
        self.assertEqual(rewritten_o.count("https://archive.ubuntu.com/ubuntu/"), 2)
        self.assertNotIn("http://archive.ubuntu.com/ubuntu/", rewritten_o)

    def test_one_line_adjacent_uri_after_option_bracket_is_rewritten_and_checked(self):
        adjacent = f"deb [signed-by={KEYRING} ]http://azure.archive.ubuntu.com/ubuntu/ noble main\n"
        rewritten, changed = sources.rewrite(adjacent, deb822=False)
        self.assertTrue(changed)
        self.assertEqual(rewritten, f"deb [signed-by={KEYRING} ]{sources.CANONICAL} noble main\n")
        with self.assertRaises(ValueError):
            sources.rewrite("deb [trusted=yes]http://azure.archive.ubuntu.com/ubuntu/ noble main\n", deb822=False)

    def test_deb822_non_ascii_whitespace_does_not_split_uri_tokens(self):
        unsplit = f"Types: deb\nURIs: http://evil.example/\u00a0http://azure.archive.ubuntu.com/ubuntu/\nSuites: noble\nComponents: main\nSigned-By: {KEYRING}\n"
        self.assertEqual(sources.rewrite(unsplit, deb822=True), (unsplit, False))

        neighbor = f"Types: deb\nURIs: http://evil.example/\u00a0foo http://azure.archive.ubuntu.com/ubuntu/\nSuites: noble\nComponents: main\nSigned-By: {KEYRING}\n"
        rewritten, changed = sources.rewrite(neighbor, deb822=True)
        self.assertTrue(changed)
        self.assertIn(f"URIs: http://evil.example/\u00a0foo {sources.CANONICAL}\n", rewritten)

    def test_deb822_mirror_list_and_continuation_uris(self):
        text = ("Types: deb\nURIs: mirror+file:/etc/apt/apt-mirrors.txt\n"
                "  http://azure.archive.ubuntu.com/ubuntu\n"
                f"Suites: noble\nComponents: main\nSigned-By: {KEYRING}\n")
        rewritten, changed = sources.rewrite(text, deb822=True)
        self.assertTrue(changed)
        self.assertEqual(rewritten, f"Types: deb\nURIs: {sources.CANONICAL}\n  {sources.CANONICAL}\n"
                                    f"Suites: noble\nComponents: main\nSigned-By: {KEYRING}\n")

    def test_one_line_keeps_options_suites_and_comments(self):
        text, changed = sources.rewrite(ONE_LINE, deb822=False)
        self.assertTrue(changed)
        lines = text.splitlines()
        self.assertEqual(lines[0], f"deb [signed-by={KEYRING}] {sources.CANONICAL} noble main restricted")
        self.assertEqual(lines[1], f"deb {sources.CANONICAL} noble-updates universe # updates")
        self.assertEqual(lines[2], "deb-src http://security.ubuntu.com/ubuntu noble-security main")
        self.assertEqual(lines[3], "# deb http://azure.archive.ubuntu.com/ubuntu/ noble-proposed main")

    def test_one_line_quoted_and_percent_encoded_mirror_uris_are_rewritten(self):
        quoted = f'deb [signed-by={KEYRING}] "http://azure.archive.ubuntu.com/ubuntu/" noble main\n'
        rewritten_q, changed_q = sources.rewrite(quoted, deb822=False)
        self.assertTrue(changed_q)
        self.assertEqual(rewritten_q, f"deb [signed-by={KEYRING}] {sources.CANONICAL} noble main\n")

        encoded = "deb http://azure.archive.ubuntu.com/ubuntu%2f noble main\n"
        rewritten_e, changed_e = sources.rewrite(encoded, deb822=False)
        self.assertTrue(changed_e)
        self.assertEqual(rewritten_e, f"deb {sources.CANONICAL} noble main\n")

    def test_canonical_or_foreign_sources_are_not_rewritten(self):
        for text, deb822 in (
                (DEB822.replace("us-east-2.ec2.archive", "archive"), True),
                ("deb http://ports.ubuntu.com/ubuntu-ports noble main\n", False),
                ("deb https://evil.example/archive.ubuntu.com/ubuntu noble main\n", False),
                ("deb mirror+file:/etc/apt/vendor-mirrors.txt stable main\n", False),
                ("deb mirror://etc/apt/apt-mirrors.txt noble main\n", False),
                ("Types: deb\nURIs: mirror://etc/apt/apt-mirrors.txt\nSuites: noble\n", True),
                ("Types: deb\nURIs: mirror+https://vendor.example/mirrors.txt\nSuites: stable\n", True),
                ("Types: deb\nURIs: http://archive.ubuntu.com.evil.example/ubuntu/\nSuites: noble\n", True)):
            with self.subTest(text=text):
                self.assertEqual(sources.rewrite(text, deb822), (text, False))

    def test_sources_that_disable_signatures_are_refused(self):
        for text, deb822 in (
                (DEB822.replace("Signed-By:", "Trusted: yes\nSigned-By:", 1), True),
                (DEB822.replace("Signed-By:", "Trusted : yes\nSigned-By:", 1), True),
                (DEB822.replace("Signed-By:", "Trusted: true\nSigned-By:", 1), True),
                (DEB822.replace("Signed-By:", "Trusted: 1\nSigned-By:", 1), True),
                (DEB822.replace("Signed-By:", "Trusted: 01\nSigned-By:", 1), True),
                (DEB822.replace("Signed-By:", "Trusted: 0x1\nSigned-By:", 1), True),
                (DEB822.replace("Signed-By:", "Trusted: 0b1\nSigned-By:", 1), True),
                (DEB822.replace("Signed-By:", "Trusted: 0B1\nSigned-By:", 1), True),
                (DEB822.replace("Signed-By:", "Trusted: +1\nSigned-By:", 1), True),
                (DEB822.replace("Signed-By:", "Trusted: 0x100000001\nSigned-By:", 1), True),
                (DEB822.replace("Signed-By:", "Trusted: 0b100000000000000000000000000000001\nSigned-By:", 1), True),
                # Python-only numeric forms (underscores / 0o) are rejected by APT's strtol,
                # so Enabled keeps its default (true) and the stanza remains active.
                (DEB822.replace("Signed-By:", "Enabled: 0_0\nTrusted: yes\nSigned-By:", 1), True),
                (DEB822.replace("Signed-By:", "Enabled: 0x_0\nTrusted: yes\nSigned-By:", 1), True),
                (DEB822.replace("Signed-By:", "Enabled: 0b0_0\nTrusted: yes\nSigned-By:", 1), True),
                (DEB822.replace("Signed-By:", "Enabled: 0o0\nTrusted: yes\nSigned-By:", 1), True),
                # A `.` continuation line keeps Enabled from matching `no`, leaving the stanza active.
                (DEB822.replace("Signed-By:", "Enabled: no\n .\nTrusted: yes\nSigned-By:", 1), True),
                # A tab-indented continuation after empty `Enabled:` retains `\n\t`,
                # so keyword `no` does not match and the stanza remains active;
                # `strtol` still skips leading whitespace for numeric `Trusted:\n\t1`.
                (DEB822.replace("Signed-By:", "Enabled:\n\tno\nTrusted: yes\nSigned-By:", 1), True),
                (DEB822.replace("Signed-By:", "Trusted:\n\t1\nSigned-By:", 1), True),
                # Raw NUL bytes and bare CR characters in deb822 input are refused.
                (DEB822.replace("Signed-By:", "Trusted: yes\x00no\nSigned-By:", 1), True),
                (DEB822.replace("Signed-By:", "Enabled: no\rTrusted: yes\nSigned-By:", 1), True),
                (DEB822.replace("Signed-By:", "Allow-Insecure: on\nSigned-By:", 1), True),
                (DEB822.replace("Signed-By:", "Allow-Downgrade-To-Insecure: yes\nSigned-By:", 1), True),
                (DEB822.replace("Signed-By:", "Allow-Weak:\n  enable\nSigned-By:", 1), True),
                ("deb [trusted=yes] http://azure.archive.ubuntu.com/ubuntu noble main\n", False),
                ('deb [trusted="yes"] http://azure.archive.ubuntu.com/ubuntu noble main\n', False),
                ('deb [trusted=" 1"] http://azure.archive.ubuntu.com/ubuntu noble main\n', False),
                ("deb [%74rusted=%79es] http://azure.archive.ubuntu.com/ubuntu noble main\n", False),
                ("deb [trusted%3dyes] http://azure.archive.ubuntu.com/ubuntu noble main\n", False),
                ("deb [trusted=yes%5d ] http://azure.archive.ubuntu.com/ubuntu noble main\n", False),
                ("deb [trusted=yes%00no] http://azure.archive.ubuntu.com/ubuntu noble main\n", False),
                ("deb [trusted=true] http://azure.archive.ubuntu.com/ubuntu noble main\n", False),
                ("deb [trusted=01] http://azure.archive.ubuntu.com/ubuntu noble main\n", False),
                ("deb [trusted=0x1] http://azure.archive.ubuntu.com/ubuntu noble main\n", False),
                ("deb [trusted=0b1] http://azure.archive.ubuntu.com/ubuntu noble main\n", False),
                ("deb [trusted=0x100000001] http://azure.archive.ubuntu.com/ubuntu noble main\n", False),
                ("deb [arch=amd64 allow-insecure=on] http://azure.archive.ubuntu.com/ubuntu noble main\n", False),
                ("deb [allow-downgrade-to-insecure=1] http://azure.archive.ubuntu.com/ubuntu noble main\n", False),
                ("deb [allow-weak=with] http://azure.archive.ubuntu.com/ubuntu noble main\n", False),
                ('deb [a=["]x trusted=yes b="] http://x" c=d] http://us.archive.ubuntu.com/ubuntu noble main\n', False),
                ("deb \x0b[ trusted=yes ] http://azure.archive.ubuntu.com/ubuntu/ noble-updates main\n", False),
                ("deb \x0c[ trusted=yes ] http://azure.archive.ubuntu.com/ubuntu/ noble-updates main\n", False),
                ("deb\x0b[ trusted=yes ] http://azure.archive.ubuntu.com/ubuntu/ noble-updates main\n", False),
                ("unknown-type http://azure.archive.ubuntu.com/ubuntu/ noble main\n", False)):
            with self.subTest(text=text), self.assertRaises(ValueError):
                sources.rewrite(text, deb822)

    def test_disabled_deb822_stanza_is_preserved_and_does_not_block_retry(self):
        disabled = (
            "Types: deb\n"
            "URIs: http://us-east-2.ec2.archive.ubuntu.com/ubuntu/\n"
            "   \n"
            "Enabled : no\n"
            "Trusted: yes\n"
            "Suites: resolute-proposed\n"
            "Components: main\n"
            f"Signed-By: {KEYRING}\n"
        )
        combined = DEB822 + "\n" + disabled
        rewritten, changed = sources.rewrite(combined, deb822=True)
        self.assertTrue(changed)
        self.assertIn(sources.CANONICAL, rewritten)
        self.assertTrue(rewritten.endswith(disabled), "disabled stanza stays untouched")

        # C23 binary `0b0`, C int narrowing `0x100000000`, space-indented
        # continuation `\n  no`, and tab-indented numeric `\n\t0` all disable.
        for enabled_field in ("Enabled: 0b0", "Enabled: 0x100000000", "Enabled:\n  no", "Enabled:\n\t0"):
            with self.subTest(enabled=enabled_field):
                variant = disabled.replace("Enabled : no", enabled_field)
                rewritten_v, changed_v = sources.rewrite(DEB822 + "\n" + variant, deb822=True)
                self.assertTrue(changed_v)
                self.assertTrue(rewritten_v.endswith(variant))

    def test_comments_and_explicit_false_trust_flags_are_allowed(self):
        deb822_with_comment = "# Trusted: yes\n" + DEB822.replace("Signed-By:", "Trusted: no\nSigned-By:", 1)
        rewritten, changed = sources.rewrite(deb822_with_comment, deb822=True)
        self.assertTrue(changed)
        self.assertIn(sources.CANONICAL, rewritten)

        one_line_with_comment = (
            "# deb [trusted=yes] http://azure.archive.ubuntu.com/ubuntu noble main\n"
            f'deb [signed-by={KEYRING} trusted="no"] http://azure.archive.ubuntu.com/ubuntu noble main # [trusted=yes]\n'
        )
        rewritten_one, changed_one = sources.rewrite(one_line_with_comment, deb822=False)
        self.assertTrue(changed_one)
        self.assertIn(sources.CANONICAL, rewritten_one)

    def test_cli_exit_codes_and_crlf_preservation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "ubuntu.sources"
            source.write_text(DEB822)
            dest = root / "out.sources"
            self.assertEqual(sources.main(["x", str(source), str(dest)]), 0)
            self.assertIn(sources.CANONICAL, dest.read_text())
            dest.unlink()
            self.assertEqual(sources.main(["x", str(source), str(root / "out.list")]), 2)
            source.write_text(DEB822.replace("us-east-2.ec2.archive", "archive"))
            self.assertEqual(sources.main(["x", str(source), str(dest)]), 3)
            self.assertFalse(dest.exists())

            disabled_crlf = (
                "Types: deb\r\n"
                "Enabled: no\r\n"
                "Trusted: yes\r\n"
                "URIs: http://us-east-2.ec2.archive.ubuntu.com/ubuntu/\r\n"
                "Suites: resolute-proposed\r\n"
                "Components: main\r\n"
                f"Signed-By: {KEYRING}\r\n"
            )
            combined_crlf = DEB822.replace("\n", "\r\n") + "\r\n" + disabled_crlf
            source.write_bytes(combined_crlf.encode("utf-8"))
            self.assertEqual(sources.main(["x", str(source), str(dest)]), 0)
            raw_out = dest.read_bytes().decode("utf-8")
            self.assertIn(f"URIs: {sources.CANONICAL}\r\n", raw_out)
            self.assertTrue(raw_out.endswith(disabled_crlf), "disabled CRLF stanza preserved byte for byte")


FAKE_APT = r"""#!/usr/bin/env bash
set -u
list=""
action=update
for arg in "$@"; do
  case "$arg" in
    Dir::Etc::sourcelist=*) list=${arg#Dir::Etc::sourcelist=} ;;
    --download-only) action=download ;;
    --no-download) action=unpack ;;
  esac
done
case "$list" in "$FAKE_ETC"/*) phase=primary ;; *) phase=fallback ;; esac
printf '%s\t%s\t%s\t%s\t%s\n' "$phase" "$action" "${DEBIAN_FRONTEND:-}" "${IN_TIMEOUT:-0}" "$*" >> "$FAKE_LOG/apt.log"
if [ "$phase" = fallback ] && [ -f "$list" ]; then cp "$list" "$FAKE_LOG/fallback-source"; fi
case "${FAKE_APT_FAIL:-}" in
  primary-update) [ "$phase/$action" = primary/update ] && exit 100 ;;
  primary-update-warn)
    if [ "$phase/$action" = primary/update ]; then
      case " $* " in
        *" APT::Update::Error-Mode=any "*) exit 100 ;;
      esac
    fi
    ;;
  primary-download) [ "$phase/$action" = primary/download ] && exit 100 ;;
  stall) [ "$phase/$action" = primary/download ] && exec sleep 60 ;;
  all) [ "$action" = download ] && exit 100 ;;
esac
exit 0
"""

TIMEOUT_SHIM = r"""#!/usr/bin/env bash
export IN_TIMEOUT=1
exec "$REAL_TIMEOUT" "$@"
"""


@unittest.skipUnless(shutil.which("timeout") and shutil.which("bash"), "needs GNU timeout and bash")
class InstallScriptTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.etc, self.log, self.bin = root / "etc", root / "log", root / "bin"
        for path in (self.etc / "sources.list.d", self.log, self.bin):
            path.mkdir(parents=True)
        self.real_timeout = shutil.which("timeout")
        (self.bin / "apt-get").write_text(FAKE_APT)
        (self.bin / "timeout").write_text(TIMEOUT_SHIM)
        for tool in ("apt-get", "timeout"):
            (self.bin / tool).chmod(0o755)

    def tearDown(self):
        self.tmp.cleanup()

    def run_script(self, fail="", primary_timeout="300", packages=("clang-18", "llvm-18")):
        env = dict(os.environ, PATH=f"{self.bin}:{os.environ['PATH']}", FAKE_ETC=str(self.etc),
                   FAKE_LOG=str(self.log), FAKE_APT_FAIL=fail, REAL_TIMEOUT=self.real_timeout,
                   H1_APT_SUDO="", H1_APT_ETC_DIR=str(self.etc),
                   H1_APT_PRIMARY_TIMEOUT=primary_timeout, H1_APT_FALLBACK_TIMEOUT="60")
        env.pop("DEBIAN_FRONTEND", None)
        env.pop("IN_TIMEOUT", None)
        return subprocess.run(["bash", str(SCRIPT), *packages], env=env, capture_output=True,
                              text=True, timeout=120)

    def calls(self):
        path = self.log / "apt.log"
        return [line.split("\t") for line in path.read_text().splitlines()] if path.exists() else []

    def assert_apt_options(self, argv, source):
        for option in (f"Dir::Etc::sourcelist={source}", "Dir::Etc::sourceparts=-",
                       "Acquire::Retries=3", "Acquire::http::Timeout=30",
                       "Acquire::https::Timeout=30"):
            self.assertIn(f"-o {option}", argv)

    def test_primary_success_fetches_bounded_then_unpacks_offline(self):
        (self.etc / "sources.list.d/ubuntu.sources").write_text(DEB822)
        (self.etc / "sources.list").write_text("# moved to ubuntu.sources\n")
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.calls()
        self.assertEqual([(p, a, t) for p, a, _, t, _ in calls],
                         [("primary", "update", "1"),
                          ("primary", "download", "1"),
                          ("primary", "unpack", "0")])
        for _, action, frontend, _, argv in calls:
            self.assertEqual(frontend, "noninteractive")
            self.assert_apt_options(argv, self.etc / "sources.list.d/ubuntu.sources")
            if action == "update":
                self.assertIn("-o APT::Update::Error-Mode=any", argv)
        self.assertTrue(calls[1][4].endswith("install -y --no-install-recommends --download-only -- clang-18 llvm-18"))
        self.assertTrue(calls[2][4].endswith("install -y --no-install-recommends --no-download -- clang-18 llvm-18"))

    def test_failed_or_stalled_primary_falls_back_to_signed_canonical_archive(self):
        for fail, primary_timeout in (
                ("primary-update", "300"),
                ("primary-update-warn", "300"),
                ("primary-download", "300"),
                ("stall", "2")):
            with self.subTest(fail=fail):
                for leftover in self.log.iterdir():
                    leftover.unlink()
                (self.etc / "sources.list.d/ubuntu.sources").write_text(DEB822)
                started = time.monotonic()
                result = self.run_script(fail, primary_timeout)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertLess(time.monotonic() - started, 30)
                self.assertIn("::warning::", result.stdout)
                fallback = [c for c in self.calls() if c[0] == "fallback"]
                self.assertEqual([(a, t) for _, a, _, t, _ in fallback],
                                 [("update", "1"), ("download", "1"), ("unpack", "0")])
                source = re.search(r"Dir::Etc::sourcelist=(\S+)", fallback[0][4]).group(1)
                self.assertTrue(source.endswith(".sources"))
                for _, action, frontend, _, argv in fallback:
                    self.assertEqual(frontend, "noninteractive")
                    self.assert_apt_options(argv, source)
                    if action == "update":
                        self.assertIn("-o APT::Update::Error-Mode=any", argv)
                self.assertFalse(Path(source).exists(), "temporary fallback source is removed")
                self.assertEqual((self.log / "fallback-source").read_text(),
                                 sources.rewrite(DEB822, deb822=True)[0])

    def test_one_line_sources_list_falls_back_with_list_format(self):
        (self.etc / "sources.list").write_text(ONE_LINE)
        result = self.run_script("primary-download")
        self.assertEqual(result.returncode, 0, result.stderr)
        fallback = [c for c in self.calls() if c[0] == "fallback"]
        source = re.search(r"Dir::Etc::sourcelist=(\S+)", fallback[0][4]).group(1)
        self.assertTrue(source.endswith(".list"))
        self.assertEqual((self.log / "fallback-source").read_text(),
                         sources.rewrite(ONE_LINE, deb822=False)[0])

    def test_failure_on_both_mirrors_fails_the_step(self):
        (self.etc / "sources.list.d/ubuntu.sources").write_text(DEB822)
        result = self.run_script("all")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual([(p, a) for p, a, _, _, _ in self.calls()],
                         [("primary", "update"), ("primary", "download"),
                          ("fallback", "update"), ("fallback", "download")])

    def test_missing_ubuntu_sources_fails_before_apt(self):
        result = self.run_script()
        self.assertEqual(result.returncode, 1)
        self.assertIn("canonical Ubuntu apt sources are unavailable", result.stderr)
        self.assertEqual(self.calls(), [])

    def test_unsigned_source_is_never_rewritten(self):
        (self.etc / "sources.list").write_text(
            'deb [trusted="yes"] http://azure.archive.ubuntu.com/ubuntu noble main\n')
        result = self.run_script("primary-download")
        self.assertEqual(result.returncode, 1)
        self.assertEqual([c[0] for c in self.calls()], ["primary", "primary"])


class WorkflowWiringTests(unittest.TestCase):
    @staticmethod
    def jobs():
        text = WORKFLOW.read_text()
        body = text[text.index("\njobs:\n"):]
        starts = [(m.group(1), m.start()) for m in re.finditer(r"^  ([a-z][a-z-]*):\n", body, re.M)]
        return {name: body[start:(starts[i + 1][1] if i + 1 < len(starts) else len(body))]
                for i, (name, start) in enumerate(starts)}

    def test_every_job_installs_through_the_bounded_helper(self):
        jobs = self.jobs()
        self.assertEqual(set(jobs), {"checks", "cadence", "trace-fixtures", "measurement"})
        for name, job in jobs.items():
            with self.subTest(job=name):
                self.assertNotRegex(job, r"\bapt-get\b")
                self.assertIn("bash tests/performance/multi_protocol/h1_apt_install.sh ", job)

    def test_trace_fixture_packages_and_budget(self):
        job = self.jobs()["trace-fixtures"]
        self.assertIn("timeout-minutes: 30\n", job)
        install = re.search(r"h1_apt_install\.sh ((?:[^\n\\]|\\\n)+)", job).group(1)
        self.assertEqual(" ".join(install.replace("\\\n", " ").split()), TRACE_PACKAGES)
        self.assertIn("test_h1_apt_install.py", job)

    def test_helper_path_triggers_the_workflow(self):
        self.assertIn("      - tests/performance/multi_protocol/h1_*\n", WORKFLOW.read_text())


if __name__ == "__main__":
    unittest.main()
