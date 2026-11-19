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
        text, changed = sources.rewrite(DEB822, deb822=True)
        self.assertTrue(changed)
        self.assertEqual(text, DEB822.replace("http://us-east-2.ec2.archive.ubuntu.com/ubuntu/",
                                              sources.CANONICAL))
        self.assertIn("URIs: http://security.ubuntu.com/ubuntu/", text)
        self.assertEqual(text.count(f"Signed-By: {KEYRING}"), 2)
        self.assertIn("Suites: resolute resolute-updates resolute-backports", text)

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

    def test_canonical_or_foreign_sources_are_not_rewritten(self):
        for text, deb822 in (
                (DEB822.replace("us-east-2.ec2.archive", "archive"), True),
                ("deb http://ports.ubuntu.com/ubuntu-ports noble main\n", False),
                ("deb https://evil.example/archive.ubuntu.com/ubuntu noble main\n", False),
                ("deb mirror+file:/etc/apt/vendor-mirrors.txt stable main\n", False),
                ("Types: deb\nURIs: mirror+https://vendor.example/mirrors.txt\nSuites: stable\n", True),
                ("Types: deb\nURIs: http://archive.ubuntu.com.evil.example/ubuntu/\nSuites: noble\n", True)):
            with self.subTest(text=text):
                self.assertEqual(sources.rewrite(text, deb822), (text, False))

    def test_sources_that_disable_signatures_are_refused(self):
        for text, deb822 in (
                (DEB822.replace("Signed-By:", "Trusted: yes\nSigned-By:", 1), True),
                (DEB822.replace("Signed-By:", "Trusted: true\nSigned-By:", 1), True),
                (DEB822.replace("Signed-By:", "Trusted: 1\nSigned-By:", 1), True),
                (DEB822.replace("Signed-By:", "Allow-Insecure: on\nSigned-By:", 1), True),
                (DEB822.replace("Signed-By:", "Allow-Weak:\n  enable\nSigned-By:", 1), True),
                ("deb [trusted=yes] http://azure.archive.ubuntu.com/ubuntu noble main\n", False),
                ("deb [trusted=true] http://azure.archive.ubuntu.com/ubuntu noble main\n", False),
                ("deb [trusted=1] http://azure.archive.ubuntu.com/ubuntu noble main\n", False),
                ("deb [arch=amd64 allow-insecure=on] http://azure.archive.ubuntu.com/ubuntu noble main\n", False),
                ("deb [allow-weak=with] http://azure.archive.ubuntu.com/ubuntu noble main\n", False)):
            with self.subTest(text=text), self.assertRaises(ValueError):
                sources.rewrite(text, deb822)

    def test_comments_and_explicit_false_trust_flags_are_allowed(self):
        deb822_with_comment = "# Trusted: yes\n" + DEB822.replace("Signed-By:", "Trusted: no\nSigned-By:", 1)
        rewritten, changed = sources.rewrite(deb822_with_comment, deb822=True)
        self.assertTrue(changed)
        self.assertIn(sources.CANONICAL, rewritten)

        one_line_with_comment = (
            "# deb [trusted=yes] http://azure.archive.ubuntu.com/ubuntu noble main\n"
            f"deb [signed-by={KEYRING} trusted=no] http://azure.archive.ubuntu.com/ubuntu noble main # [trusted=yes]\n"
        )
        rewritten_one, changed_one = sources.rewrite(one_line_with_comment, deb822=False)
        self.assertTrue(changed_one)
        self.assertIn(sources.CANONICAL, rewritten_one)

    def test_cli_exit_codes(self):
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
printf '%s\t%s\t%s\t%s\n' "$phase" "$action" "${DEBIAN_FRONTEND:-}" "$*" >> "$FAKE_LOG/apt.log"
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


@unittest.skipUnless(shutil.which("timeout") and shutil.which("bash"), "needs GNU timeout and bash")
class InstallScriptTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.etc, self.log, self.bin = root / "etc", root / "log", root / "bin"
        for path in (self.etc / "sources.list.d", self.log, self.bin):
            path.mkdir(parents=True)
        (self.bin / "apt-get").write_text(FAKE_APT)
        (self.bin / "dpkg").write_text('#!/usr/bin/env bash\nprintf "%s\\n" "$*" >> "$FAKE_LOG/dpkg.log"\n')
        for tool in ("apt-get", "dpkg"):
            (self.bin / tool).chmod(0o755)

    def tearDown(self):
        self.tmp.cleanup()

    def run_script(self, fail="", primary_timeout="300", packages=("clang-18", "llvm-18")):
        env = dict(os.environ, PATH=f"{self.bin}:{os.environ['PATH']}", FAKE_ETC=str(self.etc),
                   FAKE_LOG=str(self.log), FAKE_APT_FAIL=fail, H1_APT_SUDO="",
                   H1_APT_ETC_DIR=str(self.etc), H1_APT_PRIMARY_TIMEOUT=primary_timeout,
                   H1_APT_FALLBACK_TIMEOUT="60")
        env.pop("DEBIAN_FRONTEND", None)
        return subprocess.run(["bash", str(SCRIPT), *packages], env=env, capture_output=True,
                              text=True, timeout=120)

    def calls(self):
        path = self.log / "apt.log"
        return [line.split("\t") for line in path.read_text().splitlines()] if path.exists() else []

    def assert_apt_options(self, argv, source):
        for option in (f"Dir::Etc::sourcelist={source}", "Dir::Etc::sourceparts=-",
                       "Acquire::Retries=3", "Acquire::http::Timeout=30"):
            self.assertIn(f"-o {option}", argv)

    def test_primary_success_fetches_bounded_then_unpacks_offline(self):
        (self.etc / "sources.list.d/ubuntu.sources").write_text(DEB822)
        (self.etc / "sources.list").write_text("# moved to ubuntu.sources\n")
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.calls()
        self.assertEqual([(p, a) for p, a, _, _ in calls],
                         [("primary", "update"), ("primary", "download"), ("primary", "unpack")])
        for _, action, frontend, argv in calls:
            self.assertEqual(frontend, "noninteractive")
            self.assert_apt_options(argv, self.etc / "sources.list.d/ubuntu.sources")
            if action == "update":
                self.assertIn("-o APT::Update::Error-Mode=any", argv)
        self.assertTrue(calls[1][3].endswith("install -y --no-install-recommends --download-only clang-18 llvm-18"))
        self.assertTrue(calls[2][3].endswith("install -y --no-install-recommends --no-download clang-18 llvm-18"))
        self.assertFalse((self.log / "dpkg.log").exists())

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
                self.assertEqual([a for _, a, _, _ in fallback], ["update", "download", "unpack"])
                source = re.search(r"Dir::Etc::sourcelist=(\S+)", fallback[0][3]).group(1)
                self.assertTrue(source.endswith(".sources"))
                for _, action, frontend, argv in fallback:
                    self.assertEqual(frontend, "noninteractive")
                    self.assert_apt_options(argv, source)
                    if action == "update":
                        self.assertIn("-o APT::Update::Error-Mode=any", argv)
                self.assertFalse(Path(source).exists(), "temporary fallback source is removed")
                self.assertEqual((self.log / "fallback-source").read_text(),
                                 sources.rewrite(DEB822, deb822=True)[0])
                self.assertFalse((self.log / "dpkg.log").exists(),
                                 "bounded fetch never kills dpkg mid-unpack")

    def test_one_line_sources_list_falls_back_with_list_format(self):
        (self.etc / "sources.list").write_text(ONE_LINE)
        result = self.run_script("primary-download")
        self.assertEqual(result.returncode, 0, result.stderr)
        fallback = [c for c in self.calls() if c[0] == "fallback"]
        source = re.search(r"Dir::Etc::sourcelist=(\S+)", fallback[0][3]).group(1)
        self.assertTrue(source.endswith(".list"))
        self.assertEqual((self.log / "fallback-source").read_text(),
                         sources.rewrite(ONE_LINE, deb822=False)[0])

    def test_failure_on_both_mirrors_fails_the_step(self):
        (self.etc / "sources.list.d/ubuntu.sources").write_text(DEB822)
        result = self.run_script("all")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual([(p, a) for p, a, _, _ in self.calls()],
                         [("primary", "update"), ("primary", "download"),
                          ("fallback", "update"), ("fallback", "download")])

    def test_missing_ubuntu_sources_fails_before_apt(self):
        result = self.run_script()
        self.assertEqual(result.returncode, 1)
        self.assertIn("canonical Ubuntu apt sources are unavailable", result.stderr)
        self.assertEqual(self.calls(), [])

    def test_unsigned_source_is_never_rewritten(self):
        (self.etc / "sources.list").write_text(
            "deb [trusted=true] http://azure.archive.ubuntu.com/ubuntu noble main\n")
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
