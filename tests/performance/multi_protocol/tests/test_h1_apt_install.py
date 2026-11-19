"""H1 Internal Profile hosted apt install: canonical-mirror fallback and workflow wiring.

Scheduled runs failed when the runner's regional Ubuntu mirror throttled
downloads (run 44302253556) and when `apt-get install` did not read the same
Ubuntu-only source as `apt-get update` (run 43587602406).
"""
import os
from pathlib import Path
import re
import shutil
import stat
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
            "URIs: http://archive.ubuntu.com:/ubuntu/\n"
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
            f"deb [signed-by={KEYRING}] http://archive.ubuntu.com:/ubuntu/ resolute main\n"
            f"deb [signed-by={KEYRING}] https://azure.archive.ubuntu.com/ubuntu/ resolute universe\n"
        )
        rewritten_o, changed_o = sources.rewrite(mixed_one_line, deb822=False)
        self.assertTrue(changed_o)
        self.assertEqual(rewritten_o.count("https://archive.ubuntu.com/ubuntu/"), 2)
        self.assertNotIn("http://archive.ubuntu.com", rewritten_o)

    def test_distinct_signing_policies_preserve_distinct_release_indexes(self):
        alt_keyring = "/etc/apt/keyrings/ubuntu-alt.gpg"
        # Canonical + regional for the same suite with different Signed-By must not
        # merge onto one canonical Release index (which APT would reject).
        deb822_conflict = (
            "Types: deb\n"
            "URIs: http://archive.ubuntu.com/ubuntu/\n"
            "Suites: resolute\n"
            "Components: main\n"
            f"Signed-By: {KEYRING}\n\n"
            "Types: deb\n"
            "URIs: https://us-east-2.ec2.archive.ubuntu.com/ubuntu/\n"
            "Suites: resolute\n"
            "Components: universe\n"
            f"Signed-By: {alt_keyring}\n"
        )
        self.assertEqual(sources.rewrite(deb822_conflict, deb822=True), (deb822_conflict, False))

        # Two regional mirrors for the same suite with different Signed-By: first
        # rewrites to canonical HTTPS; second keeps its distinct regional index.
        deb822_two_regional = (
            "Types: deb\n"
            "URIs: https://us-east-2.ec2.archive.ubuntu.com/ubuntu/\n"
            "Suites: resolute\n"
            "Components: main\n"
            f"Signed-By: {KEYRING}\n\n"
            "Types: deb\n"
            "URIs: https://azure.archive.ubuntu.com/ubuntu/\n"
            "Suites: resolute\n"
            "Components: universe\n"
            f"Signed-By: {alt_keyring}\n"
        )
        rewritten_r, changed_r = sources.rewrite(deb822_two_regional, deb822=True)
        self.assertTrue(changed_r)
        self.assertIn("URIs: https://archive.ubuntu.com/ubuntu/\n", rewritten_r)
        self.assertIn("URIs: https://azure.archive.ubuntu.com/ubuntu/\n", rewritten_r)

        one_line_conflict = (
            f"deb [signed-by={KEYRING}] http://archive.ubuntu.com/ubuntu/ resolute main\n"
            f"deb [signed-by={alt_keyring}] https://azure.archive.ubuntu.com/ubuntu/ resolute universe\n"
        )
        self.assertEqual(sources.rewrite(one_line_conflict, deb822=False), (one_line_conflict, False))

        one_line_two_regional = (
            f"deb [signed-by={KEYRING}] https://us-east-2.ec2.archive.ubuntu.com/ubuntu/ resolute main\n"
            f"deb [signed-by={alt_keyring}] https://azure.archive.ubuntu.com/ubuntu/ resolute universe\n"
        )
        rewritten_or, changed_or = sources.rewrite(one_line_two_regional, deb822=False)
        self.assertTrue(changed_or)
        self.assertIn(f"deb [signed-by={KEYRING}] https://archive.ubuntu.com/ubuntu/ resolute main\n", rewritten_or)
        self.assertIn(f"deb [signed-by={alt_keyring}] https://azure.archive.ubuntu.com/ubuntu/ resolute universe\n", rewritten_or)

        # Explicit `:80` keeps its own Release index in APT; a regional rewrite
        # on another suite must NOT merge `:80` onto portless HTTPS.
        deb822_port80 = (
            "Types: deb\nURIs: http://archive.ubuntu.com:80/ubuntu/\nSuites: resolute\n"
            f"Components: main\nSigned-By: {KEYRING}\n\n"
            "Types: deb\nURIs: https://archive.ubuntu.com/ubuntu/\nSuites: resolute\n"
            f"Components: universe\nSigned-By: {alt_keyring}\n\n"
            "Types: deb\nURIs: https://us-east-2.ec2.archive.ubuntu.com/ubuntu/\nSuites: resolute-updates\n"
            f"Components: main\nSigned-By: {KEYRING}\n"
        )
        rewritten_p80, changed_p80 = sources.rewrite(deb822_port80, deb822=True)
        self.assertTrue(changed_p80)
        self.assertIn("URIs: http://archive.ubuntu.com:80/ubuntu/\n", rewritten_p80)
        self.assertEqual(rewritten_p80.count("URIs: https://archive.ubuntu.com/ubuntu/\n"), 2)

        # Portless HTTP + HTTPS with conflicting Signed-By on the same suite must
        # not be merged when another suite triggers a regional rewrite.
        deb822_http_https_conflict = deb822_port80.replace(
            "http://archive.ubuntu.com:80/ubuntu/",
            "http://archive.ubuntu.com/ubuntu/",
            1,
        )
        rewritten_hhc, changed_hhc = sources.rewrite(deb822_http_https_conflict, deb822=True)
        self.assertTrue(changed_hhc)
        self.assertIn("URIs: http://archive.ubuntu.com/ubuntu/\n", rewritten_hhc)

        # Conflicting Snapshot / snapshot= pins keep distinct Release indexes.
        deb822_snapshot = (
            "Types: deb\nURIs: https://us-east-2.ec2.archive.ubuntu.com/ubuntu/\nSuites: resolute\n"
            f"Components: main\nSigned-By: {KEYRING}\nSnapshot: 20260401T000000Z\n\n"
            "Types: deb\nURIs: https://azure.archive.ubuntu.com/ubuntu/\nSuites: resolute\n"
            f"Components: universe\nSigned-By: {KEYRING}\nSnapshot: 20260501T000000Z\n"
        )
        rewritten_snap_d, changed_snap_d = sources.rewrite(deb822_snapshot, deb822=True)
        self.assertTrue(changed_snap_d)
        self.assertIn("URIs: https://archive.ubuntu.com/ubuntu/\n", rewritten_snap_d)
        self.assertIn("URIs: https://azure.archive.ubuntu.com/ubuntu/\n", rewritten_snap_d)

        one_line_snapshot = (
            f"deb [signed-by={KEYRING} snapshot=20260401T000000Z] https://us-east-2.ec2.archive.ubuntu.com/ubuntu/ resolute main\n"
            f"deb [signed-by={KEYRING} snapshot=20260501T000000Z] https://azure.archive.ubuntu.com/ubuntu/ resolute universe\n"
        )
        rewritten_snap_o, changed_snap_o = sources.rewrite(one_line_snapshot, deb822=False)
        self.assertTrue(changed_snap_o)
        self.assertIn("https://archive.ubuntu.com/ubuntu/ resolute main\n", rewritten_snap_o)
        self.assertIn("https://azure.archive.ubuntu.com/ubuntu/ resolute universe\n", rewritten_snap_o)

        # One-line options are case-sensitive in APT: `Signed-By=` does not
        # overwrite lowercase `signed-by=`, so these two entries have different keyrings.
        one_line_case = (
            f"deb [signed-by={KEYRING} Signed-By={alt_keyring}] https://us-east-2.ec2.archive.ubuntu.com/ubuntu/ resolute main\n"
            f"deb [signed-by={alt_keyring}] https://azure.archive.ubuntu.com/ubuntu/ resolute universe\n"
        )
        rewritten_case, changed_case = sources.rewrite(one_line_case, deb822=False)
        self.assertTrue(changed_case)
        self.assertIn("https://archive.ubuntu.com/ubuntu/ resolute main\n", rewritten_case)
        self.assertIn("https://azure.archive.ubuntu.com/ubuntu/ resolute universe\n", rewritten_case)

        # APT ignores capitalized `Trusted=yes` in one-line options (exact-case lookup).
        one_line_upper_trusted = (
            f"deb [signed-by={KEYRING} Trusted=yes] https://azure.archive.ubuntu.com/ubuntu/ noble main\n"
        )
        rewritten_ut, changed_ut = sources.rewrite(one_line_upper_trusted, deb822=False)
        self.assertTrue(changed_ut)
        self.assertIn("https://archive.ubuntu.com/ubuntu/", rewritten_ut)

        # Userinfo (`reader@`) shares APT's scheme-and-userinfo-stripped Release
        # filename with `https://archive.ubuntu.com/ubuntu/`, so a regional mirror
        # for the same suite must not merge onto it (with either same or distinct keyring).
        for second_key in (KEYRING, alt_keyring):
            with self.subTest(userinfo_second_key=second_key):
                deb822_userinfo = (
                    "Types: deb\nURIs: http://reader@archive.ubuntu.com/ubuntu/\nSuites: resolute\n"
                    f"Components: main\nSigned-By: {KEYRING}\n\n"
                    "Types: deb\nURIs: https://us-east-2.ec2.archive.ubuntu.com/ubuntu/\nSuites: resolute\n"
                    f"Components: universe\nSigned-By: {second_key}\n"
                )
                self.assertEqual(sources.rewrite(deb822_userinfo, deb822=True), (deb822_userinfo, False))

        # Flat-repository suite `dists/resolute/` maps to the exact same APT Release
        # filename as ordinary suite `resolute`.
        deb822_flat_suite = (
            "Types: deb\nURIs: http://archive.ubuntu.com/ubuntu/\nSuites: resolute\n"
            f"Components: main\nSigned-By: {KEYRING}\n\n"
            "Types: deb\nURIs: https://us-east-2.ec2.archive.ubuntu.com/ubuntu/\nSuites: dists/resolute/\n"
            f"Signed-By: {alt_keyring}\n"
        )
        self.assertEqual(sources.rewrite(deb822_flat_suite, deb822=True), (deb822_flat_suite, False))

        # Multi-suite HTTP canonical stanza whose second suite is blocked must
        # block its other suites too so a regional mirror cannot merge onto HTTP.
        deb822_multi_suite_blocked = (
            "Types: deb\nURIs: http://archive.ubuntu.com/ubuntu/\nSuites: resolute resolute-updates\n"
            f"Components: main\nSigned-By: {KEYRING}\n\n"
            "Types: deb\nURIs: http://reader@archive.ubuntu.com/ubuntu/\nSuites: resolute-updates\n"
            f"Components: universe\nSigned-By: {KEYRING}\n\n"
            "Types: deb\nURIs: https://us-east-2.ec2.archive.ubuntu.com/ubuntu/\nSuites: resolute\n"
            f"Components: universe\nSigned-By: {KEYRING}\n"
        )
        self.assertEqual(
            sources.rewrite(deb822_multi_suite_blocked, deb822=True),
            (deb822_multi_suite_blocked, False),
        )

        # URI/suite split (`.../ubuntu/dists/` + `resolute/`) resolves to the
        # same Release path as `.../ubuntu/` + `resolute`.
        deb822_uri_suite_split = (
            "Types: deb\nURIs: http://archive.ubuntu.com/ubuntu/dists/\nSuites: resolute/\n"
            f"Signed-By: {KEYRING}\n\n"
            "Types: deb\nURIs: https://us-east-2.ec2.archive.ubuntu.com/ubuntu/\nSuites: resolute\n"
            f"Components: main\nSigned-By: {KEYRING}\n"
        )
        self.assertEqual(
            sources.rewrite(deb822_uri_suite_split, deb822=True),
            (deb822_uri_suite_split, False),
        )

        # APT preserves host spelling in Release filenames, so uppercase HTTPS
        # `ARCHIVE.UBUNTU.COM` with a different keyring does not collide with
        # rewriting a regional mirror onto lowercase `archive.ubuntu.com`.
        deb822_upper_host = (
            "Types: deb\nURIs: https://ARCHIVE.UBUNTU.COM/ubuntu/\nSuites: resolute\n"
            f"Components: main\nSigned-By: {alt_keyring}\n\n"
            "Types: deb\nURIs: https://us-east-2.ec2.archive.ubuntu.com/ubuntu/\nSuites: resolute\n"
            f"Components: universe\nSigned-By: {KEYRING}\n"
        )
        rewritten_uh, changed_uh = sources.rewrite(deb822_upper_host, deb822=True)
        self.assertTrue(changed_uh)
        self.assertIn("URIs: https://ARCHIVE.UBUNTU.COM/ubuntu/\n", rewritten_uh)
        self.assertIn("URIs: https://archive.ubuntu.com/ubuntu/\n", rewritten_uh)

        # One-line equivalents for URI/suite split and uppercase host.
        one_line_uri_suite_split = (
            f"deb [signed-by={KEYRING}] http://archive.ubuntu.com/ubuntu/dists/ resolute/\n"
            f"deb [signed-by={KEYRING}] https://us-east-2.ec2.archive.ubuntu.com/ubuntu/ resolute main\n"
        )
        self.assertEqual(
            sources.rewrite(one_line_uri_suite_split, deb822=False),
            (one_line_uri_suite_split, False),
        )
        one_line_upper_host = (
            f"deb [signed-by={alt_keyring}] https://ARCHIVE.UBUNTU.COM/ubuntu/ resolute main\n"
            f"deb [signed-by={KEYRING}] https://us-east-2.ec2.archive.ubuntu.com/ubuntu/ resolute universe\n"
        )
        rewritten_ouh, changed_ouh = sources.rewrite(one_line_upper_host, deb822=False)
        self.assertTrue(changed_ouh)
        self.assertIn("https://ARCHIVE.UBUNTU.COM/ubuntu/ resolute main\n", rewritten_ouh)
        self.assertIn("https://archive.ubuntu.com/ubuntu/ resolute universe\n", rewritten_ouh)

        # Differing Include/Exclude package filters keep distinct Release indexes.
        deb822_include = (
            "Types: deb\nURIs: https://us-east-2.ec2.archive.ubuntu.com/ubuntu/\nSuites: resolute\n"
            f"Components: main\nSigned-By: {KEYRING}\nInclude: curl\n\n"
            "Types: deb\nURIs: https://azure.archive.ubuntu.com/ubuntu/\nSuites: resolute\n"
            f"Components: main\nSigned-By: {KEYRING}\nInclude: libssl-dev\n"
        )
        rewritten_inc_d, changed_inc_d = sources.rewrite(deb822_include, deb822=True)
        self.assertTrue(changed_inc_d)
        self.assertIn("URIs: https://archive.ubuntu.com/ubuntu/\n", rewritten_inc_d)
        self.assertIn("URIs: https://azure.archive.ubuntu.com/ubuntu/\n", rewritten_inc_d)

        one_line_include = (
            f"deb [signed-by={KEYRING} include=curl] https://us-east-2.ec2.archive.ubuntu.com/ubuntu/ resolute main\n"
            f"deb [signed-by={KEYRING} include=libssl-dev] https://azure.archive.ubuntu.com/ubuntu/ resolute main\n"
        )
        rewritten_inc_o, changed_inc_o = sources.rewrite(one_line_include, deb822=False)
        self.assertTrue(changed_inc_o)
        self.assertIn("https://archive.ubuntu.com/ubuntu/ resolute main\n", rewritten_inc_o)
        self.assertIn("https://azure.archive.ubuntu.com/ubuntu/ resolute main\n", rewritten_inc_o)

        # Flat HTTPS entry (`.../ubuntu/dists/` + `resolute/`) and component-based
        # regional entry (`resolute` + `main`) share the same Release filename but
        # have incompatible layouts and must not merge.
        deb822_flat_vs_comp = (
            "Types: deb\nURIs: https://archive.ubuntu.com/ubuntu/dists/\nSuites: resolute/\n"
            f"Signed-By: {KEYRING}\n\n"
            "Types: deb\nURIs: https://us-east-2.ec2.archive.ubuntu.com/ubuntu/\nSuites: resolute\n"
            f"Components: main\nSigned-By: {KEYRING}\n"
        )
        self.assertEqual(
            sources.rewrite(deb822_flat_vs_comp, deb822=True),
            (deb822_flat_vs_comp, False),
        )
        one_line_flat_vs_comp = (
            f"deb [signed-by={KEYRING}] https://archive.ubuntu.com/ubuntu/dists/ resolute/\n"
            f"deb [signed-by={KEYRING}] https://us-east-2.ec2.archive.ubuntu.com/ubuntu/ resolute main\n"
        )
        self.assertEqual(
            sources.rewrite(one_line_flat_vs_comp, deb822=False),
            (one_line_flat_vs_comp, False),
        )

        # Two-hop multi-suite HTTP propagation (A B + B C + userinfo blocking C):
        # both HTTP stanzas stay HTTP, regional A stays regional, only D rewrites.
        deb822_two_hop = (
            "Types: deb\nURIs: http://archive.ubuntu.com/ubuntu/\nSuites: resolute resolute-updates\n"
            f"Components: main\nSigned-By: {KEYRING}\n\n"
            "Types: deb\nURIs: http://archive.ubuntu.com/ubuntu/\nSuites: resolute-updates resolute-backports\n"
            f"Components: main\nSigned-By: {KEYRING}\n\n"
            "Types: deb\nURIs: http://reader@archive.ubuntu.com/ubuntu/\nSuites: resolute-backports\n"
            f"Components: universe\nSigned-By: {KEYRING}\n\n"
            "Types: deb\nURIs: https://us-east-2.ec2.archive.ubuntu.com/ubuntu/\nSuites: resolute\n"
            f"Components: universe\nSigned-By: {KEYRING}\n\n"
            "Types: deb\nURIs: https://us-east-2.ec2.archive.ubuntu.com/ubuntu/\nSuites: resolute-proposed\n"
            f"Components: main\nSigned-By: {KEYRING}\n"
        )
        rewritten_2h, changed_2h = sources.rewrite(deb822_two_hop, deb822=True)
        self.assertTrue(changed_2h)
        self.assertEqual(rewritten_2h.count("URIs: http://archive.ubuntu.com/ubuntu/\n"), 2)
        self.assertIn(
            "URIs: https://us-east-2.ec2.archive.ubuntu.com/ubuntu/\nSuites: resolute\n",
            rewritten_2h,
        )
        self.assertIn(
            "URIs: https://archive.ubuntu.com/ubuntu/\nSuites: resolute-proposed\n",
            rewritten_2h,
        )

        # Alternate APT URI spelling without `//` (`http:archive.ubuntu.com/ubuntu/`)
        # normalizes in APT to the same Release index and must block merges.
        deb822_no_slashes = (
            "Types: deb\nURIs: http:archive.ubuntu.com/ubuntu/\nSuites: resolute\n"
            f"Components: main\nSigned-By: {KEYRING}\n\n"
            "Types: deb\nURIs: https://us-east-2.ec2.archive.ubuntu.com/ubuntu/\nSuites: resolute\n"
            f"Components: universe\nSigned-By: {alt_keyring}\n"
        )
        self.assertEqual(sources.rewrite(deb822_no_slashes, deb822=True), (deb822_no_slashes, False))

        # `$(ARCH)` expands dynamically at APT runtime and must not merge onto
        # an existing canonical entry with a conflicting keyring.
        deb822_arch_var = (
            "Types: deb\nURIs: https://archive.ubuntu.com/ubuntu/\nSuites: resolute-$(ARCH)\n"
            f"Components: main\nSigned-By: {KEYRING}\n\n"
            "Types: deb\nURIs: https://us-east-2.ec2.archive.ubuntu.com/ubuntu/\nSuites: resolute-amd64\n"
            f"Components: universe\nSigned-By: {alt_keyring}\n"
        )
        self.assertEqual(sources.rewrite(deb822_arch_var, deb822=True), (deb822_arch_var, False))

        # Matching flat layouts with different REPO_URI roots (`/ubuntu/dists/resolute/`
        # + `/` vs `/ubuntu/` + `dists/resolute/`) must not merge.
        deb822_flat_roots = (
            "Types: deb\nURIs: https://archive.ubuntu.com/ubuntu/dists/resolute/\nSuites: /\n"
            f"Signed-By: {KEYRING}\n\n"
            "Types: deb\nURIs: https://us-east-2.ec2.archive.ubuntu.com/ubuntu/\nSuites: dists/resolute/\n"
            f"Signed-By: {KEYRING}\n"
        )
        self.assertEqual(sources.rewrite(deb822_flat_roots, deb822=True), (deb822_flat_roots, False))

        # Bracketed host alias `http://[archive.ubuntu.com]/ubuntu/` and non-HTTP
        # slashless `tor+https:archive.ubuntu.com/ubuntu/` normalize to the same
        # APT Release key and must block merges; compatible `https:archive.ubuntu.com/ubuntu/`
        # normalizes to HTTPS canonical and allows merging.
        deb822_bracket_http = (
            "Types: deb\nURIs: http://[archive.ubuntu.com]/ubuntu/\nSuites: resolute\n"
            f"Components: main\nSigned-By: {KEYRING}\n\n"
            "Types: deb\nURIs: https://us-east-2.ec2.archive.ubuntu.com/ubuntu/\nSuites: resolute\n"
            f"Components: universe\nSigned-By: {KEYRING}\n"
        )
        self.assertEqual(sources.rewrite(deb822_bracket_http, deb822=True), (deb822_bracket_http, False))

        deb822_tor_slashless = (
            "Types: deb\nURIs: tor+https:archive.ubuntu.com/ubuntu/\nSuites: resolute\n"
            f"Components: main\nSigned-By: {KEYRING}\n\n"
            "Types: deb\nURIs: https://us-east-2.ec2.archive.ubuntu.com/ubuntu/\nSuites: resolute\n"
            f"Components: universe\nSigned-By: {alt_keyring}\n"
        )
        self.assertEqual(sources.rewrite(deb822_tor_slashless, deb822=True), (deb822_tor_slashless, False))

        deb822_https_slashless = (
            "Types: deb\nURIs: https:archive.ubuntu.com/ubuntu/\nSuites: resolute\n"
            f"Components: main\nSigned-By: {KEYRING}\n\n"
            "Types: deb\nURIs: https://us-east-2.ec2.archive.ubuntu.com/ubuntu/\nSuites: resolute\n"
            f"Components: universe\nSigned-By: {KEYRING}\n"
        )
        rewritten_hs, changed_hs = sources.rewrite(deb822_https_slashless, deb822=True)
        self.assertTrue(changed_hs)
        self.assertIn("URIs: https://archive.ubuntu.com/ubuntu/\n", rewritten_hs)

        # Credentialed HTTPS canonical entry (`https://reader@archive.ubuntu.com/ubuntu/`)
        # keeps a distinct REPO_URI from anonymous `https://archive.ubuntu.com/ubuntu/`
        # and must not merge even when Signed-By matches.
        deb822_https_userinfo = (
            "Types: deb\nURIs: https://reader@archive.ubuntu.com/ubuntu/\nSuites: resolute\n"
            f"Components: main\nSigned-By: {KEYRING}\n\n"
            "Types: deb\nURIs: https://us-east-2.ec2.archive.ubuntu.com/ubuntu/\nSuites: resolute\n"
            f"Components: universe\nSigned-By: {KEYRING}\n"
        )
        self.assertEqual(sources.rewrite(deb822_https_userinfo, deb822=True), (deb822_https_userinfo, False))

        # Parse errors must not echo inline credentials from malformed source lines.
        with self.assertRaises(ValueError) as exc:
            sources.rewrite("deb [unclosed https://user:secretpass@example.com/ubuntu/ noble main\n", deb822=False)
        self.assertNotIn("secretpass", str(exc.exception))

        # APT's pkgAcquire::URIEncode encodes `+` as `%2b`, so regional suite
        # `profile+debug` collides with flat `/ubuntu/dists/profile%2bdebug/` + `/`.
        deb822_encoded_plus = (
            "Types: deb\nURIs: https://archive.ubuntu.com/ubuntu/dists/profile%2bdebug/\nSuites: /\n"
            f"Signed-By: {KEYRING}\n\n"
            "Types: deb\nURIs: https://us-east-2.ec2.archive.ubuntu.com/ubuntu/\nSuites: profile+debug\n"
            f"Components: main\nSigned-By: {alt_keyring}\n"
        )
        self.assertEqual(sources.rewrite(deb822_encoded_plus, deb822=True), (deb822_encoded_plus, False))

        # Bracketed host containing `/` flattens to the same URItoFileName key.
        deb822_bracket_slash = (
            "Types: deb\nURIs: http://[archive.ubuntu.com/ubuntu]/\nSuites: resolute\n"
            f"Components: main\nSigned-By: {KEYRING}\n\n"
            "Types: deb\nURIs: https://us-east-2.ec2.archive.ubuntu.com/ubuntu/\nSuites: resolute\n"
            f"Components: universe\nSigned-By: {KEYRING}\n"
        )
        self.assertEqual(sources.rewrite(deb822_bracket_slash, deb822=True), (deb822_bracket_slash, False))

        # Capitalized `HTTPS:` selects a different APT method than `https:` and
        # must block merges rather than being treated as ordinary `https:`.
        deb822_upper_scheme = (
            "Types: deb\nURIs: HTTPS://archive.ubuntu.com/ubuntu/\nSuites: resolute\n"
            f"Components: main\nSigned-By: {KEYRING}\n\n"
            "Types: deb\nURIs: https://us-east-2.ec2.archive.ubuntu.com/ubuntu/\nSuites: resolute\n"
            f"Components: universe\nSigned-By: {KEYRING}\n"
        )
        self.assertEqual(sources.rewrite(deb822_upper_scheme, deb822=True), (deb822_upper_scheme, False))

        # Percent-decoded UTF-8 bytes in one-line suites (`profile%c3%a9`) must
        # match both literal `profileé` and flat `/ubuntu/dists/profile%25c3%25a9/` + `/`.
        one_line_utf8_bytes = (
            f"deb [signed-by={KEYRING}] https://archive.ubuntu.com/ubuntu/dists/profile%25c3%25a9/ /\n"
            f"deb [signed-by={alt_keyring}] https://us-east-2.ec2.archive.ubuntu.com/ubuntu/ profile%c3%a9 main\n"
        )
        self.assertEqual(sources.rewrite(one_line_utf8_bytes, deb822=False), (one_line_utf8_bytes, False))

        one_line_utf8_literal_vs_pct = (
            f"deb [signed-by={KEYRING}] ftp://archive.ubuntu.com/ubuntu/ %c3%a9 main\n"
            f"deb [signed-by={KEYRING}] https://us-east-2.ec2.archive.ubuntu.com/ubuntu/ \u00e9 universe\n"
        )
        self.assertEqual(
            sources.rewrite(one_line_utf8_literal_vs_pct, deb822=False),
            (one_line_utf8_literal_vs_pct, False),
        )

        # `#` inside `[...]` brackets in a one-line suite is NOT a comment in APT,
        # matching APT's full-line `[` > `]` count loop (`sourcelist.cc:385-399`).
        one_line_bracket_hash = (
            f"deb [signed-by={KEYRING}] https://archive.ubuntu.com/ubuntu/dists/%5bprofile%23debug%5d/ /\n"
            f"deb [signed-by={alt_keyring}] https://us-east-2.ec2.archive.ubuntu.com/ubuntu/ [profile#debug] main\n"
        )
        self.assertEqual(sources.rewrite(one_line_bracket_hash, deb822=False), (one_line_bracket_hash, False))

        one_line_nested_bracket_hash = (
            f"deb [signed-by={KEYRING}] https://archive.ubuntu.com/ubuntu/ [[profile]#debug] main\n"
            f"deb [signed-by={alt_keyring}] https://us-east-2.ec2.archive.ubuntu.com/ubuntu/ %5b%5bprofile%5d%23debug%5d main\n"
        )
        self.assertEqual(
            sources.rewrite(one_line_nested_bracket_hash, deb822=False),
            (one_line_nested_bracket_hash, False),
        )

        one_line_unbalanced_bracket_hash = (
            f"deb [signed-by={KEYRING}] https://archive.ubuntu.com/ubuntu/dists/%5b%5bx%5d%23y/ /\n"
            f"deb [signed-by={alt_keyring}] https://us-east-2.ec2.archive.ubuntu.com/ubuntu/ [[x]#y main\n"
        )
        self.assertEqual(
            sources.rewrite(one_line_unbalanced_bracket_hash, deb822=False),
            (one_line_unbalanced_bracket_hash, False),
        )

        one_line_quoted_bracket_hash = (
            f"deb [signed-by={KEYRING}] https://archive.ubuntu.com/ubuntu/dists/%5b%23y/ /\n"
            f'deb [signed-by={alt_keyring}] https://us-east-2.ec2.archive.ubuntu.com/ubuntu/ "["#y main\n'
        )
        self.assertEqual(
            sources.rewrite(one_line_quoted_bracket_hash, deb822=False),
            (one_line_quoted_bracket_hash, False),
        )

        # 32-bit atoi port wrap (including >4300 leading zeroes exceeding
        # CPython's decimal int string limit): wraps to port 0 and blocks merges.
        for port_text in ("4294967296", "0" * 5000 + "4294967296"):
            with self.subTest(port_len=len(port_text)):
                deb822_port_wrap = (
                    f"Types: deb\nURIs: http://archive.ubuntu.com:{port_text}/ubuntu/\nSuites: resolute\n"
                    f"Components: main\nSigned-By: {KEYRING}\n\n"
                    "Types: deb\nURIs: https://us-east-2.ec2.archive.ubuntu.com/ubuntu/\nSuites: resolute\n"
                    f"Components: universe\nSigned-By: {KEYRING}\n"
                )
                self.assertEqual(sources.rewrite(deb822_port_wrap, deb822=True), (deb822_port_wrap, False))

        # Replacing a mirror URI whose raw text contains `[` or `]` must not
        # shift where APT's `#` comment boundary falls.
        for bracket_uri_line in (
            f'deb [signed-by={KEYRING}] "mirror+https://mirrors.ubuntu.com/list[" profile#debug main\n',
            f"deb [signed-by={KEYRING}] mirror://mirrors.ubuntu.com/mirrors.txt] noble x[[y] # comment extra\n",
        ):
            with self.subTest(line=bracket_uri_line):
                self.assertEqual(sources.rewrite(bracket_uri_line, deb822=False), (bracket_uri_line, False))

    @unittest.skipUnless(shutil.which("apt-get") and Path(KEYRING).exists(), "needs hosted Ubuntu apt-get")
    def test_hosted_apt_accepts_rewritten_mixed_and_distinct_policy_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lists = root / "lists"
            (lists / "partial").mkdir(parents=True)
            alt_keyring = root / "ubuntu-alt.gpg"
            shutil.copyfile(KEYRING, alt_keyring)
            for name, raw, deb822, expect_changed, required_uris, required_targets, forbid_substr in (
                (
                    "same-policy.sources",
                    "Types: deb\nURIs: http://archive.ubuntu.com:/ubuntu/\nSuites: resolute\n"
                    f"Components: main\nSigned-By: {KEYRING}\n\n"
                    "Types: deb\nURIs: https://us-east-2.ec2.archive.ubuntu.com/ubuntu/\nSuites: resolute\n"
                    f"Components: universe\nSigned-By: {KEYRING}\n",
                    True,
                    True,
                    ("https://archive.ubuntu.com/ubuntu/dists/resolute/InRelease",),
                    (
                        "https://archive.ubuntu.com/ubuntu/dists/resolute/main/binary-",
                        "https://archive.ubuntu.com/ubuntu/dists/resolute/universe/binary-",
                    ),
                    "http://archive.ubuntu.com",
                ),
                (
                    "distinct-policy.sources",
                    "Types: deb\nURIs: https://us-east-2.ec2.archive.ubuntu.com/ubuntu/\nSuites: resolute\n"
                    f"Components: main\nSigned-By: {KEYRING}\n\n"
                    "Types: deb\nURIs: https://azure.archive.ubuntu.com/ubuntu/\nSuites: resolute\n"
                    f"Components: universe\nSigned-By: {alt_keyring}\n",
                    True,
                    True,
                    (
                        "https://archive.ubuntu.com/ubuntu/dists/resolute/InRelease",
                        "https://azure.archive.ubuntu.com/ubuntu/dists/resolute/InRelease",
                    ),
                    (),
                    "http://archive.ubuntu.com",
                ),
                (
                    "distinct-policy.list",
                    f"deb [signed-by={KEYRING}] https://us-east-2.ec2.archive.ubuntu.com/ubuntu/ resolute main\n"
                    f"deb [signed-by={alt_keyring}] https://azure.archive.ubuntu.com/ubuntu/ resolute universe\n",
                    False,
                    True,
                    (
                        "https://archive.ubuntu.com/ubuntu/dists/resolute/InRelease",
                        "https://azure.archive.ubuntu.com/ubuntu/dists/resolute/InRelease",
                    ),
                    (),
                    "http://archive.ubuntu.com",
                ),
                (
                    "port80-distinct.sources",
                    "Types: deb\nURIs: http://archive.ubuntu.com:80/ubuntu/\nSuites: resolute\n"
                    f"Components: main\nSigned-By: {KEYRING}\n\n"
                    "Types: deb\nURIs: https://archive.ubuntu.com/ubuntu/\nSuites: resolute\n"
                    f"Components: universe\nSigned-By: {alt_keyring}\n\n"
                    "Types: deb\nURIs: https://us-east-2.ec2.archive.ubuntu.com/ubuntu/\nSuites: resolute-updates\n"
                    f"Components: main\nSigned-By: {KEYRING}\n",
                    True,
                    True,
                    ("https://archive.ubuntu.com/ubuntu/dists/resolute-updates/InRelease",),
                    (),
                    None,
                ),
                (
                    "snapshot-distinct.sources",
                    "Types: deb\nURIs: https://us-east-2.ec2.archive.ubuntu.com/ubuntu/\nSuites: resolute\n"
                    f"Components: main\nSigned-By: {KEYRING}\nSnapshot: 20260401T000000Z\n\n"
                    "Types: deb\nURIs: https://azure.archive.ubuntu.com/ubuntu/\nSuites: resolute\n"
                    f"Components: universe\nSigned-By: {KEYRING}\nSnapshot: 20260501T000000Z\n",
                    True,
                    True,
                    ("/dists/resolute/InRelease",),
                    (),
                    "http://archive.ubuntu.com",
                ),
                (
                    "snapshot-distinct.list",
                    f"deb [signed-by={KEYRING} snapshot=20260401T000000Z] https://us-east-2.ec2.archive.ubuntu.com/ubuntu/ resolute main\n"
                    f"deb [signed-by={KEYRING} snapshot=20260501T000000Z] https://azure.archive.ubuntu.com/ubuntu/ resolute universe\n",
                    False,
                    True,
                    ("/dists/resolute/InRelease",),
                    (),
                    "http://archive.ubuntu.com",
                ),
                (
                    "mixed-case-option.list",
                    f"deb [signed-by={KEYRING} Signed-By={alt_keyring}] https://us-east-2.ec2.archive.ubuntu.com/ubuntu/ resolute main\n"
                    f"deb [signed-by={alt_keyring}] https://azure.archive.ubuntu.com/ubuntu/ resolute universe\n",
                    False,
                    True,
                    (
                        "https://archive.ubuntu.com/ubuntu/dists/resolute/InRelease",
                        "https://azure.archive.ubuntu.com/ubuntu/dists/resolute/InRelease",
                    ),
                    (),
                    "http://archive.ubuntu.com",
                ),
                (
                    "userinfo-distinct.sources",
                    "Types: deb\nURIs: http://reader@archive.ubuntu.com/ubuntu/\nSuites: resolute\n"
                    f"Components: main\nSigned-By: {KEYRING}\n\n"
                    "Types: deb\nURIs: https://us-east-2.ec2.archive.ubuntu.com/ubuntu/\nSuites: resolute\n"
                    f"Components: universe\nSigned-By: {alt_keyring}\n\n"
                    "Types: deb\nURIs: https://us-east-2.ec2.archive.ubuntu.com/ubuntu/\nSuites: resolute-updates\n"
                    f"Components: main\nSigned-By: {KEYRING}\n",
                    True,
                    True,
                    (
                        "https://archive.ubuntu.com/ubuntu/dists/resolute-updates/InRelease",
                        "https://us-east-2.ec2.archive.ubuntu.com/ubuntu/dists/resolute/InRelease",
                    ),
                    (),
                    None,
                ),
                (
                    "userinfo-same-policy.list",
                    f"deb [signed-by={KEYRING}] http://reader@archive.ubuntu.com/ubuntu/ resolute main\n"
                    f"deb [signed-by={KEYRING}] https://us-east-2.ec2.archive.ubuntu.com/ubuntu/ resolute universe\n"
                    f"deb [signed-by={KEYRING}] https://us-east-2.ec2.archive.ubuntu.com/ubuntu/ resolute-updates main\n",
                    False,
                    True,
                    (
                        "https://archive.ubuntu.com/ubuntu/dists/resolute-updates/InRelease",
                        "https://us-east-2.ec2.archive.ubuntu.com/ubuntu/dists/resolute/InRelease",
                    ),
                    (),
                    None,
                ),
                (
                    "flat-suite-distinct.sources",
                    "Types: deb\nURIs: http://archive.ubuntu.com/ubuntu/\nSuites: resolute\n"
                    f"Components: main\nSigned-By: {KEYRING}\n\n"
                    "Types: deb\nURIs: https://us-east-2.ec2.archive.ubuntu.com/ubuntu/\nSuites: dists/resolute/\n"
                    f"Signed-By: {alt_keyring}\n\n"
                    "Types: deb\nURIs: https://us-east-2.ec2.archive.ubuntu.com/ubuntu/\nSuites: resolute-updates\n"
                    f"Components: main\nSigned-By: {KEYRING}\n",
                    True,
                    True,
                    (
                        "https://archive.ubuntu.com/ubuntu/dists/resolute-updates/InRelease",
                        "https://us-east-2.ec2.archive.ubuntu.com/ubuntu/dists/resolute/InRelease",
                    ),
                    (),
                    None,
                ),
                (
                    "multi-suite-two-hop-blocked.sources",
                    "Types: deb\nURIs: http://archive.ubuntu.com/ubuntu/\nSuites: resolute resolute-updates\n"
                    f"Components: main\nSigned-By: {KEYRING}\n\n"
                    "Types: deb\nURIs: http://archive.ubuntu.com/ubuntu/\nSuites: resolute-updates resolute-backports\n"
                    f"Components: main\nSigned-By: {KEYRING}\n\n"
                    "Types: deb\nURIs: http://reader@archive.ubuntu.com/ubuntu/\nSuites: resolute-backports\n"
                    f"Components: universe\nSigned-By: {KEYRING}\n\n"
                    "Types: deb\nURIs: https://us-east-2.ec2.archive.ubuntu.com/ubuntu/\nSuites: resolute\n"
                    f"Components: universe\nSigned-By: {KEYRING}\n\n"
                    "Types: deb\nURIs: https://us-east-2.ec2.archive.ubuntu.com/ubuntu/\nSuites: resolute-proposed\n"
                    f"Components: main\nSigned-By: {KEYRING}\n",
                    True,
                    True,
                    (
                        "https://archive.ubuntu.com/ubuntu/dists/resolute-proposed/InRelease",
                        "https://us-east-2.ec2.archive.ubuntu.com/ubuntu/dists/resolute/InRelease",
                    ),
                    (),
                    None,
                ),
                (
                    "uri-suite-split.sources",
                    "Types: deb\nURIs: http://archive.ubuntu.com/ubuntu/dists/\nSuites: resolute/\n"
                    f"Signed-By: {KEYRING}\n\n"
                    "Types: deb\nURIs: https://us-east-2.ec2.archive.ubuntu.com/ubuntu/\nSuites: resolute\n"
                    f"Components: main\nSigned-By: {KEYRING}\n\n"
                    "Types: deb\nURIs: https://us-east-2.ec2.archive.ubuntu.com/ubuntu/\nSuites: resolute-updates\n"
                    f"Components: main\nSigned-By: {KEYRING}\n",
                    True,
                    True,
                    (
                        "https://archive.ubuntu.com/ubuntu/dists/resolute-updates/InRelease",
                        "https://us-east-2.ec2.archive.ubuntu.com/ubuntu/dists/resolute/InRelease",
                    ),
                    ("https://us-east-2.ec2.archive.ubuntu.com/ubuntu/dists/resolute/main/binary-",),
                    None,
                ),
                (
                    "uri-suite-split.list",
                    f"deb [signed-by={KEYRING}] http://archive.ubuntu.com/ubuntu/dists/ resolute/\n"
                    f"deb [signed-by={KEYRING}] https://us-east-2.ec2.archive.ubuntu.com/ubuntu/ resolute main\n"
                    f"deb [signed-by={KEYRING}] https://us-east-2.ec2.archive.ubuntu.com/ubuntu/ resolute-updates main\n",
                    False,
                    True,
                    (
                        "https://archive.ubuntu.com/ubuntu/dists/resolute-updates/InRelease",
                        "https://us-east-2.ec2.archive.ubuntu.com/ubuntu/dists/resolute/InRelease",
                    ),
                    ("https://us-east-2.ec2.archive.ubuntu.com/ubuntu/dists/resolute/main/binary-",),
                    None,
                ),
                (
                    "upper-host-distinct.sources",
                    "Types: deb\nURIs: https://ARCHIVE.UBUNTU.COM/ubuntu/\nSuites: resolute\n"
                    f"Components: main\nSigned-By: {alt_keyring}\n\n"
                    "Types: deb\nURIs: https://us-east-2.ec2.archive.ubuntu.com/ubuntu/\nSuites: resolute\n"
                    f"Components: universe\nSigned-By: {KEYRING}\n",
                    True,
                    True,
                    (
                        "https://ARCHIVE.UBUNTU.COM/ubuntu/dists/resolute/InRelease",
                        "https://archive.ubuntu.com/ubuntu/dists/resolute/InRelease",
                    ),
                    (),
                    "http://archive.ubuntu.com",
                ),
                (
                    "upper-host-distinct.list",
                    f"deb [signed-by={alt_keyring}] https://ARCHIVE.UBUNTU.COM/ubuntu/ resolute main\n"
                    f"deb [signed-by={KEYRING}] https://us-east-2.ec2.archive.ubuntu.com/ubuntu/ resolute universe\n",
                    False,
                    True,
                    (
                        "https://ARCHIVE.UBUNTU.COM/ubuntu/dists/resolute/InRelease",
                        "https://archive.ubuntu.com/ubuntu/dists/resolute/InRelease",
                    ),
                    (),
                    "http://archive.ubuntu.com",
                ),
                (
                    "include-filter-distinct.sources",
                    "Types: deb\nURIs: https://us-east-2.ec2.archive.ubuntu.com/ubuntu/\nSuites: resolute\n"
                    f"Components: main\nSigned-By: {KEYRING}\nInclude: curl\n\n"
                    "Types: deb\nURIs: https://azure.archive.ubuntu.com/ubuntu/\nSuites: resolute\n"
                    f"Components: main\nSigned-By: {KEYRING}\nInclude: libssl-dev\n",
                    True,
                    True,
                    (
                        "https://archive.ubuntu.com/ubuntu/dists/resolute/InRelease",
                        "https://azure.archive.ubuntu.com/ubuntu/dists/resolute/InRelease",
                    ),
                    (
                        "https://archive.ubuntu.com/ubuntu/dists/resolute/main/binary-",
                        "https://azure.archive.ubuntu.com/ubuntu/dists/resolute/main/binary-",
                    ),
                    "http://archive.ubuntu.com",
                ),
                (
                    "include-filter-distinct.list",
                    f"deb [signed-by={KEYRING} include=curl] https://us-east-2.ec2.archive.ubuntu.com/ubuntu/ resolute main\n"
                    f"deb [signed-by={KEYRING} include=libssl-dev] https://azure.archive.ubuntu.com/ubuntu/ resolute main\n",
                    False,
                    True,
                    (
                        "https://archive.ubuntu.com/ubuntu/dists/resolute/InRelease",
                        "https://azure.archive.ubuntu.com/ubuntu/dists/resolute/InRelease",
                    ),
                    (
                        "https://archive.ubuntu.com/ubuntu/dists/resolute/main/binary-",
                        "https://azure.archive.ubuntu.com/ubuntu/dists/resolute/main/binary-",
                    ),
                    "http://archive.ubuntu.com",
                ),
                (
                    "flat-vs-component-https.sources",
                    "Types: deb\nURIs: https://archive.ubuntu.com/ubuntu/dists/\nSuites: resolute/\n"
                    f"Signed-By: {KEYRING}\n\n"
                    "Types: deb\nURIs: https://us-east-2.ec2.archive.ubuntu.com/ubuntu/\nSuites: resolute\n"
                    f"Components: main\nSigned-By: {KEYRING}\n\n"
                    "Types: deb\nURIs: https://us-east-2.ec2.archive.ubuntu.com/ubuntu/\nSuites: resolute-updates\n"
                    f"Components: main\nSigned-By: {KEYRING}\n",
                    True,
                    True,
                    (
                        "https://archive.ubuntu.com/ubuntu/dists/resolute-updates/InRelease",
                        "https://us-east-2.ec2.archive.ubuntu.com/ubuntu/dists/resolute/InRelease",
                    ),
                    (
                        "https://archive.ubuntu.com/ubuntu/dists/resolute/Packages",
                        "https://us-east-2.ec2.archive.ubuntu.com/ubuntu/dists/resolute/main/binary-",
                    ),
                    "http://archive.ubuntu.com",
                ),
                (
                    "flat-vs-component-https.list",
                    f"deb [signed-by={KEYRING}] https://archive.ubuntu.com/ubuntu/dists/ resolute/\n"
                    f"deb [signed-by={KEYRING}] https://us-east-2.ec2.archive.ubuntu.com/ubuntu/ resolute main\n"
                    f"deb [signed-by={KEYRING}] https://us-east-2.ec2.archive.ubuntu.com/ubuntu/ resolute-updates main\n",
                    False,
                    True,
                    (
                        "https://archive.ubuntu.com/ubuntu/dists/resolute-updates/InRelease",
                        "https://us-east-2.ec2.archive.ubuntu.com/ubuntu/dists/resolute/InRelease",
                    ),
                    (
                        "https://archive.ubuntu.com/ubuntu/dists/resolute/Packages",
                        "https://us-east-2.ec2.archive.ubuntu.com/ubuntu/dists/resolute/main/binary-",
                    ),
                    "http://archive.ubuntu.com",
                ),
                (
                    "no-slashes-http.sources",
                    "Types: deb\nURIs: http:archive.ubuntu.com/ubuntu/\nSuites: resolute\n"
                    f"Components: main\nSigned-By: {KEYRING}\n\n"
                    "Types: deb\nURIs: https://us-east-2.ec2.archive.ubuntu.com/ubuntu/\nSuites: resolute\n"
                    f"Components: universe\nSigned-By: {alt_keyring}\n\n"
                    "Types: deb\nURIs: https://us-east-2.ec2.archive.ubuntu.com/ubuntu/\nSuites: resolute-updates\n"
                    f"Components: main\nSigned-By: {KEYRING}\n",
                    True,
                    True,
                    (
                        "https://archive.ubuntu.com/ubuntu/dists/resolute-updates/InRelease",
                        "https://us-east-2.ec2.archive.ubuntu.com/ubuntu/dists/resolute/InRelease",
                    ),
                    (),
                    None,
                ),
                (
                    "arch-var-distinct.sources",
                    "Types: deb\nURIs: https://archive.ubuntu.com/ubuntu/\nSuites: resolute-$(ARCH)\n"
                    f"Components: main\nSigned-By: {KEYRING}\n\n"
                    "Types: deb\nURIs: https://us-east-2.ec2.archive.ubuntu.com/ubuntu/\nSuites: resolute-amd64 resolute-arm64\n"
                    f"Components: universe\nSigned-By: {alt_keyring}\n",
                    True,
                    False,
                    ("https://us-east-2.ec2.archive.ubuntu.com/ubuntu/dists/resolute-amd64/InRelease",),
                    (),
                    "http://archive.ubuntu.com",
                ),
                (
                    "flat-repo-root-distinct.sources",
                    "Types: deb\nURIs: https://archive.ubuntu.com/ubuntu/dists/resolute/\nSuites: /\n"
                    f"Signed-By: {KEYRING}\n\n"
                    "Types: deb\nURIs: https://us-east-2.ec2.archive.ubuntu.com/ubuntu/\nSuites: dists/resolute/\n"
                    f"Signed-By: {KEYRING}\n\n"
                    "Types: deb\nURIs: https://us-east-2.ec2.archive.ubuntu.com/ubuntu/\nSuites: resolute-updates\n"
                    f"Components: main\nSigned-By: {KEYRING}\n",
                    True,
                    True,
                    (
                        "https://archive.ubuntu.com/ubuntu/dists/resolute-updates/InRelease",
                        "https://us-east-2.ec2.archive.ubuntu.com/ubuntu/dists/resolute/InRelease",
                    ),
                    (
                        "Repo-URI: https://archive.ubuntu.com/ubuntu/dists/resolute/",
                        "Repo-URI: https://us-east-2.ec2.archive.ubuntu.com/ubuntu/",
                    ),
                    "http://archive.ubuntu.com",
                ),
                (
                    "bracket-host-http.sources",
                    "Types: deb\nURIs: http://[archive.ubuntu.com]/ubuntu/\nSuites: resolute\n"
                    f"Components: main\nSigned-By: {KEYRING}\n\n"
                    "Types: deb\nURIs: https://us-east-2.ec2.archive.ubuntu.com/ubuntu/\nSuites: resolute\n"
                    f"Components: universe\nSigned-By: {alt_keyring}\n\n"
                    "Types: deb\nURIs: https://us-east-2.ec2.archive.ubuntu.com/ubuntu/\nSuites: resolute-updates\n"
                    f"Components: main\nSigned-By: {KEYRING}\n",
                    True,
                    True,
                    (
                        "https://archive.ubuntu.com/ubuntu/dists/resolute-updates/InRelease",
                        "https://us-east-2.ec2.archive.ubuntu.com/ubuntu/dists/resolute/InRelease",
                    ),
                    (),
                    None,
                ),
                (
                    "slashless-https-compatible.sources",
                    "Types: deb\nURIs: https:archive.ubuntu.com/ubuntu/\nSuites: resolute\n"
                    f"Components: main\nSigned-By: {KEYRING}\n\n"
                    "Types: deb\nURIs: https://us-east-2.ec2.archive.ubuntu.com/ubuntu/\nSuites: resolute\n"
                    f"Components: universe\nSigned-By: {KEYRING}\n",
                    True,
                    True,
                    ("https://archive.ubuntu.com/ubuntu/dists/resolute/InRelease",),
                    (
                        "https://archive.ubuntu.com/ubuntu/dists/resolute/main/binary-",
                        "https://archive.ubuntu.com/ubuntu/dists/resolute/universe/binary-",
                    ),
                    "http://archive.ubuntu.com",
                ),
                (
                    "https-userinfo-distinct.sources",
                    "Types: deb\nURIs: https://reader@archive.ubuntu.com/ubuntu/\nSuites: resolute\n"
                    f"Components: main\nSigned-By: {KEYRING}\n\n"
                    "Types: deb\nURIs: https://us-east-2.ec2.archive.ubuntu.com/ubuntu/\nSuites: resolute\n"
                    f"Components: universe\nSigned-By: {KEYRING}\n\n"
                    "Types: deb\nURIs: https://us-east-2.ec2.archive.ubuntu.com/ubuntu/\nSuites: resolute-updates\n"
                    f"Components: main\nSigned-By: {KEYRING}\n",
                    True,
                    True,
                    (
                        "https://archive.ubuntu.com/ubuntu/dists/resolute-updates/InRelease",
                        "https://us-east-2.ec2.archive.ubuntu.com/ubuntu/dists/resolute/InRelease",
                    ),
                    (
                        "Repo-URI: https://reader@archive.ubuntu.com/ubuntu/",
                        "Repo-URI: https://us-east-2.ec2.archive.ubuntu.com/ubuntu/",
                    ),
                    "http://archive.ubuntu.com",
                ),
                (
                    "encoded-suite-plus.sources",
                    "Types: deb\nURIs: https://archive.ubuntu.com/ubuntu/dists/profile%2bdebug/\nSuites: /\n"
                    f"Signed-By: {KEYRING}\n\n"
                    "Types: deb\nURIs: https://us-east-2.ec2.archive.ubuntu.com/ubuntu/\nSuites: profile+debug\n"
                    f"Components: main\nSigned-By: {alt_keyring}\n\n"
                    "Types: deb\nURIs: https://us-east-2.ec2.archive.ubuntu.com/ubuntu/\nSuites: resolute-updates\n"
                    f"Components: main\nSigned-By: {KEYRING}\n",
                    True,
                    True,
                    (
                        "https://archive.ubuntu.com/ubuntu/dists/resolute-updates/InRelease",
                        "https://us-east-2.ec2.archive.ubuntu.com/ubuntu/dists/profile%2bdebug/InRelease",
                    ),
                    (
                        "Repo-URI: https://archive.ubuntu.com/ubuntu/dists/profile%2bdebug/",
                        "Repo-URI: https://us-east-2.ec2.archive.ubuntu.com/ubuntu/",
                    ),
                    "http://archive.ubuntu.com",
                ),
                (
                    "tor-slashless-distinct.sources",
                    "Types: deb\nURIs: tor+https:archive.ubuntu.com/ubuntu/\nSuites: resolute\n"
                    f"Components: main\nSigned-By: {KEYRING}\n\n"
                    "Types: deb\nURIs: https://us-east-2.ec2.archive.ubuntu.com/ubuntu/\nSuites: resolute\n"
                    f"Components: universe\nSigned-By: {alt_keyring}\n\n"
                    "Types: deb\nURIs: https://us-east-2.ec2.archive.ubuntu.com/ubuntu/\nSuites: resolute-updates\n"
                    f"Components: main\nSigned-By: {KEYRING}\n",
                    True,
                    True,
                    (),
                    (
                        "Repo-URI: tor+https://archive.ubuntu.com/ubuntu/",
                        "Repo-URI: https://us-east-2.ec2.archive.ubuntu.com/ubuntu/",
                        "https://archive.ubuntu.com/ubuntu/dists/resolute-updates/main/binary-",
                    ),
                    "http://archive.ubuntu.com",
                ),
                (
                    "percent-utf8-suite.list",
                    f"deb [signed-by={KEYRING}] https://archive.ubuntu.com/ubuntu/dists/profile%25c3%25a9/ /\n"
                    f"deb [signed-by={alt_keyring}] https://us-east-2.ec2.archive.ubuntu.com/ubuntu/ profile%c3%a9 main\n"
                    f"deb [signed-by={KEYRING}] https://us-east-2.ec2.archive.ubuntu.com/ubuntu/ resolute-updates main\n",
                    False,
                    True,
                    (
                        "https://archive.ubuntu.com/ubuntu/dists/resolute-updates/InRelease",
                        "https://us-east-2.ec2.archive.ubuntu.com/ubuntu/dists/profile%c3%a9/InRelease",
                    ),
                    (
                        "Repo-URI: https://archive.ubuntu.com/ubuntu/dists/profile%c3%a9/",
                        "Repo-URI: https://us-east-2.ec2.archive.ubuntu.com/ubuntu/",
                    ),
                    "http://archive.ubuntu.com",
                ),
                (
                    "bracket-hash-suite.list",
                    f"deb [signed-by={KEYRING}] https://archive.ubuntu.com/ubuntu/dists/%5bprofile%23debug%5d/ /\n"
                    f"deb [signed-by={alt_keyring}] https://us-east-2.ec2.archive.ubuntu.com/ubuntu/ [profile#debug] main\n"
                    f"deb [signed-by={KEYRING}] https://us-east-2.ec2.archive.ubuntu.com/ubuntu/ resolute-updates main\n",
                    False,
                    True,
                    (
                        "https://archive.ubuntu.com/ubuntu/dists/resolute-updates/InRelease",
                        "https://us-east-2.ec2.archive.ubuntu.com/ubuntu/dists/[profile#debug]/InRelease",
                    ),
                    (
                        "Repo-URI: https://archive.ubuntu.com/ubuntu/dists/[profile#debug]/",
                        "Repo-URI: https://us-east-2.ec2.archive.ubuntu.com/ubuntu/",
                    ),
                    "http://archive.ubuntu.com",
                ),
                (
                    "nested-bracket-hash-suite.list",
                    f"deb [signed-by={KEYRING}] https://archive.ubuntu.com/ubuntu/ [[profile]#debug] main\n"
                    f"deb [signed-by={alt_keyring}] https://us-east-2.ec2.archive.ubuntu.com/ubuntu/ %5b%5bprofile%5d%23debug%5d main\n"
                    f"deb [signed-by={KEYRING}] https://us-east-2.ec2.archive.ubuntu.com/ubuntu/ resolute-updates main\n",
                    False,
                    True,
                    (
                        "https://archive.ubuntu.com/ubuntu/dists/resolute-updates/InRelease",
                        "https://us-east-2.ec2.archive.ubuntu.com/ubuntu/dists/[[profile]#debug]/InRelease",
                    ),
                    (
                        "Repo-URI: https://archive.ubuntu.com/ubuntu/",
                        "Repo-URI: https://us-east-2.ec2.archive.ubuntu.com/ubuntu/",
                    ),
                    "http://archive.ubuntu.com",
                ),
                (
                    "unbalanced-and-quoted-bracket-hash.list",
                    f"deb [signed-by={KEYRING}] https://archive.ubuntu.com/ubuntu/dists/%5b%5bx%5d%23y/ /\n"
                    f"deb [signed-by={alt_keyring}] https://us-east-2.ec2.archive.ubuntu.com/ubuntu/ [[x]#y main\n"
                    f"deb [signed-by={KEYRING}] https://archive.ubuntu.com/ubuntu/dists/%5b%23z/ /\n"
                    f'deb [signed-by={alt_keyring}] https://us-east-2.ec2.archive.ubuntu.com/ubuntu/ "["#z main\n'
                    f"deb [signed-by={KEYRING}] https://us-east-2.ec2.archive.ubuntu.com/ubuntu/ resolute-updates main\n",
                    False,
                    True,
                    (
                        "https://archive.ubuntu.com/ubuntu/dists/resolute-updates/InRelease",
                        "https://us-east-2.ec2.archive.ubuntu.com/ubuntu/dists/[[x]#y/InRelease",
                        "https://us-east-2.ec2.archive.ubuntu.com/ubuntu/dists/[#z/InRelease",
                    ),
                    (),
                    "http://archive.ubuntu.com",
                ),
                (
                    "port-wrap-http.sources",
                    "Types: deb\nURIs: http://archive.ubuntu.com:4294967296/ubuntu/\nSuites: resolute\n"
                    f"Components: main\nSigned-By: {KEYRING}\n\n"
                    "Types: deb\nURIs: https://us-east-2.ec2.archive.ubuntu.com/ubuntu/\nSuites: resolute\n"
                    f"Components: universe\nSigned-By: {alt_keyring}\n\n"
                    "Types: deb\nURIs: https://us-east-2.ec2.archive.ubuntu.com/ubuntu/\nSuites: resolute-updates\n"
                    f"Components: main\nSigned-By: {KEYRING}\n",
                    True,
                    True,
                    (
                        "https://archive.ubuntu.com/ubuntu/dists/resolute-updates/InRelease",
                        "https://us-east-2.ec2.archive.ubuntu.com/ubuntu/dists/resolute/InRelease",
                    ),
                    (),
                    None,
                ),
                (
                    "bracket-in-uri-comment-boundary.list",
                    f'deb [signed-by={KEYRING}] "mirror+https://mirrors.ubuntu.com/list[" profile#debug main\n'
                    f"deb [signed-by={KEYRING}] https://us-east-2.ec2.archive.ubuntu.com/ubuntu/ resolute-updates main\n",
                    False,
                    True,
                    (),
                    (
                        "https://archive.ubuntu.com/ubuntu/dists/resolute-updates/main/binary-",
                        "mirror+https://mirrors.ubuntu.com/list[/dists/profile#debug/main/binary-",
                    ),
                    "http://archive.ubuntu.com",
                ),
            ):
                with self.subTest(case=name):
                    rewritten, changed = sources.rewrite(raw, deb822)
                    self.assertEqual(changed, expect_changed)
                    out = root / name
                    out.write_text(rewritten)
                    base_opts = [
                        "-o", f"Dir::Etc::sourcelist={out}",
                        "-o", "Dir::Etc::sourceparts=-",
                        "-o", f"Dir::State::lists={lists}",
                        "-o", "Acquire::URIEncode=+~ ",
                        "-o", "Debug::NoLocking=1",
                    ]
                    if required_uris:
                        proc = subprocess.run(
                            ["apt-get", *base_opts, "update", "--print-uris"],
                            capture_output=True,
                            text=True,
                            timeout=30,
                        )
                        self.assertEqual(proc.returncode, 0, proc.stderr)
                        for expected in required_uris:
                            self.assertIn(expected, proc.stdout)
                        if forbid_substr:
                            self.assertNotIn(forbid_substr, proc.stdout)
                    if required_targets:
                        targets = subprocess.run(
                            [
                                "apt-get",
                                *base_opts,
                                "-o", "Dir::Cache::pkgcache=",
                                "-o", "Dir::Cache::srcpkgcache=",
                                "-o", "APT::Get::IndexTargets::ReleaseInfo=0",
                                "indextargets",
                            ],
                            capture_output=True,
                            text=True,
                            timeout=30,
                        )
                        self.assertEqual(targets.returncode, 0, targets.stderr)
                        for expected_target in required_targets:
                            self.assertIn(expected_target, targets.stdout)
                        if forbid_substr:
                            self.assertNotIn(forbid_substr, targets.stdout)

    def test_one_line_adjacent_uri_after_option_bracket_is_rewritten_and_checked(self):
        adjacent = f"deb [signed-by={KEYRING} ]http://azure.archive.ubuntu.com/ubuntu/ noble main\n"
        rewritten, changed = sources.rewrite(adjacent, deb822=False)
        self.assertTrue(changed)
        self.assertEqual(rewritten, f"deb [signed-by={KEYRING} ]{sources.CANONICAL} noble main\n")
        for unsafe_or_ambiguous in (
            "deb [trusted=yes ]http://azure.archive.ubuntu.com/ubuntu/ noble main\n",
            "deb [signed-by=K]http://azure.archive.ubuntu.com/ubuntu/ trusted=yes ]http://evil.example/ noble main\n",
            "deb [signed-by=K]x trusted=yes ]http://evil.example/ noble main\n",
        ):
            with self.subTest(line=unsafe_or_ambiguous), self.assertRaises(ValueError):
                sources.rewrite(unsafe_or_ambiguous, deb822=False)

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
                ("Types: deb\nURIs: http://archive.ubuntu.com.evil.example/ubuntu/\nSuites: noble\n", True),
                ("deb HTTPS://azure.archive.ubuntu.com/ubuntu/ noble main\n", False),
                ("deb MIRROR+HTTPS://mirrors.ubuntu.com/mirrors.txt noble main\n", False),
                ("Types: deb\nURIs: HTTPS://us-east-2.ec2.archive.ubuntu.com/ubuntu/\nSuites: noble\n", True),
                ("Types: deb\nURIs: MIRROR+FILE:/etc/apt/apt-mirrors.txt\nSuites: noble\n", True),
                ("Types: deb\nURIs: https://us-east-2.ec2.arch\u0131ve.ubuntu.com/ubuntu/\nSuites: noble\n", True)):
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
            self.assertEqual(stat.S_IMODE(dest.stat().st_mode), 0o600)
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
joined=""
for arg in "$@"; do
  if [ -n "$joined" ]; then joined+=$'\x1f'; fi
  joined+="$arg"
done
printf '%s\t%s\t%s\t%s\t%s\n' "$phase" "$action" "${DEBIAN_FRONTEND:-}" "${IN_TIMEOUT:-0}" "$joined" >> "$FAKE_LOG/apt.log"
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
        if not path.exists():
            return []
        rows = []
        for line in path.read_text().splitlines():
            phase, action, frontend, in_timeout, argv = line.split("\t", 4)
            rows.append((phase, action, frontend, in_timeout, argv.split("\x1f")))
        return rows

    def assert_apt_options(self, argv, source, phase):
        pairs = list(zip(argv, argv[1:]))
        for option in (f"Dir::Etc::sourcelist={source}", "Dir::Etc::sourceparts=-",
                       "Acquire::URIEncode=+~ "):
            self.assertIn(("-o", option), pairs)
        fallback_only = ("Acquire::Retries=3", "Acquire::http::Timeout=30", "Acquire::https::Timeout=30")
        for option in fallback_only:
            if phase == "fallback":
                self.assertIn(("-o", option), pairs)
            else:
                self.assertNotIn(("-o", option), pairs)

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
        for phase, action, frontend, _, argv in calls:
            self.assertEqual(frontend, "noninteractive")
            self.assert_apt_options(argv, self.etc / "sources.list.d/ubuntu.sources", phase)
            if action == "update":
                self.assertIn(("-o", "APT::Update::Error-Mode=any"), list(zip(argv, argv[1:])))
        self.assertEqual(
            calls[1][4][-7:],
            ["install", "-y", "--no-install-recommends", "--download-only", "--", "clang-18", "llvm-18"],
        )
        self.assertEqual(
            calls[2][4][-7:],
            ["install", "-y", "--no-install-recommends", "--no-download", "--", "clang-18", "llvm-18"],
        )

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
                source = next(
                    arg.split("=", 1)[1]
                    for arg in fallback[0][4]
                    if arg.startswith("Dir::Etc::sourcelist=")
                )
                self.assertTrue(source.endswith(".sources"))
                for phase, action, frontend, _, argv in fallback:
                    self.assertEqual(frontend, "noninteractive")
                    self.assert_apt_options(argv, source, phase)
                    if action == "update":
                        self.assertIn(("-o", "APT::Update::Error-Mode=any"), list(zip(argv, argv[1:])))
                self.assertFalse(Path(source).exists(), "temporary fallback source is removed")
                self.assertEqual((self.log / "fallback-source").read_text(),
                                 sources.rewrite(DEB822, deb822=True)[0])

    def test_one_line_sources_list_falls_back_with_list_format(self):
        (self.etc / "sources.list").write_text(ONE_LINE)
        result = self.run_script("primary-download")
        self.assertEqual(result.returncode, 0, result.stderr)
        fallback = [c for c in self.calls() if c[0] == "fallback"]
        source = next(
            arg.split("=", 1)[1]
            for arg in fallback[0][4]
            if arg.startswith("Dir::Etc::sourcelist=")
        )
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
