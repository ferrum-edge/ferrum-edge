#!/usr/bin/env python3
"""Contracts and failure-path regressions for policy/compilation overlap (#4680).

Executed by verify_required_ci.py in Tests. These checks share that checker's
PR-mutable trust tier; the immutable pull_request_target policy remains the
admission authority and is deliberately not relaxed for this migration.
"""

import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

from verify_ci_runtime_cache import job_steps
from verify_publication_gate import (
    StructuralError, _mapping, _parse_job, _protected_job_body, _scalar, _sequence,
)


# Complete active steps: pinning, extraction, failure propagation and event
# inputs must move together. Never derive expected text from the candidate.
PIN_STEP = r"""      - id: trusted-base
        name: Pin trusted CI base
        env:
          EVENT_NAME: ${{ github.event_name }}
          BASE_REF: ${{ github.base_ref }}
          EVENT_BASE_SHA: ${{ github.event.pull_request.base.sha || github.event.merge_group.base_sha }}
          MERGE_HEAD_SHA: ${{ github.event.merge_group.head_sha }}
        run: |
          set -euo pipefail
          checked_out="$(git rev-parse HEAD)"
          if [ "$checked_out" != "$GITHUB_SHA" ]; then
            echo "::error::checkout does not match the triggering SHA" >&2
            exit 1
          fi
          trusted_base="$checked_out"
          if [ "$EVENT_NAME" = "pull_request" ] || [ "$EVENT_NAME" = "merge_group" ]; then
            if [[ ! "$EVENT_BASE_SHA" =~ ^[0-9a-f]{40}$ ]]; then
              echo "::error::event base SHA missing or malformed" >&2
              exit 1
            fi
            if ! git cat-file -e "${EVENT_BASE_SHA}^{commit}" 2>/dev/null; then
              git fetch --no-tags origin "$EVENT_BASE_SHA"
            fi
            if [ "$EVENT_NAME" = "pull_request" ]; then
              if [[ ! "$BASE_REF" =~ ^[A-Za-z0-9._/-]+$ ]] || [[ "$BASE_REF" == *".."* ]] \
                || [[ "$BASE_REF" == -* ]] || [[ "$BASE_REF" == */ ]]; then
                echo "::error::invalid triggering base ref" >&2
                exit 1
              fi
              git fetch --no-tags origin \
                "+refs/heads/${BASE_REF}:refs/remotes/trusted-ci-base"
              trusted_base="$(git rev-parse "refs/remotes/trusted-ci-base^{commit}")"
              if ! git merge-base --is-ancestor "$EVENT_BASE_SHA" "$trusted_base"; then
                echo "::error::live base does not descend from the event base" >&2
                exit 1
              fi
            else
              if [ "$checked_out" != "$MERGE_HEAD_SHA" ]; then
                echo "::error::checkout is not the merge-group head" >&2
                exit 1
              fi
              trusted_base="$EVENT_BASE_SHA"
            fi
          fi
          if [[ ! "$trusted_base" =~ ^[0-9a-f]{40}$ ]]; then
            echo "::error::trusted base did not resolve to a commit" >&2
            exit 1
          fi
          echo "sha=$trusted_base" >> "$GITHUB_OUTPUT"
""".rstrip()

VERIFY_STEP = r"""      - id: verify
        name: Validate trusted Cross policy
        env:
          TRUSTED_BASE_SHA: ${{ steps.trusted-base.outputs.sha }}
        run: |
          set -euo pipefail
          policy=.github/scripts/verify_cross_build_policy.py
          entry="$(git ls-tree "$TRUSTED_BASE_SHA" -- "$policy")"
          if [[ "$entry" != "100644 blob "* && "$entry" != "100755 blob "* ]]; then
            echo "::error::trusted policy must be a regular blob" >&2
            exit 1
          fi
          trusted_policy="$RUNNER_TEMP/verify-cross-build-policy.py"
          git show "${TRUSTED_BASE_SHA}:${policy}" > "$trusted_policy"
          python3 -I "$trusted_policy" \
            --self-test \
            --config Cross.toml \
            --cargo-config Cargo.toml \
            --ci-workflow .github/workflows/ci.yml \
            --release-workflow .github/workflows/release.yml \
            --workflows-dir .github/workflows
          echo "verified=true" >> "$GITHUB_OUTPUT"
""".rstrip()

EARLY_STEP = r"""      - name: Reject edits to frozen policy files early
        if: github.event_name == 'pull_request' || github.event_name == 'merge_group'
        env:
          TRUSTED_BASE_SHA: ${{ steps.trusted-base.outputs.sha }}
        run: |
          set -euo pipefail
          # This cheap rejection mirrors the protected-policy workflow. The
          # complete semantic scan runs independently in CI Policy.
          if ! git diff --no-ext-diff --quiet "${TRUSTED_BASE_SHA}...HEAD" -- \
            .github/scripts/verify_cross_build_policy.py \
            .github/workflows/cross-build-policy.yml; then
            echo "::error::frozen policy files changed; a reviewed policy migration is required" >&2
            exit 1
          fi"""

CHECKOUT = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
AGGREGATE_IF = (
    "always() && (github.event_name == 'pull_request' || github.event_name == "
    "'merge_group' || (github.event_name == 'push' && github.ref == 'refs/heads/main'))"
)
REQUIRED_POLICY_GUARD = '''if [ "$PLAN_RESULT" != "success" ] || [ "$POLICY_RESULT" != "success" ] || [ "$POLICY_VERIFIED" != "true" ]; then
  echo "::error::CI planning and complete trusted policy verification must succeed"
  failures=1
fi'''


def parsed_job(workflow, name):
    body = _protected_job_body(workflow, name)
    # The strict publication parser accepts mapping sequences, not scalar
    # needs lists. Validate and remove this one canonical field first.
    needs = re.search(r"(?m)^    needs:\n(?:      - [a-z0-9-]+\n)+", body)
    dependencies = set()
    if needs:
        dependencies = set(re.findall(r"      - ([a-z0-9-]+)", needs[0]))
        body = body[:needs.start()] + body[needs.end():]
    return _parse_job(body), dependencies


def policy_contract_errors(workflow):
    errors = []
    try:
        plan, plan_dependencies = parsed_job(workflow, "ci-plan")
        policy, dependencies = parsed_job(workflow, "ci-policy")
        aggregate, aggregate_needs = parsed_job(workflow, "test")
        if set(policy) != {"name", "runs-on", "timeout-minutes", "permissions", "outputs", "steps"} or dependencies:
            errors.append("CI Policy must be an unconditional independent readonly job")
        if _scalar(policy, "name") != "CI Policy" or _scalar(policy, "runs-on") != "ubuntu-latest":
            errors.append("CI Policy identity or runner changed")
        if _scalar(policy, "timeout-minutes") != "10":
            errors.append("CI Policy must retain the full verifier time budget")
        if _mapping(policy, "permissions") != {"contents": ("scalar", "read")}:
            errors.append("CI Policy permissions must be contents: read only")
        if _mapping(policy, "outputs") != {"verified": ("scalar", "${{ steps.verify.outputs.verified }}")}:
            errors.append("CI Policy must expose the verifier completion output")
        steps = job_steps(_protected_job_body(workflow, "ci-policy"))
        if len(steps) != 3 or steps[1].rstrip() != PIN_STEP or steps[2].rstrip() != VERIFY_STEP:
            errors.append("CI Policy must pin, extract and run the complete isolated trusted verifier")
        for name, job in (("ci-plan", plan), ("ci-policy", policy)):
            checkout = _sequence(job, "steps")[0]
            if checkout != {
                "uses": ("scalar", CHECKOUT),
                "with": ("mapping", {"fetch-depth": ("scalar", "0"), "persist-credentials": ("scalar", "false")}),
            }:
                errors.append(f"{name} checkout must preserve triggering SHA and fork-safe credentials")
        plan_body = _protected_job_body(workflow, "ci-plan")
        plan_steps = job_steps(plan_body)
        if len(plan_steps) < 4 or plan_steps[1].rstrip() != PIN_STEP or plan_steps[2].rstrip() != EARLY_STEP:
            errors.append("CI Plan must pin independently and reject frozen edits before planning")
        if "--workflows-dir" in plan_body or 'python3 -I "$policy"' in plan_body or 'python3 -I "$trusted_policy"' in plan_body:
            errors.append("CI Plan must not run the expensive policy scan")
        if plan_dependencies or "needs" in plan or "if" in plan or "continue-on-error" in plan:
            errors.append("CI Plan cannot wait for policy or skip/fail open")
        # The two planner invocations keep both trusted modules, isolated
        # import roots, payload merge base and the existing NUL handshake.
        planners = [step for step in _sequence(plan, "steps")
                    if _scalar(step, "name") in {"Validate trusted PR CI planner examples", "Select CI mode"}]
        if len(planners) != 2:
            errors.append("CI Plan must retain both trusted planner invocations")
        for step in planners:
            env = _mapping(step, "env")
            if _scalar(env, "TRUSTED_BASE_SHA") != "${{ steps.trusted-base.outputs.sha }}" or _scalar(env, "MERGE_BASE_SHA") != "${{ github.event.merge_group.base_sha }}":
                errors.append("planner trust must come from the pin step/payload, never planner outputs")
            script = step.get("run", (None, ""))[1]
            for marker in (
                'base_ref="$TRUSTED_BASE_SHA"',
                'git show "${base_ref}:${planner}" > "$trusted_planner"',
                'git show "${MERGE_BASE_SHA}:${planner}" > "$trusted_planner"',
                '"${base_ref}:.github/scripts/live_suite_path_filter.py"',
                '"${MERGE_BASE_SHA}:.github/scripts/live_suite_path_filter.py"',
                "python3 -I -c 'import runpy, sys; sys.path.insert(0, sys.argv.pop(1));",
            ):
                if marker not in script:
                    errors.append(f"trusted planner missing {marker}")
            if "if git cat-file" in script:
                errors.append("planner must not bootstrap missing trusted modules from candidate")
        if not {"ci-plan", "ci-policy"} <= aggregate_needs or _scalar(aggregate, "if") != AGGREGATE_IF:
            errors.append("Tests must always await both planning and policy")
        if "continue-on-error" in aggregate:
            errors.append("Tests cannot tolerate errors")
        summary = [step for step in _sequence(aggregate, "steps")
                   if _scalar(step, "name") == "Summarize required CI results"]
        if len(summary) != 1 or set(summary[0]) != {"name", "run", "env"}:
            errors.append("Tests summary must execute unconditionally without error suppression")
        else:
            env = _mapping(summary[0], "env")
            for key, expression in (
                ("PLAN_RESULT", "${{ needs.ci-plan.result }}"),
                ("POLICY_RESULT", "${{ needs.ci-policy.result }}"),
                ("POLICY_VERIFIED", "${{ needs.ci-policy.outputs.verified }}"),
            ):
                if _scalar(env, key) != expression:
                    errors.append(f"Tests must bind {key} to its actual dependency")
            script = summary[0].get("run", (None, ""))[1]
            normalized = "\n".join(line.strip() for line in script.splitlines()).strip()
            guard = "\n".join(line.strip() for line in REQUIRED_POLICY_GUARD.splitlines())
            if normalized.count(guard) != 1 or not normalized.endswith('if [ "$failures" -ne 0 ]; then\nexit 1\nfi'):
                errors.append("Tests must fail closed on incomplete policy, including light mode")
    except (StructuralError, IndexError, KeyError, TypeError, AttributeError) as error:
        errors.append(f"policy job structure is invalid: {error}")
    return errors


class PolicyParallelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = Path('.github/workflows/ci.yml').read_text()

    def test_complete_contract(self):
        self.assertEqual(policy_contract_errors(self.workflow), [])

    def test_rejects_policy_and_trust_wiring_regressions(self):
        mutations = (
            ("  ci-policy:\n", "  ci-policy:\n    if: false\n"),
            ("  ci-policy:\n", "  ci-policy:\n    continue-on-error: true\n"),
            ("  ci-policy:\n", "  ci-policy:\n    needs: ci-plan\n"),
            ("  ci-policy:\n", "  removed-policy:\n"),
            ("      - id: verify\n", "      - id: verify\n        if: false\n"),
            ("      - id: verify\n", "      - id: verify\n        continue-on-error: true\n"),
            ("  ci-plan:\n", "  ci-plan:\n    needs: ci-policy\n"),
            ("      - ci-policy\n", ""),
            ("POLICY_RESULT: ${{ needs.ci-policy.result }}", "POLICY_RESULT: success"),
            ("POLICY_VERIFIED: ${{ needs.ci-policy.outputs.verified }}", "POLICY_VERIFIED: 'true'"),
            ('verified: ${{ steps.verify.outputs.verified }}', "verified: 'true'"),
            ('python3 -I "$trusted_policy"', 'python3 "$policy"'),
            ('            --self-test \\\n            --config Cross.toml', '            --config Cross.toml'),
            ('git show "${TRUSTED_BASE_SHA}:${policy}"', 'git show "HEAD:${policy}"'),
            ('base_ref="$TRUSTED_BASE_SHA"', 'base_ref="HEAD"'),
            ('trusted_base="$EVENT_BASE_SHA"', 'trusted_base="$checked_out"'),
            ('git merge-base --is-ancestor "$EVENT_BASE_SHA" "$trusted_base"', 'true'),
            ('TRUSTED_BASE_SHA: ${{ steps.trusted-base.outputs.sha }}', 'TRUSTED_BASE_SHA: ${{ steps.plan.outputs.sha }}'),
            ('"$POLICY_RESULT" != "success"', '"$POLICY_RESULT" = "failure"'),
            ('"$POLICY_VERIFIED" != "true"', '"$POLICY_VERIFIED" = "false"'),
            ('persist-credentials: false', 'persist-credentials: true'),
        )
        for old, new in mutations:
            with self.subTest(old=old):
                mutated = self.workflow.replace(old, new)
                self.assertNotEqual(mutated, self.workflow)
                self.assertTrue(policy_contract_errors(mutated))
        policy = _protected_job_body(self.workflow, "ci-policy")
        for field in ('    permissions:\n      contents: write\n', '    if: false\n'):
            mutated = self.workflow + '\n  "ci-policy":\n' + field + policy + '\n'
            self.assertTrue(policy_contract_errors(mutated))

    def test_actual_aggregate_rejects_every_incomplete_policy_state(self):
        # Execute the real summary body with synthetic Actions needs values.
        # No GitHub requests or builds; this also proves light-mode skips never
        # override the mandatory policy result/output assertion.
        aggregate, _ = parsed_job(self.workflow, "test")
        summary = next(step for step in _sequence(aggregate, "steps")
                       if _scalar(step, "name") == "Summarize required CI results")
        script = summary['run'][1]
        with tempfile.TemporaryDirectory() as directory:
            for mode in ("full", "light"):
                replaced = re.sub(r"\$\{\{ needs\.([a-z0-9-]+)\.result }}",
                                  lambda m: "success" if mode == "full" or m[1] in {"ci-plan", "ci-policy"} else "skipped", script)
                replaced = re.sub(r"\$\{\{ needs\.ci-plan\.outputs\.[a-z0-9_]+ }}", "true" if mode == "full" else "false", replaced)
                for result in ("success", "failure", "cancelled", "skipped", "", "timed_out"):
                    for verified in ("true", "false", "", "TRUE"):
                        with self.subTest(mode=mode, result=result, verified=verified):
                            env = {**os.environ, "CI_MODE": mode, "PLAN_RESULT": "success",
                                   "POLICY_RESULT": result, "POLICY_VERIFIED": verified,
                                   "GITHUB_STEP_SUMMARY": f"{directory}/summary"}
                            completed = subprocess.run(["bash", "-c", replaced], env=env, capture_output=True, text=True)
                            self.assertEqual(completed.returncode == 0, result == "success" and verified == "true", completed.stderr)
                for result in ("failure", "cancelled", "skipped", ""):
                    env = {**os.environ, "CI_MODE": mode, "PLAN_RESULT": result,
                           "POLICY_RESULT": "success", "POLICY_VERIFIED": "true",
                           "GITHUB_STEP_SUMMARY": f"{directory}/summary"}
                    self.assertNotEqual(subprocess.run(["bash", "-c", replaced], env=env, capture_output=True).returncode, 0)

    def test_actual_pin_uses_authenticated_event_identity(self):
        # Fake only git transport; execute the literal workflow pin script.
        # A fork's HEAD never selects trusted executable source.
        pin = _sequence(_parse_job("    steps:\n" + PIN_STEP), "steps")[0]["run"][1]
        head, base, live = "a" * 40, "b" * 40, "c" * 40
        with tempfile.TemporaryDirectory() as directory:
            git = Path(directory, "git")
            git.write_text('''#!/bin/bash
set -eu
printf '%s\\n' "$*" >> "$GIT_CALLS"
case "$1" in
  rev-parse)
    if [ "$2" = HEAD ]; then printf '%s\\n' "$FAKE_HEAD";
    else printf '%s\\n' "$FAKE_LIVE"; fi ;;
  cat-file) exit "${FAKE_MISSING:-0}" ;;
  fetch) exit "${FAKE_FETCH_FAIL:-0}" ;;
  merge-base) exit "${FAKE_DIVERGED:-0}" ;;
  *) exit 99 ;;
esac
''')
            git.chmod(0o755)
            common = {**os.environ, "PATH": directory + os.pathsep + os.environ["PATH"],
                      "FAKE_HEAD": head, "FAKE_LIVE": live, "GITHUB_SHA": head,
                      "GITHUB_OUTPUT": f"{directory}/outputs", "GIT_CALLS": f"{directory}/calls",
                      "BASE_REF": "main", "EVENT_BASE_SHA": base, "MERGE_HEAD_SHA": head}
            cases = [
                ("PR live tip", "pull_request", {}, live),
                ("merge group parent", "merge_group", {}, base),
                ("main", "push", {}, head),
                ("manual", "workflow_dispatch", {}, head),
                ("missing base fetched", "pull_request", {"FAKE_MISSING": "1"}, live),
                ("missing group base fetched", "merge_group", {"FAKE_MISSING": "1"}, base),
                ("malformed base", "pull_request", {"EVENT_BASE_SHA": "main"}, None),
                ("missing group base", "merge_group", {"EVENT_BASE_SHA": ""}, None),
                ("diverged live tip", "pull_request", {"FAKE_DIVERGED": "1"}, None),
                ("fetch failure", "pull_request", {"FAKE_FETCH_FAIL": "1"}, None),
                ("wrong checkout", "pull_request", {"FAKE_HEAD": base}, None),
                ("wrong group head", "merge_group", {"MERGE_HEAD_SHA": base}, None),
                ("unsafe base ref", "pull_request", {"BASE_REF": "../topic"}, None),
                ("invalid live tip", "pull_request", {"FAKE_LIVE": "main"}, None),
            ]
            for label, event, overrides, expected in cases:
                with self.subTest(label=label):
                    Path(common["GITHUB_OUTPUT"]).write_text("")
                    Path(common["GIT_CALLS"]).write_text("")
                    result = subprocess.run(["bash", "-c", pin],
                                            env={**common, "EVENT_NAME": event, **overrides},
                                            capture_output=True, text=True)
                    output = Path(common["GITHUB_OUTPUT"]).read_text()
                    self.assertEqual(result.returncode == 0, expected is not None, result.stderr)
                    self.assertEqual(output, "" if expected is None else f"sha={expected}\n")
                    calls = Path(common["GIT_CALLS"]).read_text()
                    if expected and event == "pull_request":
                        self.assertIn("+refs/heads/main:refs/remotes/trusted-ci-base", calls)
                        self.assertIn(f"merge-base --is-ancestor {base} {live}", calls)
                    if event in {"push", "workflow_dispatch", "merge_group"}:
                        self.assertNotIn("refs/heads/", calls)

    def test_verifier_failure_never_emits_completion(self):
        verify = _sequence(_parse_job("    steps:\n" + VERIFY_STEP), "steps")[0]["run"][1]
        with tempfile.TemporaryDirectory() as directory:
            git = Path(directory, "git")
            git.write_text('''#!/bin/bash
set -eu
case "$1" in
  ls-tree) printf '100644 blob %040d\\t.github/scripts/verify_cross_build_policy.py\\n' 0 ;;
  show) exit "${FAKE_EXTRACT_FAIL:-0}" ;;
  *) exit 99 ;;
esac
''')
            python = Path(directory, "python3")
            python.write_text('#!/bin/bash\nexit "$FAKE_VERIFY_EXIT"\n')
            git.chmod(0o755)
            python.chmod(0o755)
            for extract, code in ((0, 0), (1, 0), (0, 1), (0, 130), (0, 137)):
                with self.subTest(extract=extract, code=code):
                    output = Path(directory, "outputs")
                    output.write_text("")
                    env = {**os.environ, "PATH": directory + os.pathsep + os.environ["PATH"],
                           "RUNNER_TEMP": directory, "TRUSTED_BASE_SHA": "b" * 40,
                           "GITHUB_OUTPUT": str(output), "FAKE_EXTRACT_FAIL": str(extract),
                           "FAKE_VERIFY_EXIT": str(code)}
                    result = subprocess.run(["bash", "-c", verify], env=env, capture_output=True)
                    self.assertEqual(result.returncode == 0, extract == 0 and code == 0)
                    self.assertEqual(output.read_text(), "verified=true\n" if result.returncode == 0 else "")


def run_self_test():
    result = unittest.TestResult()
    unittest.defaultTestLoader.loadTestsFromTestCase(PolicyParallelTests).run(result)
    return [trace for _, trace in result.failures + result.errors]


if __name__ == '__main__':
    unittest.main()
