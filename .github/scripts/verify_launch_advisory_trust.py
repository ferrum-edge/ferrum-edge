#!/usr/bin/env python3
"""Static trust-boundary contract for the private-advisory credential.

Issue #3802: a `v*` tag can be created at an arbitrary commit, and for a `push`
event GitHub loads both the workflow definition and every file it executes from
that tag target. Any tag-reachable job that references
`secrets.LAUNCH_ADVISORY_READ_TOKEN` therefore hands a privileged credential to
candidate-controlled code before the release SHA has any provenance.

This verifier is the checked-in proof that no such path exists. It reads the
workflow definitions as text — it executes nothing — and asserts:

* the credential is referenced in exactly one workflow, and that workflow is
  reachable only from events whose definition GitHub loads from the protected
  default branch (`workflow_run`, `schedule`);
* the secret-bearing job is gated behind the secretless trust job and is bound to
  the protected deployment environment;
* that job is a *closed step sequence*: exactly two steps, the first being the
  pinned `actions/checkout` at the trusted anchor commit the secretless job
  already established (with a closed set of inputs), the second being the one
  credential-bearing checker invocation. Step scoping alone is not enough. A
  secretless step needs no credential and no candidate expression to be
  dangerous: it shares the credential job's workspace, so it can read the
  candidate from `$GITHUB_EVENT_PATH`, the API, or `printenv`, fetch candidate
  bytes, or simply overwrite `scripts/check_launch_readiness.py` — and the exact
  credential command would then execute the replaced file with the credential
  bound. So no arbitrary executable step may exist in that job at all, before or
  after the credential step;
* the credential is delivered to exactly one *step*, identified structurally by
  parsing the job's `steps:` list, that step is the second and final one, and it
  is a plain single-line `run:` step whose whole command is the default-branch
  checker with its trusted-execution pins. A `run: |` block on the credential
  step would let arbitrary shell run beside the checker with the credential
  already in the environment;
* that step's `env:` is an *exact closed mapping* — every admitted key with its
  exact admitted value and nothing else. An anchored command is only as exact as
  the environment that resolves it: `BASH_ENV`, `PATH`, `PYTHONPATH`,
  `LD_PRELOAD`, or any interpreter/loader variable nobody has named yet would
  make Bash or Python execute something other than the command the contract just
  matched. Missing, duplicate, extra, empty, block-scalar, flow-mapping, or
  anchor/alias/merge-key entries are all refused, and an env line this parser
  cannot parse is an error rather than a silently ignored entry;
* the trusted workflow declares no inherited execution surface at all: its
  top-level keys are a closed allowlist, so a workflow-level `env:` or
  `defaults:` (`run.shell`, `run.working-directory`) — which every job inherits
  without appearing in either validated step — is refused, as is any unparseable
  top-level or `jobs:`-level entry and any YAML anchor, alias, or merge key in
  the credential job;
* the whole document is unambiguous, because a text contract that reads a
  workflow one way while GitHub's YAML parser reads it another has verified a
  workflow that does not exist. A duplicate mapping key is not an error GitHub
  reports — one occurrence wins, and *which* one is a property of the consumer —
  so a workflow could keep the safe block-form `on:` this contract derives events
  from and append a duplicate `on: [push]` that makes it tag-reachable. The same
  ambiguity reaches every other mapping: a duplicate last `steps:` on
  `establish-trust` that exports a candidate-controlled `trusted_sha`, a
  duplicate `outputs:` redirecting the anchor, a duplicate `run:` on a trust step
  behind the exact admitted command, a duplicate or flow `steps:`/`env:` on the
  publisher. So the refusal is *whole-document*: one indentation-aware,
  block-scalar-aware structural pass over `launch-advisory-trust.yml` refuses a
  repeated key in ANY mapping — the document root, `on`, `jobs`, every job
  mapping, `outputs`/`permissions`/`env`/`with`, and every step mapping,
  sequence items included — and refuses every value that puts structure where a
  block reader sees none: a flow collection (`on: [push]`, `jobs: {…}`,
  `steps: [{run: …}]`, `with: {ref: …}`), an anchor, an alias, a merge key, a
  YAML tag, a block scalar with an explicit indentation indicator, a second YAML
  document, tab indentation, and any node the pass cannot classify. It fails closed and
  never deserializes or executes the document; shell inside a `run: |` body is
  skipped whole, so YAML-shaped text in a command is neither a duplicate key nor
  a way to end the enclosing mapping. The per-surface duplicate/flow checks for
  the credential job, its steps, its `env:`, and the checkout `with:` remain as
  defence in depth;
* `establish-trust` runs both secretless preflights as real executable steps
  before the protected environment can release the credential: the launch
  readiness checker's own self-test and *this* verifier's `--self-test`, so the
  boundary contract is proved on the trusted tree in the same run that then uses
  the credential;
* the trusted anchor is proved fail-closed in the secretless job: derived from
  the literal protected-branch checkout, validated as a 40-hex commit, and
  required to be reachable from protected `main` before it is exported;
* the candidate commit reaches the secret-bearing job only as an inert SHA in an
  environment mapping, never as a checkout ref, and no candidate-derived
  environment variable is ever expanded on an executable line anywhere in that
  job — including inside a multiline block of a secretless step;
* the tag-triggered release job consumes the trusted verdict as a published
  commit status instead of evaluating advisories itself;
* that verdict is bound to the exact Release run ID and run attempt on both
  sides — the publisher derives the context from the triggering run, the release
  gate accepts only the context carrying its own `github.run_id` /
  `github.run_attempt`, and the scheduled default-branch audit uses a context of
  a different shape. A commit-wide context would be replayable: a daily audit, an
  earlier tag release on the same commit, or an earlier attempt of the same
  Release run would satisfy a later release before its own evaluation finished;
* the trusted workflow triggers on `workflow_run: in_progress`, because GitHub
  documents that `requested` does not fire for a re-run;
* the untrusted standalone gate holds no credential on any event.

`--self-test` runs an adversarial fixture table — a malicious tagged workflow, a
malicious tagged checker invocation, a candidate-tree checkout, a credential
step turned into a `run: |` block that checks out or sources candidate material
before calling the checker, a second command chained onto the credential
invocation, a command substitution in the trusted-tree pin, an action added as a
second execution surface on the credential step, a job-level credential binding,
candidate environment expansion in a secretless step, an *indirect* pre-credential
step that extracts the candidate from `$GITHUB_EVENT_PATH` and replaces the
checker without naming any candidate expression, an extra step appended after the
credential step, a swapped or unpinned checkout action, a redirected checkout
ref, a dropped or altered checkout input, a checkout step that also runs a
command, a swapped step order, a job-level `defaults:` working directory, a `BASH_ENV`
or `PATH` redirect on the credential step, a duplicated or unparseable env
entry, a workflow-level `env:` or `defaults:` shell/working-directory, an
anchor/alias/merge-key bypass, either secretless self-test dropped, commented
out, or relocated into the credential job, a dropped trusted-anchor ancestry
proof, a missing environment binding, a dropped trust edge, a constant
commit-wide status context, an omitted run-attempt binding, a `requested`-only
trigger, a release gate that reuses another run's status, a release job that
stops requiring the trusted verdict, a safe block-form `on:` followed by a
duplicate `on: [push]` (and the reversed ordering), a duplicate `jobs:`,
`advisory-verdict`, `needs`, `environment`, `steps`, step key, or checkout input,
an `on:`/`steps:`/`with:` written as an inline flow collection, a duplicate
`steps:` or `outputs:` on `establish-trust` (both orderings), a duplicate `run:`
on a trust step behind the exact admitted command, a duplicate flow
`steps:`/`env:` on the publisher, a duplicate key in a mapping no value-level
check reads, an unclassifiable document node, and YAML-shaped shell inside a
`run: |` body that must NOT be read as structure — and then applies the same
contract to the real `.github/workflows` tree. Each duplicate and flow fixture
asserts the structural rejection AND, where it matters, that the corresponding
value-level check did not fire: that absence is the proof the structural refusal
is what catches the bypass.
Comments are stripped before every contract decision, so prose can neither
satisfy a requirement nor stand in for a rejected command.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import NamedTuple

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_WORKFLOWS_DIR = ROOT / ".github" / "workflows"

TOKEN_REFERENCE = "secrets.LAUNCH_ADVISORY_READ_TOKEN"
TRUSTED_WORKFLOW = "launch-advisory-trust.yml"
RELEASE_WORKFLOW = "release.yml"
STANDALONE_WORKFLOW = "launch-readiness.yml"

TRUSTED_REF = "refs/heads/main"
TRUST_JOB = "establish-trust"
SECRET_JOB = "advisory-verdict"
PUBLISH_JOB = "publish-verdict"
RELEASE_GATE_JOB = "validate-launch-readiness"
PROTECTED_ENVIRONMENT = "launch-advisory"
STATUS_CONTEXT_PREFIX = "trusted-launch-advisory-gate"
# The scheduled default-branch audit's context. Deliberately not of the release
# shape, so an audit verdict can never satisfy a release gate.
AUDIT_STATUS_CONTEXT = f"{STATUS_CONTEXT_PREFIX}/main-audit"
TRUSTED_CHECKER = "python3 -I scripts/check_launch_readiness.py"
SELF_TEST_STEP = "python3 -I .github/scripts/verify_launch_advisory_trust.py --self-test"
# The secretless checker self-test. It belongs to the trust job: hosted in the
# credential-bearing job it would be an executable step sharing that job's
# workspace with the credential step.
CHECKER_SELF_TEST_STEP = f"{TRUSTED_CHECKER} --self-test"

# The credential-bearing job checks out the anchor commit the secretless job
# already established from the literal protected branch, so no in-job command is
# needed to move HEAD onto it. Bumping the checkout pin means bumping this
# constant; see docs/dependency-policy.md on coordinated action-pin bumps.
CHECKOUT_ACTION_PIN = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
TRUSTED_SHA_REF_EXPRESSION = "${{ needs.establish-trust.outputs.trusted_sha }}"

# Events whose workflow definition and checked-out code GitHub resolves from the
# protected default branch. Every other event can be reached from a ref whose
# contents an untrusted principal controls.
TRUSTED_EVENTS = frozenset({"workflow_run", "schedule"})

# Payload fields that carry candidate-controlled values.
CANDIDATE_EXPRESSIONS = (
    "github.event.workflow_run.head_sha",
    "github.event.workflow_run.head_branch",
    "github.event.inputs",
    "inputs.release_tag",
    "outputs.candidate_sha",
    "needs.establish-trust.outputs.candidate_sha",
)

TOP_LEVEL_KEY = re.compile(r"^(?P<key>[A-Za-z_][A-Za-z0-9_-]*):(?P<rest>.*)$")
NESTED_KEY = re.compile(r"^  (?P<key>[A-Za-z_][A-Za-z0-9_-]*):(?P<rest>.*)$")
REF_FIELD = re.compile(r"^\s*ref:\s*(?P<value>\S.*?)\s*$")
USES_FIELD = re.compile(r"^\s*(?:-\s+)?uses:\s*(?P<value>\S+)")
PINNED_ACTION = re.compile(r"^[A-Za-z0-9._-]+/[A-Za-z0-9._/-]+@[0-9a-f]{40}$")
CANDIDATE_ENV_BINDING = re.compile(
    r"^\s*LAUNCH_TARGET_SHA:\s*\$\{\{\s*needs\.establish-trust\.outputs\."
    r"candidate_sha\s*\}\}\s*$"
)
PUBLISH_ENV_BINDING = re.compile(
    r"^\s*CANDIDATE_SHA:\s*\$\{\{\s*needs\.establish-trust\.outputs\."
    r"candidate_sha\s*\}\}\s*$"
)
PUBLISH_CONTEXT_BINDING = re.compile(
    r"^\s*STATUS_CONTEXT:\s*\$\{\{\s*needs\.establish-trust\.outputs\."
    r"status_context\s*\}\}\s*$"
)

# The publisher derives the release context from its own shell operands; the
# release gate derives the identical string from its own run. Both derivations
# are pinned here so neither side can silently drop the run or attempt operand.
TRUSTED_RUN_CONTEXT_DERIVATION = re.compile(
    re.escape(STATUS_CONTEXT_PREFIX)
    + r"/release-\$\{?release_run_id\}?-attempt-\$\{?release_run_attempt\}?"
)
RELEASE_GATE_CONTEXT_DERIVATION = re.compile(
    re.escape(STATUS_CONTEXT_PREFIX)
    + r"/release-\$\{?RELEASE_RUN_ID\}?-attempt-\$\{?RELEASE_RUN_ATTEMPT\}?"
)
# The shape a published release verdict may take. Used to prove statically that
# the audit context can never be mistaken for one.
RELEASE_CONTEXT_SHAPE = re.compile(
    re.escape(STATUS_CONTEXT_PREFIX)
    + r"/release-[1-9][0-9]{0,17}-attempt-[1-9][0-9]{0,17}$"
)
# Any use of the bare prefix that is not the run-bound release namespace. In the
# release gate that is a commit-wide, replayable context.
COMMIT_WIDE_CONTEXT = re.compile(re.escape(STATUS_CONTEXT_PREFIX) + r"(?!/release-)")

# ---------------------------------------------------------------------------
# Step-level structure for the credential-bearing job
# ---------------------------------------------------------------------------

STEPS_KEY = re.compile(r"^(?P<indent> *)steps:\s*$")
STEP_ITEM = re.compile(r"^(?P<lead> *)-(?P<gap> +)(?=\S)")
KEY_LINE = re.compile(r"^(?P<indent> *)(?P<key>[A-Za-z_][A-Za-z0-9_-]*):(?P<rest>.*)$")
# `|`, `>`, `|-`, `>+`, `|2` … every YAML block-scalar indicator. A credential
# step written as a block can carry any number of extra shell commands, which is
# exactly the bypass this module must refuse.
BLOCK_SCALAR = re.compile(r"^[|>][+-]?[0-9]*[+-]?$")

# The only keys the credential-bearing step may declare. `uses`, `shell`, and
# `working-directory` are each a way to redirect or duplicate the execution
# surface while the credential is already bound to the step.
CREDENTIAL_STEP_ALLOWED_KEYS = frozenset({"name", "id", "if", "env", "run"})

# The complete environment the credential-bearing step may declare: an exact
# allowlist of key AND value. Anchoring the command is not enough on its own,
# because the environment decides how that command resolves — `BASH_ENV` runs a
# file before the shell reaches the command, `PATH` picks a different `python3`,
# `PYTHONPATH`/`PYTHONSTARTUP`/`LD_PRELOAD` reach inside the interpreter. An
# allowlist (rather than a blacklist of known-bad names) is the point: a variable
# nobody has thought of yet fails closed because it is simply not in this map.
CREDENTIAL_STEP_ENV = {
    "GITHUB_TOKEN": "${{ github.token }}",
    "LAUNCH_TIER": "ga",
    "LAUNCH_TARGET_SHA": "${{ needs.establish-trust.outputs.candidate_sha }}",
    "TRUSTED_SHA": "${{ needs.establish-trust.outputs.trusted_sha }}",
    "LAUNCH_PRIVATE_BLOCKER_COUNT": "${{ vars.LAUNCH_PRIVATE_BLOCKER_COUNT }}",
    "LAUNCH_PRIVATE_ADVISORY_AS_OF": "${{ vars.LAUNCH_PRIVATE_ADVISORY_AS_OF }}",
    "LAUNCH_ADVISORY_READ_TOKEN": "${{ secrets.LAUNCH_ADVISORY_READ_TOKEN }}",
}
# Environment variable names only: no dashes, no dotted paths, no sequence items.
# Anything in an `env:` body that does not match this exactly, at exactly the
# mapping's own indentation, is reported rather than skipped.
ENV_ENTRY = re.compile(r"^(?P<indent> *)(?P<key>[A-Za-z_][A-Za-z0-9_]*):(?P<rest>.*)$")

# YAML aliasing forms. An anchor defined anywhere and merged or aliased into the
# credential job would inject keys this contract never saw in the two validated
# steps. Deliberately narrow so shell text (`&&`, `2>&1`, `*)` case patterns, a
# `* * *` cron) cannot false-positive: a marker only counts where YAML would
# read a node — right after `key:` or a `- ` sequence dash.
YAML_MERGE_KEY = re.compile(r"^\s*(?:-\s+)?<<\s*:")
YAML_ANCHOR_DECL = re.compile(r"(?::|^\s*-)\s+&[A-Za-z_][A-Za-z0-9_-]*(?=\s|$)")
YAML_ALIAS_USE = re.compile(r"(?::|^\s*-)\s+\*[A-Za-z_][A-Za-z0-9_-]*(?=\s|$)")


def yaml_aliasing_marker(line: str) -> bool:
    """True if `line` declares a YAML anchor, uses an alias, or merges a map."""

    return bool(
        YAML_MERGE_KEY.search(line)
        or YAML_ANCHOR_DECL.search(line)
        or YAML_ALIAS_USE.search(line)
    )


# Top-level keys the trusted workflow may declare. `env:` and `defaults:` are the
# load-bearing exclusions: both are inherited by every job, so either could
# redirect the credential step's shell, working directory, or environment without
# ever appearing inside the two steps this contract validates.
TRUSTED_WORKFLOW_ALLOWED_TOP_LEVEL_KEYS = frozenset(
    {"name", "on", "concurrency", "permissions", "jobs"}
)

# The credential-bearing job is a closed sequence: the trusted-anchor checkout
# and then the credential step. Nothing else may run in that workspace.
CREDENTIAL_JOB_STEP_COUNT = 2
# The checkout step is declarative only: no `run`, no `env`, no `if` that could
# skip it, no `id` another step could consume.
CREDENTIAL_CHECKOUT_ALLOWED_KEYS = frozenset({"name", "uses", "with"})
# Exactly these inputs, exactly these values. `path`/`repository`/`token`/
# `submodules`/`sparse-checkout`/`clean` would each change what lands in the
# workspace the credential step then executes.
CREDENTIAL_CHECKOUT_INPUTS = {
    "ref": TRUSTED_SHA_REF_EXPRESSION,
    "fetch-depth": "1",
    "persist-credentials": "false",
}
# Job-level keys admitted on the credential job. `defaults:`, `container:`,
# `services:`, `strategy:`, `env:`, and `uses:` would each add a surface — a
# working-directory rewrite, a foreign image, a matrix, a job-wide credential, or
# a whole reusable workflow — outside the two verified steps.
CREDENTIAL_JOB_ALLOWED_KEYS = frozenset(
    {
        "name",
        "needs",
        "runs-on",
        "timeout-minutes",
        "environment",
        "permissions",
        "steps",
    }
)
JOB_KEY = re.compile(r"^    (?P<key>[A-Za-z_][A-Za-z0-9_-]*):(?P<rest>.*)$")
# Job-level keys whose body this contract parses as a block mapping/sequence. An
# inline (flow) value there is not "an empty block": it is a whole structure the
# block reader never sees, so it must be refused rather than silently dropped.
CREDENTIAL_JOB_BLOCK_KEYS = frozenset({"steps"})
# Top-level keys the trusted workflow's structure is derived from. Same reason.
TRUSTED_WORKFLOW_BLOCK_TOP_LEVEL_KEYS = frozenset({"on", "jobs"})
# A value that opens a flow collection or an aliasing node. `on: [push]`,
# `jobs: {…}`, `permissions: &a …`, `concurrency: *a` all put structure where the
# block reader looks for none.
FLOW_OR_ALIASED_VALUE = re.compile(r"^[\[{&*]")
MAPPING_ENTRY = re.compile(
    r"^\s*(?P<key>[A-Za-z_][A-Za-z0-9_-]*):\s*(?P<value>.*?)\s*$"
)

# The trusted anchor must be proved, not asserted: taken from the literal
# protected-branch checkout, validated as a commit, and required to be reachable
# from protected `main` before it is exported to the credential job.
TRUST_ANCHOR_PROOFS = (
    (
        re.compile(r'trusted_sha="\$\(git rev-parse HEAD\)"'),
        "derive the trusted anchor from the literal protected-branch checkout "
        '(`trusted_sha="$(git rev-parse HEAD)"`)',
    ),
    (
        re.compile(r'\[\[\s*"\$trusted_sha"\s*=~\s*\^\[0-9a-f\]\{40\}\$\s*\]\]'),
        "validate the trusted anchor as a 40-hex commit",
    ),
    (
        re.compile(r'git merge-base --is-ancestor "\$trusted_sha" "\$main_tip"'),
        "require the trusted anchor to be reachable from protected `main`",
    ),
)
TRUSTED_SHA_OUTPUT_BINDING = re.compile(
    r"^\s*trusted_sha:\s*\$\{\{\s*steps\.[A-Za-z0-9_-]+\.outputs\.trusted_sha\s*\}\}\s*$"
)

# The complete command the credential-bearing step may execute, anchored at both
# ends. Anchoring is the contract: no leading `cd`, no trailing `&& …`, no `;`,
# no pipe, no command substitution, no alternate interpreter, and no alternate
# path to the checker can survive it, and the trusted-tree pin must be the
# literal environment reference the anchor-pin step already validated.
CREDENTIAL_RUN_COMMAND = re.compile(
    r"^python3 -I scripts/check_launch_readiness\.py"
    r"(?: --(?:verify|require-pass|trusted-execution))+"
    r' --trusted-tree-sha "\$TRUSTED_SHA"$'
)
CREDENTIAL_REQUIRED_FLAGS = ("--verify", "--trusted-execution")

# Environment variables in the credential-bearing job that carry the candidate
# commit. The checker reads them from the process environment; any *shell*
# expansion of one puts candidate-derived bytes on an executable line, so it is
# refused in every step of that job, block scalars included.
CANDIDATE_ENV_NAMES = ("LAUNCH_TARGET_SHA", "CANDIDATE_SHA")
_CANDIDATE_ENV_ALTERNATION = "|".join(CANDIDATE_ENV_NAMES)
CANDIDATE_ENV_EXPANSION = re.compile(
    r"\$(?:\{\{\s*env\.(?:"
    + _CANDIDATE_ENV_ALTERNATION
    + r")\s*\}\}|\{(?:"
    + _CANDIDATE_ENV_ALTERNATION
    + r")[:\-\}]|(?:"
    + _CANDIDATE_ENV_ALTERNATION
    + r")\b)"
)

WORKFLOW_RUN_TYPE_ITEM = re.compile(r"^\s*-\s*(?P<value>[a-z_]+)\s*$")
# `requested` does not fire for a re-run, so a re-run Release attempt would
# never obtain its own verdict and would fail closed permanently.
REQUIRED_WORKFLOW_RUN_TYPE = "in_progress"


# ---------------------------------------------------------------------------
# Minimal structural reader (text only; nothing is evaluated)
# ---------------------------------------------------------------------------


class BlockMapping(NamedTuple):
    """A YAML mapping read as text, with its ambiguities kept rather than lost.

    A text reader that keeps one entry per key silently resolves a duplicate for
    the whole contract, and GitHub's YAML parser may resolve it the other way. So
    every ambiguity is carried out of the reader instead of being decided by it:

    * `blocks` — the union of every occurrence's body lines, so nothing a
      duplicate introduced can hide from a body-level check;
    * `duplicates` — every key introduced more than once, in order;
    * `inline` — every inline (same-line) value each key was introduced with, so
      a flow collection written where a block is expected (`on: [push]`,
      `steps: [{run: …}]`) is visible instead of being discarded as "no body".
    """

    blocks: dict[str, list[str]]
    duplicates: tuple[str, ...]
    inline: dict[str, list[str]]


EMPTY_BLOCK_MAPPING = BlockMapping({}, (), {})


def split_blocks(lines: list[str], pattern: re.Pattern[str]) -> BlockMapping:
    """Split lines into blocks introduced by `pattern`, keyed by the match.

    Duplicate keys are recorded, never merged away, and the value written on the
    introducing line is recorded too. Both are how a workflow can read one way to
    this contract and another way to GitHub.
    """

    blocks: dict[str, list[str]] = {}
    inline: dict[str, list[str]] = {}
    duplicates: list[str] = []
    current: str | None = None
    for line in lines:
        match = pattern.match(line)
        if match:
            current = match.group("key")
            if current in blocks:
                duplicates.append(current)
            else:
                blocks[current] = []
                inline[current] = []
            rest = match.groupdict().get("rest") or ""
            inline[current].append(inline_value(rest))
            continue
        if current is not None:
            blocks[current].append(line)
    return BlockMapping(blocks, tuple(duplicates), inline)


def duplicate_keys(mapping: BlockMapping) -> list[str]:
    return sorted(set(mapping.duplicates))


def top_level_blocks(text: str) -> BlockMapping:
    # Comments are removed before any structure is derived, so a commented-out
    # key can neither introduce nor terminate a block.
    return split_blocks(
        [strip_comment(line) for line in text.splitlines()], TOP_LEVEL_KEY
    )


def job_blocks(text: str) -> BlockMapping:
    jobs = top_level_blocks(text).blocks.get("jobs")
    if jobs is None:
        return EMPTY_BLOCK_MAPPING
    return split_blocks(jobs, NESTED_KEY)


def event_names(text: str) -> set[str]:
    block = top_level_blocks(text).blocks.get("on")
    if block is None:
        return set()
    return set(split_blocks(block, NESTED_KEY).blocks)


def workflow_run_types(text: str) -> set[str]:
    """Return the declared `on.workflow_run.types` entries."""

    block = top_level_blocks(text).blocks.get("on")
    if block is None:
        return set()
    run_block = split_blocks(block, NESTED_KEY).blocks.get("workflow_run")
    if run_block is None:
        return set()

    types: set[str] = set()
    collecting = False
    for line in code_lines(run_block):
        stripped = line.strip()
        if stripped.startswith("types:"):
            inline = stripped[len("types:") :].strip()
            if inline.startswith("["):
                types.update(
                    item.strip().strip("\"'")
                    for item in inline.strip("[]").split(",")
                    if item.strip()
                )
                collecting = False
            else:
                collecting = True
            continue
        if collecting:
            item = WORKFLOW_RUN_TYPE_ITEM.match(line)
            if item:
                types.add(item.group("value"))
            else:
                collecting = False
    return types


def strip_comment(line: str) -> str:
    """Drop a trailing full-line comment so prose cannot satisfy a contract."""

    stripped = line.lstrip()
    return "" if stripped.startswith("#") else line


def code_lines(lines: list[str]) -> list[str]:
    return [line for line in (strip_comment(item) for item in lines) if line.strip()]


def job_steps(job_lines: list[str]) -> list[list[str]]:
    """Split a job block into its `steps:` items by indentation.

    Each returned step is the list of its code lines, starting with the `- `
    item line. This is what makes the credential's *step* scope visible: a
    secret bound by a step's `env:` is readable only by that step's command, so
    the contract has to be applied to the step, not to the job.
    """

    lines = code_lines(job_lines)
    start: int | None = None
    steps_indent = 0
    for index, line in enumerate(lines):
        match = STEPS_KEY.match(line)
        if match:
            start = index
            steps_indent = len(match.group("indent"))
            break
    if start is None:
        return []

    steps: list[list[str]] = []
    item_indent: int | None = None
    for line in lines[start + 1 :]:
        indent = len(line) - len(line.lstrip())
        if indent <= steps_indent:
            break
        item = STEP_ITEM.match(line)
        # A `- ` at the item indent opens a new step. Anything deeper — including
        # a shell line inside a block scalar that happens to start with `-` —
        # belongs to the step already open.
        if item and (item_indent is None or len(item.group("lead")) == item_indent):
            item_indent = len(item.group("lead"))
            steps.append([line])
            continue
        if steps:
            steps[-1].append(line)
    return steps


def step_entries(step_lines: list[str]) -> list[tuple[str, str, list[str]]]:
    """Return `(key, inline value, body lines)` for each top-level step key."""

    if not step_lines:
        return []
    item = STEP_ITEM.match(step_lines[0])
    if item is None:
        return []
    key_indent = len(item.group(0))
    # Rewrite the `- ` marker as plain indentation so the first key is read the
    # same way as every later one.
    normalized = [" " * key_indent + step_lines[0][key_indent:], *step_lines[1:]]

    entries: list[tuple[str, str, list[str]]] = []
    current: tuple[str, str, list[str]] | None = None
    for line in normalized:
        match = KEY_LINE.match(line)
        if match and len(match.group("indent")) == key_indent:
            current = (match.group("key"), match.group("rest").strip(), [])
            entries.append(current)
            continue
        if current is not None:
            current[2].append(line)
    return entries


def step_run_text(step_lines: list[str]) -> str:
    """Every executable line of every `run:` in a step, inline value and body."""

    parts: list[str] = []
    for key, value, body in step_entries(step_lines):
        if key != "run":
            continue
        if not BLOCK_SCALAR.match(value):
            parts.append(value)
        parts.extend(body)
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Document-wide structural ambiguity pass
# ---------------------------------------------------------------------------
#
# Every other check in this module is a *single structural reading* of some part
# of the workflow. That reading is a proof only if GitHub's YAML parser cannot
# read the same bytes differently, and a duplicate mapping key is exactly where
# the two diverge: it is not an error GitHub reports, one occurrence wins, and
# *which* one is a property of the consumer. The block readers above stop at the
# first occurrence of a key, so a safe first `steps:`/`outputs:`/`run:` can stand
# in front of a hostile last one and satisfy every value-level check while a
# different occurrence is what actually runs.
#
# Scoping that refusal to one job or one step is what left the residual this pass
# closes. So the pass is deliberately *whole-document* and *uniform*: one
# indentation-aware walk of `launch-advisory-trust.yml` that refuses a repeated
# key in any mapping — the document root, `on`, `jobs`, every job mapping,
# `outputs`/`permissions`/`env`/`with`, and every step mapping including
# sequence items — plus every value that puts structure where this contract's
# block readers see none.
#
# It reads text and nothing else: no YAML library, no deserialization of
# candidate bytes, no execution. It is conservative by construction — a line it
# cannot classify is an error rather than a line it drops — and it is aware of
# block scalars, so the shell inside `run: |` is skipped whole instead of being
# mistaken for YAML structure.

# A key is `name:` followed by end-of-line or whitespace. `key:value` with no
# space is a plain scalar to YAML, not a mapping entry, so it deliberately does
# not match here and is reported as unclassifiable instead.
STRUCT_PLAIN_KEY = re.compile(
    r"^(?P<key>[A-Za-z_][A-Za-z0-9_.-]*):(?P<rest>(?:\s.*)?)$"
)
# `"steps":` and `steps:` are the same key to YAML. Quoted keys are normalized so
# a quoted duplicate cannot hide from the bare-name comparison.
STRUCT_QUOTED_KEY = re.compile(
    r"^(?P<quote>[\"'])(?P<key>[^\"']+)(?P=quote):(?P<rest>(?:\s.*)?)$"
)
STRUCT_SEQUENCE_ITEM = re.compile(r"^-(?:\s|$)")
STRUCT_MERGE_KEY = re.compile(r"^<<\s*:")
STRUCT_DOCUMENT_MARKER = re.compile(r"^(?:---|\.\.\.)(?:\s|$)")
# A block scalar with an explicit indentation indicator (`|2`) decides its own
# body extent, so this reader could disagree with YAML about where the shell
# ends and the next mapping key begins. Refused rather than guessed at.
STRUCT_INDENTED_BLOCK_SCALAR = re.compile(r"^[|>][+-]?[0-9]")

STRUCT_ROOT_LABEL = "<document root>"


class _StructuralFrame:
    """One open block collection: a mapping's keys or a sequence's item count."""

    __slots__ = ("indent", "path", "is_mapping", "keys", "items")

    def __init__(self, indent: int, path: str, is_mapping: bool) -> None:
        self.indent = indent
        self.path = path
        self.is_mapping = is_mapping
        self.keys: set[str] = set()
        self.items = 0

    def label(self) -> str:
        return self.path or STRUCT_ROOT_LABEL


def structural_value_kind(value: str) -> str:
    """Classify a node's inline value without interpreting it.

    Returns `empty` (a block may open below), `scalar`, `block` (a block-scalar
    header), `indented-block` (a block scalar with an explicit indentation
    indicator), `flow`, `alias`, `tag`, or `unreadable`.
    """

    text = value.strip()
    if text.startswith("#"):
        text = ""
    else:
        text = text.split(" #", 1)[0].strip()
    if not text:
        return "empty"
    # A quoted scalar is a scalar whatever it starts with, so a value like
    # `"[not a flow sequence]"` is not misread as structure.
    if text[0] in "\"'":
        return "scalar"
    if STRUCT_INDENTED_BLOCK_SCALAR.match(text):
        return "indented-block"
    if BLOCK_SCALAR.match(text):
        return "block"
    if text[0] in "[{":
        return "flow"
    if text[0] in "&*":
        return "alias"
    # A tag is a node property, not a plain scalar. In particular,
    # `steps: !!seq [{run: ...}]` is a flow sequence hidden behind a tag; a
    # line-oriented reader that treats the leading `!` as scalar text would see
    # no steps while GitHub's YAML consumer may see an entire sequence.
    if text[0] == "!":
        return "tag"
    if text[0] in "|>":
        return "unreadable"
    return "scalar"


def _skip_block_scalar(lines: list[str], index: int, indent: int) -> int:
    """Consume a block scalar body: everything more indented than its key.

    This is what keeps shell out of the structural reading. `fail() {`,
    `case … in`, and a line that happens to read `name: value` are opaque text
    inside a `run: |`, not mapping entries, so they can neither be counted as a
    duplicate key nor terminate an enclosing mapping.
    """

    while index < len(lines):
        line = lines[index]
        if line.strip() and (len(line) - len(line.lstrip(" "))) <= indent:
            break
        index += 1
    return index


def structural_ambiguity_errors(text: str, label: str) -> list[str]:  # noqa: C901
    """Refuse duplicate keys and inline structure anywhere in one document.

    One indentation-aware walk, applied uniformly to every mapping in the file
    rather than to the handful of jobs a value-level check happens to read. It
    fails closed: a sequence item where a key belongs, an unexpected indentation,
    a merge key, a document marker, a tab, and any line it cannot classify are
    all reported, because an unreadable node is exactly where a second `steps:`
    or a redirected `outputs:` would hide.
    """

    errors: list[str] = []
    lines = text.splitlines()
    stack: list[_StructuralFrame] = []
    # The path a block collection would take if one opens at a deeper indent.
    # `None` means the previous node already took its value, so nothing deeper
    # may follow it.
    pending_path: str | None = ""
    index = 0

    while index < len(lines):
        raw = lines[index]
        index += 1
        body = raw.lstrip(" ")
        if not body.strip() or body.startswith("#"):
            continue
        indent = len(raw) - len(body)
        content = body.rstrip()
        if "\t" in raw[:indent] or content.startswith("\t"):
            errors.append(
                f"{label} indents {content.strip()!r} with a tab; YAML forbids tab "
                "indentation, so this contract's structural reading of the document "
                "cannot be trusted to match GitHub's"
            )
            pending_path = None
            continue
        if STRUCT_DOCUMENT_MARKER.match(content):
            errors.append(
                f"{label} declares the YAML document marker {content.strip()!r}; the "
                "trusted workflow must be a single implicit document, because a "
                "second document is a whole second workflow definition this "
                "contract's readers never see"
            )
            pending_path = None
            continue

        while stack and indent < stack[-1].indent:
            stack.pop()

        if STRUCT_SEQUENCE_ITEM.match(content):
            frame: _StructuralFrame | None = None
            if stack and not stack[-1].is_mapping and stack[-1].indent == indent:
                frame = stack[-1]
            elif pending_path is not None and (not stack or indent >= stack[-1].indent):
                frame = _StructuralFrame(indent, pending_path, is_mapping=False)
                stack.append(frame)
            if frame is None:
                errors.append(
                    f"{label} declares the sequence item {content.strip()!r} where "
                    "this contract reads a mapping key; a node it cannot place is "
                    "refused rather than skipped"
                )
                pending_path = None
                continue
            frame.items += 1
            item_path = f"{frame.path}[{frame.items}]"
            pending_path = None

            after = content[1:]
            rest = after.lstrip(" ")
            if not rest:
                # The item's own collection opens on the following lines.
                pending_path = item_path
                continue
            node_indent = indent + 1 + (len(after) - len(rest))
            if STRUCT_MERGE_KEY.match(rest):
                errors.append(
                    f"{label} merges a mapping into `{item_path}` ({rest.strip()!r}); "
                    "a merge key injects keys this contract never saw in source form"
                )
                continue
            item_key = STRUCT_PLAIN_KEY.match(rest) or STRUCT_QUOTED_KEY.match(rest)
            if item_key is None:
                kind = structural_value_kind(rest)
                if kind == "scalar":
                    continue
                if kind == "block":
                    index = _skip_block_scalar(lines, index, indent)
                    continue
                errors.append(
                    f"{label} declares the sequence item `{item_path}` as "
                    f"{rest.strip()!r}; every value in this workflow must be a plain "
                    "scalar or an explicit block, never a flow collection, an "
                    "anchor, an alias, a YAML tag, or a block scalar this reader "
                    "cannot bound"
                )
                continue
            # An item that opens with a key is a mapping whose keys all start in
            # the column that first key starts in.
            stack.append(_StructuralFrame(node_indent, item_path, is_mapping=True))
            indent = node_indent
            content = rest
            # Falls through to the mapping-key handling below.

        if STRUCT_MERGE_KEY.match(content):
            top = stack[-1].label() if stack else STRUCT_ROOT_LABEL
            errors.append(
                f"{label} merges a mapping into `{top}` ({content.strip()!r}); a "
                "merge key injects keys this contract never saw in source form"
            )
            pending_path = None
            continue

        key_match = STRUCT_PLAIN_KEY.match(content) or STRUCT_QUOTED_KEY.match(content)
        if key_match is None:
            errors.append(
                f"{label} declares {content.strip()!r}, which this contract cannot "
                "classify as a mapping key, a sequence item, or block-scalar text; an "
                "unreadable node is refused rather than dropped, because dropping it "
                "is how a duplicate or redirected key would survive"
            )
            pending_path = None
            continue

        # A block sequence written at its parent key's own indentation ends here.
        while stack and not stack[-1].is_mapping and stack[-1].indent == indent:
            stack.pop()

        mapping: _StructuralFrame | None = None
        if stack and stack[-1].is_mapping and stack[-1].indent == indent:
            mapping = stack[-1]
        elif pending_path is not None and (not stack or indent > stack[-1].indent):
            mapping = _StructuralFrame(indent, pending_path, is_mapping=True)
            stack.append(mapping)
        if mapping is None:
            errors.append(
                f"{label} declares {content.strip()!r} at an indentation this "
                "contract cannot place in the surrounding mapping; an unplaceable key "
                "is refused rather than attached to a guess"
            )
            pending_path = None
            continue

        key = key_match.group("key")
        if key in mapping.keys:
            errors.append(
                f"{label} declares the mapping key `{key}` more than once in "
                f"`{mapping.label()}`; a duplicated mapping key is not an error "
                "GitHub reports — one occurrence wins, and which one is a property "
                "of the consumer, so a safe occurrence this contract reads can stand "
                "in front of an untrusted one that actually runs"
            )
        mapping.keys.add(key)
        node_path = f"{mapping.path}.{key}" if mapping.path else key
        pending_path = None

        kind = structural_value_kind(key_match.group("rest"))
        if kind == "empty":
            pending_path = node_path
        elif kind == "block":
            index = _skip_block_scalar(lines, index, indent)
        elif kind == "indented-block":
            errors.append(
                f"{label} declares `{node_path}` as a block scalar with an explicit "
                "indentation indicator; that indicator decides where the scalar ends, "
                "so this reader and GitHub could disagree about which lines are shell "
                "and which are mapping keys"
            )
            index = _skip_block_scalar(lines, index, indent)
        elif kind in ("flow", "alias", "tag", "unreadable"):
            errors.append(
                f"{label} declares `{node_path}` with the "
                f"{'flow' if kind == 'flow' else 'tagged, aliased, or unreadable'} "
                "value "
                f"{key_match.group('rest').strip()!r}; every value in this workflow "
                "must be a plain scalar or an explicit block, because a flow "
                "collection, tag, anchor, or alias can carry whole entries — a "
                "`steps:`, an `outputs:`, an `env:`, a `with:` — that this "
                "contract's block readers never see"
            )

    return errors


# ---------------------------------------------------------------------------
# Contract
# ---------------------------------------------------------------------------


def inline_value(value: str) -> str:
    """A step/mapping scalar with a trailing comment and quotes removed."""

    text = value.split(" #", 1)[0].strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        text = text[1:-1]
    return text.strip()


def duplicate_step_key_errors(
    where: str, label: str, entries: list[tuple[str, str, list[str]]]
) -> list[str]:
    """Refuse any repeated top-level key inside one step mapping.

    A step written with two `name:`, `if:`, `uses:`, or `with:` keys is not a
    YAML error GitHub reports: one of them wins. Which one is an implementation
    detail of the consumer, so a contract that reads a different occurrence than
    the runner applies has verified a workflow that does not exist.
    """

    seen: set[str] = set()
    repeated: list[str] = []
    for key, _, _ in entries:
        if key in seen:
            repeated.append(key)
        seen.add(key)
    if not repeated:
        return []
    return [
        f"{where} {label} step declares duplicate step key(s) "
        f"{', '.join(sorted(set(repeated)))}; a duplicated mapping key is ambiguous "
        "— this contract reads one occurrence while GitHub may apply the other"
    ]


def check_trusted_checkout_step(step_lines: list[str]) -> list[str]:
    """The first step of the credential job: the trusted-anchor checkout.

    This step is what makes the credential job's workspace trustworthy without
    any in-job command. It is held to an exact action pin, an exact ref
    expression, and a closed input set, and it may declare nothing executable.
    """

    where = f"{TRUSTED_WORKFLOW} job `{SECRET_JOB}`"
    entries = step_entries(step_lines)
    if not entries:
        return [f"{where} first step is not parseable as a step"]

    errors: list[str] = []
    errors.extend(duplicate_step_key_errors(where, "trusted-anchor checkout", entries))
    disallowed = sorted(
        {key for key, _, _ in entries if key not in CREDENTIAL_CHECKOUT_ALLOWED_KEYS}
    )
    if disallowed:
        errors.append(
            f"{where} trusted-anchor checkout step declares {', '.join(disallowed)}; "
            "only name/uses/with are admitted, so it can neither run a command in "
            "this workspace nor be conditionally skipped"
        )

    uses = [inline_value(value) for key, value, _ in entries if key == "uses"]
    if uses != [CHECKOUT_ACTION_PIN]:
        errors.append(
            f"{where} must begin with exactly one `uses: {CHECKOUT_ACTION_PIN}` "
            f"step (found {uses}); the credential job's workspace must come from "
            "the pinned checkout action and nothing else"
        )

    with_entries = [(value, body) for key, value, body in entries if key == "with"]
    if len(with_entries) != 1:
        errors.append(
            f"{where} trusted-anchor checkout must declare exactly one `with:` "
            f"input mapping (found {len(with_entries)})"
        )
        return errors

    # `step_entries` has already stripped the value, so re-pad it before dropping
    # a trailing comment: a bare `with:  # note` must still read as "no value".
    with_inline = inline_value(f" {with_entries[0][0]}")
    with_body = with_entries[0][1]
    if with_inline:
        # A flow mapping is not "an empty `with:`". The block reader below sees no
        # body at all, so every input inside the braces would vanish from the
        # exact-input comparison while GitHub still applies it.
        errors.append(
            f"{where} trusted-anchor checkout declares an inline or flow `with:` "
            f"value {with_inline!r}; the checkout inputs must be an explicit block "
            "mapping so every input is individually compared against the admitted set"
        )
        return errors

    inputs: dict[str, str] = {}
    duplicate_inputs: list[str] = []
    for line in with_body:
        entry = MAPPING_ENTRY.match(line)
        if entry is None:
            errors.append(
                f"{where} trusted-anchor checkout declares a `with:` entry this "
                f"contract cannot parse ({line.strip()!r}); an unreadable input is "
                "exactly how a redirected ref or an extra input would slip past the "
                "exact-input comparison"
            )
            continue
        key = entry.group("key")
        if key in inputs:
            duplicate_inputs.append(key)
        inputs[key] = inline_value(entry.group("value"))
    if duplicate_inputs:
        errors.append(
            f"{where} trusted-anchor checkout declares duplicate `with:` input(s) "
            f"{', '.join(sorted(set(duplicate_inputs)))}; a duplicated input is "
            "ambiguous — this contract compares one of them while GitHub may apply "
            "the other, so the workspace the credential step executes would not be "
            "the one verified here"
        )
    if inputs != CREDENTIAL_CHECKOUT_INPUTS:
        errors.append(
            f"{where} trusted-anchor checkout declares inputs {inputs!r}; it must "
            f"declare exactly {CREDENTIAL_CHECKOUT_INPUTS!r} — the established "
            "anchor commit, a single-commit fetch, and no persisted credential — "
            "so no other ref, repository, path, or credential can reach the "
            "workspace the credential step executes"
        )
    return errors


def check_credential_step_env(
    entries: list[tuple[str, str, list[str]]],
) -> list[str]:
    """The exact closed-environment contract for the credential-bearing step.

    The command is anchored end to end, but a command is only as exact as the
    environment that resolves it. `BASH_ENV` makes Bash source a file before it
    reaches the command; `PATH` chooses a different `python3`; `PYTHONPATH`,
    `PYTHONSTARTUP`, and `LD_PRELOAD` reach inside the interpreter. So the
    environment is verified as an *exact mapping* — the admitted keys, their
    admitted values, and nothing else — instead of a blacklist of names anyone
    has happened to think of.
    """

    where = f"{TRUSTED_WORKFLOW} job `{SECRET_JOB}`"
    errors: list[str] = []

    env_blocks = [(value, body) for key, value, body in entries if key == "env"]
    if len(env_blocks) != 1:
        errors.append(
            f"{where} credential-bearing step must declare exactly one `env:` "
            f"block mapping (found {len(env_blocks)}); the whole environment that "
            "resolves the anchored command is part of the contract"
        )
        return errors

    inline, body = env_blocks[0]
    if inline.strip():
        errors.append(
            f"{where} credential-bearing step declares a flow, alias, or inline "
            f"`env:` value {inline.strip()!r}; the environment must be an explicit "
            "block mapping so every key and every value is individually verified"
        )
        return errors
    if not body:
        errors.append(
            f"{where} credential-bearing step declares an empty `env:` mapping; it "
            f"must declare exactly {sorted(CREDENTIAL_STEP_ENV)}"
        )
        return errors

    entry_indent = len(body[0]) - len(body[0].lstrip())
    declared: dict[str, str] = {}
    duplicates: list[str] = []
    for line in body:
        if yaml_aliasing_marker(line):
            errors.append(
                f"{where} credential-bearing step env entry {line.strip()!r} uses a "
                "YAML anchor, alias, or merge key; the environment must be written "
                "out literally so no key or value can be injected from elsewhere in "
                "the document"
            )
            continue
        match = ENV_ENTRY.match(line)
        if match is None or len(match.group("indent")) != entry_indent:
            # Never skipped: an entry this parser cannot read is exactly how a
            # nested or reshaped mapping would slip past an allowlist.
            errors.append(
                f"{where} credential-bearing step declares an env entry this "
                f"contract cannot parse ({line.strip()!r}); every entry must be one "
                "`NAME: value` pair at the mapping's own indentation, so nothing is "
                "silently ignored"
            )
            continue
        key = match.group("key")
        value = inline_value(match.group("rest"))
        if not value or BLOCK_SCALAR.match(value):
            errors.append(
                f"{where} credential-bearing step declares env key {key} with a "
                "block-scalar, nested, or empty value; every admitted value is an "
                "exact single-line scalar"
            )
            continue
        if key in declared:
            duplicates.append(key)
        declared[key] = value

    if duplicates:
        errors.append(
            f"{where} credential-bearing step declares duplicate env key(s) "
            f"{', '.join(sorted(set(duplicates)))}; YAML keeps only the last "
            "occurrence, so a duplicate silently overrides a verified binding"
        )
    if declared != CREDENTIAL_STEP_ENV:
        errors.append(
            f"{where} credential-bearing step declares environment {declared!r}; it "
            f"must declare exactly {CREDENTIAL_STEP_ENV!r}. This is an allowlist of "
            "key and value, not a blacklist: any other name — `BASH_ENV`, `PATH`, "
            "`PYTHONPATH`, `LD_PRELOAD`, or one nobody has named yet — could make "
            "Bash or Python resolve something other than the anchored command"
        )
    return errors


def check_credential_job_steps(steps: list[list[str]]) -> list[str]:
    """The closed step-sequence contract for the credential-bearing job.

    Step scoping bounds who can *read* the credential; it does not bound who can
    change what the credential step *executes*. Any additional step in this job
    shares its workspace, needs no secret, and needs no candidate expression: it
    can read `.workflow_run.head_sha` from `$GITHUB_EVENT_PATH`, ask the API, or
    read `printenv`, then fetch candidate bytes or overwrite
    `scripts/check_launch_readiness.py`, and the exact credential command would
    execute the replaced file with the credential bound. So the sequence itself
    is verified: a pinned trusted-anchor checkout, then the credential step, and
    nothing before, between, or after.
    """

    errors: list[str] = []
    where = f"{TRUSTED_WORKFLOW} job `{SECRET_JOB}`"

    # Executable candidate data anywhere in the job, block scalars included. The
    # checker receives the candidate SHA through the process environment and
    # never through the shell, so any expansion here is a new execution path.
    # This survives as defence in depth; the closed sequence below is what makes
    # an *indirectly* derived candidate unreachable too.
    for step in steps:
        run_text = step_run_text(step)
        match = CANDIDATE_ENV_EXPANSION.search(run_text)
        if match:
            errors.append(
                f"{where} expands candidate-derived {match.group(0)!r} on an "
                "executable line; the candidate commit may only be read from the "
                "process environment by the trusted checker, never by shell"
            )

    if len(steps) != CREDENTIAL_JOB_STEP_COUNT:
        errors.append(
            f"{where} must consist of exactly {CREDENTIAL_JOB_STEP_COUNT} steps — "
            f"the pinned `{CHECKOUT_ACTION_PIN}` checkout of the established "
            "trusted anchor, immediately followed by the one credential-bearing "
            f"checker invocation — but declares {len(steps)}. Any other step "
            "shares this job's workspace and can replace the checker (or derive "
            "the candidate from $GITHUB_EVENT_PATH, the API, or printenv) before "
            "the credential is used, with no secret and no candidate expression "
            "of its own"
        )
    if not steps:
        return errors

    errors.extend(check_trusted_checkout_step(steps[0]))

    positions = [
        index
        for index, step in enumerate(steps)
        if any(TOKEN_REFERENCE in line for line in step)
    ]
    if positions and (
        positions != [CREDENTIAL_JOB_STEP_COUNT - 1] or positions[0] != len(steps) - 1
    ):
        errors.append(
            f"{where} credential-bearing step must be step "
            f"{CREDENTIAL_JOB_STEP_COUNT} of {CREDENTIAL_JOB_STEP_COUNT} — "
            "immediately after the trusted-anchor checkout and the last step of "
            f"the job (found at step {positions[0] + 1} of {len(steps)})"
        )
    errors.extend(check_credential_step(steps))
    return errors


def check_credential_step(steps: list[list[str]]) -> list[str]:
    """The step-scoped contract for the step that receives the credential.

    A secret bound by one step's `env:` is visible only to that step's command,
    so this contract is applied to the step that actually receives it.
    """

    errors: list[str] = []
    where = f"{TRUSTED_WORKFLOW} job `{SECRET_JOB}`"

    bearing = [step for step in steps if any(TOKEN_REFERENCE in line for line in step)]
    if len(bearing) != 1:
        errors.append(
            f"{where} must deliver the advisory credential to exactly one step "
            f"(found {len(bearing)}); a job-level or workflow-level binding would "
            "hand the credential to every command in the job"
        )
        return errors

    entries = step_entries(bearing[0])
    if not entries:
        errors.append(f"{where} credential-bearing step is not parseable as a step")
        return errors

    errors.extend(duplicate_step_key_errors(where, "credential-bearing", entries))
    disallowed = sorted(
        {key for key, _, _ in entries if key not in CREDENTIAL_STEP_ALLOWED_KEYS}
    )
    if disallowed:
        errors.append(
            f"{where} credential-bearing step declares {', '.join(disallowed)}; "
            "only name/id/if/env/run are admitted, so no action, shell override, "
            "or working directory can add or redirect an execution surface while "
            "the credential is bound"
        )

    errors.extend(check_credential_step_env(entries))

    runs = [(value, body) for key, value, body in entries if key == "run"]
    if len(runs) != 1:
        errors.append(
            f"{where} credential-bearing step must have exactly one `run:` "
            f"execution surface (found {len(runs)})"
        )
        return errors

    value, body = runs[0]
    if BLOCK_SCALAR.match(value) or body or not value:
        errors.append(
            f"{where} credential-bearing step uses a multiline `run:` block; it "
            "must be a single-line invocation of the default-branch checker so "
            "no other shell command — a candidate checkout, a `source`, or any "
            "other statement — can run beside it with the credential already in "
            "the environment"
        )
        return errors

    if not CREDENTIAL_RUN_COMMAND.match(value):
        errors.append(
            f"{where} credential-bearing step runs {value!r}; it may run only "
            f'`{TRUSTED_CHECKER} [--verify] [--require-pass] --trusted-execution '
            '--trusted-tree-sha "$TRUSTED_SHA"` with no other command, operator, '
            "substitution, interpreter, or path"
        )
    missing = [flag for flag in CREDENTIAL_REQUIRED_FLAGS if flag not in value]
    if missing:
        errors.append(
            f"{where} credential-bearing step omits {', '.join(missing)}; without "
            "the trusted-execution pins the checker will not prove the executing "
            "tree is the trusted anchor before using the credential"
        )
    return errors


def job_runs_exact_command(steps: list[list[str]], command: str) -> bool:
    """True if some step of `steps` is a real single-line `run:` of `command`.

    Structural on purpose: a comment, a `name:` mentioning the command, or an
    occurrence in a different job does not satisfy it, and neither does a
    multiline block that merely contains the command among other shell.
    """

    for step in steps:
        for key, value, body in step_entries(step):
            if key != "run" or body or BLOCK_SCALAR.match(value):
                continue
            if inline_value(value) == command:
                return True
    return False


def check_trusted_workflow_structure(text: str) -> list[str]:
    """Close the inherited execution surfaces outside the two validated steps.

    A workflow-level `env:` or `defaults:` is inherited by every job, so either
    can change how the credential step's anchored command resolves — the shell it
    runs under, the directory it runs in, the variables it sees — without
    appearing anywhere in the two steps this contract validates. The top-level
    key set is therefore an allowlist, and any structural line the reader cannot
    place is an error rather than a line it quietly drops.
    """

    errors: list[str] = []
    # The whole-document pass first: it is the general gate for the ambiguity
    # family, and it covers every mapping in the file — `establish-trust`'s
    # `steps:`/`outputs:`, a trust step's `run:`, the publisher's `steps:`/`env:`,
    # and every job or step key nobody has enumerated below. The per-surface
    # checks that follow stay as defence in depth and for their specific
    # value-level messages.
    errors.extend(structural_ambiguity_errors(text, TRUSTED_WORKFLOW))

    mapping = top_level_blocks(text)
    blocks = mapping.blocks

    # A duplicate mapping key is the whole ambiguity: a workflow can keep the
    # safe block-form `on:` first and append `on: [push]`, and a reader that
    # derives events from the first occurrence still sees only trusted events
    # while a consumer applying the last duplicate sees a tag-reachable push
    # trigger. Every duplicate is refused, including the admitted keys.
    for key in duplicate_keys(mapping):
        errors.append(
            f"{TRUSTED_WORKFLOW} declares top-level key `{key}` more than once; a "
            "duplicated mapping key makes this contract's single structural reading "
            "and GitHub's YAML reading disagree, so a safe first occurrence could "
            "stand in front of an untrusted last one"
        )

    for key, values in sorted(mapping.inline.items()):
        for value in values:
            if key in TRUSTED_WORKFLOW_BLOCK_TOP_LEVEL_KEYS:
                if value:
                    errors.append(
                        f"{TRUSTED_WORKFLOW} declares top-level `{key}:` with the "
                        f"inline value {value!r}; `{key}` must be an explicit block "
                        "mapping, because a flow collection written here carries "
                        "whole entries — `on: [push]`, `jobs: {…}` — that this "
                        "contract's block reader would never see"
                    )
            elif FLOW_OR_ALIASED_VALUE.match(value) or BLOCK_SCALAR.match(value):
                errors.append(
                    f"{TRUSTED_WORKFLOW} declares top-level `{key}:` with the flow, "
                    f"aliased, or block-scalar value {value!r}; every top-level "
                    "value must be a plain scalar or an explicit block, so nothing "
                    "structural can hide from this contract"
                )

    on_block = blocks.get("on")
    if on_block is not None:
        for key in duplicate_keys(split_blocks(on_block, NESTED_KEY)):
            errors.append(
                f"{TRUSTED_WORKFLOW} declares the `{key}` trigger more than once "
                "under `on:`; a duplicated event key is ambiguous, so the events "
                "this contract reads need not be the events GitHub applies"
            )

    jobs_mapping = job_blocks(text)
    for key in duplicate_keys(jobs_mapping):
        errors.append(
            f"{TRUSTED_WORKFLOW} declares job `{key}` more than once; a duplicated "
            "job ID is ambiguous — this contract would hold one definition to the "
            "credential contract while GitHub runs the other"
        )
    for key, values in sorted(jobs_mapping.inline.items()):
        for value in values:
            if value:
                errors.append(
                    f"{TRUSTED_WORKFLOW} declares job `{key}` with the inline value "
                    f"{value!r}; every job must be an explicit block mapping, "
                    "because a flow mapping carries steps, environment, and "
                    "permissions this contract's block reader never sees"
                )

    extra = sorted(set(blocks) - TRUSTED_WORKFLOW_ALLOWED_TOP_LEVEL_KEYS)
    if extra:
        errors.append(
            f"{TRUSTED_WORKFLOW} declares top-level {', '.join(extra)}; only "
            f"{'/'.join(sorted(TRUSTED_WORKFLOW_ALLOWED_TOP_LEVEL_KEYS))} are "
            f"admitted. A workflow-level `env:` or `defaults:` (`run.shell`, "
            f"`run.working-directory`) is inherited by `{SECRET_JOB}` and would "
            "redirect the credential step's environment, interpreter, or working "
            "directory without appearing in either validated step"
        )

    for line in code_lines(text.splitlines()):
        if len(line) - len(line.lstrip()) == 0 and not TOP_LEVEL_KEY.match(line):
            errors.append(
                f"{TRUSTED_WORKFLOW} declares a top-level entry this contract "
                f"cannot parse ({line.strip()!r}); an unreadable document node "
                "could carry inherited environment, shell, or merge keys"
            )

    jobs_block = blocks.get("jobs")
    if jobs_block is not None:
        for line in code_lines(jobs_block):
            if len(line) - len(line.lstrip()) <= 2 and not NESTED_KEY.match(line):
                errors.append(
                    f"{TRUSTED_WORKFLOW} declares an entry at the `jobs:` mapping "
                    f"level this contract cannot parse ({line.strip()!r}); a merge "
                    "key or alias there would inject keys into every job"
                )
    return errors


def check_trusted_workflow(text: str) -> list[str]:
    errors: list[str] = []
    lines = code_lines(text.splitlines())
    jobs = job_blocks(text).blocks

    errors.extend(check_trusted_workflow_structure(text))

    events = event_names(text)
    if not events:
        errors.append(f"{TRUSTED_WORKFLOW} declares no triggering events")
    untrusted = sorted(events - TRUSTED_EVENTS)
    if untrusted:
        errors.append(
            f"{TRUSTED_WORKFLOW} must not be reachable from candidate-controlled "
            f"events: {', '.join(untrusted)}"
        )

    if "workflow_run" in events and REQUIRED_WORKFLOW_RUN_TYPE not in workflow_run_types(
        text
    ):
        errors.append(
            f"{TRUSTED_WORKFLOW} must trigger on `workflow_run` type "
            f"`{REQUIRED_WORKFLOW_RUN_TYPE}`; `requested` alone does not fire for a "
            "re-run, so a re-run Release attempt could never obtain its own verdict"
        )

    occurrences = sum(line.count(TOKEN_REFERENCE) for line in lines)
    if occurrences != 1:
        errors.append(
            f"{TRUSTED_WORKFLOW} must reference the advisory credential exactly "
            f"once (found {occurrences})"
        )

    for line in lines:
        uses = USES_FIELD.match(line)
        if uses and not PINNED_ACTION.match(uses.group("value")):
            errors.append(
                f"{TRUSTED_WORKFLOW} uses unpinned or local action "
                f"{uses.group('value')!r}"
            )

    # Checkout refs are judged per job. Every secretless job may check out only
    # the literal protected branch; the credential-bearing job checks out the
    # anchor commit that literal checkout already established, so its workspace
    # is trusted without running any command of its own.
    declared_refs = sum(1 for line in lines if REF_FIELD.match(line))
    scanned_refs = 0
    for job_name in sorted(jobs):
        for line in code_lines(jobs[job_name]):
            ref = REF_FIELD.match(line)
            if not ref:
                continue
            scanned_refs += 1
            value = inline_value(ref.group("value"))
            if job_name == SECRET_JOB:
                if value != TRUSTED_SHA_REF_EXPRESSION:
                    errors.append(
                        f"{TRUSTED_WORKFLOW} job `{SECRET_JOB}` checks out "
                        f"{value!r}; it must check out exactly "
                        f"{TRUSTED_SHA_REF_EXPRESSION!r}, the anchor commit the "
                        "literal protected-branch checkout already established"
                    )
            elif value != TRUSTED_REF:
                errors.append(
                    f"{TRUSTED_WORKFLOW} job `{job_name}` checks out {value!r}; "
                    f"every secretless ref must be the literal trusted ref "
                    f"{TRUSTED_REF!r}"
                )
    if scanned_refs != declared_refs:
        errors.append(
            f"{TRUSTED_WORKFLOW} declares a checkout ref outside any job block"
        )

    for job_name in (TRUST_JOB, SECRET_JOB, PUBLISH_JOB):
        if job_name not in jobs:
            errors.append(f"{TRUSTED_WORKFLOW} is missing job `{job_name}`")
    if TRUST_JOB not in jobs or SECRET_JOB not in jobs:
        return errors

    trust_lines = code_lines(jobs[TRUST_JOB])
    trust_text = "\n".join(trust_lines)
    if any(TOKEN_REFERENCE in line for line in trust_lines):
        errors.append(
            f"{TRUSTED_WORKFLOW} job `{TRUST_JOB}` must establish provenance "
            "without any credential"
        )

    # The credential job executes whatever the trusted anchor names, so the
    # anchor itself must be proved here: taken from the literal protected-branch
    # checkout, validated as a commit, reachable from protected `main`, and
    # exported from that step's own output.
    for pattern, detail in TRUST_ANCHOR_PROOFS:
        if not pattern.search(trust_text):
            errors.append(
                f"{TRUSTED_WORKFLOW} job `{TRUST_JOB}` must {detail}; the "
                f"`{SECRET_JOB}` job checks that anchor out directly and executes "
                "it with the credential bound"
            )
    if not any(TRUSTED_SHA_OUTPUT_BINDING.match(line) for line in trust_lines):
        errors.append(
            f"{TRUSTED_WORKFLOW} job `{TRUST_JOB}` must export `trusted_sha` from "
            "the step that resolved and validated it"
        )

    # Secretless prerequisites belong here, not in the credential job, whose
    # workspace must reach the credential step untouched by any other step. Both
    # must be *real* executable steps of this job: the protected environment
    # releases the credential only after this job succeeds, so this is the only
    # place the boundary contract can be proved on the trusted tree in the same
    # run that then uses the credential.
    trust_steps = job_steps(jobs[TRUST_JOB])
    for command, detail in (
        (CHECKER_SELF_TEST_STEP, "the secretless launch-readiness checker self-test"),
        (SELF_TEST_STEP, "this trust-boundary verifier's own self-test"),
    ):
        if not job_runs_exact_command(trust_steps, command):
            errors.append(
                f"{TRUSTED_WORKFLOW} job `{TRUST_JOB}` must run {detail} as a real "
                f"executable step (`run: {command}`) before the protected "
                f"environment can release the credential. A comment, a mention in "
                f"another job, or a relocation into `{SECRET_JOB}` — where it would "
                "be an executable step sharing the credential step's workspace — "
                "does not satisfy it"
            )

    # The verdict must be bound to the exact Release run AND run attempt that
    # asked for it, or an older success on the same commit satisfies a newer
    # release before its own evaluation has run.
    for expression, detail in (
        ("github.event.workflow_run.id", "the triggering Release run ID"),
        ("github.event.workflow_run.run_attempt", "the triggering Release run attempt"),
    ):
        if expression not in trust_text:
            errors.append(
                f"{TRUSTED_WORKFLOW} job `{TRUST_JOB}` must bind {detail} "
                f"(`{expression}`) so the published verdict cannot be replayed"
            )
    if "status_context:" not in trust_text:
        errors.append(
            f"{TRUSTED_WORKFLOW} job `{TRUST_JOB}` must export the derived "
            "`status_context` for the publisher"
        )
    if not TRUSTED_RUN_CONTEXT_DERIVATION.search(trust_text):
        errors.append(
            f"{TRUSTED_WORKFLOW} job `{TRUST_JOB}` must derive a status context "
            f"of the form `{STATUS_CONTEXT_PREFIX}/release-<run id>-attempt-"
            "<run attempt>`; a commit-wide or attempt-less context is replayable"
        )
    if AUDIT_STATUS_CONTEXT not in trust_text:
        errors.append(
            f"{TRUSTED_WORKFLOW} job `{TRUST_JOB}` must publish default-branch "
            f"audits under the distinct `{AUDIT_STATUS_CONTEXT}` context so an "
            "audit can never satisfy a release"
        )

    secret_lines = code_lines(jobs[SECRET_JOB])
    secret_text = "\n".join(secret_lines)
    if not any(TOKEN_REFERENCE in line for line in secret_lines):
        errors.append(
            f"{TRUSTED_WORKFLOW} job `{SECRET_JOB}` must be the only holder of "
            "the advisory credential"
        )
    if f"environment: {PROTECTED_ENVIRONMENT}" not in secret_text:
        errors.append(
            f"{TRUSTED_WORKFLOW} job `{SECRET_JOB}` must bind the credential to "
            f"the protected `{PROTECTED_ENVIRONMENT}` environment"
        )
    if f"needs: {TRUST_JOB}" not in secret_text:
        errors.append(
            f"{TRUSTED_WORKFLOW} job `{SECRET_JOB}` must require `{TRUST_JOB}` so "
            "provenance is established before the credential is released"
        )
    # The candidate may reach the secret-bearing job only as an inert SHA in an
    # environment mapping. A checkout ref, a fetch, or any shell operand would
    # make candidate-controlled bytes executable here.
    for line in secret_lines:
        for expression in CANDIDATE_EXPRESSIONS:
            if expression in line and not CANDIDATE_ENV_BINDING.match(line):
                errors.append(
                    f"{TRUSTED_WORKFLOW} job `{SECRET_JOB}` exposes candidate "
                    f"input {expression!r} outside the inert LAUNCH_TARGET_SHA "
                    "environment binding"
                )

    # The credential job must be written out literally. An anchor defined
    # anywhere in the document and aliased or merged in here would add keys —
    # `env:`, `defaults:`, a whole extra step — that neither the job-key
    # allowlist nor the two-step contract ever saw in source form.
    for line in secret_lines:
        if yaml_aliasing_marker(line):
            errors.append(
                f"{TRUSTED_WORKFLOW} job `{SECRET_JOB}` uses a YAML anchor, alias, "
                f"or merge key ({line.strip()!r}); every key and value in this job "
                "must be literal, so what this contract validated is what runs"
            )

    for line in secret_lines:
        stripped = line.strip()
        if "python" in stripped and TRUSTED_CHECKER not in stripped:
            errors.append(
                f"{TRUSTED_WORKFLOW} job `{SECRET_JOB}` invokes an interpreter "
                "other than the default-branch checker"
            )

    # The credential job's own mapping, read in source order. A duplicated key
    # here is decided by whichever consumer reads it: `environment:` twice keeps
    # the protected binding this contract matches while GitHub may apply the
    # second, and a second `steps:` is invisible to the block reader that stops
    # at the first one.
    job_key_entries = [
        (match.group("key"), inline_value(match.group("rest")))
        for match in (JOB_KEY.match(line) for line in secret_lines)
        if match
    ]
    seen_job_keys: set[str] = set()
    repeated_job_keys: list[str] = []
    for key, _ in job_key_entries:
        if key in seen_job_keys:
            repeated_job_keys.append(key)
        seen_job_keys.add(key)
    if repeated_job_keys:
        errors.append(
            f"{TRUSTED_WORKFLOW} job `{SECRET_JOB}` declares duplicate job key(s) "
            f"{', '.join(sorted(set(repeated_job_keys)))}; a duplicated mapping key "
            "is ambiguous — this contract verifies one occurrence (the protected "
            "environment, the trust edge, the closed two-step sequence) while "
            "GitHub may apply the other"
        )
    for key, value in job_key_entries:
        if key in CREDENTIAL_JOB_BLOCK_KEYS:
            if value:
                errors.append(
                    f"{TRUSTED_WORKFLOW} job `{SECRET_JOB}` declares `{key}:` with "
                    f"the inline value {value!r}; it must be an explicit block, "
                    "because a flow sequence there carries steps the closed "
                    "two-step contract would never see"
                )
        elif value and (
            FLOW_OR_ALIASED_VALUE.match(value) or BLOCK_SCALAR.match(value)
        ):
            errors.append(
                f"{TRUSTED_WORKFLOW} job `{SECRET_JOB}` declares `{key}:` with the "
                f"flow, aliased, or block-scalar value {value!r}; every job-level "
                "value must be a plain scalar or an explicit block"
            )

    declared_job_keys = sorted(seen_job_keys - CREDENTIAL_JOB_ALLOWED_KEYS)
    if declared_job_keys:
        errors.append(
            f"{TRUSTED_WORKFLOW} job `{SECRET_JOB}` declares "
            f"{', '.join(declared_job_keys)}; only "
            f"{'/'.join(sorted(CREDENTIAL_JOB_ALLOWED_KEYS))} are admitted, so no "
            "job-wide credential, working-directory rewrite, container, matrix, "
            "or reusable workflow can add a surface outside the two verified steps"
        )

    errors.extend(check_credential_job_steps(job_steps(jobs[SECRET_JOB])))

    if PUBLISH_JOB in jobs:
        publish_lines = code_lines(jobs[PUBLISH_JOB])
        if any(TOKEN_REFERENCE in line for line in publish_lines):
            errors.append(
                f"{TRUSTED_WORKFLOW} job `{PUBLISH_JOB}` must publish the verdict "
                "without any credential"
            )
        context_lines = [line for line in publish_lines if "context=" in line]
        if not context_lines:
            errors.append(
                f"{TRUSTED_WORKFLOW} job `{PUBLISH_JOB}` must publish the "
                f"`{STATUS_CONTEXT_PREFIX}` commit status"
            )
        for line in context_lines:
            if "$STATUS_CONTEXT" not in line and "${STATUS_CONTEXT}" not in line:
                errors.append(
                    f"{TRUSTED_WORKFLOW} job `{PUBLISH_JOB}` publishes a constant "
                    "commit-wide status context; it must publish the run-bound "
                    "context established by the trust job"
                )
        if not any(PUBLISH_CONTEXT_BINDING.match(line) for line in publish_lines):
            errors.append(
                f"{TRUSTED_WORKFLOW} job `{PUBLISH_JOB}` must consume the "
                "established `status_context` output"
            )
        if not any(PUBLISH_ENV_BINDING.match(line) for line in publish_lines):
            errors.append(
                f"{TRUSTED_WORKFLOW} job `{PUBLISH_JOB}` must publish against the "
                "established candidate SHA"
            )
    return errors


def check_release_workflow(text: str) -> list[str]:
    errors: list[str] = []
    jobs = job_blocks(text).blocks
    if RELEASE_GATE_JOB not in jobs:
        errors.append(f"{RELEASE_WORKFLOW} is missing job `{RELEASE_GATE_JOB}`")
        return errors
    gate = "\n".join(code_lines(jobs[RELEASE_GATE_JOB]))
    if not RELEASE_GATE_CONTEXT_DERIVATION.search(gate):
        errors.append(
            f"{RELEASE_WORKFLOW} job `{RELEASE_GATE_JOB}` must require the "
            f"`{STATUS_CONTEXT_PREFIX}` verdict published for its own run ID and "
            "run attempt"
        )
    # Any surviving bare use of the context prefix is a commit-wide status the
    # daily audit or an earlier release/attempt on the same commit already
    # satisfies.
    if COMMIT_WIDE_CONTEXT.search(gate):
        errors.append(
            f"{RELEASE_WORKFLOW} job `{RELEASE_GATE_JOB}` must not accept a "
            "commit-wide advisory status context; a stale or replayed verdict "
            "from another run or attempt would satisfy this release"
        )
    for expression in ("github.run_id", "github.run_attempt"):
        if expression not in gate:
            errors.append(
                f"{RELEASE_WORKFLOW} job `{RELEASE_GATE_JOB}` must bind "
                f"`{expression}` so the verdict it accepts is its own"
            )
    if "--verify" in gate:
        errors.append(
            f"{RELEASE_WORKFLOW} job `{RELEASE_GATE_JOB}` must not evaluate the "
            "live launch verdict itself; the tag target is not trusted code"
        )
    return errors


def check_standalone_workflow(text: str) -> list[str]:
    errors: list[str] = []
    # Comment-stripped: a commented-out or merely documented invocation must not
    # satisfy the requirement that the self-test actually runs.
    if not any(SELF_TEST_STEP in line for line in code_lines(text.splitlines())):
        errors.append(
            f"{STANDALONE_WORKFLOW} must run the advisory trust-boundary "
            "self-test on every pull request"
        )
    return errors


def evaluate(workflows: dict[str, str]) -> list[str]:
    """Apply the whole contract to a name -> text mapping of workflows."""

    errors: list[str] = []
    for name in sorted(workflows):
        if name == TRUSTED_WORKFLOW:
            continue
        for line in code_lines(workflows[name].splitlines()):
            if TOKEN_REFERENCE in line:
                errors.append(
                    f"{name} references the advisory credential; only "
                    f"{TRUSTED_WORKFLOW} may, because every other workflow is "
                    "reachable from a candidate-controlled ref"
                )
                break

    if TRUSTED_WORKFLOW not in workflows:
        errors.append(f"{TRUSTED_WORKFLOW} is missing")
    else:
        errors.extend(check_trusted_workflow(workflows[TRUSTED_WORKFLOW]))

    if RELEASE_WORKFLOW in workflows:
        errors.extend(check_release_workflow(workflows[RELEASE_WORKFLOW]))
    if STANDALONE_WORKFLOW in workflows:
        errors.extend(check_standalone_workflow(workflows[STANDALONE_WORKFLOW]))
    return errors


def load_workflows(directory: Path) -> dict[str, str]:
    workflows: dict[str, str] = {}
    for path in sorted(directory.iterdir()):
        if path.is_file() and path.suffix in (".yml", ".yaml"):
            workflows[path.name] = path.read_text(encoding="utf-8")
    return workflows


# ---------------------------------------------------------------------------
# Adversarial fixtures
# ---------------------------------------------------------------------------


FIXTURE_TRUSTED = """name: Trusted Launch Advisory Gate

on:
  workflow_run:
    workflows:
      - Release
    types:
      - in_progress
  schedule:
    - cron: "45 6 * * *"
permissions:
  contents: read

jobs:
  establish-trust:
    name: Establish candidate trust
    runs-on: ubuntu-latest
    outputs:
      candidate_sha: ${{ steps.candidate.outputs.candidate_sha }}
      trusted_sha: ${{ steps.candidate.outputs.trusted_sha }}
      status_context: ${{ steps.candidate.outputs.status_context }}
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v6
        with:
          ref: refs/heads/main
      - name: Synthetic policy/checker self-tests
        run: python3 -I scripts/check_launch_readiness.py --self-test
      - name: Trust-boundary contract self-test
        run: python3 -I .github/scripts/verify_launch_advisory_trust.py --self-test
      - name: Resolve
        id: candidate
        env:
          WORKFLOW_RUN_ID: ${{ github.event.workflow_run.id }}
          WORKFLOW_RUN_ATTEMPT: ${{ github.event.workflow_run.run_attempt }}
        run: |
          trusted_sha="$(git rev-parse HEAD)"
          [[ "$trusted_sha" =~ ^[0-9a-f]{40}$ ]] || exit 1
          git merge-base --is-ancestor "$trusted_sha" "$main_tip" || exit 1
          status_context="trusted-launch-advisory-gate/main-audit"
          status_context="trusted-launch-advisory-gate/release-${release_run_id}-attempt-${release_run_attempt}"
          echo "trusted_sha=${trusted_sha}" >> "$GITHUB_OUTPUT"
          echo "status_context=${status_context}" >> "$GITHUB_OUTPUT"

  advisory-verdict:
    name: Evaluate advisories from trusted code
    needs: establish-trust
    runs-on: ubuntu-latest
    environment: launch-advisory
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v6
        with:
          ref: ${{ needs.establish-trust.outputs.trusted_sha }}
          fetch-depth: 1
          persist-credentials: false
      - name: Evaluate
        env:
          GITHUB_TOKEN: ${{ github.token }}
          LAUNCH_TIER: ga
          LAUNCH_TARGET_SHA: ${{ needs.establish-trust.outputs.candidate_sha }}
          TRUSTED_SHA: ${{ needs.establish-trust.outputs.trusted_sha }}
          LAUNCH_PRIVATE_BLOCKER_COUNT: ${{ vars.LAUNCH_PRIVATE_BLOCKER_COUNT }}
          LAUNCH_PRIVATE_ADVISORY_AS_OF: ${{ vars.LAUNCH_PRIVATE_ADVISORY_AS_OF }}
          LAUNCH_ADVISORY_READ_TOKEN: ${{ secrets.LAUNCH_ADVISORY_READ_TOKEN }}
        run: python3 -I scripts/check_launch_readiness.py --verify --trusted-execution --trusted-tree-sha "$TRUSTED_SHA"

  publish-verdict:
    name: Publish trusted advisory verdict
    needs:
      - establish-trust
      - advisory-verdict
    runs-on: ubuntu-latest
    permissions:
      statuses: write
    steps:
      - name: Publish
        env:
          CANDIDATE_SHA: ${{ needs.establish-trust.outputs.candidate_sha }}
          STATUS_CONTEXT: ${{ needs.establish-trust.outputs.status_context }}
        run: gh api --method POST "repos/x/statuses/$CANDIDATE_SHA" -f "context=${STATUS_CONTEXT}"
"""

FIXTURE_RELEASE = """name: Release

on:
  push:
    tags:
      - 'v*'

jobs:
  validate-launch-readiness:
    name: Validate launch readiness
    runs-on: ubuntu-latest
    steps:
      - name: Require the trusted verdict
        env:
          RELEASE_RUN_ID: ${{ github.run_id }}
          RELEASE_RUN_ATTEMPT: ${{ github.run_attempt }}
        run: |
          expected_context="trusted-launch-advisory-gate/release-${RELEASE_RUN_ID}-attempt-${RELEASE_RUN_ATTEMPT}"
          gh api statuses | jq --arg ctx "$expected_context" 'select(.context == $ctx)'
"""

FIXTURE_STANDALONE = """name: Launch Readiness

on:
  pull_request:
  push:
    tags:
      - "v*"

jobs:
  launch-readiness:
    runs-on: ubuntu-latest
    steps:
      - name: Verify the advisory-credential trust boundary
        run: python3 -I .github/scripts/verify_launch_advisory_trust.py --self-test
"""


def baseline_fixture() -> dict[str, str]:
    return {
        TRUSTED_WORKFLOW: FIXTURE_TRUSTED,
        RELEASE_WORKFLOW: FIXTURE_RELEASE,
        STANDALONE_WORKFLOW: FIXTURE_STANDALONE,
    }


def run_self_test() -> int:  # noqa: C901 — a flat fixture table stays readable
    failures: list[str] = []

    def check(name: str, condition: bool, detail: str = "") -> None:
        if not condition:
            failures.append(f"{name}: {detail}" if detail else name)

    baseline = baseline_fixture()
    baseline_errors = evaluate(baseline)
    check("compliant fixture is accepted", not baseline_errors, str(baseline_errors))

    def mutated(name: str, replacement: str) -> dict[str, str]:
        workflows = baseline_fixture()
        workflows[name] = replacement
        return workflows

    # A malicious tagged workflow: the tag target rewrites the release workflow
    # (or adds a new one) so a tag-triggered job receives the credential.
    hostile_release = FIXTURE_RELEASE.replace(
        "          RELEASE_RUN_ATTEMPT: ${{ github.run_attempt }}",
        "          RELEASE_RUN_ATTEMPT: ${{ github.run_attempt }}\n"
        "          LAUNCH_ADVISORY_READ_TOKEN: ${{ secrets.LAUNCH_ADVISORY_READ_TOKEN }}",
    )
    check(
        "a tag-triggered job that claims the credential is rejected",
        any(
            "references the advisory credential" in err
            for err in evaluate(mutated(RELEASE_WORKFLOW, hostile_release))
        ),
    )

    hostile_new_workflow = dict(baseline)
    hostile_new_workflow["attacker.yml"] = (
        "name: Attacker\non:\n  push:\n    tags:\n      - 'v*'\njobs:\n"
        "  steal:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - run: echo ${{ secrets.LAUNCH_ADVISORY_READ_TOKEN }}\n"
    )
    check(
        "a newly added tag-triggered credential consumer is rejected",
        any(
            "attacker.yml references the advisory credential" in err
            for err in evaluate(hostile_new_workflow)
        ),
    )

    # A malicious tagged checker: the credential-bearing job is redirected at
    # candidate-controlled code instead of the default-branch checker.
    hostile_checker = FIXTURE_TRUSTED.replace(
        'run: python3 -I scripts/check_launch_readiness.py --verify '
        '--trusted-execution --trusted-tree-sha "$TRUSTED_SHA"',
        "run: python3 -I ./candidate/check_launch_readiness.py --dump-env",
    )
    check(
        "a credential-bearing job running candidate code is rejected",
        any(
            "credential-bearing step runs" in err
            or "invokes an interpreter other than" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, hostile_checker))
        ),
    )

    # ---- Step-scoped credential contract -------------------------------------
    #
    # Every fixture below is accepted by a verifier that inspects only the first
    # line of a `run:`, which is precisely why each one is here: with the
    # credential already bound to the step, the extra shell runs beside the
    # checker and can check out, source, or otherwise execute candidate material.

    credential_run = (
        "run: python3 -I scripts/check_launch_readiness.py --verify "
        '--trusted-execution --trusted-tree-sha "$TRUSTED_SHA"'
    )

    block_checkout = FIXTURE_TRUSTED.replace(
        credential_run,
        "run: |\n"
        '          git checkout "$LAUNCH_TARGET_SHA"\n'
        "          python3 -I scripts/check_launch_readiness.py --verify "
        '--trusted-execution --trusted-tree-sha "$TRUSTED_SHA"',
    )
    block_checkout_errors = evaluate(mutated(TRUSTED_WORKFLOW, block_checkout))
    check(
        "a credential-bearing `run: |` block that checks out the candidate is rejected",
        any("must be a single-line invocation" in err for err in block_checkout_errors),
        str(block_checkout_errors),
    )
    check(
        "the candidate checkout in that block is itself reported",
        any(
            "on an executable line" in err and "LAUNCH_TARGET_SHA" in err
            for err in block_checkout_errors
        ),
        str(block_checkout_errors),
    )

    block_source = FIXTURE_TRUSTED.replace(
        credential_run,
        "run: |\n"
        '          . "./candidate/${LAUNCH_TARGET_SHA}.env"\n'
        "          python3 -I scripts/check_launch_readiness.py --verify "
        '--trusted-execution --trusted-tree-sha "$TRUSTED_SHA"',
    )
    check(
        "a credential-bearing block that sources candidate material is rejected",
        any(
            "must be a single-line invocation" in err or "on an executable line" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, block_source))
        ),
    )

    chained_command = FIXTURE_TRUSTED.replace(
        credential_run, credential_run + " && sh ./candidate/postscript.sh"
    )
    check(
        "a second command chained onto the credential invocation is rejected",
        any(
            "credential-bearing step runs" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, chained_command))
        ),
    )

    substituted_pin = FIXTURE_TRUSTED.replace(
        '--trusted-tree-sha "$TRUSTED_SHA"',
        '--trusted-tree-sha "$(git rev-parse HEAD)"',
    )
    check(
        "a command substitution in the trusted-tree pin is rejected",
        any(
            "credential-bearing step runs" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, substituted_pin))
        ),
    )

    second_surface = FIXTURE_TRUSTED.replace(
        "      - name: Evaluate\n        env:\n",
        "      - name: Evaluate\n"
        "        uses: actions/github-script@3d3c42e5aac5ba805825da76410c181273ba90b1\n"
        "        env:\n",
    )
    check(
        "an action added as a second execution surface on the credential step is "
        "rejected",
        any(
            "only name/id/if/env/run are admitted" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, second_surface))
        ),
    )

    job_level_credential = FIXTURE_TRUSTED.replace(
        "    environment: launch-advisory\n    steps:\n",
        "    environment: launch-advisory\n"
        "    env:\n"
        "      LAUNCH_ADVISORY_READ_TOKEN: ${{ secrets.LAUNCH_ADVISORY_READ_TOKEN }}\n"
        "    steps:\n",
    ).replace(
        "          LAUNCH_ADVISORY_READ_TOKEN: "
        "${{ secrets.LAUNCH_ADVISORY_READ_TOKEN }}\n",
        "",
    )
    check(
        "widening the credential from the step to the whole job is rejected",
        any(
            "exactly one step (found 0)" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, job_level_credential))
        ),
    )

    # ---- Closed step sequence for the credential-bearing job -----------------
    #
    # Step scoping bounds who can *read* the credential. It does not bound who
    # can change what the credential step *executes*: every fixture below is a
    # secretless step sharing that job's workspace, and each one was accepted by
    # a verifier that only closed the credential step's own command.

    before_evaluate = "          persist-credentials: false\n      - name: Evaluate"
    checkout_block = (
        "      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v6\n"
        "        with:\n"
        "          ref: ${{ needs.establish-trust.outputs.trusted_sha }}\n"
        "          fetch-depth: 1\n"
        "          persist-credentials: false\n"
    )

    candidate_in_secretless_step = FIXTURE_TRUSTED.replace(
        before_evaluate,
        "          persist-credentials: false\n"
        "      - name: Pin\n"
        "        env:\n"
        "          LAUNCH_TARGET_SHA: "
        "${{ needs.establish-trust.outputs.candidate_sha }}\n"
        "        run: |\n"
        '          git checkout --detach "$LAUNCH_TARGET_SHA"\n'
        "      - name: Evaluate",
    )
    check(
        "candidate execution in a secretless step of the credential job is rejected",
        any(
            "on an executable line" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, candidate_in_secretless_step))
        ),
    )

    # The accepted bypass this contract exists for: a secretless step that names
    # no candidate expression at all, derives the candidate indirectly from the
    # event payload, and replaces the checker the credential step then executes.
    indirect_replacement = FIXTURE_TRUSTED.replace(
        before_evaluate,
        "          persist-credentials: false\n"
        "      - name: Prepare the workspace\n"
        "        run: |\n"
        "          head=$(jq -r '.workflow_run.head_sha' \"$GITHUB_EVENT_PATH\")\n"
        '          git fetch --depth 1 origin "$head"\n'
        '          git show "$head:scripts/check_launch_readiness.py" '
        "> scripts/check_launch_readiness.py\n"
        "      - name: Evaluate",
    )
    indirect_errors = evaluate(mutated(TRUSTED_WORKFLOW, indirect_replacement))
    check(
        "a pre-credential step that rebuilds the checker from $GITHUB_EVENT_PATH is "
        "rejected",
        any("must consist of exactly 2 steps" in err for err in indirect_errors),
        str(indirect_errors),
    )
    check(
        "that bypass expands no candidate variable and names no candidate "
        "expression, so only the closed sequence catches it",
        not any(
            "on an executable line" in err or "exposes candidate input" in err
            for err in indirect_errors
        ),
        str(indirect_errors),
    )

    trailing_step = FIXTURE_TRUSTED.replace(
        credential_run,
        credential_run + "\n"
        "      - name: Post\n"
        "        run: sh ./candidate/postscript.sh",
    )
    trailing_errors = evaluate(mutated(TRUSTED_WORKFLOW, trailing_step))
    check(
        "a step appended after the credential step is rejected",
        any("must consist of exactly 2 steps" in err for err in trailing_errors),
        str(trailing_errors),
    )
    check(
        "the credential step must be the last step of its job",
        any("must be step 2 of 2" in err for err in trailing_errors),
        str(trailing_errors),
    )

    swapped_order = FIXTURE_TRUSTED.replace(checkout_block, "").replace(
        credential_run, credential_run + "\n" + checkout_block.rstrip("\n")
    )
    check(
        "running the credential step before the trusted-anchor checkout is rejected",
        any(
            "must be step 2 of 2" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, swapped_order))
        ),
    )

    # A block-scalar body line that begins with `- ` must not fragment the step
    # list; the extra step still has to be visible to the sequence contract.
    dash_body_step = FIXTURE_TRUSTED.replace(
        before_evaluate,
        "          persist-credentials: false\n"
        "      - name: Prepare\n"
        "        run: |\n"
        "          printf '%s\\n' \\\n"
        "            - one \\\n"
        "            - two > scripts/check_launch_readiness.py\n"
        "      - name: Evaluate",
    )
    check(
        "a block-scalar line starting with `- ` does not hide an extra step",
        any(
            "must consist of exactly 2 steps" in err and "declares 3" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, dash_body_step))
        ),
        str(evaluate(mutated(TRUSTED_WORKFLOW, dash_body_step))),
    )

    self_test_in_credential_job = FIXTURE_TRUSTED.replace(
        "      - name: Synthetic policy/checker self-tests\n"
        f"        run: {CHECKER_SELF_TEST_STEP}\n",
        "",
    ).replace(
        "      - name: Evaluate",
        "      - name: Synthetic policy/checker self-tests\n"
        f"        run: {CHECKER_SELF_TEST_STEP}\n"
        "      - name: Evaluate",
    )
    self_test_errors = evaluate(mutated(TRUSTED_WORKFLOW, self_test_in_credential_job))
    check(
        "hosting the secretless self-test inside the credential job is rejected",
        any("must consist of exactly 2 steps" in err for err in self_test_errors),
        str(self_test_errors),
    )
    check(
        "dropping the checker self-test from the secretless trust job is rejected",
        any(
            "the secretless launch-readiness checker self-test" in err
            for err in self_test_errors
        ),
        str(self_test_errors),
    )

    # ---- The trusted preflight that must run before the credential is released
    #
    # `establish-trust` is the only place this whole contract can be proved on the
    # trusted tree in the same run that then uses the credential: the protected
    # environment releases the credential only after that job succeeds.

    boundary_self_test_block = (
        "      - name: Trust-boundary contract self-test\n"
        f"        run: {SELF_TEST_STEP}\n"
    )

    dropped_boundary_self_test = FIXTURE_TRUSTED.replace(boundary_self_test_block, "")
    check(
        "dropping the trusted-job boundary self-test is rejected",
        any(
            "this trust-boundary verifier's own self-test" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, dropped_boundary_self_test))
        ),
        str(evaluate(mutated(TRUSTED_WORKFLOW, dropped_boundary_self_test))),
    )

    commented_boundary_self_test = FIXTURE_TRUSTED.replace(
        f"        run: {SELF_TEST_STEP}\n",
        f"        # run: {SELF_TEST_STEP}\n        run: true\n",
    )
    check(
        "a trusted-job boundary self-test surviving only as a comment is rejected",
        any(
            "this trust-boundary verifier's own self-test" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, commented_boundary_self_test))
        ),
    )

    # Relocating it into the credential job breaks it twice: the trust job no
    # longer runs it, and it becomes an executable step sharing the credential
    # step's workspace.
    relocated_boundary_self_test = FIXTURE_TRUSTED.replace(
        boundary_self_test_block, ""
    ).replace(
        "      - name: Evaluate",
        boundary_self_test_block + "      - name: Evaluate",
    )
    relocated_errors = evaluate(mutated(TRUSTED_WORKFLOW, relocated_boundary_self_test))
    check(
        "relocating the boundary self-test into the credential job is rejected",
        any("must consist of exactly 2 steps" in err for err in relocated_errors),
        str(relocated_errors),
    )
    check(
        "and the trust job is then reported as no longer running it",
        any(
            "this trust-boundary verifier's own self-test" in err
            for err in relocated_errors
        ),
        str(relocated_errors),
    )

    # ---- The credential step's environment is an exact closed mapping --------
    #
    # An anchored command is only as exact as the environment that resolves it.
    # Every fixture below leaves the command byte-identical and still changes
    # what actually executes, so a verifier that closes only the command accepts
    # all of them.

    credential_env_block = (
        "        env:\n"
        "          GITHUB_TOKEN: ${{ github.token }}\n"
        "          LAUNCH_TIER: ga\n"
        "          LAUNCH_TARGET_SHA: "
        "${{ needs.establish-trust.outputs.candidate_sha }}\n"
        "          TRUSTED_SHA: ${{ needs.establish-trust.outputs.trusted_sha }}\n"
        "          LAUNCH_PRIVATE_BLOCKER_COUNT: "
        "${{ vars.LAUNCH_PRIVATE_BLOCKER_COUNT }}\n"
        "          LAUNCH_PRIVATE_ADVISORY_AS_OF: "
        "${{ vars.LAUNCH_PRIVATE_ADVISORY_AS_OF }}\n"
        "          LAUNCH_ADVISORY_READ_TOKEN: "
        "${{ secrets.LAUNCH_ADVISORY_READ_TOKEN }}\n"
    )
    check(
        "the fixture's credential env block is the one the contract admits",
        credential_env_block in FIXTURE_TRUSTED,
    )
    tier_line = "          LAUNCH_TIER: ga\n"

    # Bash sources `$BASH_ENV` before it reaches the command line, so this runs
    # candidate-authored shell with the credential already bound.
    bash_env_redirect = FIXTURE_TRUSTED.replace(
        tier_line, "          BASH_ENV: ./candidate/preamble.sh\n" + tier_line
    )
    check(
        "a BASH_ENV preamble on the credential step is rejected",
        any(
            "declares environment" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, bash_env_redirect))
        ),
        str(evaluate(mutated(TRUSTED_WORKFLOW, bash_env_redirect))),
    )

    # `python3` in the anchored command is resolved through PATH.
    path_redirect = FIXTURE_TRUSTED.replace(
        tier_line, "          PATH: ./candidate/bin:/usr/bin:/bin\n" + tier_line
    )
    check(
        "a PATH redirect on the credential step is rejected",
        any(
            "declares environment" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, path_redirect))
        ),
    )

    # Not in any blacklist this module maintains; refused because it is not in
    # the allowlist, which is the whole point of an allowlist.
    unknown_loader_variable = FIXTURE_TRUSTED.replace(
        tier_line, "          NODE_OPTIONS: --require ./candidate/hook.js\n" + tier_line
    )
    check(
        "an unnamed future interpreter variable fails closed on the allowlist",
        any(
            "declares environment" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, unknown_loader_variable))
        ),
    )

    duplicate_env_key = FIXTURE_TRUSTED.replace(
        tier_line, tier_line + "          LAUNCH_TIER: ${{ vars.CANDIDATE_TIER }}\n"
    )
    check(
        "a duplicated credential env key is rejected",
        any(
            "duplicate env key" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, duplicate_env_key))
        ),
        str(evaluate(mutated(TRUSTED_WORKFLOW, duplicate_env_key))),
    )

    unparseable_env_entry = FIXTURE_TRUSTED.replace(
        tier_line, tier_line + "          - BASH_ENV=./candidate/preamble.sh\n"
    )
    check(
        "an env entry the contract cannot parse is reported, not ignored",
        any(
            "cannot parse" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, unparseable_env_entry))
        ),
        str(evaluate(mutated(TRUSTED_WORKFLOW, unparseable_env_entry))),
    )

    nested_env_mapping = FIXTURE_TRUSTED.replace(
        tier_line, "          LAUNCH_TIER:\n            from: ./candidate/tier\n"
    )
    check(
        "a nested credential env value is rejected",
        any(
            "block-scalar, nested, or empty value" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, nested_env_mapping))
        ),
        str(evaluate(mutated(TRUSTED_WORKFLOW, nested_env_mapping))),
    )

    block_scalar_env_value = FIXTURE_TRUSTED.replace(
        tier_line, "          LAUNCH_TIER: |\n            ga\n"
    )
    check(
        "a block-scalar credential env value is rejected",
        any(
            "block-scalar, nested, or empty value" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, block_scalar_env_value))
        ),
    )

    flow_env_mapping = FIXTURE_TRUSTED.replace(
        credential_env_block,
        "        env: { LAUNCH_ADVISORY_READ_TOKEN: "
        '"${{ secrets.LAUNCH_ADVISORY_READ_TOKEN }}", BASH_ENV: ./candidate/p.sh }\n',
    )
    check(
        "a flow-mapping credential env is rejected",
        any(
            "flow, alias, or inline" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, flow_env_mapping))
        ),
        str(evaluate(mutated(TRUSTED_WORKFLOW, flow_env_mapping))),
    )

    anchored_env_value = FIXTURE_TRUSTED.replace(
        tier_line, "          LAUNCH_TIER: &tier ga\n"
    )
    check(
        "a YAML anchor on a credential env value is rejected",
        any(
            "credential-bearing step env entry" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, anchored_env_value))
        ),
        str(evaluate(mutated(TRUSTED_WORKFLOW, anchored_env_value))),
    )

    merged_env_mapping = FIXTURE_TRUSTED.replace(
        tier_line, tier_line + "          <<: *hostile\n"
    )
    check(
        "a merge key inside the credential env mapping is rejected",
        any(
            "credential-bearing step env entry" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, merged_env_mapping))
        ),
        str(evaluate(mutated(TRUSTED_WORKFLOW, merged_env_mapping))),
    )

    merged_credential_job = FIXTURE_TRUSTED.replace(
        "    environment: launch-advisory\n",
        "    environment: launch-advisory\n    <<: *hostile\n",
    )
    check(
        "a merge key at the credential job level is rejected",
        any(
            "uses a YAML anchor, alias, or merge key" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, merged_credential_job))
        ),
        str(evaluate(mutated(TRUSTED_WORKFLOW, merged_credential_job))),
    )

    # ---- Inherited workflow-level execution surfaces -------------------------
    #
    # None of these appear in either validated step, and all of them are
    # inherited by the credential job.

    top_permissions = "permissions:\n  contents: read\n"

    workflow_level_env = FIXTURE_TRUSTED.replace(
        top_permissions,
        top_permissions + "env:\n  BASH_ENV: ./candidate/preamble.sh\n",
    )
    check(
        "a workflow-level env: is rejected",
        any(
            "declares top-level env" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, workflow_level_env))
        ),
        str(evaluate(mutated(TRUSTED_WORKFLOW, workflow_level_env))),
    )

    workflow_level_shell = FIXTURE_TRUSTED.replace(
        top_permissions,
        top_permissions
        + "defaults:\n  run:\n    shell: bash -x ./candidate/wrapper.sh {0}\n",
    )
    check(
        "a workflow-level defaults.run.shell is rejected",
        any(
            "declares top-level defaults" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, workflow_level_shell))
        ),
        str(evaluate(mutated(TRUSTED_WORKFLOW, workflow_level_shell))),
    )

    workflow_level_workdir = FIXTURE_TRUSTED.replace(
        top_permissions,
        top_permissions + "defaults:\n  run:\n    working-directory: ./candidate\n",
    )
    check(
        "a workflow-level defaults.run.working-directory is rejected",
        any(
            "declares top-level defaults" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, workflow_level_workdir))
        ),
    )

    top_level_anchor = FIXTURE_TRUSTED.replace(
        "jobs:\n", "x-shared: &hostile\n  shell: bash\njobs:\n"
    )
    check(
        "a top-level anchor block outside the admitted keys is rejected",
        any(
            "declares top-level x-shared" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, top_level_anchor))
        ),
        str(evaluate(mutated(TRUSTED_WORKFLOW, top_level_anchor))),
    )

    jobs_level_merge = FIXTURE_TRUSTED.replace(
        "jobs:\n  establish-trust:\n", "jobs:\n  <<: *hostile\n  establish-trust:\n"
    )
    check(
        "a merge key at the jobs mapping level is rejected",
        any(
            "at the `jobs:` mapping level" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, jobs_level_merge))
        ),
        str(evaluate(mutated(TRUSTED_WORKFLOW, jobs_level_merge))),
    )

    # ---- Duplicate and inline/flow mapping keys ------------------------------
    #
    # A duplicate mapping key is not an error GitHub reports: one occurrence
    # wins, and *which* one is a property of the consumer. So a workflow can keep
    # the safe block-form `on:` this contract reads and append a duplicate
    # `on: [push]` that a last-key-wins consumer applies — every event-derived
    # check still sees only `workflow_run`/`schedule` while the workflow is
    # actually tag-reachable. The same ambiguity reaches job IDs, the credential
    # job's own keys, step keys, and checkout inputs. An inline flow value is the
    # other half of the family: written where this contract reads a block, its
    # entries are not "an empty block" but a whole structure the block reader
    # never sees.
    #
    # Where the difference is load-bearing, each fixture also asserts that the
    # corresponding value-level check did NOT fire. That absence is the proof the
    # structural rejection is what catches the bypass, not an incidental
    # downstream error.

    on_block_form = (
        "on:\n"
        "  workflow_run:\n"
        "    workflows:\n"
        "      - Release\n"
        "    types:\n"
        "      - in_progress\n"
        "  schedule:\n"
        '    - cron: "45 6 * * *"\n'
    )
    check(
        "the fixture's `on:` block is the block form this contract reads",
        on_block_form in FIXTURE_TRUSTED,
    )

    # The root finding: safe block `on:` first, untrusted `on: [push]` appended.
    duplicate_on_appended = FIXTURE_TRUSTED.replace(
        on_block_form, on_block_form + "on: [push]\n"
    )
    duplicate_on_appended_errors = evaluate(
        mutated(TRUSTED_WORKFLOW, duplicate_on_appended)
    )
    check(
        "a duplicate `on: [push]` appended after the safe block form is rejected",
        any(
            "declares top-level key `on` more than once" in err
            for err in duplicate_on_appended_errors
        ),
        str(duplicate_on_appended_errors),
    )
    check(
        "and the appended flow value is itself reported, not discarded",
        any(
            "declares top-level `on:` with the inline value" in err
            for err in duplicate_on_appended_errors
        ),
        str(duplicate_on_appended_errors),
    )
    check(
        "the derived events still look trusted, so only the structural rejection "
        "catches that bypass",
        event_names(duplicate_on_appended) == {"workflow_run", "schedule"}
        and not any(
            "candidate-controlled events" in err
            for err in duplicate_on_appended_errors
        ),
        str(duplicate_on_appended_errors),
    )

    # The reversed ordering: the untrusted trigger introduces the key and the
    # safe block form follows it.
    duplicate_on_prepended = FIXTURE_TRUSTED.replace(
        on_block_form, "on: push\n" + on_block_form
    )
    duplicate_on_prepended_errors = evaluate(
        mutated(TRUSTED_WORKFLOW, duplicate_on_prepended)
    )
    check(
        "a duplicate `on:` in the reversed order is rejected",
        any(
            "declares top-level key `on` more than once" in err
            for err in duplicate_on_prepended_errors
        ),
        str(duplicate_on_prepended_errors),
    )
    check(
        "the reversed ordering also derives only trusted events",
        event_names(duplicate_on_prepended) == {"workflow_run", "schedule"}
        and not any(
            "candidate-controlled events" in err
            for err in duplicate_on_prepended_errors
        ),
        str(duplicate_on_prepended_errors),
    )

    # No duplicate at all: a single `on:` whose whole value is a flow sequence.
    # The block reader sees an empty body, so the trigger list would simply
    # disappear from the contract.
    flow_on_sequence = FIXTURE_TRUSTED.replace(
        on_block_form, "on: [push, workflow_run]\n"
    )
    check(
        "a single `on:` written as a flow sequence is rejected",
        any(
            "declares top-level `on:` with the inline value" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, flow_on_sequence))
        ),
        str(evaluate(mutated(TRUSTED_WORKFLOW, flow_on_sequence))),
    )

    scalar_on_value = FIXTURE_TRUSTED.replace(on_block_form, "on: push\n")
    check(
        "a single `on:` written as an inline scalar is rejected",
        any(
            "declares top-level `on:` with the inline value" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, scalar_on_value))
        ),
        str(evaluate(mutated(TRUSTED_WORKFLOW, scalar_on_value))),
    )

    duplicate_jobs_key = FIXTURE_TRUSTED.replace(
        "jobs:\n",
        "jobs:\n"
        "  hostile:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: sh ./candidate/postscript.sh\n"
        "jobs:\n",
        1,
    )
    check(
        "a duplicate top-level `jobs:` mapping is rejected",
        any(
            "declares top-level key `jobs` more than once" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, duplicate_jobs_key))
        ),
        str(evaluate(mutated(TRUSTED_WORKFLOW, duplicate_jobs_key))),
    )

    duplicate_event_key = FIXTURE_TRUSTED.replace(
        "  schedule:\n", "  workflow_run:\n    types:\n      - completed\n  schedule:\n"
    )
    check(
        "a duplicated event key under `on:` is rejected",
        any(
            "declares the `workflow_run` trigger more than once" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, duplicate_event_key))
        ),
        str(evaluate(mutated(TRUSTED_WORKFLOW, duplicate_event_key))),
    )

    duplicate_secret_job = FIXTURE_TRUSTED.replace(
        "  publish-verdict:\n",
        "  advisory-verdict:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: sh ./candidate/postscript.sh\n"
        "  publish-verdict:\n",
    )
    check(
        "a duplicate `advisory-verdict` job ID is rejected",
        any(
            "declares job `advisory-verdict` more than once" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, duplicate_secret_job))
        ),
        str(evaluate(mutated(TRUSTED_WORKFLOW, duplicate_secret_job))),
    )

    flow_job_mapping = FIXTURE_TRUSTED.replace(
        "  publish-verdict:\n    name: Publish trusted advisory verdict\n",
        "  publish-verdict: { runs-on: ubuntu-latest }\n"
        "    name: Publish trusted advisory verdict\n",
    )
    check(
        "a job written as an inline flow mapping is rejected",
        any(
            "declares job `publish-verdict` with the inline value" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, flow_job_mapping))
        ),
        str(evaluate(mutated(TRUSTED_WORKFLOW, flow_job_mapping))),
    )

    duplicate_needs = FIXTURE_TRUSTED.replace(
        "    needs: establish-trust\n",
        "    needs: establish-trust\n    needs: publish-verdict\n",
    )
    duplicate_needs_errors = evaluate(mutated(TRUSTED_WORKFLOW, duplicate_needs))
    check(
        "a duplicated `needs:` on the credential job is rejected",
        any(
            "declares duplicate job key(s) needs" in err
            for err in duplicate_needs_errors
        ),
        str(duplicate_needs_errors),
    )
    check(
        "the trust edge still reads as present, so only the duplicate check "
        "catches a second `needs:`",
        not any(
            "must require `establish-trust`" in err for err in duplicate_needs_errors
        ),
        str(duplicate_needs_errors),
    )

    duplicate_environment = FIXTURE_TRUSTED.replace(
        "    environment: launch-advisory\n",
        "    environment: launch-advisory\n    environment: candidate-controlled\n",
    )
    duplicate_environment_errors = evaluate(
        mutated(TRUSTED_WORKFLOW, duplicate_environment)
    )
    check(
        "a duplicated `environment:` on the credential job is rejected",
        any(
            "declares duplicate job key(s) environment" in err
            for err in duplicate_environment_errors
        ),
        str(duplicate_environment_errors),
    )
    check(
        "the protected environment binding still reads as present, so only the "
        "duplicate check catches a second `environment:`",
        not any(
            "protected `launch-advisory` environment" in err
            for err in duplicate_environment_errors
        ),
        str(duplicate_environment_errors),
    )

    # The second `steps:` is at the job's own indentation, so the block reader
    # stops at the first one and the closed two-step contract is fully satisfied
    # by a job that may actually run a third step.
    duplicate_steps = FIXTURE_TRUSTED.replace(
        credential_run + "\n\n  publish-verdict:",
        credential_run + "\n"
        "    steps:\n"
        "      - run: sh ./candidate/postscript.sh\n"
        "\n  publish-verdict:",
    )
    duplicate_steps_errors = evaluate(mutated(TRUSTED_WORKFLOW, duplicate_steps))
    check(
        "a duplicated `steps:` on the credential job is rejected",
        any(
            "declares duplicate job key(s) steps" in err
            for err in duplicate_steps_errors
        ),
        str(duplicate_steps_errors),
    )
    check(
        "the closed two-step sequence still reads as satisfied, so only the "
        "duplicate check catches a second `steps:`",
        not any(
            "must consist of exactly 2 steps" in err for err in duplicate_steps_errors
        ),
        str(duplicate_steps_errors),
    )

    flow_steps_sequence = FIXTURE_TRUSTED.replace(
        "    environment: launch-advisory\n    steps:\n",
        "    environment: launch-advisory\n"
        "    steps: [{ run: sh ./candidate/postscript.sh }]\n",
    )
    check(
        "a `steps:` written as an inline flow sequence is rejected",
        any(
            "declares `steps:` with the inline value" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, flow_steps_sequence))
        ),
        str(evaluate(mutated(TRUSTED_WORKFLOW, flow_steps_sequence))),
    )

    # A YAML node tag can sit in front of a collection. Treating the leading
    # `!` as ordinary scalar text would hide the same flow sequence from every
    # block reader even though the YAML consumer can still see its steps.
    tagged_flow_steps = FIXTURE_TRUSTED.replace(
        "    environment: launch-advisory\n    steps:\n",
        "    environment: launch-advisory\n"
        "    steps: !!seq [{ run: sh ./candidate/postscript.sh }]\n",
    )
    tagged_flow_steps_errors = evaluate(
        mutated(TRUSTED_WORKFLOW, tagged_flow_steps)
    )
    check(
        "a YAML tag cannot hide an inline `steps:` flow sequence",
        any(
            "declares `jobs.advisory-verdict.steps` with the tagged" in err
            for err in tagged_flow_steps_errors
        ),
        str(tagged_flow_steps_errors),
    )

    duplicate_step_key = FIXTURE_TRUSTED.replace(
        "      - name: Evaluate\n        env:\n",
        "      - name: Evaluate\n        name: Evaluate again\n        env:\n",
    )
    duplicate_step_key_errors_seen = evaluate(
        mutated(TRUSTED_WORKFLOW, duplicate_step_key)
    )
    check(
        "a duplicated top-level step key on the credential step is rejected",
        any(
            "declares duplicate step key(s) name" in err
            for err in duplicate_step_key_errors_seen
        ),
        str(duplicate_step_key_errors_seen),
    )
    check(
        "the step's admitted-key set still reads as satisfied, so only the "
        "duplicate check catches it",
        not any(
            "only name/id/if/env/run are admitted" in err
            for err in duplicate_step_key_errors_seen
        ),
        str(duplicate_step_key_errors_seen),
    )

    duplicate_checkout_input = FIXTURE_TRUSTED.replace(
        before_evaluate,
        "          persist-credentials: false\n"
        "          persist-credentials: true\n"
        "      - name: Evaluate",
    )
    check(
        "a duplicated trusted-anchor checkout input is rejected",
        any(
            "duplicate `with:` input(s) persist-credentials" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, duplicate_checkout_input))
        ),
        str(evaluate(mutated(TRUSTED_WORKFLOW, duplicate_checkout_input))),
    )

    # The proof that an inline flow mapping cannot simply disappear: written this
    # way the redirected `ref:` matches no line-oriented check in this module at
    # all, so without the structural refusal the candidate ref would be invisible.
    flow_checkout_with = FIXTURE_TRUSTED.replace(
        "        with:\n"
        "          ref: ${{ needs.establish-trust.outputs.trusted_sha }}\n"
        "          fetch-depth: 1\n"
        "          persist-credentials: false\n",
        "        with: { ref: refs/tags/v9.9.9, fetch-depth: 1, "
        "persist-credentials: false }\n",
    )
    flow_checkout_errors = evaluate(mutated(TRUSTED_WORKFLOW, flow_checkout_with))
    check(
        "an inline flow `with:` on the trusted-anchor checkout is rejected",
        any(
            "inline or flow `with:` value" in err for err in flow_checkout_errors
        ),
        str(flow_checkout_errors),
    )
    check(
        "the redirected ref inside that flow mapping reaches no value-level check, "
        "so only the structural refusal catches it",
        not any(
            "it must check out exactly" in err or "it must declare exactly" in err
            for err in flow_checkout_errors
        ),
        str(flow_checkout_errors),
    )

    # ---- The same ambiguity outside the credential job ------------------------
    #
    # Scoping the duplicate/flow refusal to `advisory-verdict` left the rest of
    # the document ambiguous, and the rest of the document is what *derives* the
    # trusted anchor and *publishes* the verdict. Every fixture below leaves the
    # credential job byte-identical; each one is caught only by the whole-document
    # structural pass, and each also asserts that the value-level proof it
    # subverts still reads as satisfied.

    # First: the pass must not mistake shell for structure. A `run: |` body is
    # opaque text, so YAML-shaped lines inside it are neither duplicate keys nor
    # a way to close the enclosing mapping early.
    yaml_shaped_shell = FIXTURE_TRUSTED.replace(
        '          trusted_sha="$(git rev-parse HEAD)"\n',
        '          trusted_sha="$(git rev-parse HEAD)"\n'
        "          steps: not a key\n"
        "          steps: still not a key\n"
        "          with: { ref: shell text }\n",
    )
    yaml_shaped_shell_errors = evaluate(mutated(TRUSTED_WORKFLOW, yaml_shaped_shell))
    check(
        "YAML-shaped shell inside a block scalar is not read as structure",
        not yaml_shaped_shell_errors,
        str(yaml_shaped_shell_errors),
    )

    trust_job_tail = (
        '          echo "status_context=${status_context}" >> "$GITHUB_OUTPUT"\n'
        "\n  advisory-verdict:"
    )
    check(
        "the fixture's trust job ends where these fixtures append",
        trust_job_tail in FIXTURE_TRUSTED,
    )

    # A safe first `steps:` block that satisfies both secretless preflights and
    # the anchor proofs, followed by a duplicate last `steps:` that exports a
    # candidate-controlled `trusted_sha` — which the credential job then checks
    # out and executes.
    duplicate_trust_steps = FIXTURE_TRUSTED.replace(
        trust_job_tail,
        '          echo "status_context=${status_context}" >> "$GITHUB_OUTPUT"\n'
        "    steps:\n"
        "      - id: candidate\n"
        '        run: echo "trusted_sha=$(cat ./candidate/sha)" >> "$GITHUB_OUTPUT"\n'
        "\n  advisory-verdict:",
    )
    duplicate_trust_steps_errors = evaluate(
        mutated(TRUSTED_WORKFLOW, duplicate_trust_steps)
    )
    check(
        "a duplicated `steps:` on the trust job is rejected",
        any(
            "mapping key `steps` more than once in `jobs.establish-trust`" in err
            for err in duplicate_trust_steps_errors
        ),
        str(duplicate_trust_steps_errors),
    )
    check(
        "both secretless preflights still read as real steps, so only the "
        "structural pass catches a second `steps:`",
        not any(
            "self-test" in err and "as a real" in err
            for err in duplicate_trust_steps_errors
        ),
        str(duplicate_trust_steps_errors),
    )
    check(
        "and the trusted-anchor proofs still read as satisfied",
        not any(
            "literal protected-branch checkout" in err
            or "40-hex commit" in err
            or "reachable from protected `main`" in err
            or "must export `trusted_sha`" in err
            for err in duplicate_trust_steps_errors
        ),
        str(duplicate_trust_steps_errors),
    )

    trust_outputs_block = (
        "    outputs:\n"
        "      candidate_sha: ${{ steps.candidate.outputs.candidate_sha }}\n"
        "      trusted_sha: ${{ steps.candidate.outputs.trusted_sha }}\n"
        "      status_context: ${{ steps.candidate.outputs.status_context }}\n"
    )
    check(
        "the fixture's trust outputs block is the one the contract reads",
        trust_outputs_block in FIXTURE_TRUSTED,
    )
    # A second `outputs:` redirecting the trusted anchor at the candidate. The
    # line-oriented export binding still matches the safe first occurrence.
    redirected_outputs_block = (
        "    outputs:\n"
        "      trusted_sha: ${{ steps.candidate.outputs.candidate_sha }}\n"
    )
    for ordering, mutation in (
        ("appended", trust_outputs_block + redirected_outputs_block),
        ("prepended", redirected_outputs_block + trust_outputs_block),
    ):
        duplicate_outputs_errors = evaluate(
            mutated(
                TRUSTED_WORKFLOW,
                FIXTURE_TRUSTED.replace(trust_outputs_block, mutation),
            )
        )
        check(
            f"a duplicated `outputs:` on the trust job is rejected ({ordering})",
            any(
                "mapping key `outputs` more than once in `jobs.establish-trust`" in err
                for err in duplicate_outputs_errors
            ),
            str(duplicate_outputs_errors),
        )
        check(
            f"the `trusted_sha` export still reads as bound ({ordering}), so only "
            "the structural pass catches the redirect",
            not any(
                "must export `trusted_sha`" in err for err in duplicate_outputs_errors
            ),
            str(duplicate_outputs_errors),
        )

    # A trust step carrying the exact admitted command AND a duplicate `run:`.
    # `job_runs_exact_command` finds the admitted occurrence and is satisfied.
    duplicate_trust_run = FIXTURE_TRUSTED.replace(
        boundary_self_test_block,
        boundary_self_test_block + "        run: sh ./candidate/preflight.sh\n",
    )
    duplicate_trust_run_errors = evaluate(mutated(TRUSTED_WORKFLOW, duplicate_trust_run))
    check(
        "a duplicated `run:` on a trust-job step is rejected",
        any(
            "mapping key `run` more than once" in err
            and "jobs.establish-trust.steps" in err
            for err in duplicate_trust_run_errors
        ),
        str(duplicate_trust_run_errors),
    )
    check(
        "the boundary self-test still reads as a real executable step, so only "
        "the structural pass catches the second `run:`",
        not any(
            "this trust-boundary verifier's own self-test" in err
            for err in duplicate_trust_run_errors
        ),
        str(duplicate_trust_run_errors),
    )

    # The publisher is the only writer of the verdict status. A duplicate flow
    # `steps:` replaces what it publishes while every publisher binding this
    # contract reads still matches the block form above it.
    duplicate_publisher_steps = (
        FIXTURE_TRUSTED.rstrip("\n")
        + "\n    steps: [{ run: sh ./candidate/publish.sh }]\n"
    )
    duplicate_publisher_steps_errors = evaluate(
        mutated(TRUSTED_WORKFLOW, duplicate_publisher_steps)
    )
    check(
        "a duplicated `steps:` on the publisher is rejected",
        any(
            "mapping key `steps` more than once in `jobs.publish-verdict`" in err
            for err in duplicate_publisher_steps_errors
        ),
        str(duplicate_publisher_steps_errors),
    )
    check(
        "and its flow value is itself reported, not discarded",
        any(
            "declares `jobs.publish-verdict.steps` with the flow value" in err
            for err in duplicate_publisher_steps_errors
        ),
        str(duplicate_publisher_steps_errors),
    )
    check(
        "every publisher binding still reads as satisfied, so only the structural "
        "pass catches a second `steps:`",
        not any(
            "must consume the established `status_context` output" in err
            or "must publish against the established candidate SHA" in err
            or "publishes a constant commit-wide status context" in err
            or "must publish the `trusted-launch-advisory-gate` commit status" in err
            for err in duplicate_publisher_steps_errors
        ),
        str(duplicate_publisher_steps_errors),
    )

    publisher_env_block = (
        "        env:\n"
        "          CANDIDATE_SHA: ${{ needs.establish-trust.outputs.candidate_sha }}\n"
        "          STATUS_CONTEXT: ${{ needs.establish-trust.outputs.status_context }}\n"
    )
    check(
        "the fixture's publisher env block is the one the contract reads",
        publisher_env_block in FIXTURE_TRUSTED,
    )
    duplicate_publisher_env = FIXTURE_TRUSTED.replace(
        publisher_env_block,
        publisher_env_block
        + "        env: { PATH: ./candidate/bin, BASH_ENV: ./candidate/p.sh }\n",
    )
    duplicate_publisher_env_errors = evaluate(
        mutated(TRUSTED_WORKFLOW, duplicate_publisher_env)
    )
    check(
        "a duplicated flow `env:` on the publisher step is rejected",
        any(
            "mapping key `env` more than once" in err
            and "jobs.publish-verdict.steps" in err
            for err in duplicate_publisher_env_errors
        ),
        str(duplicate_publisher_env_errors),
    )
    check(
        "and that flow env mapping is itself reported",
        any(
            "with the flow value" in err and ".env" in err
            for err in duplicate_publisher_env_errors
        ),
        str(duplicate_publisher_env_errors),
    )
    check(
        "the publisher's established bindings still read as satisfied under the "
        "duplicate env",
        not any(
            "must consume the established `status_context` output" in err
            or "must publish against the established candidate SHA" in err
            for err in duplicate_publisher_env_errors
        ),
        str(duplicate_publisher_env_errors),
    )

    # Ambiguity anywhere else in the document, including a mapping no
    # value-level check reads at all.
    duplicate_permission_key = FIXTURE_TRUSTED.replace(
        "permissions:\n  contents: read\n",
        "permissions:\n  contents: read\n  contents: write\n",
    )
    check(
        "a duplicated key in the top-level permissions mapping is rejected",
        any(
            "mapping key `contents` more than once in `permissions`" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, duplicate_permission_key))
        ),
        str(evaluate(mutated(TRUSTED_WORKFLOW, duplicate_permission_key))),
    )

    unreadable_node = FIXTURE_TRUSTED.replace(
        "jobs:\n", "jobs:\n  &hostile\n", 1
    )
    check(
        "a document node this contract cannot classify is refused, not dropped",
        any(
            "cannot classify" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, unreadable_node))
        ),
        str(evaluate(mutated(TRUSTED_WORKFLOW, unreadable_node))),
    )

    # ---- The trusted-anchor checkout itself ----------------------------------

    redirected_checkout = FIXTURE_TRUSTED.replace(
        checkout_block,
        checkout_block.replace(
            TRUSTED_SHA_REF_EXPRESSION,
            "${{ needs.establish-trust.outputs.candidate_sha }}",
        ),
    )
    check(
        "redirecting the credential job's checkout at the candidate is rejected",
        any(
            "it must check out exactly" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, redirected_checkout))
        ),
    )

    dropped_input = FIXTURE_TRUSTED.replace(
        checkout_block, checkout_block.replace("          persist-credentials: false\n", "")
    )
    check(
        "dropping a trusted-anchor checkout input is rejected",
        any(
            "it must declare exactly" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, dropped_input))
        ),
    )

    extra_input = FIXTURE_TRUSTED.replace(
        checkout_block, checkout_block + "          path: candidate\n"
    )
    check(
        "an extra trusted-anchor checkout input is rejected",
        any(
            "it must declare exactly" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, extra_input))
        ),
    )

    swapped_action = FIXTURE_TRUSTED.replace(
        checkout_block,
        checkout_block.replace(
            CHECKOUT_ACTION_PIN,
            "actions/github-script@3d3c42e5aac5ba805825da76410c181273ba90b1",
        ),
    )
    check(
        "swapping the credential job's checkout for another action is rejected",
        any(
            "must begin with exactly one `uses:" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, swapped_action))
        ),
    )

    executable_checkout = FIXTURE_TRUSTED.replace(
        checkout_block, checkout_block + "        run: sh ./candidate/pre.sh\n"
    )
    check(
        "a trusted-anchor checkout step that also runs a command is rejected",
        any(
            "only name/uses/with are admitted" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, executable_checkout))
        ),
    )

    skippable_checkout = FIXTURE_TRUSTED.replace(
        checkout_block, checkout_block + "        if: ${{ false }}\n"
    )
    check(
        "a conditionally skippable trusted-anchor checkout is rejected",
        any(
            "only name/uses/with are admitted" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, skippable_checkout))
        ),
    )

    job_defaults = FIXTURE_TRUSTED.replace(
        "    environment: launch-advisory\n    steps:\n",
        "    environment: launch-advisory\n"
        "    defaults:\n"
        "      run:\n"
        "        working-directory: ./candidate\n"
        "    steps:\n",
    )
    check(
        "a job-level working-directory rewrite on the credential job is rejected",
        any(
            "declares defaults" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, job_defaults))
        ),
    )

    unproven_anchor = FIXTURE_TRUSTED.replace(
        '          git merge-base --is-ancestor "$trusted_sha" "$main_tip" || exit 1\n',
        "",
    )
    check(
        "an exported trusted anchor with no protected-main ancestry proof is rejected",
        any(
            "reachable from protected `main`" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, unproven_anchor))
        ),
    )

    unvalidated_anchor = FIXTURE_TRUSTED.replace(
        '          trusted_sha="$(git rev-parse HEAD)"\n', "          trusted_sha=x\n"
    )
    check(
        "a trusted anchor not taken from the protected-branch checkout is rejected",
        any(
            "literal protected-branch checkout" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, unvalidated_anchor))
        ),
    )

    commented_credential = FIXTURE_TRUSTED.replace(
        "          LAUNCH_ADVISORY_READ_TOKEN: "
        "${{ secrets.LAUNCH_ADVISORY_READ_TOKEN }}\n",
        "          # LAUNCH_ADVISORY_READ_TOKEN: "
        "${{ secrets.LAUNCH_ADVISORY_READ_TOKEN }}\n",
    )
    check(
        "a commented-out credential binding does not satisfy the contract",
        any(
            "exactly once (found 0)" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, commented_credential))
        ),
    )

    commented_self_test = FIXTURE_STANDALONE.replace(
        f"        run: {SELF_TEST_STEP}",
        f"        # run: {SELF_TEST_STEP}\n        run: true",
    )
    check(
        "a self-test that survives only as a comment is rejected",
        any(
            "must run the advisory trust-boundary" in err
            for err in evaluate(mutated(STANDALONE_WORKFLOW, commented_self_test))
        ),
    )

    # The candidate tree checked out into a secretless job of the trusted
    # workflow, whose refs must stay the literal protected branch.
    hostile_trust_checkout = FIXTURE_TRUSTED.replace(
        "          ref: refs/heads/main\n", "          ref: refs/tags/v9.9.9\n"
    )
    check(
        "checking out a tag in the secretless trust job is rejected",
        any(
            "must be the literal trusted ref" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, hostile_trust_checkout))
        ),
    )

    # The trusted workflow made reachable from a tag.
    tag_reachable = FIXTURE_TRUSTED.replace(
        "on:\n  workflow_run:",
        "on:\n  push:\n    tags:\n      - 'v*'\n  workflow_run:",
    )
    check(
        "making the trusted workflow tag-reachable is rejected",
        any(
            "candidate-controlled events" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, tag_reachable))
        ),
    )

    dispatch_reachable = FIXTURE_TRUSTED.replace(
        "  schedule:\n    - cron: \"45 6 * * *\"",
        "  schedule:\n    - cron: \"45 6 * * *\"\n  workflow_dispatch:",
    )
    check(
        "making the trusted workflow manually dispatchable is rejected",
        any(
            "candidate-controlled events" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, dispatch_reachable))
        ),
    )

    unbound = FIXTURE_TRUSTED.replace("    environment: launch-advisory\n", "")
    check(
        "an unbound credential environment is rejected",
        any(
            "protected `launch-advisory` environment" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, unbound))
        ),
    )

    no_trust_edge = FIXTURE_TRUSTED.replace(
        "    needs: establish-trust\n    runs-on: ubuntu-latest\n"
        "    environment: launch-advisory\n",
        "    runs-on: ubuntu-latest\n    environment: launch-advisory\n",
    )
    check(
        "dropping the provenance edge is rejected",
        any(
            "must require `establish-trust`" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, no_trust_edge))
        ),
    )

    # Assembled rather than written out so this file never carries a literal
    # mutable action pin for a policy scanner to trip over.
    mutable_ref = "actions/checkout@" + "v6"
    unpinned = FIXTURE_TRUSTED.replace(
        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1", mutable_ref
    )
    check(
        "an unpinned action in the trusted workflow is rejected",
        any(
            "unpinned or local action" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, unpinned))
        ),
    )

    unflagged_checker = FIXTURE_TRUSTED.replace(
        ' --trusted-execution --trusted-tree-sha "$TRUSTED_SHA"', ""
    )
    check(
        "dropping the trusted-execution pins is rejected",
        any(
            "--trusted-execution" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, unflagged_checker))
        ),
    )

    dropped_gate = FIXTURE_RELEASE.replace("trusted-launch-advisory-gate", "anything")
    check(
        "a release gate that stops requiring the trusted verdict is rejected",
        any(
            "must require the `trusted-launch-advisory-gate` verdict" in err
            for err in evaluate(mutated(RELEASE_WORKFLOW, dropped_gate))
        ),
    )

    reevaluating_release = FIXTURE_RELEASE.replace(
        "          gh api statuses | jq --arg ctx \"$expected_context\" "
        "'select(.context == $ctx)'",
        "          python3 -I scripts/check_launch_readiness.py --verify",
    )
    check(
        "a release gate that re-evaluates the verdict from the tag is rejected",
        any(
            "must not evaluate the live launch verdict itself" in err
            for err in evaluate(mutated(RELEASE_WORKFLOW, reevaluating_release))
        ),
    )

    # ---- Run/attempt binding: stale and replayed verdict acceptance ----

    requested_only = FIXTURE_TRUSTED.replace("      - in_progress", "      - requested")
    check(
        "a `requested`-only workflow_run trigger is rejected",
        any(
            "does not fire for a re-run" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, requested_only))
        ),
    )

    constant_context = FIXTURE_TRUSTED.replace(
        '-f "context=${STATUS_CONTEXT}"',
        '-f "context=trusted-launch-advisory-gate"',
    )
    check(
        "publishing a constant commit-wide status context is rejected",
        any(
            "publishes a constant commit-wide status context" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, constant_context))
        ),
    )

    no_attempt_binding = FIXTURE_TRUSTED.replace(
        "          WORKFLOW_RUN_ATTEMPT: ${{ github.event.workflow_run.run_attempt }}\n",
        "",
    )
    check(
        "dropping the triggering run-attempt binding is rejected",
        any(
            "the triggering Release run attempt" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, no_attempt_binding))
        ),
    )

    attemptless_context = FIXTURE_TRUSTED.replace(
        "trusted-launch-advisory-gate/release-${release_run_id}"
        "-attempt-${release_run_attempt}",
        "trusted-launch-advisory-gate/release-${release_run_id}",
    )
    check(
        "a published context that omits the run attempt is rejected",
        any(
            "attempt-less context is replayable" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, attemptless_context))
        ),
    )

    audit_context_dropped = FIXTURE_TRUSTED.replace(
        'status_context="trusted-launch-advisory-gate/main-audit"',
        'status_context="trusted-launch-advisory-gate"',
    )
    check(
        "a default-branch audit sharing the release context namespace is rejected",
        any(
            "distinct `trusted-launch-advisory-gate/main-audit` context" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, audit_context_dropped))
        ),
    )

    # Cross-run reuse: the gate stops naming its own run and accepts whatever
    # success is already on the commit.
    reused_status = FIXTURE_RELEASE.replace(
        "trusted-launch-advisory-gate/release-${RELEASE_RUN_ID}"
        "-attempt-${RELEASE_RUN_ATTEMPT}",
        "trusted-launch-advisory-gate",
    )
    check(
        "a release gate accepting any run's advisory status is rejected",
        any(
            "must not accept a commit-wide advisory status context" in err
            for err in evaluate(mutated(RELEASE_WORKFLOW, reused_status))
        ),
    )

    gate_without_attempt = FIXTURE_RELEASE.replace(
        "          RELEASE_RUN_ATTEMPT: ${{ github.run_attempt }}\n", ""
    )
    check(
        "a release gate that does not bind its own run attempt is rejected",
        any(
            "must bind `github.run_attempt`" in err
            for err in evaluate(mutated(RELEASE_WORKFLOW, gate_without_attempt))
        ),
    )

    check(
        "the default-branch audit context cannot satisfy a release gate",
        not RELEASE_CONTEXT_SHAPE.match(AUDIT_STATUS_CONTEXT)
        and COMMIT_WIDE_CONTEXT.search(AUDIT_STATUS_CONTEXT) is not None,
    )
    check(
        "a run-bound release context is of the admitted shape",
        RELEASE_CONTEXT_SHAPE.match(f"{STATUS_CONTEXT_PREFIX}/release-42-attempt-2")
        is not None
        and COMMIT_WIDE_CONTEXT.search(f"{STATUS_CONTEXT_PREFIX}/release-42-attempt-2")
        is None,
    )

    dropped_self_test = FIXTURE_STANDALONE.replace(SELF_TEST_STEP, "true")
    check(
        "removing the pull-request self-test is rejected",
        any(
            "must run the advisory trust-boundary" in err
            for err in evaluate(mutated(STANDALONE_WORKFLOW, dropped_self_test))
        ),
    )

    check(
        "a prose mention of the credential does not satisfy the contract",
        code_lines(["# secrets.LAUNCH_ADVISORY_READ_TOKEN", "  a: b"]) == ["  a: b"],
    )

    # The same contract, applied to the real tree.
    if DEFAULT_WORKFLOWS_DIR.is_dir():
        live_errors = evaluate(load_workflows(DEFAULT_WORKFLOWS_DIR))
        check("repository workflows satisfy the contract", not live_errors, str(live_errors))
    else:
        check("repository workflow directory exists", False, str(DEFAULT_WORKFLOWS_DIR))

    if failures:
        print("SELF-TEST FAILURES:", file=sys.stderr)
        for item in failures:
            print(f"- {item}", file=sys.stderr)
        return 1
    print("launch-advisory trust-boundary self-test: PASS")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify the private-advisory credential trust boundary"
    )
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument(
        "--workflows-dir",
        default=str(DEFAULT_WORKFLOWS_DIR),
        help="workflow directory to evaluate (default: the repository's)",
    )
    args = parser.parse_args(argv)

    if args.self_test:
        return run_self_test()

    directory = Path(args.workflows_dir)
    if not directory.is_dir():
        print(f"error: no workflow directory at {directory}", file=sys.stderr)
        return 1
    errors = evaluate(load_workflows(directory))
    for err in errors:
        print(f"error: {err}", file=sys.stderr)
    if errors:
        return 1
    print("launch-advisory trust boundary: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
