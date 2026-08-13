# Launch readiness gate

Fail-closed release governance for Ferrum Edge. The live launch verdict is
computed by `scripts/check_launch_readiness.py` from GitHub issue and advisory
state plus the checked-in policy; it is **not** the historical static-audit prose
in `PRODUCTION_READINESS.md`.

Two checks with different jobs (issue #3803):

| Check | Question | Required on PRs? | Red when blockers are open? |
|---|---|---|---|
| `Launch Readiness Integrity` | Did this revision preserve the gate contract? | **Yes** | No |
| `Launch Readiness Gate` | Is the product launchable right now? | No — release/tag blocking | Yes, truthfully |

Keeping them separate is what makes enforcement possible: a truthful go/no-go
verdict is `FAIL` while any blocker is open, so requiring *it* on every pull
request would deadlock the very pull requests that fix blockers. The integrity
check never reads live issue or advisory state, so it stays green for a normal
blocker-fix change and red only when the governance contract itself is weakened.

## Authoritative inputs

| Input | Role |
|-------|------|
| [`docs/launch-blocker-policy.json`](launch-blocker-policy.json) | Machine-readable blocker contract: labels, tiers, state machine, tracked inventory, private-advisory redaction rules and freshness ceiling |
| [`docs/launch-exemptions.json`](launch-exemptions.json) | Structured, expiring exemptions (owner, approver, rationale, compensating control, expiry) |
| Live repository labels API | Existence proof for every configured blocker/exemption/severity label, checked before any issue listing is trusted |
| Live GitHub issues API (paginated) | Open/closed state, `state_reason`, labels, linked in-flight PRs |
| Live repository security-advisories API (paginated) | Private/draft blockers as a **redacted count only**, when a dedicated advisory token is available |
| Repository Actions variables `LAUNCH_PRIVATE_BLOCKER_COUNT` / `LAUNCH_PRIVATE_ADVISORY_AS_OF` | Externally maintained redacted count and audit timestamp used when no advisory token is available |

Issue bodies, PR bodies, and advisory text are untrusted data: never executed,
never echoed. Only public issue numbers and severity/state categories are
printed. Advisory identifiers, summaries, descriptions, links, and any other
confidential field are never read into the record, and the summary printer
refuses to emit output containing them.

The checked-in tree can never assert that private advisories are clear. The
policy file defines only the freshness ceiling; a count or an as-of value inside
it is rejected by schema validation precisely because a pull request could edit
it.

## The label vocabulary

The policy names five repository labels — `launch-blocker`, `launch-exempted`,
and `severity:{critical,high,medium}` — and they are the authoritative
classifier. Free-form issue titles and bodies are **never** parsed as
classification input.

The Issues API answers `labels=launch-blocker` with an empty list in two very
different situations: the label exists and no issue carries it, and the label
does not exist at all. It can also transiently return an empty set when a label
is renamed away and back during the request. Treating those cases as clean is
fail-open. The checker therefore calls
`GET /repos/{owner}/{repo}/labels/{name}` before and after discovery, requires an
exact case-sensitive name plus a stable unique id, and walks the unfiltered
all-state issue inventory. Blockers are selected by the verified immutable id;
every in-page id/name pair must still agree. GitHub resolves label lookups
case-insensitively, so a case-only rename is caught rather than accepted, while
the identity fences catch deletion/recreation and rename-roundtrip races.

- Missing definition ⇒ `UNKNOWN` (`label_inventory:configured label … is not
  defined in repository metadata`).
- Renamed definition ⇒ `UNKNOWN` (`label_inventory:… resolves to a differently
  named repository label`).
- Malformed label payload ⇒ `UNKNOWN` (`schema:…`).
- Denial, rate limit, or transport failure ⇒ `UNKNOWN` under its own
  `denied` / `rate_limit` / `api` code, never reported as an absent label.
- Label proven present and the inventory is empty ⇒ that empty set is real and
  may contribute to `PASS`.

Only the checked-in configured label names are echoed into the reason; nothing
from the API response body reaches the record.

Two policy roles may not share one repository label: `validate_policy` rejects a
policy whose blocker, exemption, and severity names are not pairwise distinct,
because a shared name would satisfy the existence proof while leaving the
vocabulary ambiguous.

Provisioning and backfilling these labels is repository-settings work performed
outside this tree by a maintainer. The production vocabulary was provisioned and
the open severity-classified launch inventory was backfilled on 2026-08-11.
Deleting or renaming any definition returns the gate to `UNKNOWN`, which is the
correct fail-closed answer — not a `PASS`.

## Classification

1. **Label discovery:** after the vocabulary is proven to exist, the whole
   all-state issue inventory is walked with pagination. The immutable
   blocker-label id selects the authoritative set. Pull-request nodes are
   excluded. Each remaining issue must carry exactly one configured
   `severity:{critical,high,medium}` label; zero, several, or an unconfigured
   severity-shaped label is `UNKNOWN`, never a silent omission. A newly filed
   blocker with one valid severity is discovered without editing the policy.
   Closed issues are included because `duplicate`, `not_planned`, and a missing
   close reason remain blocking until the issue is completed or explicitly
   exempted; an `open`-only walk would silently drop them.
   Because this walk is unfiltered, its size tracks the whole repository history
   rather than the blocker set, so it reads against its own page and body
   ceilings (`MAX_INVENTORY_PAGES`, `MAX_INVENTORY_RESPONSE_BYTES`) instead of
   the shared defaults, which ordinary repository growth would otherwise turn
   into a permanent `pagination` or size-cap `UNKNOWN`. Both ceilings still fail
   closed: an exhausted bound is `UNKNOWN`, never a truncated inventory.
2. **Tracked inventory:** `tracked_blockers` in the policy is an explicit,
   CODEOWNERS-reviewed list, kept as defense in depth against a labeling
   mistake. It is never the only functioning inventory: the labeled walk above
   always runs, and an unavailable label vocabulary is `UNKNOWN` rather than
   being masked by the tracked list. The tracked severity is the contract: a
   live severity label that disagrees with it is a schema mismatch (`UNKNOWN`),
   never a downgrade or a silent replacement. Every open tracked blocker must
   carry the blocker label and exactly one matching severity label; the tracked
   severity never substitutes for missing live classification.
   Drift between the two sources is detected rather than tolerated: an **open**
   tracked blocker that does not carry the `launch-blocker` label is `UNKNOWN`
   (`label_drift:tracked blocker #N is open without the launch-blocker label`),
   so an entry can never sit in a private list outside the labeled inventory. A
   tracked entry that is already closed needs no label backfill. Entries are
   added to `tracked_blockers` in the same reviewed change that files the
   blocker, and are removed only after the issue is closed as completed.
3. **States:**
   - `open` — blocking
   - `in_flight` — open issue with open implementation PR(s); still blocking
   - `merged_awaiting_issue_close` — linked PR merged, issue still open; still blocking
   - `closed_completed` — `state_reason=completed`; cleared
   - `closed_other` — `duplicate` / `not_planned` / missing reason; **not** a fix
   - `exempted` — valid, unexpired structured exemption for the selected tier
   An unrecognized close reason is `UNKNOWN`. The `launch-exempted` label without
   an active structured exemption is `UNKNOWN`; the bare label never clears a
   blocker, and an expired exemption returns the issue to the blocker set.
4. **Private advisories:** unpublished (`draft`/`triage`) advisories whose
   severity blocks the selected tier contribute only a redacted count. A
   non-object entry, a missing/unknown `state`, an unknown `severity`, or an
   incomplete pagination walk is `UNKNOWN` — malformed rows are never dropped.

## Verdicts

| Verdict | Meaning | Exit |
|---------|---------|------|
| `PASS` | No blocking public issues and zero redacted private blockers for the tier | 0 (only when the checked-in snapshot agrees) |
| `FAIL` | At least one blocking public issue or redacted private blocker | non-zero |
| `UNKNOWN` | Missing token, absent/renamed label definition, tracked-vs-labeled drift, API/rate-limit/pagination/schema/staleness failure | non-zero |

Only a computed `PASS` can make the hosted job green. A checked-in `FAIL`
snapshot that agrees with a computed `FAIL` is still a non-zero exit: while real
launch blockers are open this check is expected to be red, and that redness is
never traded for a "parity" success. A claimed `PASS` that disagrees with the
computed verdict also fails.

The snapshot inside the `launch-readiness` markers in `PRODUCTION_READINESS.md`
is a reviewed record, not an input: it may only agree with the live evaluation.
Refresh it from the workflow's printed record, which carries the exact target SHA
and as-of UTC, whenever the blocker set changes.

## Private advisory access — setup and maintenance

Repository security advisories are behind a **separate GitHub permission**. The
Actions `GITHUB_TOKEN` cannot list them, and the workflow `security-events: read`
permission does **not** grant that access — it covers code-scanning alerts. A run
that relied on it would receive `403`. Both workflows therefore omit it.

Two supported sources, in order:

1. **Live API (preferred), from trusted code only.** Provision a read-only
   credential that can list this repository's security advisories and store it
   as an **environment** secret named `LAUNCH_ADVISORY_READ_TOKEN` inside the
   protected `launch-advisory` environment. It is referenced by exactly one
   workflow, `.github/workflows/launch-advisory-trust.yml`, and only after that
   workflow's secretless job has established the candidate commit's provenance.
   Any live failure — denial, rate limit, transport, pagination, or schema — is
   `UNKNOWN`; it never falls back to a weaker source.

   A tag event is **not** a trusted execution. See "Trusted execution boundary"
   below: this used to be modelled the other way round, and that was the defect
   in issue #3802.
2. **Externally maintained redacted variables.** When no advisory token is
   configured, the checker reads the repository *variables*
   `LAUNCH_PRIVATE_BLOCKER_COUNT` (a non-negative decimal count) and
   `LAUNCH_PRIVATE_ADVISORY_AS_OF` (an ISO-8601 UTC timestamp such as
   `2026-08-11T12:00:00Z`). Repository variables are set by a maintainer in
   repository settings; a pull request can read them but cannot change them,
   which is the only reason a zero there may substantiate a clean private state.
   Missing, malformed, future-dated, or older than
   `private_advisories.trusted_fallback.max_age_seconds` (7 days) ⇒ `UNKNOWN`.
   A maintainer with advisory access re-audits the private queue within that
   window and updates both variables together. Record **only** the count and the
   timestamp: never a GHSA identifier, summary, link, or any other detail.

No credential is stored in this repository, and none is printed.

## Trusted execution boundary

A `v*` tag can be created at **any** commit. For a `push` event GitHub loads the
workflow definition *and* every file the workflow executes from that tag target,
so a tag-triggered job is candidate-controlled code. A tag name is therefore
never evidence that its target came through protected `main`, and a job that
both runs tag code and holds the advisory credential hands the credential to an
arbitrary commit before any provenance exists (issue #3802).

The boundary is drawn by *which code executes*, not by which event fired:

| Surface | Code source | Credential |
|---------|-------------|------------|
| `launch-readiness.yml` (PR, `merge_group`, `main` push, `v*` tag, schedule, dispatch) | the ref under test — untrusted | **never**, on any event |
| `release.yml` (`v*` tag push) | the tag target — untrusted | **never** |
| `launch-advisory-trust.yml` (`workflow_run: in_progress`, `schedule`) | protected default branch, always | yes, after provenance |

`workflow_run` and `schedule` resolve this workflow from the default branch,
which is what makes
`launch-advisory-trust.yml` an immutable trust anchor a tag cannot rewrite.
`workflow_dispatch` is deliberately absent: its API accepts a caller-selected
branch or tag ref, so a manual dispatch is not intrinsically trusted code.

### How a release obtains a private-advisory verdict

1. A `v*` tag push starts `Release`. That run holds no credential.
2. The `Release` run's `workflow_run: in_progress` event triggers
   `launch-advisory-trust.yml` from protected `main`, carrying the Release run
   ID and run attempt. `in_progress` rather than `requested`: GitHub documents
   that `requested` does not fire when a run is re-run, so a re-run Release
   attempt would never obtain its own verdict and would fail closed forever.
3. `establish-trust` holds no secret. It checks out the literal `refs/heads/main`,
   resolves that checkout's `HEAD` to the trusted anchor commit, validates it as
   a 40-hex commit, requires it to be reachable from protected `main`, and
   exports it as `trusted_sha`. It also runs every secretless prerequisite —
   the checker's own self-test **and** `verify_launch_advisory_trust.py
   --self-test`, so this whole boundary contract is proved on the trusted tree
   before the protected environment can release the credential — because the
   credential job may not run one. It then
   treats the candidate purely as data: normalized tag format, exactly one
   unambiguous remote tag ref, tag resolution to exactly one commit, agreement
   with the triggering event's head (a tag moved after the event is refused as
   stale), reachability from protected `main`, and successful **push** `ci.yml` +
   `coverage.yml` runs for that exact SHA. Anything missing, ambiguous, or stale
   fails closed.
4. `advisory-verdict` is a closed two-step job: a pinned `actions/checkout`
   **directly at `trusted_sha`**, immediately followed by the single
   credential-bearing invocation of the default-branch checker with
   `--trusted-execution --trusted-tree-sha <anchor>`. No command of its own moves
   HEAD, and there is deliberately no third step. The checker re-asserts the pin
   itself and **refuses the credential outright** in any invocation that did not
   declare a trusted execution, so the tag's own copy of the checker cannot use a
   credential even if one were somehow present. The candidate reaches this job
   only as `LAUNCH_TARGET_SHA`; no candidate byte is fetched, imported, or run.
   The credential comes from the protected `launch-advisory` environment.
5. `publish-verdict` holds no secret and posts a fixed-text commit status on the
   candidate SHA under the context
   `trusted-launch-advisory-gate/release-<run id>-attempt-<attempt>`. Neither
   the credential nor any advisory identifier appears in the status, the logs,
   or any artifact.
6. `release.yml`'s `validate-launch-readiness` job derives the identical context
   from its own `github.run_id` and `github.run_attempt`, waits for **only that
   context** on the commit its tag resolves to, and fails closed if it is
   absent, `failure`, or `error`. The release still cannot proceed without a
   computed `PASS`; the decision simply moved to code a tag cannot rewrite.

### Why the verdict is bound to a run attempt

Commit statuses are commit-wide. A single constant
`trusted-launch-advisory-gate` context would be replayable: the daily audit of
protected `main`, an earlier tag release on the same commit, or an earlier
attempt of the same Release run would already have posted a success, and a
release started afterwards would consume it before its own trusted evaluation
had run. A blocker opened in between would be invisible.

So every release verdict carries a context unique to one Release run **and** one
run attempt:

| Lane | Context |
|------|---------|
| Release (`workflow_run: in_progress`) | `trusted-launch-advisory-gate/release-<run id>-attempt-<attempt>` |
| Scheduled default-branch audit | `trusted-launch-advisory-gate/main-audit` |

Both operands are validated as strict positive decimals (`^[1-9][0-9]{0,17}$`)
on both sides, and the whole derived context is re-checked against the admitted
shape before it is published, so no payload or input value can lengthen or
reshape it. The audit context is not of the release shape, so an audit verdict
can never satisfy a release gate.

Every one of those preconditions fails closed. If the triggering payload does
not carry a usable tag name, run ID, or run attempt, if the tag is ambiguous, if
it moved after the event, or if it is not reachable from protected `main`, no
credential is released and no verdict is published, so the release times out red
rather than proceeding.

To recover a stuck evaluation, rerun the trusted workflow itself. To reevaluate
after a Release rerun, rerun the Release workflow; its new run attempt emits a
fresh `workflow_run: in_progress` event and receives a distinct verdict context.
There is no manual-dispatch lane because its caller-selected ref would weaken
the trusted-code proof.

Because the policy, the exemptions, and `PRODUCTION_READINESS.md` are all read
from the trusted anchor, the reviewed snapshot compared against the live verdict
is protected `main`'s — never the candidate's copy of it.

### The credential job is a closed step sequence, and the verifier checks the whole sequence

Step scoping bounds who can **read** the credential. It does not bound who can
change what the credential step **executes**. Every step of a job shares one
workspace, so a secretless step placed before the credential step needs no
secret and no candidate expression to break the boundary: it can read
`.workflow_run.head_sha` out of `$GITHUB_EVENT_PATH`, ask the API, or read
`printenv`, then fetch candidate bytes, check them out, or simply overwrite
`scripts/check_launch_readiness.py` — and the exact, fully anchored credential
command would then execute the replaced file with the credential bound. Closing
only the credential step's own command is therefore not a workspace boundary.

So `advisory-verdict` has **exactly two steps and no others**:

1. `actions/checkout` at the pinned action SHA, with `ref` set to the
   `trusted_sha` output `establish-trust` already resolved from the literal
   `refs/heads/main` checkout, `fetch-depth: 1`, and
   `persist-credentials: false`. This replaces the earlier in-job pin block: the
   workspace arrives already at the trusted anchor, so no executable step is
   needed to put it there.
2. The credential-bearing checker invocation.

Every secretless prerequisite lives in `establish-trust` instead, where it
cannot touch this workspace. Two run there as real executable steps, and the
verifier requires both structurally — a comment, a `name:` that mentions the
command, or an occurrence in another job does not satisfy it:

| Step | What it proves |
|------|----------------|
| `python3 -I scripts/check_launch_readiness.py --self-test` | the readiness checker's own deterministic fixtures |
| `python3 -I .github/scripts/verify_launch_advisory_trust.py --self-test` | this trust-boundary contract, evaluated against the real `.github/workflows` tree |

The second is the preflight that matters here: the protected `launch-advisory`
environment releases the credential only after `establish-trust` succeeds, so a
protected `main` that no longer satisfies the boundary contract cannot reach the
credential step at all. Running the verifier only on pull requests would leave
the trusted lane itself unchecked at release time.

`.github/scripts/verify_launch_advisory_trust.py` parses that job's `steps:`
list by indentation and enforces the sequence structurally:

- the job declares only `name`/`needs`/`runs-on`/`timeout-minutes`/
  `environment`/`permissions`/`steps`, so no job-level `env:`, `defaults:`
  working directory, `container:`, `services:`, `strategy:`, or reusable
  `uses:` can add a surface outside the two steps;
- there are exactly two steps. Any third step — before, between, or after — is
  rejected on sight, whatever it claims to do;
- the first step declares only `name`/`uses`/`with`; its `uses` is the exact
  pinned `actions/checkout` SHA (a coordinated action-pin bump must update the
  `CHECKOUT_ACTION_PIN` constant too); and its `with:` mapping is exactly
  `ref: ${{ needs.establish-trust.outputs.trusted_sha }}`, `fetch-depth: 1`,
  `persist-credentials: false` — no `path`, `repository`, `token`,
  `submodules`, `sparse-checkout`, or `clean`, and no `run`, `env`, or `if`
  that could execute in or skip past that checkout;
- the second step is the one carrying `secrets.LAUNCH_ADVISORY_READ_TOKEN`, and
  it must be both the second step and the last;
- `establish-trust` must prove the anchor it exports: `trusted_sha` comes from
  `git rev-parse HEAD` of the literal protected-branch checkout, is validated as
  a 40-hex commit, is required to be an ancestor of protected `main`, and is
  exported from that step's own output. Dropping any of those proofs is
  rejected, because the credential job executes whatever that value names.

The credential-bearing step is then held — as before — to a closed contract of
its own:

- it must be a plain `run:` step declaring only `name`/`id`/`if`/`env`/`run`, so
  no `uses:`, `shell:`, or `working-directory:` can add or redirect an execution
  surface;
- it must have exactly one `run:`, and that `run:` must be a **single-line**
  scalar. A `run: |` or `run: >` block is refused outright, because a block can
  carry any number of extra commands that run with the credential already in the
  environment;
- the whole command is matched end to end against
  `python3 -I scripts/check_launch_readiness.py [--verify] [--require-pass]
  --trusted-execution --trusted-tree-sha "$TRUSTED_SHA"`. An appended `&& …`, a
  `;`, a pipe, a command substitution in the pin, an alternate interpreter, or an
  alternate path to the checker all fail the match.

### Anchoring the command is not enough: the environment is closed too

A command is only as exact as the environment that resolves it. With the `run:`
scalar matched byte for byte, `BASH_ENV` still makes Bash source a file before it
reaches that line, `PATH` still chooses which `python3` runs, and
`PYTHONPATH` / `PYTHONSTARTUP` / `LD_PRELOAD` still reach inside the interpreter.
So the credential step's `env:` is verified as an **exact closed mapping** —
these keys, these values, nothing else:

| Key | Admitted value |
|-----|----------------|
| `GITHUB_TOKEN` | `${{ github.token }}` |
| `LAUNCH_TIER` | `ga` |
| `LAUNCH_TARGET_SHA` | `${{ needs.establish-trust.outputs.candidate_sha }}` |
| `TRUSTED_SHA` | `${{ needs.establish-trust.outputs.trusted_sha }}` |
| `LAUNCH_PRIVATE_BLOCKER_COUNT` | `${{ vars.LAUNCH_PRIVATE_BLOCKER_COUNT }}` |
| `LAUNCH_PRIVATE_ADVISORY_AS_OF` | `${{ vars.LAUNCH_PRIVATE_ADVISORY_AS_OF }}` |
| `LAUNCH_ADVISORY_READ_TOKEN` | `${{ secrets.LAUNCH_ADVISORY_READ_TOKEN }}` |

This is an **allowlist, not a blacklist of known-bad names**: a loader or
interpreter variable nobody has thought of yet is refused because it is simply
not in the map. A missing key, a duplicate key (YAML keeps only the last, so a
duplicate silently overrides a verified binding), a changed value, an empty or
block-scalar or nested value, a flow mapping (`env: {…}`), and a YAML anchor,
alias, or merge key inside the mapping are each rejected. An `env:` line the
parser cannot read is reported as an error rather than skipped, so a reshaped
entry cannot slip past the allowlist by being invisible to it.

The same reasoning closes the **inherited** environment, which appears in
neither validated step:

- `launch-advisory-trust.yml`'s top-level keys are an allowlist —
  `name`/`on`/`concurrency`/`permissions`/`jobs`. A workflow-level `env:` or
  `defaults:` (`run.shell`, `run.working-directory`) is inherited by
  `advisory-verdict` and would redirect the credential step's environment,
  interpreter, or working directory without touching either step, so both are
  refused outright.
- Any unparseable node at the document's top level, or at the `jobs:` mapping
  level, is an error — a merge key or alias there would inject keys into every
  job.
- No YAML anchor, alias, or merge key may appear anywhere in `advisory-verdict`.
  Every key and value in that job must be literal, so what the contract
  validated is what runs. The document-wide structural pass described below
  extends that refusal to the rest of the file: an anchor, alias, or merge key in
  any mapping of `launch-advisory-trust.yml` is rejected.

The job-level closed-key contract is unchanged and still applies:
`advisory-verdict` may declare only
`name`/`needs`/`runs-on`/`timeout-minutes`/`environment`/`permissions`/`steps`.

### The document must be unambiguous: no duplicate keys, no inline block values

Every contract above is a *single structural reading* of the workflow text. That
reading is only a proof if GitHub's YAML parser cannot read the same file
differently — and a duplicate mapping key is exactly where the two can diverge.
A duplicate key is not an error GitHub reports: one occurrence wins, and *which*
one is a property of the consumer. So a workflow could keep the safe block-form
`on:` the verifier derives its events from, append a duplicate `on: [push]`, and
a last-key-wins consumer would make the trusted workflow tag-reachable while
every event-derived check still saw only `workflow_run`/`schedule`.

Scoping that refusal to the credential job is not enough, because the rest of the
document is what *derives* the trusted anchor and *publishes* the verdict.
`establish-trust` could carry a safe first `steps:` block that satisfies both
secretless preflights and every anchor proof, plus a duplicate last `steps:` that
exports a candidate-controlled `trusted_sha` — which `advisory-verdict` then
checks out and executes with the credential bound. The same shape works with a
duplicate `outputs:`, with a duplicate `run:` sitting behind the exact admitted
command on a trust step, and with a duplicate or flow `steps:`/`env:` on the
publisher.

The contract therefore refuses the whole family outright, document-wide, rather
than picking a winner. `verify_launch_advisory_trust.py` makes **one
indentation-aware structural pass** over `launch-advisory-trust.yml` that:

- refuses a **repeated mapping key in any mapping in the file** — the document
  root (including the admitted `on`, `jobs`, `permissions`, `concurrency`), the
  `on:` event mapping, the `jobs:` mapping, every job mapping (`establish-trust`,
  `advisory-verdict`, `publish-verdict`, and any job added later),
  `outputs`/`permissions`/`env`/`with` mappings, and every step mapping,
  including the mapping a `- ` sequence item opens. Order does not matter: a safe
  occurrence first and an untrusted one last is rejected, and so is the reverse;
- refuses every value that puts structure where a block reader sees none: a
  **flow collection** (`on: [push]`, `jobs: {…}`, `steps: [{run: …}]`,
  `with: {ref: …}`, `env: {PATH: …}`), a **YAML tag, anchor, alias, or merge
  key**, a
  **block scalar with an explicit indentation indicator** (whose indicator, not
  this reader, would decide where the shell ends), a **second YAML document**,
  **tab indentation**, and any node it cannot classify — including a key at an
  indentation it cannot place. Nothing is silently dropped, because a dropped
  node is exactly where a second `steps:` or a redirected `outputs:` would hide.

The pass is text-only: it never loads a YAML library, never deserializes the
document, and executes nothing. It is **block-scalar aware**, so a `run: |` body
is skipped whole — YAML-shaped shell such as `steps: not a key` inside a command
is neither counted as a duplicate key nor allowed to end the enclosing mapping —
while `run:` scalars and block-scalar shell keep being read as executable text by
the command-level checks exactly as before.

The earlier per-surface duplicate and flow checks (top-level keys, `on:` events,
job IDs, the `advisory-verdict` job mapping, its step keys, its `env:` entries,
and the trusted-anchor checkout's `with:` inputs) remain in place as defence in
depth and for their specific value-level messages.

Separately, and as defence in depth, **no** step of that job — inside multiline
blocks included — may expand a candidate-derived variable such as
`$LAUNCH_TARGET_SHA` on an executable line, and no candidate expression may
appear anywhere in the job outside the inert `LAUNCH_TARGET_SHA` environment
binding. The candidate SHA is read from the process environment by the trusted
checker and by nothing else. That rule alone is *not* the boundary, though: it
only sees a candidate named directly. The closed sequence above is what refuses
an indirectly derived candidate — and a step that ignores the candidate entirely
and just replaces the checker.

Comments are stripped before every structural and contract decision, so prose can
neither satisfy a requirement nor stand in for a rejected command.

`.github/scripts/verify_launch_advisory_trust.py --self-test` is the checked-in
proof. It runs an adversarial fixture table — a malicious tagged workflow that
claims the credential, a newly added tag-triggered consumer, a credential-bearing
job redirected at a candidate checker, a candidate-tree checkout, a
credential-bearing `run: |` block that checks out or sources candidate material
before calling the checker, a second command chained onto the credential
invocation, a command substitution in the trusted-tree pin, an action added as a
second execution surface on the credential step, a credential widened from the
step to the whole job, candidate expansion inside a secretless step of that job,
a pre-credential step that derives the candidate from `$GITHUB_EVENT_PATH` and
overwrites the checker while naming no candidate expression at all (asserted
both to be rejected *and* to be invisible to the candidate-expansion rule, so
the closed sequence is proved to be what catches it), an extra step appended
after the credential step, the credential step and the checkout in swapped
order, a block-scalar body line beginning with `- ` that must not hide an extra
step, a self-test moved back into the credential job, a redirected checkout
ref, a dropped or extra checkout input, a swapped checkout action, a checkout
step that also runs a command or carries an `if:`, a job-level `defaults:`
working directory, a `BASH_ENV` preamble, a `PATH` redirect and an unnamed
future interpreter variable (`NODE_OPTIONS`) on the credential step, a
duplicated env key, an env entry the parser cannot read, a nested or
block-scalar env value, a flow-mapping `env:`, an anchor on an env value, a
merge key inside the env mapping and at the credential job level, a
workflow-level `env:`, a workflow-level `defaults.run.shell` and
`defaults.run.working-directory`, a top-level anchor block, a merge key at the
`jobs:` mapping level, the trusted-job boundary self-test dropped, commented
out, or relocated into the credential job, a trusted anchor exported without its protected-main
ancestry proof or without coming from the protected-branch checkout, a
commented-out credential binding, a self-test surviving only as a comment, a
tag-reachable trust workflow, a tag checkout in the secretless trust job, a
dropped environment binding, a dropped provenance edge, an unpinned action, a
constant commit-wide status context, an omitted run-attempt binding, a
`requested`-only trigger, a default-branch audit sharing the release context
namespace, a release gate that accepts another run's status, a release gate
that stops requiring the trusted verdict, a safe block-form `on:` followed by a
duplicate `on: [push]` and the reversed ordering, a duplicate `jobs:`, a
duplicate `workflow_run` trigger, a duplicate `advisory-verdict` job ID, a
duplicate `needs`, `environment`, or `steps` on the credential job, a duplicate
top-level step key, a duplicate checkout `with:` input, an `on:`, `steps:`,
`with:`, or whole job written as an inline flow collection, a duplicate `steps:`
on `establish-trust` that exports a candidate-controlled `trusted_sha`, a
duplicate `outputs:` redirecting the trusted anchor in both orderings, a
duplicate `run:` on a trust-job step behind the exact admitted command, a
duplicate flow `steps:` and a duplicate flow `env:` on the publisher, a tagged
flow sequence that would hide an inline `steps:` value, a duplicate
key in a mapping no value-level check reads at all, a document node the pass
cannot classify, and YAML-shaped shell inside a `run: |` body that must *not* be
read as structure — and then applies the same contract to the real
`.github/workflows` tree. It runs on every pull request from
`launch-readiness.yml`.

Each duplicate/flow fixture asserts the intended **structural** rejection, and
where the ambiguity is load-bearing it also asserts that the corresponding
value-level check did *not* fire — the duplicated `on:` still derives only
trusted events, the duplicated `needs:`/`environment:` still read as present, the
duplicated `steps:` still satisfies the closed two-step sequence, the redirected
ref inside a flow `with:` reaches no ref check, the trust job's duplicate
`steps:` still shows both secretless preflights and all three anchor proofs as
satisfied, the duplicate `outputs:` still shows `trusted_sha` as exported from
the step that validated it, the duplicate `run:` still shows the boundary
self-test as a real executable step, and the publisher's duplicates still show
every established binding as consumed. That absence is the proof the structural
refusal is what catches the bypass, not an incidental downstream error.

### Required repository settings (root/admin only, not code)

The code above removes the credential from every candidate-reachable job, but
repository *settings* decide whether an attacker-authored workflow could still
name the secret. These are administrator actions and are deliberately not
automated here.

**Verified live state at the time of writing:** no repository secret named
`LAUNCH_ADVISORY_READ_TOKEN` is provisioned, and no `launch-advisory`
environment exists. There is therefore nothing to delete and **no rotation is
currently required** — the checker falls back to the redacted repository
variables, and the trusted workflow's advisory read is inert until a credential
is provisioned. The code boundary is still worth keeping: it is what makes a
future provisioning safe rather than exploitable.

1. **Create and protect the environment first.** Create a `launch-advisory`
   environment and restrict its deployment branch/tag policy to the default
   branch only, so a tag-triggered workflow naming the environment is refused
   before any step runs. Add required reviewers if manual release approval is
   wanted. Do this *before* step 2: referencing a not-yet-existing environment
   auto-creates an **unprotected** one, and provisioning the secret into an
   unprotected environment would reopen the hole.
2. **Only then provision the credential as an environment secret.** Add a newly
   issued, narrowly scoped advisory-read credential as
   `LAUNCH_ADVISORY_READ_TOKEN` in that protected environment — never in
   repository-secret scope, where any workflow, including one authored by a
   `v*` tag, can name it. Prefer a short-lived GitHub App installation token or
   a fine-grained credential scoped to repository advisory read on this
   repository only.
3. **If audit history later shows a credential was independently provisioned or
   used**, treat that one as disclosed — the pre-#3802 design cannot prove it
   was never handed to an arbitrary tag target — and revoke and reissue it under
   step 2. Absent such evidence, the verified no-secret state means there is
   nothing to rotate.
4. **Protect release tags.** Create an active ruleset targeting `refs/tags/v*`
   that restricts creation to a narrow release principal, blocks update and
   deletion, and audits any bypass. Consider requiring signed annotated tags.
   Tag protection is defense in depth: trusted-code execution is still required
   because a privileged release actor can be compromised.
5. **Keep `main` protected.** The whole boundary rests on `refs/heads/main`
   being a protected default branch whose required checks cannot be bypassed.

## Hosted enforcement

- `.github/workflows/launch-readiness.yml` — pull requests, `merge_group`,
  `main` pushes, `v*` tags, a daily schedule, and `workflow_dispatch`. It runs
  the deterministic self-tests and trust-boundary self-test, then verifies the
  live verdict for the exact commit under test (PR head, merge-group head, or
  pushed SHA) and asserts that the checkout is that commit. It holds no advisory
  credential and reads only redacted variables. This is the go/no-go signal and
  is expected to be red while blockers are open; it is not a required
  pull-request context.
- `.github/workflows/launch-integrity.yml` — the required
  `Launch Readiness Integrity` context on every pull request and merge group.
  See [Trusted integrity check](#trusted-integrity-check) below.
- `.github/workflows/launch-advisory-trust.yml` — the sole advisory-credential
  holder, reachable only from `workflow_run` (`in_progress`) and `schedule`.
  Its secretless `establish-trust` job runs both self-tests on the trusted tree
  before the protected environment can release the credential. Its schedule
  publishes the live private-advisory re-audit of protected `main` under the
  separate `.../main-audit` context.
- `.github/workflows/release.yml` — the `validate-launch-readiness` job gates
  every tag release on the exact trusted
  `trusted-launch-advisory-gate/release-<run id>-attempt-<attempt>` verdict for
  the commit its tag resolves to, accepts no other context, and holds no
  advisory credential. Every other release job is downstream of it, which the
  integrity verifier re-checks as a `needs` reachability property.
- Every checkout on the advisory trust boundary uses
  `persist-credentials: false` and least permissions. This statement is scoped
  to those jobs; the release build, packaging, and publishing jobs remain
  outside this boundary.
- `.github/CODEOWNERS` covers the policy, exemptions, checker, launch workflows,
  both trust verifiers, `PRODUCTION_READINESS.md`, and itself.

## Trusted integrity check

`Launch Readiness Integrity` exists because the gate previously judged itself:
the workflow checked out the candidate head and ran that checkout's evaluator
and that checkout's self-tests, so one change could weaken the checker, its
policy, and its tests together.

**Trust anchor.** The workflow triggers on `pull_request_target` (loaded and
checked out from the base branch) and on `merge_group` (the synthesized queue
commit, whose entry already cleared this same check on its pull request). It
resolves and pins a trusted commit — the live `main` tip for a pull request,
authenticated as a descendant of the event base; the queue `base_sha` for a
merge group — and reads `.github/scripts/verify_launch_integrity.py` from that
commit. That file is the only code the job executes.

**Candidate as inert data.** The candidate revision is never checked out into
the execution path. Each governed file is extracted with `git show` into a fixed
slot name under `$RUNNER_TEMP`, after its tree entry is confirmed to be a
regular non-symlink blob, so no candidate-controlled path component is ever
joined into a filesystem path. Nothing from the candidate is imported, parsed as
code, or executed — every governed file is compared or schema-checked as text. A
missing slot is the signal that a protected file was deleted or renamed.

**Permissions.** `contents: read`, `persist-credentials: false`, no secrets at
all. `.github/scripts/verify_required_ci.py` re-asserts those properties, the
`merge_group` trigger, and the exact check name so the required context cannot
be silently renamed or downgraded.

**Byte-frozen executable gate code.** Every file that *executes* as part of the
launch/release gate must be byte-identical to the trusted base:

| Anchored path | Frozen from |
|---|---|
| `scripts/check_launch_readiness.py` | always |
| `.github/workflows/launch-readiness.yml` | always |
| `.github/workflows/release.yml` | always |
| `.github/workflows/launch-integrity.yml` | always |
| `.github/scripts/verify_launch_integrity.py` | always |
| `.github/workflows/launch-advisory-trust.yml` | once the trusted base carries it (issue #3802) |
| `.github/scripts/verify_launch_advisory_trust.py` | once the trusted base carries it (issue #3802) |

The two optional rows are treated as absent only while the trusted base also
lacks them; the moment the base carries one, deleting it or changing a byte
fails. A trusted base that is missing a *required* anchor is a broken or
tampered extraction and fails closed rather than skipping enforcement.

This is a deliberate replacement for a semantic contract. An earlier revision of
this verifier tried to *permit* checker edits that "still looked fail-closed":
it rejected a function whose body was reduced to a single success statement and
separately required certain marker strings to appear somewhere in the function.
Both are trivially defeated by prepending `return "PASS"`, `return 0`,
`sys.exit(0)`, or `if True: return []` above the original body — every previous
statement and every marker string is still present in the file, merely
unreachable. No source-level or YAML-level heuristic can prove arbitrary
executable gate code is still equivalent to what was reviewed, so byte identity
is the enforced property and the heuristics are gone.

**Consequences for contributors.**

- An ordinary pull request cannot change any anchored file. If a change is
  needed, it is an explicit administrative / root-orchestrator update: land it on
  protected `main` through an auditable bypass and re-run the integrity workflow
  (and `Launch Readiness Gate`) on `main` immediately afterwards, so the new
  bytes are the enforced anchor for everything queued behind it.
- A pull request whose branch predates such an update will go red on the anchor
  it is stale against; merging the latest protected base fixes it. The merge
  queue re-runs the same check against the synthesized commit, so the queue is
  the authoritative enforcement point.
- The proposed copy of the verifier still gets hosted execution of its own
  fixtures in the isolated `trusted-policy-candidate.yml` lane, which produces
  nothing another job reads — the same posture as `Trusted Cross Build Policy`.

On the single adoption commit the trusted base carries no verifier at all, so
there is no protected contract to preserve and nothing trustworthy to execute:
that run reports success with an explicit `::notice::` instead of pretending to
have enforced anything. Every later revision takes the enforcing path.

### What the verifier enforces

- **Byte anchors:** the table above. Deletion, rename, a whitespace-only edit, a
  comment-only edit, an early `return`/`sys.exit(0)` with the old body retained
  below it, or a YAML rewrite that keeps every historically frozen substring
  (`if: false` on the gate job, `continue-on-error: true` on the release gate)
  are all rejected on bytes alone.
- **Deletion/rename:** every protected gate path is still present and non-empty.
- **Policy downgrade:** frozen state machine and reason sets; GA blocking every
  severity; no tier dropping a severity the trusted base blocked; only
  severities the checker knows; a `default_launch_tier` the policy actually
  defines; the exact label schema, with distinct severity labels and the label
  contract unchanged (a rename silently empties the blocker set); non-empty
  policy/classification versions; the repository identity format-checked and
  pinned to the trusted base; every tracked blocker carrying a note; and no
  checked-in count/as-of key anywhere in the file.
- **Private-advisory downgrade:** enabled, redacted-count-only, unpublished
  states blocking, blocking and closed state sets disjoint and jointly covering
  every known advisory state, per-tier advisory severities covering exactly the
  policy tiers with only known severities, GA still blocking
  critical/high/medium, no tier dropping a severity the trusted base blocked,
  the never-emit set intact, the freshness window never widened, and the
  credential (`live_api.token_env`) and fallback evidence variables
  format-checked, mutually distinct, and pinned to the trusted-base names so a
  pull request cannot point the checker at a source it controls.
- **Exemption schema:** required fields; a positive issue number; owner and
  approver matching the checker's principal grammar; non-empty rationale and
  compensating control; unique non-empty ids; at least one launch tier and no
  tier the candidate policy does not define; ISO-8601 timestamps compared as
  *instants*, so an expiry strictly after approval cannot be faked with a
  timezone offset whose lexical order is the reverse of its chronological order.
  The candidate policy's tier set is passed into this check as inert parsed
  data; no candidate code is imported or executed.
- **Document markers:** exactly one begin/end/historical marker, in order, with
  the marker contract itself unchanged from the trusted base.
- **Secret exposure:** the privileged advisory token may be named only by a
  workflow that is itself an anchor (`launch-readiness.yml`, `release.yml`,
  `launch-advisory-trust.yml`). A workflow a candidate *adds* may not reference
  it at all.
- **Check-run producer identity:** the required check names may be produced by
  exactly one workflow file each, so a candidate cannot add a second workflow
  that reports an identically named, trivially green context.
- **Ownership evasion:** every governed path still has an owner in
  `.github/CODEOWNERS`, and no trusted-base owner was removed. GitHub evaluates
  CODEOWNERS from the base branch, so editing that file inside a pull request
  cannot relax that pull request's own review requirement; this check keeps the
  coverage from being dropped on the way in.

The last three run over the *whole* extracted workflow directory, including
workflows the candidate adds. They are defense in depth against a bypass built
beside the gate; they are explicitly **not** the permission model for changing
an anchored file — that is the byte anchor and nothing else.

The policy and exemption checks are held to the frozen production checker's own
schema (`scripts/check_launch_readiness.py`). The checker's bytes are anchored,
but the data it consumes is candidate-editable and is consumed from `main` the
moment a data-only edit lands, so anything the checker would reject — or any
narrowing of what it will block — has to be refused here, at pull-request time.
A trusted-base policy copy that cannot be read fails closed rather than
silently disabling every base comparison.

What it deliberately does **not** judge: live issue/advisory state, and the
*content* of the tracked-blocker inventory or the exemption list. Those are
governed by CODEOWNER review; the verifier only enforces their schema so a
malformed or unbounded entry cannot slip through. It also no longer inspects
checker semantics, workflow triggers, frozen `run:` lines, or release `needs:`
reachability: those properties are now implied by byte identity, and enforcing
them a second time from a hand-maintained contract table would only produce
false reds whenever an administrative update legitimately changed them.

### Required repository settings (root-only)

These cannot be set from a pull request and must be applied by a repository
administrator:

1. Add the required status check `Launch Readiness Integrity` (source app
   **GitHub Actions**, app id `15368`) to the `main` ruleset and to the merge
   queue's required checks. Do **not** add `Launch Readiness Gate`.
2. Set `pull_request.require_code_owner_review = true` for `main` (or add a
   narrower path-scoped ruleset) so the CODEOWNERS entries for
   `PRODUCTION_READINESS.md`, `docs/launch-blocker-policy.json`,
   `docs/launch-exemptions.json`, `docs/launch-readiness.md`,
   `scripts/check_launch_readiness.py`,
   `.github/workflows/launch-readiness.yml`,
   `.github/workflows/launch-integrity.yml`,
   `.github/scripts/verify_launch_integrity.py`,
   `.github/workflows/release.yml`, and `.github/CODEOWNERS` are enforced rather
   than advisory.
3. Keep the organization-admin bypass auditable: an emergency merge that skips
   the integrity context should be followed by a post-merge run on `main`.
4. Land every change to an anchored file (the byte-frozen table above) the same
   way: an explicit administrative update on protected `main` using an auditable
   bypass, immediately followed by a hosted post-merge run of
   `launch-integrity.yml` and `launch-readiness.yml` on the new `main` tip. The
   new bytes become the anchor for every pull request queued behind it, so a
   broken administrative update is visible on the very next run rather than at
   release time.

Until step 1 and step 2 are applied the check is advisory. Drift in either is
detectable by re-querying the ruleset; the repository-side half of the control
(workflow, verifier, contracts, ownership map) is enforced in-tree.

## Determinism

Every freshness decision is made against an explicitly injected clock: production
passes the real UTC clock, and the fixture suite passes fixed instants. There is
no test-only bypass of production freshness — the tests simply supply their own
consistent `now`, so a fixture verdict can never be collapsed by the wall clock.

## Local / CI invocation

Hosted CI is the execution gate; the deterministic self-test is offline.

```bash
python3 scripts/check_launch_readiness.py --self-test
python3 scripts/check_launch_readiness.py --verify --launch-tier ga --target-sha "$GITHUB_SHA"
python3 .github/scripts/verify_launch_integrity.py --self-test
python3 .github/scripts/verify_launch_advisory_trust.py --self-test
```

`--verify` requires a computed `PASS`; `--require-pass` is accepted for release
wiring and is implied. `--verify-checkout` additionally asserts that the working
tree HEAD is the supplied target commit. With no target supplied, the checked-out
HEAD is the target.

`--trusted-execution --trusted-tree-sha <sha>` is the credential contract. It
declares that the invocation is executing protected default-branch code and
requires the evaluation target to be supplied explicitly, so the commit under
evaluation is data and the executing tree is the pinned anchor. Without it an
advisory credential in the environment is refused before any advisory request is
made, and the refusal never echoes the credential.
