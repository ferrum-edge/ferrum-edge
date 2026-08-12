# Launch readiness gate

Fail-closed release governance for Ferrum Edge. The live launch verdict is
computed by `scripts/check_launch_readiness.py` from GitHub issue and advisory
state plus the checked-in policy; it is **not** the historical static-audit prose
in `PRODUCTION_READINESS.md`.

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

1. **Live API (preferred).** Provision a read-only credential that can list this
   repository's security advisories and store it as the repository secret
   `LAUNCH_ADVISORY_READ_TOKEN`. It is exposed **only** to trusted executions
   (`push` to `main`, tags, `schedule`, `workflow_dispatch`, and the release
   workflow). Pull-request and merge-group runs are given an empty value by
   construction, so untrusted code never sees a privileged advisory token. Any
   live failure — denial, rate limit, transport, pagination, or schema — is
   `UNKNOWN`; it never falls back to a weaker source.
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

## Hosted enforcement

- `.github/workflows/launch-readiness.yml` — pull requests, `merge_group`,
  `main` pushes, `v*` tags, a daily schedule, and `workflow_dispatch`. It runs
  the deterministic self-tests, then verifies the live verdict for the exact
  commit under test (PR head, merge-group head, or pushed SHA) and asserts that
  the checkout is that commit.
- `.github/workflows/release.yml` — the `validate-launch-readiness` job gates
  every tag release on a computed `PASS` for the tagged commit resolved from the
  checked-out tag ref.
- Both keep `persist-credentials: false` and least permissions.
- `.github/CODEOWNERS` covers the policy, the exemptions, the checker, the
  workflow, and `PRODUCTION_READINESS.md`.

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
```

`--verify` requires a computed `PASS`; `--require-pass` is accepted for release
wiring and is implied. `--verify-checkout` additionally asserts that the working
tree HEAD is the supplied target commit. With no target supplied, the checked-out
HEAD is the target.
