---
name: sol-agents
description: Dispatch and orchestrate parallel gpt-5.6-sol codex CLI subagents (medium/high/xhigh effort) for ferrum-edge issue/PR work — implementer, fix-round, and shepherd modes, with worktree isolation and the codex review loop. Use when the user asks to spawn sol/codex agents on issues, PRs, review findings, or red CI.
---

# sol-agents: codex CLI subagent orchestration

You are the ORCHESTRATOR. Agents implement/fix; you verify their diffs, drive/merge
decisions, and never let an unreviewed PR merge. This skill encodes the process
proven across the 2026-07 issue-backlog drive (20+ PRs merged).

## Dispatch command (exact shape)

Write the prompt to a file outside the repo, then launch:

```bash
<ABS_REPO>/.agents/skills/sol-agents/scripts/dispatch-agent.sh \
  --worktree <ABS_PATH_TO_WORKER_WORKTREE> \
  --prompt-file <ABS_PROMPT_FILE> \
  --effort <medium|high|xhigh>
```

Append `--fast` only when the user explicitly requests fast mode for that dispatch or fleet. Never
infer it from urgency, deadlines, task size, or available credits. Omit it otherwise; the launcher
pins `service_tier="default"` without the flag and the model's Fast `priority` tier with it.

Non-negotiables:
- Go through the launcher, not a bare `codex exec`. It resolves the binary, verifies the worktree
  root, and binds stdin to the prompt file — which is also what keeps codex from blocking forever
  on "Reading additional input from stdin..." in non-TTY shells.
- The codex binary is resolved from `CODEX_BIN`, then `/opt/homebrew/bin/codex` /
  `/usr/local/bin/codex` / `~/.local/bin/codex`, then `PATH`. Any candidate under
  `com.conductor.app` is refused — Conductor's bundle lags the standalone release.
- The launcher runs `codex exec --model gpt-5.6-sol --config model_reasoning_effort="<effort>"
  --config service_tier="<default|priority>" --sandbox danger-full-access --cd <worktree> -`.
  Worktree isolation prevents git collisions; it is not a host sandbox.
- Run each dispatch as a **background task** (`run_in_background`); prefer one task
  per agent (separate completion notifications) over one wrapper with `&`.
- **Liveness ground truth: `pgrep -x codex | wc -l`** — never trust stale output-file
  tails; capacity events can silently kill the whole fleet at once.
- **Parallel cap: 7** (user-set 2026-07-10). Group coupled PRs under one agent if over cap.

## Effort selection

- **medium** — easier tasks and quick singular code fixes: a contained single-file
  change, a mechanical refactor, a doc correction, or a review finding whose fix is
  obvious and local.
- **high** — default. Challenging multi-step coding across interconnected components:
  scoped fixes and review rounds that span several modules, test work, and doc
  reconciliation where the worker must reason about how the pieces fit together.
- **xhigh** — very high-stakes work that needs lots of thinking: security-critical
  surfaces (authz, trust boundaries, fail-closed contracts), subtle protocol
  correctness, architecturally sensitive proxy-core/dispatch work, deep multi-subsystem
  refactors, or anything where a wrong call is expensive. Use sparingly.
- The user may override per prompt ("on xhigh", "on high", "on medium") — honor it.

## Prompt construction (all modes)

Every prompt starts with:
`First read <path-to>/agent-brief.md and follow it exactly` (implementer mode) or
`Read <path-to>/continuation-brief.md AND <path-to>/agent-brief.md and follow them`
(fix/shepherd modes — give BOTH absolute paths; the continuation brief defers to
agent-brief for ground rules and must never be dispatched alone).
Use the copies in THIS skill directory (they carry worktree isolation, no-local-builds
policy, review-loop discipline, known-flake list, final-report format). Verify the
briefs' review-bot section matches reality before dispatching (codex vs claude
trigger — credits come and go); update the briefs if stale.

Every prompt must also PIN THE WORKER'S ROLE explicitly (the briefs repeat it, but the
prompt is what survives a partial brief read):
"YOU are the implementer: write, commit, and push the changes yourself in this session.
Do NOT invoke agent-dispatch skills from your environment (opus-agents, fable-agents,
grok-agents, .agents/skills/*/scripts/dispatch-agent.sh, claude CLI workers) and do NOT
spawn nested workers." The repo intentionally ships mirror skills under `.agents/skills/`
(codex→Claude/Grok dispatch, for when the USER asks codex to delegate); without this pin a
codex worker can pattern-match fix-round vocabulary onto those skills and silently delegate
the implementation to a different model at a different effort than the user chose.

Then append the mode block:

**Implementer (fresh issue):** issue number, worktree dir `issue-<N>` under a
sibling `<repo>-agents/` dir, branch name, acceptance criteria distilled from the
issue, repo-invariant callouts relevant to the surface (hot path, fail-closed,
openapi parity), scope boundaries vs neighboring in-flight PRs.

**Fix round (existing PR):** PR number, existing worktree path, current head SHA,
the verified findings verbatim (fetch full thread bodies first — findings live in
reviewThreads via the graphql query in the brief), CI-red diagnosis you already made,
and per-finding guidance (fix vs acceptable-rebuttal cases).

**Shepherd (drive to clean+green):** like fix round, plus "loop until codex clean
AND CI green". Only use when the user wants agents babysitting CI.

**Cadence override (recommended default — CI takes 20-30 min):** append:
"CADENCE OVERRIDE: do NOT wait for in-progress CI. Loop: reconstruct state -> fix
findings + RED checks -> fmt -> push -> ONE @codex review -> EXIT with report."
The orchestrator then handles verdicts/green-waiting between rounds.

## Orchestrator duties between agent rounds

1. On each agent completion: verify from GitHub (never the agent's claims alone) —
   head pushed? trigger posted to the CORRECT bot? threads replied?
2. Independently review the diff in the agent's worktree before any merge
   (`git fetch origin main && git diff origin/main...HEAD` — three-dot; two-dot lies
   once main moves). Focus: fail-closed posture, hot-path gating, docs honesty,
   no-unwrap-in-prod, scope creep.
3. Triage CI reds yourself when agents are gone: outage signature
   ("cargo fetch failed ... registry outage") → rerun; bin-target dead_code
   (lib+bin dual module tree) → real fix; known flakes (list in agent-brief) → rerun.
4. Salvage protocol for dead agents: check worktree `git status --porcelain` +
   `git log @{u}..HEAD`, commit/push stranded WIP, relaunch a continuation agent
   with a state snapshot (or a handoff file for large context).
5. Merge only when: review bot clean on the CURRENT head + CI green + your own
   review done. `gh pr merge <N> --repo <repo> --merge --delete-branch`.

## Known failure modes

- "model is at capacity" kills agents mid-loop (sometimes ALL at once, silently) —
  work is usually already pushed; check PR state before redoing anything.
- Agents may exit claiming "waiting on monitor" — there is no monitor; treat every
  completion as end-of-turn and pick up the loop yourself.
- Review triggers posted to an out-of-credits bot get no reply — re-fire on the
  working bot; treat BOTH bots' threads (chatgpt-codex-connector, claude) as state.
- Two agents naming a test identically → E0428 on merge; grep before enabling
  gated tests.
- A codex worker's own skill registry may advertise stale paths (e.g.
  `~/.codex/skills/.system/opus-agents/SKILL.md` → "No such file or directory" on its
  first read). Harmless — workers self-recover — but it is also the on-ramp to the
  nested-dispatch failure above: the worker goes looking for the repo-local
  `.agents/skills/opus-agents/` copy and then follows it. The role pin in the prompt
  (and now in both briefs) is the fix; if a completed run's report mentions
  "dispatching a worker", treat the ACTUAL implementing model/effort as unknown and
  weight your independent diff review accordingly.
