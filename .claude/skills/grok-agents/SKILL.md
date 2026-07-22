---
name: grok-agents
description: Dispatch and orchestrate local Cursor Grok 4.5 subagents via Conductor's Cursor SDK harness for ferrum-edge issue/PR work — implementer, fix-round, and shepherd modes, with worktree isolation and the review loop. Use when the user asks Claude to spawn Grok/Cursor Grok agents on issues, PRs, review findings, or red CI.
---

# grok-agents: Cursor Grok 4.5 subagent orchestration

You are the ORCHESTRATOR. Grok agents implement/fix; you verify their diffs, drive/merge
decisions, and never let an unreviewed PR merge. This skill uses the same local Conductor Cursor
harness that runs `grok-4.5` in Conductor workspaces (`@cursor/sdk` + `CURSOR_API_KEY`).

**Guard: do NOT use this skill when you are yourself a dispatched worker.** If your session prompt
references `agent-brief.md` / `continuation-brief.md`, says "YOU are the implementer", or hands
you an existing worktree and findings to fix, implement directly. Do not recursively dispatch
another Grok worker.

## Dispatch command (exact shape)

Resolve the absolute path to this repository's `.agents/skills/grok-agents` directory, write a
prompt file outside the repo, then launch:

```bash
<ABS_REPO>/.agents/skills/grok-agents/scripts/dispatch-agent.sh \
  --worktree <ABS_PATH_TO_WORKER_WORKTREE> \
  --prompt-file <ABS_PROMPT_FILE>
```

`--effort medium|high|xhigh|max` is accepted for CLI parity with sibling skills but is ignored —
the Cursor Grok harness has no effort tiers. Do not claim an effort level was applied.

Non-negotiables:
- The launcher pins **`grok-4.5`** with `fast=false` (non-Fast variant, no fast credits) through Conductor's bundled Node + `@cursor/sdk`.
- `CURSOR_API_KEY` must be available (env or Conductor provider keychain). Do not print it.
- Run each dispatch as a **background / long-lived task**; prefer one task per agent.
- **Parallel cap: 7** unless the user sets a lower limit.

## Prompt construction (all modes)

Every prompt starts with:
`First read <ABS_REPO>/.agents/skills/grok-agents/references/agent-brief.md and follow it exactly`
(implementer) or
`Read <ABS_REPO>/.agents/skills/grok-agents/references/continuation-brief.md AND
<ABS_REPO>/.agents/skills/grok-agents/references/agent-brief.md and follow them`
(fix/shepherd — give BOTH absolute paths).

Use only those `.agents/skills/grok-agents/references/` paths so Claude and Codex/GPT
orchestrators share one source of truth.

Every prompt must also PIN THE WORKER'S ROLE:
"YOU are the implementer: write, commit, and push the changes yourself in this session.
Do NOT invoke agent-dispatch skills (grok-agents, sol-agents, opus-agents, fable-agents,
.agents/skills/*/scripts/dispatch-agent.sh) and do NOT spawn nested workers."

Then append the mode block:

**Implementer (fresh issue):** issue number, worktree dir `issue-<N>` under a sibling
`<repo>-agents/` dir, branch name, acceptance criteria, repo-invariant callouts, scope
boundaries vs neighboring in-flight PRs.

**Fix round (existing PR):** PR number, existing worktree path, current head SHA, verified
findings verbatim, CI-red diagnosis, per-finding guidance (fix vs acceptable-rebuttal).

**Shepherd (drive to clean+green):** like fix round, plus loop until review-clean AND CI green.
Only when the user wants agents babysitting CI.

**Cadence override (recommended default — CI takes 20-30 min):** append:
"CADENCE OVERRIDE: do NOT wait for in-progress CI. Loop: reconstruct state -> fix findings + RED
checks -> fmt -> push -> ONE review trigger -> EXIT with report."

## Orchestrator duties between agent rounds

1. On each agent completion: verify from GitHub (never the agent's claims alone) — head pushed?
   trigger posted to the correct bot? threads replied?
2. Independently review the diff in the agent's worktree before any merge
   (`git fetch origin main && git diff origin/main...HEAD` — three-dot).
3. Triage CI reds yourself when agents are gone.
4. Salvage protocol for dead agents: check worktree status + unpushed commits, then relaunch a
   continuation agent with a state snapshot.
5. Merge only when: review bot clean on the CURRENT head + CI green + your own review done.

## Known failure modes

- Missing Conductor harness (`.../com.conductor.app/bin/.internal/node` or `cursor-node-worker.mjs`)
  or missing `CURSOR_API_KEY` — stop and report; do not fall back to another model.
- Capacity or transport kills mid-loop — work may already be pushed; check PR state first.
- Agents may exit claiming "waiting on monitor" — treat every completion as end-of-turn.
- Nested dispatch: if a completed run's report mentions "dispatching a worker", treat the actual
  implementing model as unknown and weight your independent diff review accordingly.
