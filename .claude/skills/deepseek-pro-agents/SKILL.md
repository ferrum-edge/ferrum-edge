---
name: deepseek-pro-agents
description: Dispatch and orchestrate local opencode DeepSeek V4 Pro subagents via the opencode CLI harness for ferrum-edge issue/PR work — implementer, fix-round, and shepherd modes, with worktree isolation and the review loop. DeepSeek V4 Pro is the deep-reasoning tier, suited to invariant-heavy security, protocol, and concurrency work. Use when the user asks Claude to spawn DeepSeek Pro/deepseek-v4-pro agents on issues, PRs, review findings, or red CI.
---

# deepseek-pro-agents: DeepSeek V4 Pro subagent orchestration

You are the ORCHESTRATOR. DeepSeek V4 Pro agents implement/fix; you verify their diffs, drive merge
decisions, and never let an unreviewed PR merge. This skill uses the local opencode CLI harness
(`opencode run`) pinned to `alibaba-token-plan/deepseek-v4-pro-0813` on the operator's
`alibaba-token-plan` provider.

DeepSeek V4 Pro is the deep-reasoning tier of this fleet. Prefer it for tasks that need careful
invariant reasoning — fail-closed security paths, protocol correctness, concurrency and ordering
fences, and review rounds where a finding has to be either fixed properly or rebutted with
file-and-line evidence.

**Guard: do NOT use this skill when you are yourself a dispatched worker.** If your session prompt
references `agent-brief.md` / `continuation-brief.md`, says "YOU are the implementer", or hands
you an existing worktree and findings to fix, implement directly. Do not recursively dispatch
another opencode worker.

## Dispatch command (exact shape)

Resolve the absolute path to this repository's `.agents/skills/deepseek-pro-agents`
directory, write a prompt file outside the repo, then launch:

```bash
<ABS_REPO>/.agents/skills/deepseek-pro-agents/scripts/dispatch-agent.sh \
  --worktree <ABS_PATH_TO_WORKER_WORKTREE> \
  --prompt-file <ABS_PROMPT_FILE>
```

`--effort medium|high|xhigh|max` is accepted for CLI parity with sibling skills but is ignored —
this provider has no effort tiers. Do not claim an effort level was applied.

Non-negotiables:
- The launcher pins **`alibaba-token-plan/deepseek-v4-pro-0813`** on the write-enabled `build`
  agent and feeds the prompt on stdin (`opencode run --auto`). This is a **hard pin**:
  `--model` is refused (exit 2) unless it names exactly `alibaba-token-plan/deepseek-v4-pro-0813`.
  No other Qwen/DeepSeek variant and no rolling alias can be dispatched from this skill.
- The pin is the **dated snapshot** `-0813`, chosen for its limited-time discounted rate. The
  rolling `deepseek-v4-pro` alias also serves on this plan, so this is a cost choice, not an
  availability constraint. Re-pin only after re-validating.
- **`ALIBABA_TOKEN_PLAN_API_KEY` must be in the dispatch process environment.** A non-interactive
  session does not source `~/.zshrc`, so export it yourself (or set
  `ALIBABA_TOKEN_PLAN_API_KEY_FILE` to a readable absolute path holding it). The launcher exits 2
  with remediation when it is missing. Never echo, log, or commit the key.
- The opencode binary is resolved from `OPENCODE_BIN`, then `~/.opencode/bin/opencode` /
  `/opt/homebrew/bin/opencode` / `/usr/local/bin/opencode`, then `PATH`. Any candidate under
  `com.conductor.app` is refused — Conductor's bundled ACP-provider copy lags the standalone
  release. Confirm `<opencode> models` lists the model before dispatching.
- Run each dispatch as a **background / long-lived task**; prefer one task per agent.
- **Parallel cap: 7** unless the user sets a lower limit.

## Prompt construction (all modes)

Every prompt starts with:
`First read <ABS_REPO>/.agents/skills/deepseek-pro-agents/references/agent-brief.md
and follow it exactly`
(implementer) or
`Read <ABS_REPO>/.agents/skills/deepseek-pro-agents/references/continuation-brief.md AND
<ABS_REPO>/.agents/skills/deepseek-pro-agents/references/agent-brief.md and follow them`
(fix/shepherd — give BOTH absolute paths).

Use only those `.agents/skills/deepseek-pro-agents/references/` paths so Claude and Codex/GPT
orchestrators share one source of truth.

Every prompt must also PIN THE WORKER'S ROLE:
"YOU are the implementer: write, commit, and push the changes yourself in this session.
Do NOT invoke agent-dispatch skills (qwen-agents, deepseek-pro-agents, deepseek-flash-agents,
opencode-agents, grok-agents, astra-agents, opus-agents, fable-agents, composer-agents,
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

- `ALIBABA_TOKEN_PLAN_API_KEY` absent from the dispatch environment — launcher exits 2. Export it
  and relaunch; do not fall back to another provider.
- opencode binary not resolvable, refused because the only candidate is under `com.conductor.app`,
  or the model absent from `opencode models` — stop and report; do not fall back to Conductor's
  bundle or to another model.
- Capacity or transport kills mid-loop — work may already be pushed; check PR state first.
- Agents may exit claiming "waiting on monitor" — treat every completion as end-of-turn.
- `pgrep -f 'opencode run'` cannot distinguish this fleet from sibling opencode skills; track PIDs
  or session handles per worker.
- Nested dispatch: if a completed run's report mentions "dispatching a worker", treat the actual
  implementing model as unknown and weight your independent diff review accordingly.
