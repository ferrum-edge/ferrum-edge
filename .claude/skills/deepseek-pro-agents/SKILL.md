---
name: deepseek-pro-agents
description: Dispatch and orchestrate local opencode DeepSeek V4 Pro subagents via the opencode CLI harness for ferrum-edge issue/PR work — implementer, fix-round, and shepherd modes, with worktree isolation and the review loop. DeepSeek V4 Pro is the deep-reasoning tier, suited to invariant-heavy security, protocol, and concurrency work. Use when the user asks Claude to spawn DeepSeek Pro/deepseek-v4-pro agents on issues, PRs, review findings, or red CI.
---

# DeepSeek V4 Pro agents

Act as the orchestrator. Read and follow the shared workflow in
[the canonical skill](../../../.agents/skills/deepseek-pro-agents/SKILL.md), interpreting its Codex
orchestrator role as your Claude orchestrator role. Use the shared launcher and references;
do not duplicate them in this directory.

```bash
<ABS_REPO>/.agents/skills/deepseek-pro-agents/scripts/dispatch-agent.sh \
  --worktree <ABS_WORKER_WORKTREE> \
  --prompt-file <ABS_PROMPT_FILE>
```

`--effort` is accepted for CLI parity but ignored; never claim an effort level was applied.

Read the canonical skill before dispatch for preflight, isolation, prompt construction, failure
handling, and verification. For implementer mode, read
[agent-brief.md](../../../.agents/skills/deepseek-pro-agents/references/agent-brief.md).
For fix-round or shepherd mode, also read
[continuation-brief.md](../../../.agents/skills/deepseek-pro-agents/references/continuation-brief.md).
Resolve all worker paths to absolute paths. Run each worker in its own background or long-lived
execution session and retain that session's identity. Never recursively invoke this skill from a
dispatched worker.
A worker that exits claiming it is "waiting on monitor" has ended its turn; treat every exit as a
completion and verify its state.

## Remote CI validation

Do not run local builds, tests, benchmarks, or compilation-based checks, including `cargo build`,
`cargo test`, `cargo check`, and `cargo clippy`, or wrappers that invoke them. Do not make an
exception for a targeted check, an ambiguous failure, or a controller's routine validation request.
Local source inspection, formatting with `cargo fmt`, and `git diff --check` are allowed.

Use remote CI results for the exact pushed head SHA as build/test confirmation. Inspect failed
job logs, fix the demonstrated failure, push the change, and use the next CI run to confirm it.
Pending, skipped, unavailable, or earlier-head checks are not evidence that the change passed.
Keep adding or updating relevant tests; remote CI executes them.

The controller owns post-push CI monitoring unless the worker is explicitly assigned a CI repair
or shepherd round. A worker assigned to exit after pushing must report the head SHA and CI status
as pending or unverified and exit; the controller continues the CI-driven fix loop. Never report
build/test success without matching remote evidence.

Include the no-local-build/test rule and remote CI confirmation requirement in every dispatch
prompt, including continuation prompts and any permitted nested delegation.
