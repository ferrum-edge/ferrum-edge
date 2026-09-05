---
name: astra-agents
description: Dispatch and orchestrate GPT-6 Astra CLI subagents (low|medium|high|xhigh|max|ultra effort) for Ferrum Edge issue, PR, review-feedback, CI-repair, and shepherding work. Use when the user asks Claude to delegate to GPT-6 Astra workers. Do not use when you are a dispatched worker or for ordinary single-agent edits.
---

# GPT-6 Astra agents

Act as the orchestrator. Read and follow the shared workflow in
[the canonical skill](../../../.agents/skills/astra-agents/SKILL.md), interpreting its Codex
orchestrator role as your Claude orchestrator role. Use the shared launcher and references;
do not duplicate them in this directory.

```bash
<ABS_REPO>/.agents/skills/astra-agents/scripts/dispatch-agent.sh \
  --worktree <ABS_WORKER_WORKTREE> \
  --prompt-file <ABS_PROMPT_FILE> \
  --effort <low|medium|high|xhigh|max|ultra>
```

Read the canonical skill before dispatch for effort selection, preflight, isolation, failure
handling, and verification. For implementer mode, read
[agent-brief.md](../../../.agents/skills/astra-agents/references/agent-brief.md).
For fix-round or shepherd mode, also read
[continuation-brief.md](../../../.agents/skills/astra-agents/references/continuation-brief.md).
Resolve all worker paths to absolute paths. Run each worker in its own background or long-lived
execution session and retain that session's identity. Honor the user's selected effort without
clamping or substituting. Never recursively invoke this skill from a dispatched worker.

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
