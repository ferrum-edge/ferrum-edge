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
