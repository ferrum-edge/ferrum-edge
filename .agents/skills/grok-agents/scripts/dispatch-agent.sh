#!/usr/bin/env bash

set -euo pipefail

usage() {
  printf '%s\n' \
    'Usage: dispatch-agent.sh --worktree ABS_PATH --prompt-file ABS_PATH' \
    '                         [--effort low|medium|high|xhigh|max]' \
    '                         [--fast]' \
    '                         [--name NAME]' \
    '' \
    'Runs the standalone `cursor-agent` CLI in print mode against a Cursor Grok' \
    '4.6 SKU. --effort selects the SKU (default high); Cursor exposes' \
    'low/medium/high/xhigh, so max resolves to xhigh.' >&2
}

worktree=''
prompt_file=''
effort='high'
fast='false'
name=''

while (($#)); do
  case "$1" in
    --worktree)
      if (($# < 2)); then
        printf 'Missing value for --worktree\n' >&2
        usage
        exit 2
      fi
      worktree=${2-}
      shift 2
      ;;
    --prompt-file)
      if (($# < 2)); then
        printf 'Missing value for --prompt-file\n' >&2
        usage
        exit 2
      fi
      prompt_file=${2-}
      shift 2
      ;;
    --effort)
      if (($# < 2)); then
        printf 'Missing value for --effort\n' >&2
        usage
        exit 2
      fi
      effort=${2-}
      shift 2
      ;;
    --fast)
      fast='true'
      shift
      ;;
    --name)
      if (($# < 2)); then
        printf 'Missing value for --name\n' >&2
        usage
        exit 2
      fi
      name=${2-}
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'Unknown argument: %s\n' "$1" >&2
      usage
      exit 2
      ;;
  esac
done

# Cursor publishes standard and Fast variants for four Grok 4.6 reasoning
# tiers, so max clamps to xhigh rather than silently pretending a higher tier
# was applied. Fast selection happens only after the effort mapping.
case "$effort" in
  low) model='cursor-grok-4.6-low' ;;
  medium) model='cursor-grok-4.6-medium' ;;
  high) model='cursor-grok-4.6-high' ;;
  xhigh) model='cursor-grok-4.6-xhigh' ;;
  max)
    model='cursor-grok-4.6-xhigh'
    printf '[grok-agents] clamping --effort %s to xhigh: Cursor Grok 4.6 tops out at xhigh\n' \
      "$effort" >&2
    ;;
  *)
    printf 'Invalid effort: %s\n' "${effort:-<empty>}" >&2
    usage
    exit 2
    ;;
esac

if [[ "$fast" == 'true' ]]; then
  model="${model}-fast"
fi

if [[ "$worktree" != /* || ! -d "$worktree" ]]; then
  printf 'Worktree must be an existing absolute directory: %s\n' "${worktree:-<empty>}" >&2
  exit 2
fi

if [[ "$prompt_file" != /* || ! -f "$prompt_file" ]]; then
  printf 'Prompt file must be an existing absolute file: %s\n' "${prompt_file:-<empty>}" >&2
  exit 2
fi

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
# shellcheck source=../../_lib/resolve-agent-bin.sh
. "$script_dir/../../_lib/resolve-agent-bin.sh"

cursor_bin=$(resolve_agent_bin cursor-agent CURSOR_AGENT_BIN \
  "${HOME}/.local/bin/cursor-agent" \
  /opt/homebrew/bin/cursor-agent \
  /usr/local/bin/cursor-agent)

repo_root=$(git -C "$worktree" rev-parse --show-toplevel)
physical_worktree=$(cd "$worktree" && pwd -P)
physical_root=$(cd "$repo_root" && pwd -P)

if [[ "$physical_worktree" != "$physical_root" ]]; then
  printf 'Launch path must be the git worktree root: %s\n' "$physical_root" >&2
  exit 2
fi

# Auth: cursor-agent reads CURSOR_API_KEY from the environment when it is
# exported, and otherwise uses the CLI's own stored login (`cursor-agent status`).
# Current Cursor CLI releases can initialize the default macOS credential
# manager before reaching their environment-key fallback. Force the process-local
# memory store for API-key runs so they never consult or mutate Keychain. Never
# pass the key on argv — it would be visible in `ps`.
if [[ -n "${CURSOR_API_KEY:-}" ]]; then
  auth_source='CURSOR_API_KEY'
  export AGENT_CLI_CREDENTIAL_STORE=memory
else
  auth_source='cursor-agent login'
fi

cd "$physical_worktree"

printf '[grok-agents] dispatch model=%s effort=%s fast=%s worktree=%s bin=%s auth=%s%s\n' \
  "$model" "$effort" "$fast" "$physical_worktree" "$cursor_bin" "$auth_source" \
  "${name:+ name=$name}" >&2

# --print: non-interactive, full tool access (read, write, shell).
# --force:  no per-command approval prompts; worktree isolation is the boundary.
# --trust:  accept the freshly created worktree as a trusted directory, which the
#           trust gate otherwise blocks on in a non-TTY.
exec "$cursor_bin" \
  --print \
  --force \
  --trust \
  --model "$model" \
  --output-format text \
  --workspace "$physical_worktree" \
  < "$prompt_file"
