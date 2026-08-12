#!/usr/bin/env bash

set -euo pipefail

usage() {
  printf '%s\n' \
    'Usage: dispatch-agent.sh --worktree ABS_PATH --prompt-file ABS_PATH' \
    '                         --effort medium|high' >&2
}

worktree=''
prompt_file=''
effort=''

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

case "$effort" in
  medium|high) ;;
  *)
    printf 'Invalid effort: %s\n' "${effort:-<empty>}" >&2
    usage
    exit 2
    ;;
esac

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

claude_bin=$(resolve_agent_bin claude CLAUDE_BIN \
  "${HOME}/.local/bin/claude" \
  /opt/homebrew/bin/claude \
  /usr/local/bin/claude)

repo_root=$(git -C "$worktree" rev-parse --show-toplevel)
physical_worktree=$(cd "$worktree" && pwd -P)
physical_root=$(cd "$repo_root" && pwd -P)

if [[ "$physical_worktree" != "$physical_root" ]]; then
  printf 'Launch path must be the git worktree root: %s\n' "$physical_root" >&2
  exit 2
fi

cd "$physical_worktree"

unset ANTHROPIC_MODEL
unset CLAUDE_CODE_EFFORT_LEVEL
unset CLAUDE_CODE_DISABLE_1M_CONTEXT
unset CLAUDE_CODE_DISABLE_THINKING
unset MAX_THINKING_TOKENS

printf '[fable-agents] dispatch model=claude-fable-5 effort=%s worktree=%s bin=%s\n' \
  "$effort" "$physical_worktree" "$claude_bin" >&2

exec "$claude_bin" -p \
  --model claude-fable-5 \
  --effort "$effort" \
  --permission-mode bypassPermissions \
  --output-format text \
  --verbose \
  < "$prompt_file"
