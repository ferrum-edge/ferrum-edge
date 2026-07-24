#!/usr/bin/env bash

set -euo pipefail

usage() {
  printf '%s\n' \
    'Usage: dispatch-agent.sh --worktree ABS_PATH --prompt-file ABS_PATH' \
    '                         --effort low|medium|high|xhigh|max' \
    "                         [--model 'claude-opus-5[1m]'|'opus[1m]']" >&2
}

worktree=''
prompt_file=''
effort=''
model='claude-opus-5[1m]'

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
    --model)
      if (($# < 2)); then
        printf 'Missing value for --model\n' >&2
        usage
        exit 2
      fi
      model=${2-}
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
  low|medium|high|xhigh|max) ;;
  *)
    printf 'Invalid effort: %s\n' "${effort:-<empty>}" >&2
    usage
    exit 2
    ;;
esac

case "$model" in
  'claude-opus-5[1m]'|'opus[1m]') ;;
  *)
    printf 'Invalid model: %s\n' "$model" >&2
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

if ! command -v claude >/dev/null 2>&1; then
  printf 'claude is not installed or not on PATH\n' >&2
  exit 127
fi

repo_root=$(git -C "$worktree" rev-parse --show-toplevel)
physical_worktree=$(cd "$worktree" && pwd -P)
physical_root=$(cd "$repo_root" && pwd -P)

if [[ "$physical_worktree" != "$physical_root" ]]; then
  printf 'Launch path must be the git worktree root: %s\n' "$physical_root" >&2
  exit 2
fi

cd "$physical_worktree"

unset CLAUDE_CODE_EFFORT_LEVEL
unset CLAUDE_CODE_DISABLE_1M_CONTEXT
unset CLAUDE_CODE_DISABLE_THINKING
unset MAX_THINKING_TOKENS

exec claude -p \
  --model "$model" \
  --effort "$effort" \
  --permission-mode bypassPermissions \
  --output-format text \
  --verbose \
  < "$prompt_file"
