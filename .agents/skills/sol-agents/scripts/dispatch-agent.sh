#!/usr/bin/env bash

set -euo pipefail

usage() {
  printf '%s\n' \
    'Usage: dispatch-agent.sh --worktree ABS_PATH --prompt-file ABS_PATH' \
    '                         --effort medium|high|xhigh' \
    '                         [--fast]' >&2
}

worktree=''
prompt_file=''
effort=''
fast='false'

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
  medium|high|xhigh) ;;
  *)
    printf 'Invalid effort: %s\n' "${effort:-<empty>}" >&2
    usage
    exit 2
    ;;
esac

service_tier='default'
if [[ "$fast" == 'true' ]]; then
  service_tier='priority'
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

codex_bin=$(resolve_agent_bin codex CODEX_BIN \
  /opt/homebrew/bin/codex \
  /usr/local/bin/codex \
  "${HOME}/.local/bin/codex")

repo_root=$(git -C "$worktree" rev-parse --show-toplevel)
physical_worktree=$(cd "$worktree" && pwd -P)
physical_root=$(cd "$repo_root" && pwd -P)

if [[ "$physical_worktree" != "$physical_root" ]]; then
  printf 'Launch path must be the git worktree root: %s\n' "$physical_root" >&2
  exit 2
fi

cd "$physical_worktree"

printf '[sol-agents] dispatch model=gpt-5.6-sol effort=%s fast=%s service_tier=%s worktree=%s bin=%s\n' \
  "$effort" "$fast" "$service_tier" "$physical_worktree" "$codex_bin" >&2

exec "$codex_bin" exec \
  --model gpt-5.6-sol \
  --config "model_reasoning_effort=\"$effort\"" \
  --config "service_tier=\"$service_tier\"" \
  --sandbox danger-full-access \
  --cd "$physical_worktree" \
  - < "$prompt_file"
