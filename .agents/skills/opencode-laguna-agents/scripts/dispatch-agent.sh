#!/usr/bin/env bash

set -euo pipefail

usage() {
  printf '%s\n' \
    'Usage: dispatch-agent.sh --worktree ABS_PATH --prompt-file ABS_PATH' \
    '                         [--model opencode/<model>]' \
    '                         [--effort medium|high|xhigh|max]' \
    '' \
    'Defaults model to opencode/laguna-s-2.1-free. --model may select any' \
    'opencode/* zen model (e.g. opencode/deepseek-v4-pro).' \
    '' \
    'Note: --effort is accepted for CLI parity with sibling agent skills but is' \
    'ignored. The opencode zen free models expose no documented effort tiers.' >&2
}

worktree=''
prompt_file=''
model='opencode/laguna-s-2.1-free'
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
    --model)
      if (($# < 2)); then
        printf 'Missing value for --model\n' >&2
        usage
        exit 2
      fi
      model=${2-}
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

if [[ -n "$effort" ]]; then
  case "$effort" in
    medium|high|xhigh|max)
      printf '[opencode-laguna-agents] ignoring --effort %s: opencode zen models have no effort tiers\n' \
        "$effort" >&2
      ;;
    *)
      printf 'Invalid effort: %s\n' "$effort" >&2
      usage
      exit 2
      ;;
  esac
fi

case "$model" in
  opencode/*) ;;
  *)
    printf 'Invalid model: %s (must be an opencode/* zen model)\n' "$model" >&2
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

repo_root=$(git -C "$worktree" rev-parse --show-toplevel)
physical_worktree=$(cd "$worktree" && pwd -P)
physical_root=$(cd "$repo_root" && pwd -P)

if [[ "$physical_worktree" != "$physical_root" ]]; then
  printf 'Launch path must be the git worktree root: %s\n' "$physical_root" >&2
  exit 2
fi

# Resolve the operator's own opencode install. Conductor's bundled ACP-provider
# copy under agent-binaries/acp-providers/opencode is deliberately NOT a fallback:
# it lags the standalone release and is refused by the shared resolver.
opencode_bin=$(resolve_agent_bin opencode OPENCODE_BIN \
  "${HOME}/.opencode/bin/opencode" \
  /opt/homebrew/bin/opencode \
  /usr/local/bin/opencode)

cd "$physical_worktree"

printf '[opencode-laguna-agents] dispatch model=%s worktree=%s bin=%s\n' \
  "$model" "$physical_worktree" "$opencode_bin" >&2

# `run` reads the prompt from stdin; --auto bypasses permission prompts (worktree
# isolation is the safety boundary); --agent build selects the write-enabled agent.
exec "$opencode_bin" run \
  --model "$model" \
  --agent build \
  --auto \
  < "$prompt_file"
