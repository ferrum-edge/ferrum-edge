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
      printf '[opencode-agents] ignoring --effort %s: opencode zen models have no effort tiers\n' \
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

repo_root=$(git -C "$worktree" rev-parse --show-toplevel)
physical_worktree=$(cd "$worktree" && pwd -P)
physical_root=$(cd "$repo_root" && pwd -P)

if [[ "$physical_worktree" != "$physical_root" ]]; then
  printf 'Launch path must be the git worktree root: %s\n' "$physical_root" >&2
  exit 2
fi

# Resolve the opencode binary. Preference order: explicit OPENCODE_BIN, then a
# standalone install on PATH, then the newest opencode that Conductor bundles as
# an ACP provider (not on PATH by default).
opencode_bin=''
if [[ -n "${OPENCODE_BIN:-}" ]]; then
  if [[ ! -x "$OPENCODE_BIN" ]]; then
    printf 'OPENCODE_BIN is set but not executable: %s\n' "$OPENCODE_BIN" >&2
    exit 127
  fi
  opencode_bin="$OPENCODE_BIN"
elif command -v opencode >/dev/null 2>&1; then
  opencode_bin=$(command -v opencode)
else
  conductor_oc_base="${HOME}/Library/Application Support/com.conductor.app/agent-binaries/acp-providers/opencode"
  if [[ -d "$conductor_oc_base" ]]; then
    opencode_bin=$(
      find "$conductor_oc_base" -maxdepth 2 -mindepth 2 -name opencode -type f -perm -u+x 2>/dev/null \
        | sort -V \
        | tail -1
    )
  fi
fi

if [[ -z "$opencode_bin" || ! -x "$opencode_bin" ]]; then
  printf 'opencode CLI not found.\n' >&2
  printf 'Set OPENCODE_BIN, put opencode on PATH, or open Conductor.app so its bundled opencode is available.\n' >&2
  exit 127
fi

cd "$physical_worktree"

printf '[opencode-agents] dispatch model=%s worktree=%s bin=%s\n' \
  "$model" "$physical_worktree" "$opencode_bin" >&2

# `run` reads the prompt from stdin; --auto bypasses permission prompts (worktree
# isolation is the safety boundary); --agent build selects the write-enabled agent.
exec "$opencode_bin" run \
  --model "$model" \
  --agent build \
  --auto \
  < "$prompt_file"
