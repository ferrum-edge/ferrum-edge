#!/usr/bin/env bash

set -euo pipefail

usage() {
  printf '%s\n' \
    'Usage: dispatch-agent.sh --worktree ABS_PATH --prompt-file ABS_PATH' \
    '                         [--effort medium|high|xhigh|max]' \
    '                         [--name NAME]' \
    '' \
    'Note: --effort is accepted for CLI parity with sibling agent skills but is' \
    'ignored. Composer has no effort tiers; model is always composer-2.5.' >&2
}

worktree=''
prompt_file=''
effort=''
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

if [[ -n "$effort" ]]; then
  case "$effort" in
    medium|high|xhigh|max)
      printf '[composer-agents] ignoring --effort %s: Composer has no effort tiers\n' \
        "$effort" >&2
      ;;
    *)
      printf 'Invalid effort: %s\n' "$effort" >&2
      usage
      exit 2
      ;;
  esac
fi

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

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
runner="$script_dir/run-cursor-agent.mjs"

if [[ ! -f "$runner" ]]; then
  printf 'Missing runner script: %s\n' "$runner" >&2
  exit 2
fi

conductor_bin_dir=${CONDUCTOR_INTERNAL_BIN_DIR:-"${HOME}/Library/Application Support/com.conductor.app/bin"}
node_bin="$conductor_bin_dir/.internal/node"
worker_mjs="$conductor_bin_dir/.internal/cursor-node-worker.mjs"

if [[ ! -x "$node_bin" ]]; then
  printf 'Conductor Node runtime not found at %s\n' "$node_bin" >&2
  printf 'Install/open Conductor.app so its Cursor harness is available.\n' >&2
  exit 127
fi

if [[ ! -f "$worker_mjs" ]]; then
  printf 'Conductor Cursor worker not found at %s\n' "$worker_mjs" >&2
  exit 127
fi

if [[ -z "${CURSOR_API_KEY:-}" ]]; then
  if ! CURSOR_API_KEY=$(
    security find-generic-password \
      -s 'com.conductor.app.production.settings' \
      -a 'env:local:shared:CURSOR_API_KEY' \
      -w 2>/dev/null
  ); then
    printf 'CURSOR_API_KEY is not available.\n' >&2
    printf 'Export CURSOR_API_KEY or add a Cursor API key in Conductor provider settings.\n' >&2
    exit 127
  fi
  export CURSOR_API_KEY
fi

export CONDUCTOR_INTERNAL_BIN_DIR="$conductor_bin_dir"
export CONDUCTOR_CURSOR_SDK_REQUIRE_PATH="${CONDUCTOR_CURSOR_SDK_REQUIRE_PATH:-$worker_mjs}"
export CONDUCTOR_WORKSPACE_PATH="$physical_worktree"

cd "$physical_worktree"

launch_args=(
  "$node_bin"
  "$runner"
  --worktree "$physical_worktree"
  --prompt-file "$prompt_file"
)

if [[ -n "$effort" ]]; then
  launch_args+=(--effort "$effort")
fi

if [[ -n "$name" ]]; then
  launch_args+=(--name "$name")
fi

printf '[composer-agents] dispatch model=composer-2.5 worktree=%s\n' \
  "$physical_worktree" >&2

exec "${launch_args[@]}"
