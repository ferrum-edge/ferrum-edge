#!/usr/bin/env bash

set -euo pipefail

usage() {
  printf '%s\n' \
    'Usage: dispatch-agent.sh --worktree ABS_PATH --prompt-file ABS_PATH' \
    '                         [--model alibaba-token-plan/deepseek-v4.1-flash]' \
    '                         [--effort medium|high|xhigh|max]' \
    '' \
    'Pinned to alibaba-token-plan/deepseek-v4.1-flash. --model is accepted only when' \
    'it names that exact model; any other value is refused. The dated snapshot' \
    'is the only variant this skill dispatches.' \
    '' \
    'Requires ALIBABA_TOKEN_PLAN_API_KEY (or ALIBABA_TOKEN_PLAN_API_KEY_FILE naming' \
    'a readable file holding it); the provider block in opencode.json resolves the' \
    'key from the process environment.' \
    '' \
    'Note: --effort is accepted for CLI parity with sibling agent skills but is' \
    'ignored. This provider exposes no documented effort tiers.' >&2
}

worktree=''
prompt_file=''
model='alibaba-token-plan/deepseek-v4.1-flash'
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
      printf '[deepseek-pro-agents] ignoring --effort %s: %s exposes no effort tiers\n' \
        "$effort" "$model" >&2
      ;;
    *)
      printf 'Invalid effort: %s\n' "$effort" >&2
      usage
      exit 2
      ;;
  esac
fi

# Hard pin: this skill dispatches exactly one model variant. --model survives only
# for CLI parity with sibling skills and to let a caller restate the pin; it cannot
# select a different Qwen/DeepSeek variant or a rolling alias.
readonly PINNED_MODEL='alibaba-token-plan/deepseek-v4.1-flash'
if [[ "$model" != "$PINNED_MODEL" ]]; then
  printf 'Refusing model: %s\n' "$model" >&2
  printf 'This skill is pinned to %s and dispatches no other variant.\n' \
    "$PINNED_MODEL" >&2
  usage
  exit 2
fi

if [[ "$worktree" != /* || ! -d "$worktree" ]]; then
  printf 'Worktree must be an existing absolute directory: %s\n' "${worktree:-<empty>}" >&2
  exit 2
fi

if [[ "$prompt_file" != /* || ! -f "$prompt_file" ]]; then
  printf 'Prompt file must be an existing absolute file: %s\n' "${prompt_file:-<empty>}" >&2
  exit 2
fi

# The provider block resolves {env:ALIBABA_TOKEN_PLAN_API_KEY} from the process
# environment. A non-interactive dispatch session does not source the operator's
# shell profile, so fail closed here with the remediation instead of letting
# opencode surface a bare "No API-key provided" several seconds into the run.
if [[ -z "${ALIBABA_TOKEN_PLAN_API_KEY:-}" && -n "${ALIBABA_TOKEN_PLAN_API_KEY_FILE:-}" ]]; then
  key_file=${ALIBABA_TOKEN_PLAN_API_KEY_FILE}
  if [[ "$key_file" != /* || ! -r "$key_file" ]]; then
    printf 'ALIBABA_TOKEN_PLAN_API_KEY_FILE must be a readable absolute path: %s\n' \
      "$key_file" >&2
    exit 2
  fi
  ALIBABA_TOKEN_PLAN_API_KEY=$(tr -d '\r\n' < "$key_file")
  export ALIBABA_TOKEN_PLAN_API_KEY
fi

if [[ -z "${ALIBABA_TOKEN_PLAN_API_KEY:-}" ]]; then
  printf 'ALIBABA_TOKEN_PLAN_API_KEY is not set in this environment.\n' >&2
  printf 'Export it (or set ALIBABA_TOKEN_PLAN_API_KEY_FILE to a file holding it)\n' >&2
  printf 'before dispatching; %s cannot authenticate without it.\n' "$model" >&2
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

printf '[deepseek-pro-agents] dispatch model=%s worktree=%s bin=%s\n' \
  "$model" "$physical_worktree" "$opencode_bin" >&2

# `run` reads the prompt from stdin; --auto bypasses permission prompts (worktree
# isolation is the safety boundary); --agent build selects the write-enabled agent.
exec "$opencode_bin" run \
  --model "$model" \
  --agent build \
  --auto \
  < "$prompt_file"
