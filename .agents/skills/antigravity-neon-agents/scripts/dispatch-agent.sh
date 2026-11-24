#!/usr/bin/env bash

set -euo pipefail

usage() {
  printf '%s\n' \
    'Usage: dispatch-agent.sh --worktree ABS_PATH --prompt-file ABS_PATH' \
    '                         [--effort low|medium|high|xhigh]' \
    '                         [--name NAME]' \
    '' \
    'Runs the standalone Google Antigravity agy CLI headless (agy --print)' \
    'against Gemini 4 Neon (gemini-4-neon). --effort selects the Neon thinking' \
    'level (default high). Gemini 4 Neon publishes low|medium|high|xhigh only and' \
    'has no fast tier.' >&2
}

model='gemini-4-neon'
worktree=''
prompt_file=''
effort='high'
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
      printf '[antigravity-neon-agents] refusing --fast: Gemini 4 Neon has no fast tier\n' >&2
      exit 2
      ;;
    --model)
      printf '[antigravity-neon-agents] refusing --model: this skill is pinned to %s\n' \
        "$model" >&2
      exit 2
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

# Gemini 4 Neon publishes exactly low|medium|high|xhigh (`agy models` lists them
# as gemini-4-neon-<level>). agy rejects `max`, so refuse it here with the same
# answer instead of clamping: an explicit user choice is never substituted.
case "$effort" in
  low|medium|high|xhigh) ;;
  max|ultra)
    printf 'Invalid effort: %s (Gemini 4 Neon offers low|medium|high|xhigh; not clamping)\n' \
      "$effort" >&2
    exit 2
    ;;
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

agy_bin=$(resolve_agent_bin agy AGY_BIN \
  "${HOME}/.local/bin/agy" \
  /opt/homebrew/bin/agy \
  /usr/local/bin/agy)

repo_root=$(git -C "$worktree" rev-parse --show-toplevel)
physical_worktree=$(cd "$worktree" && pwd -P)
physical_root=$(cd "$repo_root" && pwd -P)

if [[ "$physical_worktree" != "$physical_root" ]]; then
  printf 'Launch path must be the git worktree root: %s\n' "$physical_root" >&2
  exit 2
fi

# agy --print takes the prompt as its value and does not read stdin, so the
# prompt travels on argv. Prompts must never contain secrets (see SKILL.md).
prompt=$(<"$prompt_file")
if [[ -z "${prompt//[[:space:]]/}" ]]; then
  printf 'Prompt file is empty: %s\n' "$prompt_file" >&2
  exit 2
fi

# Auth: agy uses GEMINI_API_KEY when exported, Application Default Credentials
# when AGY_ADC_AUTH is set, and otherwise the account sign-in stored by an
# interactive `agy` login. Never pass a key on argv; it would be visible in `ps`.
if [[ -n "${GEMINI_API_KEY:-}" ]]; then
  auth_source='GEMINI_API_KEY'
elif [[ -n "${AGY_ADC_AUTH:-}" ]]; then
  auth_source='AGY_ADC_AUTH'
else
  auth_source='agy sign-in'
fi

cd "$physical_worktree"

printf '[antigravity-neon-agents] dispatch model=%s effort=%s worktree=%s bin=%s auth=%s%s\n' \
  "$model" "$effort" "$physical_worktree" "$agy_bin" "$auth_source" \
  "${name:+ name=$name}" >&2

# --model/--effort:              Gemini 4 Neon at the selected thinking level;
#                                agy validates the pair and fails closed.
# --dangerously-skip-permissions: no approval prompts. Workers need git, GitHub,
#                                and network access; a headless run cannot
#                                answer prompts, and worktree isolation is the
#                                boundary, not a host sandbox.
# no --sandbox:                  the terminal sandbox blocks the network and
#                                ~/.config, which git and gh need.
# --disable-slash-commands:      no slash-command or skill expansion in print
#                                mode, so candidate-authored skills (including
#                                these dispatch skills) are not expanded.
# --output-format stream-json:   one NDJSON event per step for liveness; the
#                                final `result` event carries status and the
#                                conversation_id for `agy --conversation`.
# --print-timeout 0s:            wait until the turn completes.
exec "$agy_bin" \
  --model "$model" \
  --effort "$effort" \
  --dangerously-skip-permissions \
  --disable-slash-commands \
  --output-format stream-json \
  --print-timeout 0s \
  --print="$prompt" \
  < /dev/null
