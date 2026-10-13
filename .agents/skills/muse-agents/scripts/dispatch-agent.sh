#!/usr/bin/env bash

set -euo pipefail

usage() {
  printf '%s\n' \
    'Usage: dispatch-agent.sh --worktree ABS_PATH --prompt-file ABS_PATH' \
    '                         [--effort low|medium|high|xhigh|max|ultra]' \
    '                         [--name NAME]' \
    '' \
    'Runs the standalone Muse Code `muse` CLI headless (`muse exec`) against' \
    'Muse Wonder Full (muse-wonder-full-1.0). --effort is passed through as' \
    'the Muse reasoning effort (default high). Muse Wonder Full has no fast tier.' >&2
}

model='muse-wonder-full-1.0'
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
      printf '[muse-agents] refusing --fast: Muse Wonder Full has no fast tier\n' >&2
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

# Muse publishes none|minimal|low|medium|high|xhigh|max|ultra. Implementation
# workers use low and above; the tier is passed through unchanged.
case "$effort" in
  low|medium|high|xhigh|max|ultra) ;;
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

muse_bin=$(resolve_agent_bin muse MUSE_BIN \
  "${HOME}/.local/bin/muse" \
  /opt/homebrew/bin/muse \
  /usr/local/bin/muse)

repo_root=$(git -C "$worktree" rev-parse --show-toplevel)
physical_worktree=$(cd "$worktree" && pwd -P)
physical_root=$(cd "$repo_root" && pwd -P)

if [[ "$physical_worktree" != "$physical_root" ]]; then
  printf 'Launch path must be the git worktree root: %s\n' "$physical_root" >&2
  exit 2
fi

# Auth: muse reads META_API_KEY from the environment and gives it priority over
# the stored account login (`muse login`). Never pass the key on argv — it would
# be visible in `ps`. An inherited MUSE_MODEL must not compete with the pin.
if [[ -n "${META_API_KEY:-}" ]]; then
  auth_source='META_API_KEY'
else
  auth_source='muse login'
fi
unset MUSE_MODEL

cd "$physical_worktree"

printf '[muse-agents] dispatch model=%s effort=%s worktree=%s bin=%s auth=%s%s\n' \
  "$model" "$effort" "$physical_worktree" "$muse_bin" "$auth_source" \
  "${name:+ name=$name}" >&2

# exec:                       headless, one prompt.
# --disable-approval/-sandbox: no approval prompts or OS sandbox; workers need
#                             git, GitHub, and network access, and worktree
#                             isolation is the boundary.
# no --trust-workspace/--yolo: the worktree stays untrusted, so candidate
#                             project rules and skills (including these
#                             dispatch skills) are not auto-loaded and Muse's
#                             own automatic agent delegation stays off.
# --user-input-auto-resolve:  cancel interactive questions instead of hanging.
exec "$muse_bin" exec \
  --model "$model" \
  --reasoning-effort "$effort" \
  --disable-approval \
  --disable-sandbox \
  --user-input-auto-resolve \
  --workspace "$physical_worktree" \
  --prompt-file "$prompt_file" \
  < /dev/null
