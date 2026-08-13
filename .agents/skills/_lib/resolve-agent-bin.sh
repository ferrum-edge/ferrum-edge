# shellcheck shell=bash
#
# Shared agent-CLI binary resolution for .agents/skills/*/scripts/dispatch-agent.sh.
#
# Every dispatch launcher must run the operator's OWN CLI install, never a copy
# bundled inside Conductor.app. Conductor's `agent-binaries/` and `bin/.internal/`
# trees lag behind the standalone releases (as of 2026-08-12: claude 2.1.220 vs
# 2.1.228, codex 0.146.0 vs 0.147.0, opencode 1.17.19 vs 1.18.16), and a
# Conductor-injected PATH can silently shadow the newer binary.
#
# Resolution order, per CLI:
#   1. the skill's explicit env override (CODEX_BIN, CLAUDE_BIN, ...)
#   2. the well-known standalone install paths for that CLI
#   3. PATH
# Any candidate whose path lives under com.conductor.app is refused at every
# step, so a stale bundle produces a hard error instead of a silent downgrade.

agent_bin_is_conductor_owned() {
  case "$1" in
    *com.conductor.app*) return 0 ;;
    *) return 1 ;;
  esac
}

# resolve_agent_bin <command-name> <env-var-name> [candidate-abs-path...]
# Prints the resolved absolute path on stdout; diagnostics go to stderr.
resolve_agent_bin() {
  local cmd=$1 env_var=$2
  shift 2

  local override=${!env_var:-}
  if [[ -n "$override" ]]; then
    if [[ "$override" != /* || ! -x "$override" ]]; then
      printf '%s is set but is not an executable absolute path: %s\n' \
        "$env_var" "$override" >&2
      return 127
    fi
    if agent_bin_is_conductor_owned "$override"; then
      printf '%s points at a Conductor-bundled binary: %s\n' "$env_var" "$override" >&2
      printf 'Conductor bundles lag behind; point %s at your own %s install.\n' \
        "$env_var" "$cmd" >&2
      return 127
    fi
    printf '%s\n' "$override"
    return 0
  fi

  local candidate
  for candidate in "$@"; do
    if [[ -x "$candidate" ]] && ! agent_bin_is_conductor_owned "$candidate"; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done

  if command -v "$cmd" >/dev/null 2>&1; then
    candidate=$(command -v "$cmd")
    if agent_bin_is_conductor_owned "$candidate"; then
      printf '%s on PATH resolves to a Conductor-bundled binary: %s\n' \
        "$cmd" "$candidate" >&2
      printf 'Install %s standalone or set %s to your own install.\n' "$cmd" "$env_var" >&2
      return 127
    fi
    printf '%s\n' "$candidate"
    return 0
  fi

  printf '%s CLI not found.\n' "$cmd" >&2
  printf 'Install it standalone or set %s to an absolute path.\n' "$env_var" >&2
  return 127
}
