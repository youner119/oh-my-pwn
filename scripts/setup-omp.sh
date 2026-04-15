#!/usr/bin/env bash
# setup-omp.sh — oh-my-pwn opencode 플러그인 로컬 세팅 스크립트
#
# 하는 일:
#   1) dist/plugin.js 빌드 (bun run build:plugin)
#   2) ghidra-mcp bridge 경로 탐지:
#      - --ghidra-bridge <path> 로 명시 전달
#      - 또는 ~/Tools/ghidra_*_PUBLIC/bridge_mcp_ghidra.py 자동 glob
#      - 둘 다 실패 시 사용자에게 interactive prompt (tty만)
#      - --skip-ghidra 로 opt-out 가능 (나중에 수동 설정)
#   3) ~/.config/omp/opencode/opencode.json 생성 (plugin file:// 경로 등록)
#   4) ~/.zshrc 에 omp alias 추가:
#        alias omp="OMP_GHIDRA_BRIDGE_PATH=... XDG_CONFIG_HOME=$HOME/.config/omp opencode"
#      이미 있으면 교체 (bridge 경로가 바뀔 수 있으므로 갱신).
#   5) opencode debug config 로 플러그인 로드 확인
#
# 사용법:
#   ./scripts/setup-omp.sh                               # 기본 — bridge auto-detect
#   ./scripts/setup-omp.sh --ghidra-bridge /path/to/bridge_mcp_ghidra.py
#   ./scripts/setup-omp.sh --skip-ghidra                 # bridge 미설정, plugin.ts가 MCP 등록 skip
#   ./scripts/setup-omp.sh --no-build                    # dist/plugin.js 재사용
#   ./scripts/setup-omp.sh --no-alias                    # zshrc 건드리지 말 것
#   ./scripts/setup-omp.sh --dry-run                     # 변경 없이 계획만 출력
#
# 다른 위치로 repo를 옮겼거나 Ghidra를 업그레이드했을 때 이 스크립트를 다시 돌리면
# 플러그인/브릿지 경로가 현재 환경에 맞게 갱신됨.

set -euo pipefail

DO_BUILD=1
DO_ALIAS=1
DRY_RUN=0
SKIP_GHIDRA=0
GHIDRA_BRIDGE_OVERRIDE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-build)      DO_BUILD=0; shift ;;
    --no-alias)      DO_ALIAS=0; shift ;;
    --dry-run)       DRY_RUN=1; shift ;;
    --skip-ghidra)   SKIP_GHIDRA=1; shift ;;
    --ghidra-bridge)
      GHIDRA_BRIDGE_OVERRIDE="${2:-}"
      if [[ -z "$GHIDRA_BRIDGE_OVERRIDE" ]]; then
        echo "error: --ghidra-bridge requires a path argument" >&2
        exit 2
      fi
      shift 2
      ;;
    -h|--help)
      sed -n '2,30p' "$0"
      exit 0
      ;;
    *)
      echo "unknown arg: $1" >&2
      exit 2
      ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PLUGIN_PATH="$REPO_ROOT/dist/plugin.js"
CONFIG_DIR="$HOME/.config/omp/opencode"
CONFIG_FILE="$CONFIG_DIR/opencode.json"
ZSHRC="$HOME/.zshrc"

say() { printf '\033[1;34m[setup-omp]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[setup-omp]\033[0m WARN: %s\n' "$*" >&2; }
run() {
  if [[ "$DRY_RUN" == "1" ]]; then
    printf '  (dry-run) %s\n' "$*"
  else
    eval "$@"
  fi
}

say "repo root:   $REPO_ROOT"
say "plugin path: $PLUGIN_PATH"

# ── 1) build ──────────────────────────────────────────────────────────────────
if [[ "$DO_BUILD" == "1" ]]; then
  say "building plugin (bun run build:plugin)"
  run "cd '$REPO_ROOT' && bun run build:plugin"
else
  say "skipping build (--no-build)"
fi

if [[ ! -f "$PLUGIN_PATH" && "$DRY_RUN" == "0" ]]; then
  echo "ERROR: $PLUGIN_PATH not found after build step" >&2
  exit 1
fi

# ── 2) ghidra bridge discovery ────────────────────────────────────────────────
BRIDGE_PATH=""
resolve_bridge() {
  # (a) explicit override
  if [[ -n "$GHIDRA_BRIDGE_OVERRIDE" ]]; then
    if [[ -f "$GHIDRA_BRIDGE_OVERRIDE" ]]; then
      BRIDGE_PATH="$GHIDRA_BRIDGE_OVERRIDE"
      say "ghidra bridge: $BRIDGE_PATH (from --ghidra-bridge)"
      return 0
    fi
    warn "--ghidra-bridge path does not exist: $GHIDRA_BRIDGE_OVERRIDE"
    return 1
  fi

  # (b) auto-detect under ~/Tools/ghidra_*_PUBLIC/
  local candidates=()
  shopt -s nullglob
  for cand in "$HOME"/Tools/ghidra_*_PUBLIC/bridge_mcp_ghidra.py; do
    candidates+=("$cand")
  done
  shopt -u nullglob

  if [[ ${#candidates[@]} -eq 1 ]]; then
    BRIDGE_PATH="${candidates[0]}"
    say "ghidra bridge: $BRIDGE_PATH (auto-detected)"
    return 0
  elif [[ ${#candidates[@]} -gt 1 ]]; then
    say "multiple ghidra bridge candidates found:"
    local i=1
    for cand in "${candidates[@]}"; do
      printf '  [%d] %s\n' "$i" "$cand"
      ((i++))
    done
    if [[ -t 0 && "$DRY_RUN" == "0" ]]; then
      printf '  pick one [1-%d]: ' "${#candidates[@]}"
      read -r pick
      if [[ "$pick" =~ ^[0-9]+$ ]] && (( pick >= 1 && pick <= ${#candidates[@]} )); then
        BRIDGE_PATH="${candidates[$((pick - 1))]}"
        say "ghidra bridge: $BRIDGE_PATH"
        return 0
      fi
      warn "invalid choice — falling back to interactive prompt"
    fi
  fi

  # (c) interactive prompt (fallback)
  if [[ ! -t 0 || "$DRY_RUN" == "1" ]]; then
    return 1
  fi
  printf '\n'
  printf '  ghidra bridge (bridge_mcp_ghidra.py) not found under ~/Tools/ghidra_*_PUBLIC/\n'
  printf '  Enter the absolute path (or leave empty to skip, configure later via OMP_GHIDRA_BRIDGE_PATH):\n'
  printf '  > '
  read -r user_path
  if [[ -z "$user_path" ]]; then
    return 1
  fi
  # expand leading ~/
  user_path="${user_path/#\~/$HOME}"
  if [[ ! -f "$user_path" ]]; then
    warn "path does not exist: $user_path"
    return 1
  fi
  BRIDGE_PATH="$user_path"
  say "ghidra bridge: $BRIDGE_PATH (from prompt)"
  return 0
}

if [[ "$SKIP_GHIDRA" == "1" ]]; then
  say "skipping ghidra bridge discovery (--skip-ghidra)"
else
  if ! resolve_bridge; then
    warn "ghidra bridge not configured — MCP will be skipped by plugin.ts"
    warn "set OMP_GHIDRA_BRIDGE_PATH in your shell, or re-run with --ghidra-bridge <path>"
  fi
fi

# ── 3) opencode.json ──────────────────────────────────────────────────────────
say "writing $CONFIG_FILE"
run "mkdir -p '$CONFIG_DIR'"
if [[ "$DRY_RUN" == "1" ]]; then
  printf '  (dry-run) would write:\n'
  cat <<EOF
{
  "\$schema": "https://opencode.ai/config.json",
  "plugin": ["file://$PLUGIN_PATH"]
}
EOF
else
  cat > "$CONFIG_FILE" <<EOF
{
  "\$schema": "https://opencode.ai/config.json",
  "plugin": ["file://$PLUGIN_PATH"]
}
EOF
fi

# ── 4) zshrc alias ────────────────────────────────────────────────────────────
build_alias_line() {
  if [[ -n "$BRIDGE_PATH" ]]; then
    printf 'alias omp="OMP_GHIDRA_BRIDGE_PATH=%q XDG_CONFIG_HOME=$HOME/.config/omp opencode"' "$BRIDGE_PATH"
  else
    printf 'alias omp="XDG_CONFIG_HOME=$HOME/.config/omp opencode"'
  fi
}
ALIAS_LINE="$(build_alias_line)"

if [[ "$DO_ALIAS" == "1" ]]; then
  if [[ -f "$ZSHRC" ]] && grep -Fq 'alias omp=' "$ZSHRC"; then
    say "updating existing omp alias in $ZSHRC"
    if [[ "$DRY_RUN" == "1" ]]; then
      printf '  (dry-run) would replace with:\n    %s\n' "$ALIAS_LINE"
    else
      # Portable in-place replacement: rewrite file to a tmp, then mv.
      tmpfile="$(mktemp)"
      awk -v repl="$ALIAS_LINE" '
        /^alias omp=/ { print repl; next }
        { print }
      ' "$ZSHRC" > "$tmpfile"
      mv "$tmpfile" "$ZSHRC"
    fi
  else
    say "appending omp alias to $ZSHRC"
    if [[ "$DRY_RUN" == "1" ]]; then
      printf '  (dry-run) would append:\n    %s\n' "$ALIAS_LINE"
    else
      printf '\n# oh-my-pwn (added by scripts/setup-omp.sh)\n%s\n' "$ALIAS_LINE" >> "$ZSHRC"
    fi
  fi
else
  say "skipping alias (--no-alias)"
fi

# ── 5) verify ─────────────────────────────────────────────────────────────────
if command -v opencode >/dev/null 2>&1; then
  say "verifying plugin load (opencode debug config)"
  if [[ "$DRY_RUN" == "0" ]]; then
    env_prefix=()
    if [[ -n "$BRIDGE_PATH" ]]; then
      env_prefix=(env "OMP_GHIDRA_BRIDGE_PATH=$BRIDGE_PATH")
    fi
    XDG_CONFIG_HOME="$HOME/.config/omp" "${env_prefix[@]}" opencode debug config 2>&1 \
      | grep -E "omp-(orchestrator|reverser)" >/dev/null || {
      warn "omp agents not visible in 'opencode debug config' output"
      warn "run manually: XDG_CONFIG_HOME=\$HOME/.config/omp opencode debug config"
    }
    say "plugin loaded OK"
  fi
else
  say "opencode CLI not on PATH — skipping verify step"
fi

say "done."
say "new shell session:"
printf '  source ~/.zshrc && omp\n'
