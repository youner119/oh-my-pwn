#!/usr/bin/env bash
# setup-omp.sh — oh-my-pwn opencode 플러그인 로컬 세팅 스크립트
#
# 하는 일:
#   1) 의존성 설치 + dist/plugin.js 빌드 (bun install → bun run build:plugin)
#      bun install은 런타임에 plugin.js가 import하는 external 패키지
#      (@opencode-ai/plugin/tool 등)를 node_modules로 가져옴. 빠뜨리면
#      opencode가 plugin 로드 실패 → agent picker에서 omp-* 안 보임.
#   2) BN MCP bridge 경로 탐지:
#      - --bn-bridge <path> 로 명시 전달
#      - 또는 ~/Tools/binary_ninja_mcp/bridge/dist/index.js 자동 탐지
#      - 둘 다 실패 시 사용자에게 interactive prompt (tty만)
#      - --skip-bn 으로 opt-out 가능 (나중에 수동 설정)
#   3) ~/.config/omp/opencode/opencode.json 생성 (plugin file:// 경로 등록)
#   4) ~/.zshrc 에 omp alias 추가:
#        alias omp="OMP_BN_BRIDGE_PATH=... XDG_CONFIG_HOME=$HOME/.config/omp opencode --port 4096"
#      이미 있으면 교체 (bridge 경로가 바뀔 수 있으므로 갱신).
#   5) opencode debug config 로 플러그인 로드 확인
#
# 사용법:
#   ./scripts/setup-omp.sh                               # 기본 — bridge auto-detect
#   ./scripts/setup-omp.sh --bn-bridge /path/to/dist/index.js
#   ./scripts/setup-omp.sh --skip-bn                     # bridge 미설정, plugin.ts가 MCP 등록 skip
#   ./scripts/setup-omp.sh --no-build                    # dist/plugin.js 재사용
#   ./scripts/setup-omp.sh --no-alias                    # zshrc 건드리지 말 것
#   ./scripts/setup-omp.sh --dry-run                     # 변경 없이 계획만 출력
#
# 다른 위치로 repo를 옮겼거나 BN MCP를 업데이트했을 때 이 스크립트를 다시 돌리면
# 플러그인/브릿지 경로가 현재 환경에 맞게 갱신됨.

set -euo pipefail

DO_BUILD=1
DO_ALIAS=1
DRY_RUN=0
SKIP_BN=0
BN_BRIDGE_OVERRIDE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-build)      DO_BUILD=0; shift ;;
    --no-alias)      DO_ALIAS=0; shift ;;
    --dry-run)       DRY_RUN=1; shift ;;
    --skip-bn)       SKIP_BN=1; shift ;;
    --bn-bridge)
      BN_BRIDGE_OVERRIDE="${2:-}"
      if [[ -z "$BN_BRIDGE_OVERRIDE" ]]; then
        echo "error: --bn-bridge requires a path argument" >&2
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

# ── 1) install + build ────────────────────────────────────────────────────────
# `bun install`은 plugin.js의 external import (@opencode-ai/plugin/tool 등)를
# node_modules에 가져온다. opencode가 plugin.js를 로드할 때 Node ESM resolver는
# plugin.js의 부모 트리에서 node_modules를 찾으므로 OmP repo 안에 있어야 함.
if [[ "$DO_BUILD" == "1" ]]; then
  say "installing dependencies (bun install)"
  run "cd '$REPO_ROOT' && bun install"
  say "building plugin (bun run build:plugin)"
  run "cd '$REPO_ROOT' && bun run build:plugin"
else
  say "skipping install + build (--no-build)"
fi

if [[ ! -f "$PLUGIN_PATH" && "$DRY_RUN" == "0" ]]; then
  echo "ERROR: $PLUGIN_PATH not found after build step" >&2
  exit 1
fi

# ── 2) BN MCP bridge discovery ───────────────────────────────────────────────
BRIDGE_PATH=""
resolve_bridge() {
  # (a) explicit override
  if [[ -n "$BN_BRIDGE_OVERRIDE" ]]; then
    if [[ -f "$BN_BRIDGE_OVERRIDE" ]]; then
      BRIDGE_PATH="$BN_BRIDGE_OVERRIDE"
      say "BN bridge: $BRIDGE_PATH (from --bn-bridge)"
      return 0
    fi
    warn "--bn-bridge path does not exist: $BN_BRIDGE_OVERRIDE"
    return 1
  fi

  # (b) auto-detect at ~/Tools/binary_ninja_mcp/bridge/dist/index.js
  local default_path="$HOME/Tools/binary_ninja_mcp/bridge/dist/index.js"
  if [[ -f "$default_path" ]]; then
    BRIDGE_PATH="$default_path"
    say "BN bridge: $BRIDGE_PATH (auto-detected)"
    return 0
  fi

  # (c) interactive prompt (fallback)
  if [[ ! -t 0 || "$DRY_RUN" == "1" ]]; then
    return 1
  fi
  printf '\n'
  printf '  BN MCP bridge (dist/index.js) not found at ~/Tools/binary_ninja_mcp/bridge/dist/index.js\n'
  printf '  Enter the absolute path (or leave empty to skip, configure later via OMP_BN_BRIDGE_PATH):\n'
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
  say "BN bridge: $BRIDGE_PATH (from prompt)"
  return 0
}

if [[ "$SKIP_BN" == "1" ]]; then
  say "skipping BN bridge discovery (--skip-bn)"
else
  if ! resolve_bridge; then
    warn "BN bridge not configured — MCP will be skipped by plugin.ts"
    warn "set OMP_BN_BRIDGE_PATH in your shell, or re-run with --bn-bridge <path>"
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
  # --port 4096: fix the server port so tmux panes can attach via opencode attach.
  if [[ -n "$BRIDGE_PATH" ]]; then
    printf 'alias omp="OMP_BN_BRIDGE_PATH=%q XDG_CONFIG_HOME=$HOME/.config/omp opencode --port 4096"' "$BRIDGE_PATH"
  else
    printf 'alias omp="XDG_CONFIG_HOME=$HOME/.config/omp opencode --port 4096"'
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
      env_prefix=(env "OMP_BN_BRIDGE_PATH=$BRIDGE_PATH")
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

# ── 6) pwno-mcp container (manual — pwno 호환성 수정: user-managed) ────────────
# OmP는 pwno-mcp 컨테이너 lifecycle을 관리하지 않는다 (pwno 호환성 수정 design). 사용자가
# omp 실행 전에 직접 docker run 해야 한다. 아래 명령을 그대로 복사해 쓰면 된다.
# (workspace mount 는 이 repo 의 workspace/ 폴더로 고정 — omp-setup
# agent 가 Phase 5 에서 challenge 파일을 거기로 복사한다.)
printf '\n'
say "pwno-mcp container is user-managed. Start it before running omp:"
printf '  docker run -d --name omp-pwno \\\n'
printf '    -p 5500:5500 \\\n'
printf '    --cap-add=SYS_PTRACE --cap-add=SYS_ADMIN \\\n'
printf '    --security-opt seccomp=unconfined \\\n'
printf '    -v "%s:/workspace" \\\n' "$REPO_ROOT/workspace"
printf '    ghcr.io/pwno-io/pwno-mcp:latest\n'
printf '\n'
printf '  # health check:\n'
printf '  curl -s http://127.0.0.1:5500/mcp -o /dev/null -w "HTTP %%{http_code}\\n"  # 406 = up\n'
