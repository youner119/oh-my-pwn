#!/usr/bin/env bash
# bootstrap-deps.sh — oh-my-pwn 외부 의존성 프로비저닝 (첫 머신 부트스트랩)
#
# setup-omp.sh 는 `~/Tools/pwno-mcp` / `~/Tools/binary_ninja_mcp` fork 가
# *이미 있다고 가정*하고 repo 를 opencode 에 맞춰 세팅한다. 이 스크립트는 그
# 전 단계 — 두 fork 를 clone 하고 MCP 서버를 빌드해서 그 가정을 충족시킨다.
#
# 하는 일:
#   1) 전제 도구 확인 (git / docker / node·npm / bun). 설치는 안 함 — 없으면 stop.
#   2) pwno-mcp fork clone (~/Tools/pwno-mcp) + upstream remote 등록 +
#      `pwno-mcp:latest` 도커 이미지 빌드 (docker-build.local.sh).
#   3) binary_ninja_mcp fork clone (~/Tools/binary_ninja_mcp) + bridge 빌드
#      (npm install && npm run build) + BN plugin symlink
#      (~/.binaryninja/plugins/binary_ninja_mcp).
#   4) Binary Ninja 본체는 상용 GUI라 설치 불가 — port 9009 (BN MCP HTTP)
#      reachable 여부만 확인 + 안내.
#   5) 끝에 setup-omp.sh 체이닝 (repo 세팅 + opencode.json + alias).
#
# 재실행: clone 된 repo 는 기본 skip (fork 로컬 변경 보호). --update 줄 때만 pull.
# 도커 이미지도 이미 있으면 skip, --update 시 재빌드.
#
# 사용법:
#   ./scripts/bootstrap-deps.sh                    # 전체 부트스트랩 + setup-omp 체이닝
#   ./scripts/bootstrap-deps.sh --update           # 기존 repo git pull + 재빌드
#   ./scripts/bootstrap-deps.sh --skip-bn          # BN MCP 건너뜀 (pwno 만)
#   ./scripts/bootstrap-deps.sh --skip-pwno        # pwno-mcp 도커 빌드 건너뜀
#   ./scripts/bootstrap-deps.sh --no-chain         # setup-omp.sh 호출 안 함
#   ./scripts/bootstrap-deps.sh --dry-run          # 변경 없이 계획만 출력
#
# 환경변수 override:
#   OMP_TOOLS_DIR     (기본 ~/Tools)                        — clone 위치
#   OMP_PWNO_REPO     (기본 https://github.com/youner119/pwno-mcp.git)
#   OMP_BN_REPO       (기본 https://github.com/youner119/binary_ninja_mcp.git)
#   OMP_PWNO_UPSTREAM (기본 https://github.com/pwno-io/pwno-mcp.git)
#   OMP_BN_PORT       (기본 9009)                            — BN MCP HTTP 확인 포트

set -euo pipefail

DRY_RUN=0
DO_UPDATE=0
SKIP_BN=0
SKIP_PWNO=0
DO_CHAIN=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)   DRY_RUN=1; shift ;;
    --update)    DO_UPDATE=1; shift ;;
    --skip-bn)   SKIP_BN=1; shift ;;
    --skip-pwno) SKIP_PWNO=1; shift ;;
    --no-chain)  DO_CHAIN=0; shift ;;
    -h|--help)
      sed -n '2,47p' "$0"
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

TOOLS_DIR="${OMP_TOOLS_DIR:-$HOME/Tools}"
PWNO_REPO="${OMP_PWNO_REPO:-https://github.com/youner119/pwno-mcp.git}"
PWNO_UPSTREAM="${OMP_PWNO_UPSTREAM:-https://github.com/pwno-io/pwno-mcp.git}"
BN_REPO="${OMP_BN_REPO:-https://github.com/youner119/binary_ninja_mcp.git}"
BN_PORT="${OMP_BN_PORT:-9009}"

PWNO_DIR="$TOOLS_DIR/pwno-mcp"
BN_DIR="$TOOLS_DIR/binary_ninja_mcp"
BN_PLUGIN_LINK="$HOME/.binaryninja/plugins/binary_ninja_mcp"

say()  { printf '\033[1;34m[bootstrap]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[bootstrap]\033[0m WARN: %s\n' "$*" >&2; }
err()  { printf '\033[1;31m[bootstrap]\033[0m ERROR: %s\n' "$*" >&2; }
run() {
  if [[ "$DRY_RUN" == "1" ]]; then
    printf '  (dry-run) %s\n' "$*"
  else
    eval "$@"
  fi
}

say "repo root:   $REPO_ROOT"
say "tools dir:   $TOOLS_DIR"
say "pwno-mcp:    $PWNO_REPO -> $PWNO_DIR"
say "bn-mcp:      $BN_REPO -> $BN_DIR"

# ── 1) 전제 도구 확인 (설치하지 않음) ───────────────────────────────
need_tool() {
  # $1 = command, $2 = 안내 문구
  if ! command -v "$1" >/dev/null 2>&1; then
    err "'$1' 없음 — $2"
    return 1
  fi
  return 0
}

MISSING=0
need_tool git    "git 설치 필요 (repo clone)."                       || MISSING=1
if [[ "$SKIP_PWNO" == "0" ]]; then
  need_tool docker "docker 설치 필요 (pwno-mcp 이미지 빌드). --skip-pwno 로 건너뛸 수 있음." || MISSING=1
fi
if [[ "$SKIP_BN" == "0" ]]; then
  need_tool npm  "node/npm 설치 필요 (BN bridge 빌드). --skip-bn 으로 건너뛸 수 있음." || MISSING=1
fi
if [[ "$DO_CHAIN" == "1" ]]; then
  need_tool bun  "bun 설치 필요 (setup-omp.sh 체이닝). --no-chain 으로 건너뛸 수 있음." || MISSING=1
fi
if [[ "$MISSING" == "1" ]]; then
  err "전제 도구가 빠졌다. 위 항목 설치 후 다시 실행."
  exit 1
fi

mkdir -p "$TOOLS_DIR" 2>/dev/null || true

# ── clone_or_update helper ──────────────────────────────────────────
# $1 = target dir, $2 = origin url, $3 = 이름(로그용), $4 = upstream url (선택)
clone_or_update() {
  local dir="$1" url="$2" name="$3" upstream="${4:-}"
  if [[ -d "$dir/.git" ]]; then
    if [[ "$DO_UPDATE" == "1" ]]; then
      say "$name: 기존 clone 발견 → git pull (--update)"
      run "git -C '$dir' pull --ff-only"
    else
      say "$name: 기존 clone 발견 → skip (--update 시 pull)"
    fi
  elif [[ -e "$dir" ]]; then
    warn "$name: '$dir' 가 git repo 가 아님 — 손대지 않음. 수동 확인 필요."
    return 1
  else
    say "$name: clone → $dir"
    run "git clone '$url' '$dir'"
  fi
  # upstream remote 등록 (fork 추적용, 없을 때만)
  if [[ -n "$upstream" && "$DRY_RUN" == "0" && -d "$dir/.git" ]]; then
    if ! git -C "$dir" remote get-url upstream >/dev/null 2>&1; then
      run "git -C '$dir' remote add upstream '$upstream'"
    fi
  fi
  return 0
}

# ── 2) pwno-mcp: clone + 도커 빌드 ─────────────────────────────────
if [[ "$SKIP_PWNO" == "1" ]]; then
  say "pwno-mcp: --skip-pwno → 건너뜀"
else
  clone_or_update "$PWNO_DIR" "$PWNO_REPO" "pwno-mcp" "$PWNO_UPSTREAM" || true

  # 도커 이미지 빌드 — 이미 있으면 skip, --update 시 재빌드
  IMAGE_EXISTS=0
  if [[ "$DRY_RUN" == "0" ]] && docker image inspect pwno-mcp:latest >/dev/null 2>&1; then
    IMAGE_EXISTS=1
  fi
  if [[ "$IMAGE_EXISTS" == "1" && "$DO_UPDATE" == "0" ]]; then
    say "pwno-mcp: 이미지 pwno-mcp:latest 존재 → 빌드 skip (--update 시 재빌드)"
  elif [[ -d "$PWNO_DIR" || "$DRY_RUN" == "1" ]]; then
    say "pwno-mcp: docker 이미지 빌드 (pwno-mcp:latest)"
    if [[ -x "$PWNO_DIR/docker-build.local.sh" ]]; then
      run "cd '$PWNO_DIR' && ./docker-build.local.sh"
    else
      run "cd '$PWNO_DIR' && docker build --platform linux/amd64 -t pwno-mcp:latest ."
    fi
  else
    warn "pwno-mcp: clone 실패로 도커 빌드 skip."
  fi
fi

# ── 3) binary_ninja_mcp: clone + bridge 빌드 + plugin symlink ──────
if [[ "$SKIP_BN" == "1" ]]; then
  say "bn-mcp: --skip-bn → 건너뜀"
else
  clone_or_update "$BN_DIR" "$BN_REPO" "bn-mcp" || true

  # bridge 빌드 (npm install && npm run build → dist/index.js)
  if [[ -f "$BN_DIR/bridge/package.json" || "$DRY_RUN" == "1" ]]; then
    say "bn-mcp: bridge 빌드 (npm install && npm run build)"
    run "cd '$BN_DIR/bridge' && npm install && npm run build"
  else
    warn "bn-mcp: bridge/package.json 없음 — bridge 빌드 skip."
  fi

  # BN plugin symlink — ~/.binaryninja/plugins 가 있어야(BN 설치+최초 실행 흔적)
  if [[ -d "$HOME/.binaryninja/plugins" || "$DRY_RUN" == "1" ]]; then
    if [[ -L "$BN_PLUGIN_LINK" || -e "$BN_PLUGIN_LINK" ]]; then
      say "bn-mcp: plugin symlink 이미 존재 → skip ($BN_PLUGIN_LINK)"
    else
      say "bn-mcp: plugin symlink 생성 ($BN_DIR -> $BN_PLUGIN_LINK)"
      run "ln -s '$BN_DIR' '$BN_PLUGIN_LINK'"
    fi
  else
    warn "bn-mcp: ~/.binaryninja/plugins 없음 — Binary Ninja 미설치이거나 한 번도 실행 안 함."
    warn "  BN GUI 를 한 번 실행한 뒤 이 스크립트를 다시 돌리면 plugin symlink 가 걸린다."
  fi

  # 4) BN MCP HTTP (port) reachable 확인 — 소프트 (GUI + plugin 활성화 필요)
  if [[ "$DRY_RUN" == "0" ]] && command -v curl >/dev/null 2>&1; then
    if curl -sS -m 3 "http://localhost:$BN_PORT/status" >/dev/null 2>&1; then
      say "bn-mcp: port $BN_PORT 응답 확인 ✓ (BN MCP HTTP up)"
    else
      warn "bn-mcp: port $BN_PORT 무응답 — BN GUI 실행 + Plugins 메뉴에서 BN MCP 활성화 필요."
      warn "  (Binary Ninja 본체는 상용 GUI라 이 스크립트가 설치/기동하지 않는다.)"
    fi
  fi
fi

# ── 5) setup-omp.sh 체이닝 ─────────────────────────────────────────
if [[ "$DO_CHAIN" == "1" ]]; then
  say "setup-omp.sh 체이닝 (repo 세팅 + opencode.json + alias)"
  CHAIN_ARGS=()
  [[ "$DRY_RUN" == "1" ]] && CHAIN_ARGS+=(--dry-run)
  [[ "$SKIP_BN" == "1" ]] && CHAIN_ARGS+=(--skip-bn)
  run "bash '$SCRIPT_DIR/setup-omp.sh' ${CHAIN_ARGS[*]:-}"
else
  say "--no-chain → setup-omp.sh 호출 안 함. 별도로 './scripts/setup-omp.sh' 실행 필요."
fi

say "부트스트랩 완료."
