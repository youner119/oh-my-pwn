#!/usr/bin/env bash
# Sync a vendored knowledge subdirectory from its upstream repo.
#
# Vendors are listed in the case block below. Each case sets:
#   UPSTREAM_URL    — git repo URL
#   UPSTREAM_BRANCH — branch to clone (default: main)
#   SUBPATH         — subpath within the repo, or "" for the repo root
#
# Pulls the configured subpath into knowledge/<vendor>/ via rsync -a --delete.
# Records upstream commit SHA + date in knowledge/<vendor>/.upstream.
#
# Usage:
#   bash scripts/sync-vendored.sh <vendor>           # sync to upstream HEAD
#   bash scripts/sync-vendored.sh <vendor> --dry-run # show what would change
#
# Examples:
#   bash scripts/sync-vendored.sh ctf-pwn
#   bash scripts/sync-vendored.sh how2heap --dry-run

set -euo pipefail

VENDOR=""
DRY_RUN=false

for arg in "$@"; do
  case "${arg}" in
    --dry-run) DRY_RUN=true ;;
    -h | --help)
      sed -n '2,19p' "$0"
      exit 0
      ;;
    -*)
      echo "unknown flag: ${arg}" >&2
      exit 2
      ;;
    *)
      if [[ -z "${VENDOR}" ]]; then
        VENDOR="${arg}"
      else
        echo "unexpected positional arg: ${arg}" >&2
        exit 2
      fi
      ;;
  esac
done

if [[ -z "${VENDOR}" ]]; then
  echo "missing vendor name. usage: $0 <vendor> [--dry-run]" >&2
  exit 2
fi

UPSTREAM_URL=""
UPSTREAM_BRANCH="main"
SUBPATH=""

case "${VENDOR}" in
  ctf-pwn)
    UPSTREAM_URL="https://github.com/ljagiello/ctf-skills.git"
    SUBPATH="ctf-pwn"
    ;;
  ctf-reverse)
    UPSTREAM_URL="https://github.com/ljagiello/ctf-skills.git"
    SUBPATH="ctf-reverse"
    ;;
  how2heap)
    UPSTREAM_URL="https://github.com/shellphish/how2heap.git"
    UPSTREAM_BRANCH="master"
    SUBPATH=""
    ;;
  *)
    echo "unknown vendor: ${VENDOR}" >&2
    echo "known vendors: ctf-pwn, ctf-reverse, how2heap" >&2
    exit 2
    ;;
esac

REPO_ROOT="$(git rev-parse --show-toplevel)"
TARGET="${REPO_ROOT}/knowledge/${VENDOR}"

TMPDIR="$(mktemp -d)"
trap 'rm -rf "${TMPDIR}"' EXIT

CLONE_DIR="${TMPDIR}/upstream"

echo "[sync-${VENDOR}] shallow clone ${UPSTREAM_URL} (branch ${UPSTREAM_BRANCH})"
git clone --depth 1 --branch "${UPSTREAM_BRANCH}" "${UPSTREAM_URL}" "${CLONE_DIR}" >/dev/null

UPSTREAM_SHA="$(git -C "${CLONE_DIR}" rev-parse HEAD)"
TODAY="$(date -u +%Y-%m-%d)"

if [[ -n "${SUBPATH}" ]]; then
  SRC="${CLONE_DIR}/${SUBPATH}/"
  PATH_META="${SUBPATH}/"
else
  SRC="${CLONE_DIR}/"
  PATH_META="/"
fi

RSYNC_FLAGS=(-a --delete --exclude='.upstream' --exclude='LICENSE' --exclude='.git')
if [[ "${DRY_RUN}" == true ]]; then
  RSYNC_FLAGS+=(--dry-run -i)
fi

mkdir -p "${TARGET}"
echo "[sync-${VENDOR}] rsync ${PATH_META} -> ${TARGET}"
rsync "${RSYNC_FLAGS[@]}" "${SRC}" "${TARGET}/"

if [[ "${DRY_RUN}" == true ]]; then
  echo "[sync-${VENDOR}] dry run — .upstream not updated. upstream HEAD: ${UPSTREAM_SHA}"
  exit 0
fi

if [[ -f "${CLONE_DIR}/LICENSE" ]]; then
  cp "${CLONE_DIR}/LICENSE" "${TARGET}/LICENSE"
else
  echo "[sync-${VENDOR}] warning: upstream has no LICENSE file at repo root" >&2
fi

cat > "${TARGET}/.upstream" <<EOF
repo: ${UPSTREAM_URL%.git}
commit: ${UPSTREAM_SHA}
date: ${TODAY}
path: ${PATH_META}
EOF

echo "[sync-${VENDOR}] done. upstream commit: ${UPSTREAM_SHA}"
echo "[sync-${VENDOR}] review with: git diff ${TARGET#${REPO_ROOT}/}"
