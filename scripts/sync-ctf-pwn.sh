#!/usr/bin/env bash
# Sync knowledge/ctf-pwn/ from upstream github.com/ljagiello/ctf-skills.
#
# Pulls only the ctf-pwn/ subdirectory (and LICENSE) into knowledge/ctf-pwn/.
# Records the upstream commit SHA + date in knowledge/ctf-pwn/.upstream.
#
# Usage:
#   bash scripts/sync-ctf-pwn.sh           # sync to upstream main HEAD
#   bash scripts/sync-ctf-pwn.sh --dry-run # show what would change
#
# After sync, review with `git diff knowledge/ctf-pwn/` before committing.

set -euo pipefail

UPSTREAM_URL="https://github.com/ljagiello/ctf-skills.git"
UPSTREAM_BRANCH="main"
REPO_ROOT="$(git rev-parse --show-toplevel)"
TARGET="${REPO_ROOT}/knowledge/ctf-pwn"
DRY_RUN=false

for arg in "$@"; do
  case "${arg}" in
    --dry-run) DRY_RUN=true ;;
    -h | --help)
      sed -n '2,12p' "$0"
      exit 0
      ;;
    *)
      echo "unknown arg: ${arg}" >&2
      exit 2
      ;;
  esac
done

TMPDIR="$(mktemp -d)"
trap 'rm -rf "${TMPDIR}"' EXIT

echo "[sync-ctf-pwn] shallow clone ${UPSTREAM_URL} (branch ${UPSTREAM_BRANCH})"
git clone --depth 1 --branch "${UPSTREAM_BRANCH}" "${UPSTREAM_URL}" "${TMPDIR}/ctf-skills" >/dev/null

UPSTREAM_SHA="$(git -C "${TMPDIR}/ctf-skills" rev-parse HEAD)"
TODAY="$(date -u +%Y-%m-%d)"

RSYNC_FLAGS=(-a --delete --exclude='.upstream' --exclude='LICENSE')
if [[ "${DRY_RUN}" == true ]]; then
  RSYNC_FLAGS+=(--dry-run -i)
fi

mkdir -p "${TARGET}"
echo "[sync-ctf-pwn] rsync ctf-pwn -> ${TARGET}"
rsync "${RSYNC_FLAGS[@]}" "${TMPDIR}/ctf-skills/ctf-pwn/" "${TARGET}/"

if [[ "${DRY_RUN}" == true ]]; then
  echo "[sync-ctf-pwn] dry run — .upstream not updated. upstream HEAD: ${UPSTREAM_SHA}"
  exit 0
fi

cp "${TMPDIR}/ctf-skills/LICENSE" "${TARGET}/LICENSE"

cat > "${TARGET}/.upstream" <<EOF
repo: ${UPSTREAM_URL%.git}
commit: ${UPSTREAM_SHA}
date: ${TODAY}
path: ctf-pwn/
EOF

echo "[sync-ctf-pwn] done. upstream commit: ${UPSTREAM_SHA}"
echo "[sync-ctf-pwn] review with: git diff ${TARGET#${REPO_ROOT}/}"
