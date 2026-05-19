#!/usr/bin/env bash
# Sync knowledge/ctf-reverse/ from upstream github.com/ljagiello/ctf-skills.
#
# Pulls only the ctf-reverse/ subdirectory (and LICENSE) into knowledge/ctf-reverse/.
# Records the upstream commit SHA + date in knowledge/ctf-reverse/.upstream.
#
# Usage:
#   bash scripts/sync-ctf-reverse.sh           # sync to upstream main HEAD
#   bash scripts/sync-ctf-reverse.sh --dry-run # show what would change
#
# After sync, review with `git diff knowledge/ctf-reverse/` before committing.

set -euo pipefail

UPSTREAM_URL="https://github.com/ljagiello/ctf-skills.git"
UPSTREAM_BRANCH="main"
REPO_ROOT="$(git rev-parse --show-toplevel)"
TARGET="${REPO_ROOT}/knowledge/ctf-reverse"
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

echo "[sync-ctf-reverse] shallow clone ${UPSTREAM_URL} (branch ${UPSTREAM_BRANCH})"
git clone --depth 1 --branch "${UPSTREAM_BRANCH}" "${UPSTREAM_URL}" "${TMPDIR}/ctf-skills" >/dev/null

UPSTREAM_SHA="$(git -C "${TMPDIR}/ctf-skills" rev-parse HEAD)"
TODAY="$(date -u +%Y-%m-%d)"

RSYNC_FLAGS=(-a --delete --exclude='.upstream' --exclude='LICENSE')
if [[ "${DRY_RUN}" == true ]]; then
  RSYNC_FLAGS+=(--dry-run -i)
fi

mkdir -p "${TARGET}"
echo "[sync-ctf-reverse] rsync ctf-reverse -> ${TARGET}"
rsync "${RSYNC_FLAGS[@]}" "${TMPDIR}/ctf-skills/ctf-reverse/" "${TARGET}/"

if [[ "${DRY_RUN}" == true ]]; then
  echo "[sync-ctf-reverse] dry run — .upstream not updated. upstream HEAD: ${UPSTREAM_SHA}"
  exit 0
fi

cp "${TMPDIR}/ctf-skills/LICENSE" "${TARGET}/LICENSE"

cat > "${TARGET}/.upstream" <<EOF
repo: ${UPSTREAM_URL%.git}
commit: ${UPSTREAM_SHA}
date: ${TODAY}
path: ctf-reverse/
EOF

echo "[sync-ctf-reverse] done. upstream commit: ${UPSTREAM_SHA}"
echo "[sync-ctf-reverse] review with: git diff ${TARGET#${REPO_ROOT}/}"
