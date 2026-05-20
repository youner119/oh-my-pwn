#!/usr/bin/env bash
# Thin wrapper around sync-vendored.sh for the ctf-pwn vendor.
# See `bash scripts/sync-vendored.sh --help` for details and flags.
exec "$(dirname "$0")/sync-vendored.sh" ctf-pwn "$@"
