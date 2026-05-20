#!/usr/bin/env bash
# Thin wrapper around sync-vendored.sh for the how2heap vendor.
# See `bash scripts/sync-vendored.sh --help` for details and flags.
exec "$(dirname "$0")/sync-vendored.sh" how2heap "$@"
