#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

# Simple bootstrapper: run local scripts/install.sh if present,
# otherwise download and execute it from the repo.

SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
TARGET_SCRIPT="${SCRIPT_DIR}/scripts/install.sh"
REMOTE_URL="${KERNAGENT_INSTALL_URL:-https://raw.githubusercontent.com/Karib0u/kernagent/main/scripts/install.sh}"

if [[ -f "$TARGET_SCRIPT" ]]; then
  exec "$TARGET_SCRIPT" "$@"
fi

tmp="$(mktemp)"
cleanup(){ rm -f "$tmp"; }
trap cleanup EXIT

if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$REMOTE_URL" -o "$tmp"
elif command -v wget >/dev/null 2>&1; then
  wget -qO "$tmp" "$REMOTE_URL"
else
  echo "[x] curl or wget is required" >&2
  exit 1
fi
chmod +x "$tmp"
exec "$tmp" "$@"
