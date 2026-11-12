#!/usr/bin/env bash
# Fetch Helios at the pinned commit and apply our patch into ./helios-patched,
# which helios-check/Cargo.toml depends on. Safe to re-run.
set -euo pipefail
cd "$(dirname "$0")"
HELIOS_REV=2922a475ef1b48476983333cbae7fc92fdb46cd6
PATCH=../helios-patch/0001-split-signature-check.patch

if [ ! -d helios-patched ]; then
  git clone https://github.com/a16z/helios helios-patched
fi
git -C helios-patched checkout -q "$HELIOS_REV"

if git -C helios-patched apply --reverse --check "$PATCH" 2>/dev/null; then
  echo "patch already applied"
else
  git -C helios-patched apply "$PATCH"
  echo "patch applied"
fi
git -C helios-patched diff --stat
