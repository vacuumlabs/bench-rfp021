#!/usr/bin/env bash
# Download the consensus-specs release Helios's tests target (v1.7.0-beta.2),
# check its SHA-256, and extract the minimal-preset light-client tests into
# target/consensus-spec-tests. Then compare unpatched Helios, patched Helios
# and the three steps on all of them with:
#
#   CONSENSUS_SPEC_TESTS=$PWD/target/consensus-spec-tests/tests \
#     cargo test -p equivalence -- --include-ignored --nocapture
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
DEST="$ROOT/target/consensus-spec-tests"
URL=https://github.com/ethereum/consensus-specs/releases/download/v1.7.0-beta.2/minimal.tar.gz
SHA256=86645aa51423de5dadcc279c785c1f0d03b0e07e054232c7f36ce0e3ec7ffa37

if [[ -d "$DEST/tests/minimal" ]]; then
  echo "already there: $DEST/tests"
  exit 0
fi
mkdir -p "$DEST"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
curl -sSL -o "$TMP/minimal.tar.gz" "$URL"
if command -v sha256sum >/dev/null; then
  echo "$SHA256  $TMP/minimal.tar.gz" | sha256sum -c -
else
  echo "$SHA256  $TMP/minimal.tar.gz" | shasum -a 256 -c -
fi
tar -xzf "$TMP/minimal.tar.gz" -C "$DEST" --wildcards 'tests/minimal/*/light_client/*'
echo "extracted: $DEST/tests"
