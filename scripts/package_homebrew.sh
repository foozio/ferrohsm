#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
DIST_DIR="$ROOT_DIR/dist/homebrew"
VERSION=${1:-$(grep -m1 '^version' "$ROOT_DIR/Cargo.toml" | cut -d '"' -f2)}
TARGET=${2:-macos}
ARCHIVE_NAME="ferrohsm-${VERSION}-${TARGET}.tar.gz"
STAGE_DIR="$DIST_DIR/stage"

echo "Building hsm-cli for release (version ${VERSION})"
pushd "$ROOT_DIR" >/dev/null
cargo build --release --bin hsm-cli
popd >/dev/null

mkdir -p "$STAGE_DIR"
rm -f "$DIST_DIR"/ferrohsm-*.tar.gz
rm -rf "$STAGE_DIR"/*
install -m 0755 "$ROOT_DIR/target/release/hsm-cli" "$STAGE_DIR/hsm-cli"

pushd "$STAGE_DIR" >/dev/null
tar -czf "$DIST_DIR/$ARCHIVE_NAME" hsm-cli
popd >/dev/null

SHA256=$(shasum -a 256 "$DIST_DIR/$ARCHIVE_NAME" | awk '{print $1}')

cat <<EOF
Archive created: $DIST_DIR/$ARCHIVE_NAME
SHA256: $SHA256

Suggested Homebrew formula snippet:

  url "https://github.com/foozio/ferrohsm/releases/download/v${VERSION}/$ARCHIVE_NAME"
  sha256 "$SHA256"

EOF
