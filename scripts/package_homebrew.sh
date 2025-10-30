#!/usr/bin/env bash
# This script packages FerroHSM for Homebrew distribution
# It builds the hsm-cli binary, creates a tarball, and updates the Homebrew formula
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

# Update the Homebrew formula with the new version and SHA256
FORMULA_FILE="$DIST_DIR/ferrohsm.rb"
if [ -f "$FORMULA_FILE" ]; then
    sed -i '' "s|url \".*\"|url \"https://github.com/foozio/ferrohsm/releases/download/v${VERSION}/$ARCHIVE_NAME\"|" "$FORMULA_FILE"
    sed -i '' "s/sha256 \".*\"/sha256 \"$SHA256\"/" "$FORMULA_FILE"
    sed -i '' "s/version \".*\"/version \"$VERSION\"/" "$FORMULA_FILE"
    echo "Homebrew formula updated with new version and SHA256"
else
    echo "Homebrew formula file not found, creating a new one..."
    cat > "$FORMULA_FILE" <<EOF
# frozen_string_literal: true
class Ferrohsm < Formula
  desc "Software-based Hardware Security Module implemented in Rust"
  homepage "https://github.com/foozio/ferrohsm"
  url "https://github.com/foozio/ferrohsm/releases/download/v${VERSION}/$ARCHIVE_NAME"
  sha256 "$SHA256"
  version "$VERSION"
  license "MIT"

  def install
    bin.install "hsm-cli" => "ferrohsm"
  end

  test do
    assert_match "hsm-cli", shell_output("\#{bin}/ferrohsm --help")
  end
end
EOF
fi

cat <<EOF
Archive created: $DIST_DIR/$ARCHIVE_NAME
SHA256: $SHA256

To publish on Homebrew:
1. Upload $DIST_DIR/$ARCHIVE_NAME to GitHub Releases
2. Create a tap repository named homebrew-ferrohsm
3. Copy $FORMULA_FILE to your tap repository
4. Users can install with: brew tap foozio/ferrohsm && brew install ferrohsm

See docs/homebrew/README.md for detailed instructions.
EOF
