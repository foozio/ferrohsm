#!/usr/bin/env bash
# This script packages FerroHSM for Homebrew distribution
# It builds all binaries, creates tarballs, and updates the Homebrew formulas
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
DIST_DIR="$ROOT_DIR/dist/homebrew"
VERSION=${1:-$(grep -m1 '^version' "$ROOT_DIR/Cargo.toml" | cut -d '"' -f2)}
TARGET=${2:-macos}
ARCHIVE_NAME="ferrohsm-${VERSION}-${TARGET}.tar.gz"
STAGE_DIR="$DIST_DIR/stage"

echo "Building all binaries for release (version ${VERSION})"
pushd "$ROOT_DIR" >/dev/null
cargo build --release --bins
popd >/dev/null

mkdir -p "$STAGE_DIR"
rm -f "$DIST_DIR"/ferrohsm-*.tar.gz
rm -rf "$STAGE_DIR"/*

# Copy all binaries
install -m 0755 "$ROOT_DIR/target/release/hsm-cli" "$STAGE_DIR/hsm-cli"
install -m 0755 "$ROOT_DIR/target/release/hsm-server" "$STAGE_DIR/hsm-server"
install -m 0755 "$ROOT_DIR/target/release/hsm-tui" "$STAGE_DIR/hsm-tui"

# Copy PKCS#11 library if it exists
if [ -f "$ROOT_DIR/target/release/libhsm_pkcs11.dylib" ]; then
    install -m 0755 "$ROOT_DIR/target/release/libhsm_pkcs11.dylib" "$STAGE_DIR/libhsm_pkcs11.dylib"
elif [ -f "$ROOT_DIR/target/release/libhsm_pkcs11.so" ]; then
    install -m 0755 "$ROOT_DIR/target/release/libhsm_pkcs11.so" "$STAGE_DIR/libhsm_pkcs11.so"
fi

pushd "$STAGE_DIR" >/dev/null
tar -czf "$DIST_DIR/$ARCHIVE_NAME" *
popd >/dev/null

SHA256=$(shasum -a 256 "$DIST_DIR/$ARCHIVE_NAME" | awk '{print $1}')

# Update the appropriate Homebrew formula with the new version and SHA256
if [ "$TARGET" = "macos" ]; then
    FORMULA_FILE="$DIST_DIR/ferrohsm.rb"
    FORMULA_URL="https://github.com/foozio/ferrohsm/releases/download/v${VERSION}/$ARCHIVE_NAME"
else
    FORMULA_FILE="$ROOT_DIR/dist/homebrew-linux/ferrohsm.rb"
    FORMULA_URL="https://github.com/foozio/ferrohsm/releases/download/v${VERSION}/$ARCHIVE_NAME"
fi

if [ -f "$FORMULA_FILE" ]; then
    sed -i '' "s|url \".*\"|url \"$FORMULA_URL\"|" "$FORMULA_FILE"
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
  url "$FORMULA_URL"
  sha256 "$SHA256"
  version "$VERSION"
  license "MIT"

  def install
    bin.install "hsm-cli" => "ferrohsm"
    bin.install "hsm-server"
    bin.install "hsm-tui"
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
