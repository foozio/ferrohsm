#!/bin/bash

# Package FerroHSM Linux binaries for Homebrew

set -e

echo "=== FerroHSM Linux Packaging Script ==="

# Get version from Cargo.toml
VERSION=$(grep '^version = ' Cargo.toml | head -1 | cut -d '"' -f 2)
echo "Project version: $VERSION"

# Check if binaries exist
CLI_BINARY="target/release/hsm-cli"
SERVER_BINARY="target/release/hsm-server"

if [ ! -f "$CLI_BINARY" ]; then
    echo "Error: hsm-cli binary not found at $CLI_BINARY"
    exit 1
fi

if [ ! -f "$SERVER_BINARY" ]; then
    echo "Error: hsm-server binary not found at $SERVER_BINARY"
    exit 1
fi

echo "Found binaries:"
ls -la "$CLI_BINARY" "$SERVER_BINARY"

# Create package directory
echo "Creating package directory..."
PACKAGE_DIR="ferrohsm-${VERSION}-linux-x86_64"
rm -rf "$PACKAGE_DIR"
mkdir -p "$PACKAGE_DIR"

# Copy binaries
echo "Copying binaries..."
cp "$CLI_BINARY" "$PACKAGE_DIR/"
cp "$SERVER_BINARY" "$PACKAGE_DIR/"

# Create tarball
echo "Creating tarball..."
TARBALL_NAME="${PACKAGE_DIR}.tar.gz"
tar -czf "${TARBALL_NAME}" "$PACKAGE_DIR"

# Calculate SHA256
echo "Calculating SHA256 checksum..."
SHA256=$(sha256sum "${TARBALL_NAME}" | cut -d ' ' -f 1)

echo "=== Package Summary ==="
echo "Package created: ${TARBALL_NAME}"
echo "SHA256: ${SHA256}"
echo "Size: $(du -h "${TARBALL_NAME}" | cut -f1)"

# Update Homebrew formula
echo "Updating Homebrew formula..."
FORMULA_FILE="dist/homebrew-linux/ferrohsm.rb"
if [ -f "$FORMULA_FILE" ]; then
    sed -i "s|url \".*\"|url \"https://github.com/foozio/ferrohsm/releases/download/v${VERSION}/${TARBALL_NAME}\"|" "$FORMULA_FILE"
    sed -i "s/sha256 \".*\"/sha256 \"${SHA256}\"/" "$FORMULA_FILE"
    echo "Homebrew formula updated."
    
    # Show the updated formula
    echo "=== Updated Homebrew Formula ==="
    cat "$FORMULA_FILE"
else
    echo "Warning: Homebrew formula file not found at $FORMULA_FILE"
fi

echo "=== Package ready for distribution ==="
echo "To test the package:"
echo "  tar -xzf ${TARBALL_NAME}"
echo "  ./${PACKAGE_DIR}/hsm-cli --help"
echo "  ./${PACKAGE_DIR}/hsm-server --help"