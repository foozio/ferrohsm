#!/bin/bash

# Comprehensive build and packaging script for FerroHSM Linux binaries

set -e

echo "=== FerroHSM Linux Build and Packaging Script ==="

# Get version from Cargo.toml
VERSION=$(grep '^version = ' Cargo.toml | head -1 | cut -d '"' -f 2)
echo "Project version: $VERSION"

# Clean previous builds
echo "Cleaning previous builds..."
cargo clean

# Install dependencies if needed
echo "Checking for required dependencies..."
if ! command -v pkg-config &> /dev/null; then
    echo "Installing pkg-config..."
    sudo apt-get update && sudo apt-get install -y pkg-config
fi

if ! pkg-config --exists openssl; then
    echo "Installing libssl-dev..."
    sudo apt-get install -y libssl-dev
fi

# Build the crates
echo "Building hsm-cli..."
cargo build --release -p hsm-cli

echo "Building hsm-server..."
cargo build --release -p hsm-server

# Check if binaries were created
CLI_BINARY="target/release/hsm-cli"
SERVER_BINARY="target/release/hsm-server"

if [ ! -f "$CLI_BINARY" ]; then
    echo "Error: hsm-cli binary not found at $CLI_BINARY"
    # Try to find it in deps
    CLI_DEPS=$(find target/release/deps -name "hsm_cli*" -type f -executable 2>/dev/null | head -1)
    if [ -n "$CLI_DEPS" ]; then
        echo "Found hsm-cli in deps: $CLI_DEPS"
        cp "$CLI_DEPS" "$CLI_BINARY"
    else
        echo "Error: Cannot find hsm-cli binary"
        exit 1
    fi
fi

if [ ! -f "$SERVER_BINARY" ]; then
    echo "Error: hsm-server binary not found at $SERVER_BINARY"
    # Try to find it in deps
    SERVER_DEPS=$(find target/release/deps -name "hsm_server*" -type f -executable 2>/dev/null | head -1)
    if [ -n "$SERVER_DEPS" ]; then
        echo "Found hsm-server in deps: $SERVER_DEPS"
        cp "$SERVER_DEPS" "$SERVER_BINARY"
    else
        echo "Error: Cannot find hsm-server binary"
        exit 1
    fi
fi

# Verify binaries
echo "Verifying binaries..."
if [ -f "$CLI_BINARY" ]; then
    echo "hsm-cli: $(file "$CLI_BINARY")"
    ls -la "$CLI_BINARY"
else
    echo "Error: hsm-cli binary not found"
    exit 1
fi

if [ -f "$SERVER_BINARY" ]; then
    echo "hsm-server: $(file "$SERVER_BINARY")"
    ls -la "$SERVER_BINARY"
else
    echo "Error: hsm-server binary not found"
    exit 1
fi

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

echo "=== Build Summary ==="
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
else
    echo "Warning: Homebrew formula file not found at $FORMULA_FILE"
fi

echo "=== Package ready for distribution ==="
echo "To install via Homebrew on Linux:"
echo "  brew install ./dist/homebrew-linux/ferrohsm.rb"