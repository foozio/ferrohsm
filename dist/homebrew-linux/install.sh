#!/bin/bash

# Simple installation script for FerroHSM on Linux
# This script downloads and installs FerroHSM binaries

set -e

echo "=== FerroHSM Linux Installer ==="

# Default values
VERSION="0.4.0"
INSTALL_DIR="/usr/local/bin"
PACKAGE_URL="https://github.com/foozio/ferrohsm/releases/download/v${VERSION}/ferrohsm-${VERSION}-linux-x86_64.tar.gz"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "This script needs to run as root. Please run with sudo:"
    echo "sudo $0"
    exit 1
fi

# Check dependencies
echo "Checking dependencies..."
if ! command -v curl &> /dev/null; then
    echo "Error: curl is required but not installed"
    exit 1
fi

if ! command -v tar &> /dev/null; then
    echo "Error: tar is required but not installed"
    exit 1
fi

# Download package
echo "Downloading FerroHSM v${VERSION}..."
TEMP_DIR=$(mktemp -d)
cd "$TEMP_DIR"
curl -L -o ferrohsm.tar.gz "$PACKAGE_URL"

# Extract package
echo "Extracting package..."
tar -xzf ferrohsm.tar.gz
cd ferrohsm-${VERSION}-linux-x86_64

# Install binaries
echo "Installing binaries to $INSTALL_DIR..."
install -m 755 hsm-cli "$INSTALL_DIR/"
install -m 755 hsm-server "$INSTALL_DIR/"

# Cleanup
cd /
rm -rf "$TEMP_DIR"

echo "=== Installation Complete ==="
echo "FerroHSM has been installed to $INSTALL_DIR"
echo "You can now use the commands:"
echo "  hsm-cli --help"
echo "  hsm-server --help"
