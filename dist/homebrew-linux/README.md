# FerroHSM Homebrew Package for Linux

This directory contains the Homebrew formula for installing FerroHSM on Linux systems.

## Installation

To install FerroHSM on Linux using Homebrew:

```bash
brew install ./ferrohsm.rb
```

Or if you want to install from a remote URL (once published):

```bash
brew install ferrohsm
```

## Package Contents

The package includes:
- `hsm-cli`: Command-line interface for managing the HSM
- `hsm-server`: HSM server daemon

## Usage

After installation, you can use the commands:

```bash
hsm-cli --help
hsm-server --help
```

## Building from Source

If you want to build the package from source:

1. Clone the repository
2. Run the packaging script:
   ```bash
   ./scripts/package_linux.sh
   ```
3. The script will create a tarball and update the Homebrew formula

## SHA256 Checksum

The current package SHA256 checksum is:
47dbe4c61f232907df1aa86a35603f3775fae10ebc114b2efa842c24c4230403

## Notes

- This package is for x86_64 Linux systems
- Requires Homebrew to be installed on your Linux system