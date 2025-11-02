# Homebrew Installation

FerroHSM is now available on Homebrew for both macOS and Linux users.

## Installing via Homebrew

### macOS

To install FerroHSM on macOS using Homebrew:

```bash
brew tap foozio/ferrohsm
brew install ferrohsm
```

### Linux

To install FerroHSM on Linux using Homebrew:

```bash
brew install ./dist/homebrew-linux/ferrohsm.rb
```

This will install the `ferrohsm` CLI tool, which can be used to interact with the FerroHSM server.

## Verifying Installation

After installation, you can verify that FerroHSM is properly installed by checking the version:

```bash
ferrohsm --version
```

You can also view the available commands:

```bash
ferrohsm --help
```

## Updating

To update FerroHSM to the latest version:

```bash
brew update
brew upgrade ferrohsm
```

## Uninstalling

To uninstall FerroHSM:

```bash
brew uninstall ferrohsm
```

## Troubleshooting

If you encounter any issues during installation:

1. Make sure you have the latest version of Homebrew:
   ```bash
   brew update
   ```

2. If you have previously installed FerroHSM from a different tap, you may need to uninstall it first:
   ```bash
   brew uninstall ferrohsm
   ```

3. Try installing with the fully qualified name:
   ```bash
   brew install foozio/ferrohsm/ferrohsm
   ```