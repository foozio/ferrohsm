# Homebrew Installation

FerroHSM is now available on Homebrew for macOS users.

## Installing via Homebrew

To install FerroHSM using Homebrew:

```bash
brew tap foozio/ferrohsm
brew install ferrohsm
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