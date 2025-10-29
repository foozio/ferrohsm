# Summary of Changes to poc_demo.sh

## Issues Fixed

1. **Certificate Generation**: Fixed the OpenSSL certificate generation commands to work properly on macOS.

2. **Server Startup**: Ensured the server starts with proper TLS certificates and waits for it to be ready before sending requests.

3. **CLI Certificate Trust**: Added an `--insecure` option to the CLI to skip certificate verification for local development.

4. **Key ID Extraction**: Fixed the parsing of key IDs from CLI output.

5. **Error Handling**: Added proper error handling and logging throughout the script.

## Changes Made

### 1. Added `--insecure` option to CLI
- Modified `crates/hsm-cli/src/main.rs` to add an `--insecure` flag
- Updated the `build_client` function to use `danger_accept_invalid_certs(true)` when the insecure flag is set

### 2. Fixed certificate generation
- Simplified the OpenSSL commands to work properly on macOS
- Removed complex SAN configuration that was causing issues

### 3. Improved server readiness checking
- Added a loop to wait for the server to be ready before sending requests
- Used `nc` to check if the port is open

### 4. Updated CLI function to use insecure option
- Modified the `run_cli` function to use the `--insecure` flag
- This allows the CLI to connect to the server with self-signed certificates

## Known Issues

1. **Encryption Operations**: There is a bug in the server implementation that causes a stack overflow when handling encryption requests. This needs to be fixed in the server code.

2. **Post-Quantum Algorithms**: The CLI doesn't currently support post-quantum algorithms like ML-DSA. These were removed from the demo script until support is added.

## Usage

The fixed script can be run with:
```bash
./poc_demo_fixed.sh
```

It will:
1. Generate temporary credentials
2. Create a self-signed TLS certificate
3. Start the FerroHSM server
4. Create AES and RSA keys
5. List the created keys
6. Clean up all temporary files on exit

The script demonstrates the core functionality of FerroHSM and can be used as a starting point for further development and testing.