# FerroHSM PKCS#11 Interface

This crate provides a PKCS#11 compatible interface for FerroHSM, allowing it to be used with standard PKCS#11 applications and tools.

## Overview

The PKCS#11 interface allows FerroHSM to be used as a standard cryptographic token that can be accessed through the PKCS#11 API. This enables integration with a wide range of applications and tools that support PKCS#11, including:

- OpenSSL
- SSH
- Web browsers
- Certificate management tools
- Custom applications using PKCS#11 libraries

## Features

- **Key Management**: Generate, store, and manage cryptographic keys
- **Cryptographic Operations**: Sign, verify, encrypt, and decrypt data
- **Object Handling**: Manage PKCS#11 objects and attributes
- **Session Management**: Handle user sessions and authentication
- **Hardware Integration**: Support for SoftHSM and other PKCS#11 modules
- **Standards Compliance**: Implementation of the PKCS#11 v2.40 specification

## Supported Mechanisms

The following cryptographic mechanisms are currently supported:

- **AES**: AES-256-GCM encryption/decryption
- **RSA**: RSA PKCS#1 v1.5 signing/verification
- **ECC**: ECDSA signing/verification with P-256 and P-384 curves
- **Random Number Generation**: Secure random number generation

## Building

To build the PKCS#11 module, run:

```bash
cargo build -p hsm-pkcs11
```

This will produce a shared library that can be used with PKCS#11 applications.

## Installation

The PKCS#11 module can be installed by copying the shared library to a suitable location and configuring your PKCS#11 application to use it.

## Configuration

The PKCS#11 module can be configured through environment variables and configuration files. The following environment variables are supported:

- `FERRoHSM_CONFIG`: Path to the FerroHSM configuration file
- `FERRoHSM_PKCS11_LOG_LEVEL`: Log level for the PKCS#11 module

## Usage

### With OpenSSL

To use the PKCS#11 module with OpenSSL, you can use the `-engine` option:

```bash
openssl engine -t dynamic -pre SO_PATH:/path/to/libhsm_pkcs11.so -pre ID:pkcs11 -pre LOAD
```

### With SSH

To use the PKCS#11 module with SSH, you can add the following to your SSH configuration:

```bash
PKCS11Provider /path/to/libhsm_pkcs11.so
```

## API Reference

The PKCS#11 module implements the following functions:

- `C_Initialize` / `C_Finalize`: Library initialization and finalization
- `C_GetInfo`: Get library information
- `C_GetSlotList` / `C_GetSlotInfo`: Slot enumeration and information
- `C_OpenSession` / `C_CloseSession`: Session management
- `C_Login` / `C_Logout`: User authentication
- `C_GenerateKey`: Key generation
- `C_FindObjectsInit` / `C_FindObjects` / `C_FindObjectsFinal`: Object search
- `C_Sign` / `C_Verify`: Digital signatures
- `C_Encrypt` / `C_Decrypt`: Data encryption/decryption
- `C_GenerateRandom`: Random number generation

## Hardware Integration

The PKCS#11 module supports integration with hardware security modules through the following adapters:

- **SoftHSM**: Software-based HSM for testing and development
- **Cloud HSM**: Integration with cloud-based HSM services
- **Hardware HSM**: Support for PCIe/USB HSM devices

## Security Considerations

- All cryptographic operations are performed in secure memory
- Keys are protected with tamper-evident storage
- Access control is enforced through role-based authentication
- Audit logging tracks all cryptographic operations
- Secure key material caching prevents plaintext exposure

## Testing

The PKCS#11 module includes comprehensive tests to ensure compliance with the PKCS#11 specification and proper integration with FerroHSM core functionality.

To run the tests:

```bash
cargo test -p hsm-pkcs11
```

## Contributing

Contributions to the PKCS#11 module are welcome. Please follow the standard contribution guidelines for the FerroHSM project.

## License

This project is licensed under the MIT License. See the LICENSE file for details.