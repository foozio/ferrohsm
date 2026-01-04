# Technology Stack

## Core Language
- **Rust:** Used for the entire project to ensure memory safety, performance, and a robust type system, which are critical for cryptographic applications.

## Backend Service (`hsm-server`)
- **Axum:** A web framework for Rust, used to implement the high-performance HTTPS service and REST API.
- **Tokio:** The underlying asynchronous runtime.
- **Serde:** For efficient serialization and deserialization of JSON payloads.

## Cryptographic Core (`hsm-core`)
- **NIST Post-Quantum Cryptography:** Implementation of ML-KEM, ML-DSA, and SLH-DSA.
- **Classical Cryptography:** Support for AES-256-GCM, RSA (2048/4096), and Elliptic Curve Cryptography (P-256, P-384).
- **Hybrid Schemes:** Combining classical and post-quantum algorithms for transitional security.

## User Interfaces
- **TUI (`hsm-tui`):** Built with **Ratatui** for a responsive and feature-rich terminal management experience.
- **CLI (`hsm-cli`):** Administrative command-line tool for remote management.
- **PKCS#11 (`hsm-pkcs11`):** A shim providing a standard cryptographic interface for compatibility with existing applications.

## Security & Authentication
- **JWT (JSON Web Tokens):** For stateless authentication across APIs and the CLI.
- **Mutual TLS (mTLS):** Optional layer for strong machine-to-machine authentication.

## Development & Infrastructure
- **Cargo:** Rust's build system and package manager.
- **GitHub Actions:** For automated security scans and CI/CD.
- **Homebrew:** Primary distribution method for macOS and Linux.
