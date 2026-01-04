# Initial Concept
FerroHSM is a software-based Hardware Security Module (HSM) implemented in Rust, designed to provide high-assurance cryptographic services with a focus on Secure by Design principles and Post-Quantum Cryptography (PQC). It aims to offer a portable, software-defined alternative to traditional hardware HSMs while maintaining strong security guarantees and supporting modern integration patterns.

# Vision
To become the leading open-source, software-defined cryptographic foundation for modern infrastructure, enabling organizations to seamlessly transition to post-quantum security while maintaining compatibility with legacy standards.

# Target Audience
- **Security & DevOps Engineers:** Professionals managing secrets, keys, and compliance in cloud-native or hybrid environments.
- **Software Developers:** Teams needing to integrate NIST-standardized PQC and robust key management into their applications via REST APIs or standard interfaces.
- **Legacy System Integrators:** Organizations requiring PKCS#11 compatibility for existing applications without the cost and complexity of physical hardware.

# Core Value Proposition
- **Quantum Readiness:** Built-in support for NIST-standardized PQC algorithms (ML-KEM, ML-DSA, SLH-DSA) and hybrid schemes.
- **Memory Safety:** Leveraging Rust to eliminate common classes of memory vulnerabilities inherent in many cryptographic implementations.
- **Unified Management:** A consistent management experience across CLI, TUI, and REST interfaces.
- **Secure Policy Enforcement:** Granular RBAC, dual-control approval workflows, and automated audit logging.

# Key Features
- **Extensive Algorithm Support:** AES-GCM, RSA, ECC (P-256/P-384), and standardized Post-Quantum algorithms.
- **Hybrid Cryptography:** Support for combining classical and quantum-resistant algorithms for immediate security with future-proofing.
- **Flexible Interfaces:** REST API (Axum), interactive TUI (Ratatui), administrative CLI, and a PKCS#11 provider.
- **Governance & Audit:** Role-based access control, mandatory approval workflows for sensitive operations, and tamper-evident audit logs.
- **Automated Lifecycle:** Key rotation, retention policies, and secure destruction.
