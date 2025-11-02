# 🧠 AGENTS Architecture Overview

## 1. Overview
FerroHSM is a software-based Hardware Security Module implemented with a modular, agent-based architecture. The system consists of multiple independent components (agents) that handle specific responsibilities such as cryptographic operations, key management, policy enforcement, audit logging, and user interfaces. These agents communicate through well-defined interfaces and coordinate through shared state management.

## 2. Hierarchical Structure

- **Main Orchestrator** → `hsm-server` supervises the full agent system
  - **Security Core Agents**
    - `KeyManager` – Central key lifecycle management
    - `CryptoEngine` – Cryptographic operations provider
    - `SessionManager` – PKCS#11 session handling
  - **Storage Agents**
    - `KeyStore` – Key material persistence (File/SQLite/Remote)
    - `AuditLog` – Tamper-evident audit trail
    - `ApprovalStore` – Dual-control workflow persistence
  - **Policy Agents**
    - `PolicyEngine` – Access control decision engine
    - `RbacAuthorizer` – Role-based access control
    - `PqcPolicyController` – Post-quantum cryptography policies
  - **Background Workers**
    - `RetentionScheduler` – Automated key purge orchestration
    - `AuditRetentionWorker` – Audit log cleanup tasks
    - `ApprovalRetentionWorker` – Approval record cleanup tasks
  - **Network Agents**
    - `HttpAgent` – REST API request handling via Axum
    - `AuthVerifier` – JWT authentication and validation
    - `RateLimiter` – Request throttling and abuse prevention
    - `TlsManager` – Certificate provisioning and OCSP stapling
  - **UI Agents**
    - `TuiOrchestrator` – Terminal-based interface coordinator
    - `CliAgent` – Command-line interface processor
    - `WebDashboard` – Browser-based management UI

## 3. Agent Details

### 🧩 `KeyManager`
**Path:** `crates/hsm-core/src/lib.rs`  
**Implements:** Core key lifecycle management facade  
**Role:** Primary façade for key lifecycle management and controlled cryptographic access  
**Key Dependencies:** `CryptoEngine`, `KeyStore`, `AuditLog`, `PolicyEngine`  
**Concurrency:** Thread-safe through `Arc` wrappers  
**Interactions:** Central hub coordinating all key operations

---

### 🔐 `CryptoEngine`
**Path:** `crates/hsm-core/src/crypto.rs`  
**Implements:** Cryptographic operations provider  
**Role:** Memory-safe cryptographic core featuring AES-256-GCM, RSA-2048/4096, P-256/P-384, post-quantum cryptography (ML-KEM, ML-DSA, SLH-DSA), hybrid cryptography, and audit logging  
**Key Dependencies:** `ring`, `aws-lc-rs`, `p256`, `p384`, `oqs` (post-quantum)  
**Concurrency:** Thread-safe cryptographic operations  
**Interactions:** Used by `KeyManager` for all crypto operations

---

### 🗃️ `KeyStore`
**Path:** `crates/hsm-core/src/storage.rs`  
**Implements:** Key material persistence backends  
**Role:** Tamper-evident storage with multiple backend implementations (File, SQLite, Remote)  
**Key Dependencies:** `rusqlite`, `serde`, `parking_lot`  
**Concurrency:** Thread-safe through `Arc` and `RwLock`  
**Interactions:** Used by `KeyManager` for key persistence

---

### 📜 `AuditLog`
**Path:** `crates/hsm-core/src/audit.rs`  
**Implements:** Tamper-evident audit trail  
**Role:** Audit logging with hash-chain integrity and verification tooling  
**Key Dependencies:** `serde`, `sha2`, `hmac`, `time`  
**Concurrency:** Thread-safe through `Arc` and `RwLock`  
**Interactions:** Used by `KeyManager` for audit record persistence

---

### 🛡️ `PolicyEngine`
**Path:** `crates/hsm-core/src/policy.rs`  
**Implements:** Access control decision engine  
**Role:** RBAC and custom policy enforcement with dual-control workflows  
**Key Dependencies:** `serde`, `parking_lot`  
**Concurrency:** Thread-safe through `Arc` and `RwLock`  
**Interactions:** Used by `KeyManager` for authorization decisions

---

### ⏰ `RetentionScheduler`
**Path:** `crates/hsm-server/src/retention.rs`  
**Implements:** Automated key purge orchestration  
**Role:** Key retention and purge scheduling with attestation  
**Key Dependencies:** `tokio::time`, `time`, `parking_lot`  
**Concurrency:** Async background task via `tokio::spawn`  
**Interactions:** Periodic key purge operations coordinated with `KeyManager`

---

### 🌐 `HttpAgent`
**Path:** `crates/hsm-server/src/main.rs`  
**Implements:** REST API request handling  
**Role:** Axum-based HTTPS service delivering REST APIs and a management UI  
**Key Dependencies:** `axum`, `tower-http`, `serde`  
**Concurrency:** Async request handling with Axum runtime  
**Interactions:** Routes HTTP requests to appropriate `KeyManager` operations

---

### 🔐 `AuthVerifier`
**Path:** `crates/hsm-server/src/auth.rs`  
**Implements:** JWT authentication and validation  
**Role:** Authentication layer validating JWTs with reloadable keysets  
**Key Dependencies:** `jsonwebtoken`, `tokio::fs`  
**Concurrency:** Async config reloading via `tokio::spawn`  
**Interactions:** Validates requests before passing to `HttpAgent`

---

### 💻 `TuiOrchestrator`
**Path:** `crates/hsm-tui/src/main.rs`  
**Implements:** Terminal-based interface coordinator  
**Role:** Advanced text-based user interface with ATAC-inspired modular design  
**Key Dependencies:** `ratatui`, `crossterm`, `comfy-table`  
**Concurrency:** Event-driven TUI with async input handling  
**Interactions:** Communicates with `HttpAgent` via REST API

---

### 🖥️ `CliAgent`
**Path:** `crates/hsm-cli/src/main.rs`  
**Implements:** Command-line interface processor  
**Role:** Administrative client for day-to-day operations built on REST API  
**Key Dependencies:** `clap`, `reqwest`, `serde`  
**Concurrency:** Single-threaded command execution  
**Interactions:** Communicates with `HttpAgent` via REST API

---

### 🔧 `SessionManager`
**Path:** `crates/hsm-core/src/session.rs`  
**Implements:** PKCS#11 session handling  
**Role:** Session management for PKCS#11 compatibility layer  
**Key Dependencies:** `parking_lot`, `std::sync::atomic`  
**Concurrency:** Thread-safe session state management  
**Interactions:** Used by `hsm-pkcs11` crate for session operations

---

## 4. Messaging Graph

```
MainOrchestrator (hsm-server) → KeyManager → CryptoEngine
MainOrchestrator → KeyManager → KeyStore
MainOrchestrator → KeyManager → AuditLog
MainOrchestrator → KeyManager → PolicyEngine
MainOrchestrator → RetentionScheduler → KeyManager
MainOrchestrator → HttpAgent → KeyManager
MainOrchestrator → AuthVerifier → HttpAgent
MainOrchestrator → RateLimiter → HttpAgent
MainOrchestrator → TlsManager → HttpAgent

TuiOrchestrator ↔ HttpAgent
CliAgent ↔ HttpAgent
WebDashboard ↔ HttpAgent

PKCS11Agent ↔ SessionManager ↔ KeyManager
```

## 5. Key Architectural Patterns

### 🔄 Concurrency Model
- **Shared State**: `Arc<RwLock<T>>` for thread-safe shared data
- **Async Workers**: `tokio::spawn` for background tasks
- **Blocking Operations**: `tokio::task::spawn_blocking` for CPU-intensive work

### 🔌 Communication Patterns
- **Direct Method Calls**: Synchronous component interactions
- **HTTP/REST**: Client-server communication between UIs and core
- **Shared Memory**: Thread-safe access to common data structures

### 🛡️ Security Boundaries
1. **Network Boundary**: TLS 1.3 with optional mutual authentication
2. **Gateway Boundary**: Authentication layer validates JWTs
3. **Policy Boundary**: Policy evaluation and session management
4. **Core Boundary**: `hsm-core` is the sole module with direct access to key material
5. **Storage Boundary**: Keys are encrypted-at-rest using operator-provisioned secrets

### 🧱 Core Components in hsm-core
- **Crypto**: Cryptographic operations (AES, RSA, ECC, Post-Quantum)
- **Storage**: Key storage with tamper-evident mechanisms
- **Audit**: Audit logging with hash-chain integrity
- **Policy**: RBAC and custom policy enforcement
- **Approvals**: Dual-control workflow system
- **Session**: Session management
- **Retention**: Key retention and purge scheduling