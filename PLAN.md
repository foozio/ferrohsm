# PKCS#11 Compatibility & Hardware Security Integration Plan

## Context
- FerroHSM currently exposes REST/CLI interfaces backed by `hsm-core`; regulated customers require legacy PKCS#11 client support and deeper hardware roots of trust.
- Roadmap item 3.2 commits to a PKCS#11 shim plus interoperability with major vendor suites ahead of the `v1.0` release.
- The plan below sequences delivery across discovery, implementation, validation, and launch, balancing reuse of existing abstractions with new hardware adapters.

## Goals
- Deliver a PKCS#11-compatible interface that maps core cryptographic operations onto existing FerroHSM capabilities.
- Enable hardware-backed key storage and cryptographic operations via modular hardware/KMS adapters.
- Achieve interoperability with at least SoftHSM (open-source reference) and one commercial HSM vendor before GA.
- Maintain security posture: constant-time critical paths, strict memory hygiene, audited logging, and no sensitive data leakage.
- Provide multiple user interface options (CLI, TUI, REST, PKCS#11) for different use cases.
- Enable easy distribution and installation via package managers (Homebrew).

## Non-Goals
- FIPS 140-3 certification work (tracked separately under Compliance).
- Replacing REST/CLI clients; goal is additive compatibility.
- Hardware attestation story for secure enclaves (covered in Future Horizons).

## Stakeholders & Roles
- **Tech Lead (Security Platform):** architecture decisions, cross-team alignment.
- **Core Maintainers (`hsm-core`/`hsm-server`):** API exposure, storage model updates, code review.
- **Infrastructure Team:** hardware lab access, CI builders with hardware, vendor contract coordination.
- **QA/Compliance:** test plan authoring, interoperability matrix, evidence capture.
- **Developer Relations:** SDK docs, migration guides, sample apps.

## Assumptions
- `hsm-core` abstractions for key management can be extended without breaking backward compatibility.
- We can rely on the Rust `cryptoki` crate for PKCS#11 constants/types, complemented by custom glue.
- Hardware vendors expose either PKCS#11 or REST/gRPC APIs that we can wrap behind a trait-based adapter.
- Budget secured for at least one commercial HSM (e.g., Luna, SafeNet) and cloud HSM sandbox accounts.
- Users will benefit from multiple interface options (CLI, TUI, REST, PKCS#11).

## Phase Breakdown

### Phase 0 — Discovery & Architecture (2–3 weeks)
- [x] Audit `hsm-core` operations needed for PKCS#11 (session management, key lifecycles, mechanisms).
- [x] Document PKCS#11 function coverage priorities (C_Login, C_GenerateKey, C_Sign, etc.) and map to `hsm-core` APIs.
- [x] Define adapter trait for hardware devices (`HardwareSigner`, `HardwareKeyStore`) and capability matrix.
- [x] Identify storage implications for PKCS#11 object handles/attributes (persisted vs session scoped).
- [x] Produce architecture decision record (ADR) covering shim boundaries, threading model, and error translation.

### Phase 1 — Foundation (4–6 weeks)
- Implement PKCS#11 front-end crate (`hsm-pkcs11`) exposing C ABI compatible entry points.
- Build session/token management layer (slot enumeration, session pooling, state machine adherence).
- Extend `hsm-core` with metadata required for PKCS#11 attributes (object classes, mechanisms, key policies).
- Develop mock hardware adapter that proxies to existing software keystore for early testing.
- Establish conformance test harness using OASIS PKCS#11 test suite and SoftHSM.
- Integrate TUI interface for enhanced user experience.

### Phase 2 — Hardware Integration (6–8 weeks)
- Implement adapter for SoftHSM/Software fallback; ensure parity with existing storage.
- Integrate with at least one cloud HSM (AWS CloudHSM or Azure Managed HSM) via backend trait.
- Prototype PCIe/USB HSM integration (e.g., YubiHSM 2) to validate device communication layers.
- Add secure key material caching rules (no long-lived plaintext in memory, zeroization on drop).
- Provide configuration surfaces (`hsm-server` config, CLI) for selecting hardware backends and slots.
- Enhance distribution mechanisms (Homebrew, container images).

### Phase 3 — Hardening & Interop (4–5 weeks)
- Run interoperability testing against vendor test suites (SafeNet Luna, Thales, Utimaco as available).
- Expand mechanism coverage (RSA/ECC sign/verify, key wrapping, AES-GCM, EdDSA).
- Implement auditing hooks for PKCS#11 operations and map to existing telemetry.
- Perform load/stress tests with concurrent sessions and long-lived operations.
- Address compliance feedback; update threat model and security review.
- Finalize TUI interface with full feature set.

### Phase 4 — Launch Readiness (2 weeks)
- Finalize documentation: admin guides, migration paths, SDK updates, sample code.
- Produce certification packet: conformance results, interoperability matrix, performance benchmarks.
- Deliver enablement materials (release notes, webinars, partner outreach).
- Feature-flagged GA in `v1.0`, with rollout checklist and post-launch monitoring plan.
- Ensure Homebrew distribution is stable and well-documented.

## Workstreams

### 1. PKCS#11 Compatibility Layer
- **Interface Binding:** Create `#[no_mangle]` ABI exports, argument validation, and conversion to internal command structs.
- **Session & Slot Management:** Implement slot registry, token info, session pooling, and state transitions per spec.
- **Object Handling:** Persist object attributes, enforce visibility per session/user, support template-based searches.
- **Mechanism Support:** Prioritize RSA/ECC sign/verify, AES key gen/wrap/unwrap, digest operations; design extensible mechanism registry.
- **Error Mapping:** Translate FerroHSM errors to PKCS#11 `CKR_*` codes, ensuring no sensitive info leaks.
- **Telemetry & Logging:** Correlate PKCS#11 requests with audit log IDs; provide per-session metrics.

### 2. Hardware Security Integrations
- **Adapter Abstraction:** Define trait for operations (generate, import, sign, derive, wrap) with capability negotiation.
- **SoftHSM Adapter:** Default software backend for CI and local development; supports automated tests.
- **Cloud HSM Adapter:** Integrate with AWS/Azure/GCP HSMs, handling credential rotation and network resilience.
- **On-Prem Device Adapter:** Implement USB/PCIe device support (YubiHSM, SafeNet) with secure channel establishment.
- **Configuration & Policy:** Extend configuration files/CLI to bind tokens to hardware slots and enforce usage policies.
- **Monitoring:** Add health checks (device reachability, key checksum verification) and alerting hooks.

### 3. User Experience Enhancement
- **TUI Interface:** Provide interactive terminal experience with keyboard navigation.
- **Distribution:** Enable easy installation via package managers (Homebrew).
- **Documentation:** Create comprehensive guides for all interface options.
- **Examples:** Provide sample applications demonstrating each interface.

## Deliverables
- `hsm-pkcs11` crate with documented API surface and published crate docs.
- Updated `hsm-core`/`hsm-server` modules with PKCS#11-aware capabilities and hardware adapter hooks.
- Automated conformance suite integrated into CI pipelines.
- Interoperability report summarizing vendor compatibility results.
- Operations runbook covering deployment, monitoring, backup/restore, and incident response.
- TUI interface for enhanced user experience.
- Homebrew distribution for macOS users.

## Validation Strategy
- Unit tests for argument parsing, session lifecycle, and mechanism mapping.
- Integration tests using SoftHSM containers executed via `cargo test -p hsm-pkcs11 --features soft-hsm`.
- End-to-end regression suite wrapping existing FerroHSM flows through PKCS#11 clients.
- Fuzzing harness for request parsing to catch malformed templates and concurrency edge cases.
- Security review including memory sanitizers (ASan), Valgrind, and secret scanning on crash dumps.
- User experience testing for TUI interface.

## Dependencies
- Availability of vendor SDKs/drivers (license agreements, NDAs).
- Infrastructure for hardware labs and secure secrets management in CI.
- Upstream crates (`cryptoki`, `tokio`) compatibility with targeted Rust version.
- Coordination with compliance team for audit logging requirements.
- Package manager integration tools (Homebrew formula creation).

## Risks & Mitigations
- **Spec Ambiguity:** PKCS#11 implementations vary; mitigate with extensive compatibility testing and configurable quirks.
- **Hardware Latency:** Network/cloud HSMs introduce latency; implement async session pooling and configurable timeouts.
- **Security Regression:** Bridging C ABI increases attack surface; enforce strict fuzzing and defensive coding (bounds checks, zeroization).
- **Resource Contention:** Limited hardware units; schedule shared lab time and provide SoftHSM fallback for developers.
- **Timeline Creep:** Vendor onboarding delays; maintain optional milestone to ship with SoftHSM first while parallelizing vendor work.
- **User Adoption:** Multiple interfaces may confuse users; provide clear documentation and migration guides.

## Success Metrics
- 95% pass rate on PKCS#11 conformance suite and zero critical defects in launch review.
- ≤5% performance regression on existing `hsm-core` operations when PKCS#11 layer enabled.
- At least two reference customers completing pilot using PKCS#11 interface.
- MTTR < 1 hour for hardware adapter failures detected via monitoring alerts.
- <5 minutes for Homebrew installation, <10 minutes for first operation.
- 90% user satisfaction rating for TUI interface in beta testing.

## Open Questions
- Which vendor HSM has priority for initial certification (SafeNet vs Thales)?
- Do we need multi-tenant isolation per PKCS#11 slot for managed service offerings?
- Should we expose PKCS#11 via shared library download or containerized sidecar by default?
- How will licensing and NDAs impact automated test distribution?
- What additional package managers should we support beyond Homebrew?

## Next Steps
- Secure stakeholder sign-off on scope and timeline.
- Spin up ADR drafting session and assign owners for Phase 0 tasks.
- Procure required hardware and schedule lab time aligned with Phase 2.
- Begin implementation of PKCS#11 compatibility layer.
- Enhance TUI interface with additional features.
- Prepare Homebrew distribution for wider release.
