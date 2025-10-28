# FerroHSM Domain Model (ERD)

```mermaid
erDiagram
    AuthContext ||--o{ AuditRecord : "initiates"
    AuthContext {
        string actor_id
        uuid session_id
        string[] roles
        string? client_fingerprint
        string? source_ip
    }

    KeyMetadata ||--|| KeyRecord : "describes"
    KeyRecord {
        string id PK
        json metadata
        bytes nonce
        bytes ciphertext
        bytes hmac
        enum material_type
    }

    KeyMetadata {
        string id PK
        int version
        enum algorithm
        string[] usage
        string? description
        datetime created_at
        enum state
        string[] policy_tags
        enum tamper_status
    }

    AuditRecord {
        uuid id PK
        datetime timestamp
        string actor_id FK
        uuid session_id
        enum action
        string? key_id FK
        string message
        string? signature
    }

    PolicyTag }o--o{ KeyMetadata : "labels"
    PolicyTag {
        string name PK
        bool dual_control
    }

    Role ||--o{ AuthContext : "granted"
    Role {
        string name PK
    }

    PendingApproval {
        uuid approval_id PK
        enum action
        string requester
        string subject
        datetime created_at
        string? approved_by
        datetime? approved_at
    }

    PendingApproval }o--|| AuthContext : "requested_by"
    PendingApproval }o--|| KeyMetadata : "targets"
```

## Notes
- `KeyRecord` stores sealed key material and metadata in the filesystem-backed store, with immutable per-version files (`keys/<id>/vNNNNNNNN.json`) and a `current.json` pointer to the active version.
- `AuditRecord` entries include optional HMAC signatures for tamper evidence.
- `PolicyTag` represents the configuration driving dual-control requirements; currently stored in-memory but modeled for future persistence.
- JWT bearer tokens establish `AuthContext` values; tokens include roles, optional session UUID, and context fingerprints.
- `PendingApproval` records are persisted on disk and represent queued dual-control requests plus completed approvals.
- Per-actor rate limiting is enforced outside the core domain model but uses the `actor_id` from `AuthContext` as the throttle key.
