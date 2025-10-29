use std::{
    fs::OpenOptions,
    io::{BufRead, BufReader, BufWriter, Write},
    path::{Path, PathBuf},
};

use fs2::FileExt;
use parking_lot::Mutex;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use uuid::Uuid;

use crate::{
    error::{HsmError, HsmResult},
    fs_utils,
    models::{AuthContext, KeyId},
    rbac::Action,
};

use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub id: Uuid,
    pub timestamp: OffsetDateTime,
    pub actor_id: String,
    pub session_id: Uuid,
    pub action: Action,
    pub key_id: Option<KeyId>,
    pub message: String,
}

impl AuditRecord {
    pub fn new(
        ctx: AuthContext,
        key_id: KeyId,
        action: Action,
        message: impl Into<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: OffsetDateTime::now_utc(),
            actor_id: ctx.actor_id,
            session_id: ctx.session_id,
            action,
            key_id: Some(key_id),
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub record: AuditRecord,
    pub signature: Option<String>,
    pub prev_hash: Option<String>,
    pub hash: String,
}

pub trait AuditLog: Send + Sync {
    fn record(&self, record: AuditRecord) -> HsmResult<()>;
}

pub type AuditSink = Box<dyn AuditLog>;

/// Append-only audit logger that writes JSON lines and leverages file locks to emit
/// tamper-evident records.
pub struct FileAuditLog {
    path: PathBuf,
    key: Option<Vec<u8>>,
    lock: Mutex<()>,
    chain: Mutex<AuditChainState>,
}

impl FileAuditLog {
    pub fn new<P: AsRef<Path>>(path: P) -> HsmResult<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(dir) = path.parent() {
            fs_utils::ensure_secure_dir(dir).map_err(HsmError::audit)?;
        }
        if path.exists() {
            fs_utils::ensure_file_permissions(&path).map_err(HsmError::audit)?;
        }
        Ok(Self {
            path,
            key: None,
            lock: Mutex::new(()),
            chain: Mutex::new(AuditChainState::new()),
        })
    }

    pub fn with_signing_key(mut self, key: Vec<u8>) -> Self {
        self.key = Some(key);
        self
    }

    fn load_last_hash(&self) -> HsmResult<Option<String>> {
        if !self.path.exists() {
            return Ok(None);
        }
        fs_utils::ensure_file_permissions(&self.path).map_err(HsmError::audit)?;
        let file = std::fs::File::open(&self.path).map_err(HsmError::audit)?;
        let reader = BufReader::new(file);
        let mut last = None;
        for line in reader.lines() {
            let line = line.map_err(HsmError::audit)?;
            if line.trim().is_empty() {
                continue;
            }
            let event: AuditEvent = serde_json::from_str(&line).map_err(HsmError::audit)?;
            last = Some(event.hash);
        }
        Ok(last)
    }

    pub fn tail(&self, limit: usize) -> HsmResult<Vec<AuditEvent>> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        fs_utils::ensure_file_permissions(&self.path).map_err(HsmError::audit)?;
        let file = std::fs::File::open(&self.path).map_err(HsmError::audit)?;
        let reader = BufReader::new(file);
        let mut events = Vec::new();
        for line in reader.lines() {
            let line = line.map_err(HsmError::audit)?;
            if line.trim().is_empty() {
                continue;
            }
            let event: AuditEvent = serde_json::from_str(&line).map_err(HsmError::audit)?;
            events.push(event);
        }
        let start = events.len().saturating_sub(limit);
        let mut result: Vec<_> = events.into_iter().skip(start).collect();
        result.reverse();
        Ok(result)
    }
}

impl AuditLog for FileAuditLog {
    fn record(&self, record: AuditRecord) -> HsmResult<()> {
        let _guard = self.lock.lock();
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        let file = fs_utils::open_secure(&self.path, &mut options).map_err(HsmError::audit)?;
        FileExt::lock_exclusive(&file).map_err(HsmError::audit)?;
        let signature = self
            .key
            .as_ref()
            .map(|key| crate::crypto::sign_audit_record(key, &record));

        let mut chain = self.chain.lock();
        if !chain.initialized {
            chain.last_hash = self.load_last_hash()?;
            chain.initialized = true;
        }

        let prev_hash = chain.last_hash.clone();
        let hash = compute_event_hash(&record, signature.as_deref(), prev_hash.as_deref())?;
        let event = AuditEvent {
            record,
            signature,
            prev_hash,
            hash: hash.clone(),
        };
        let mut writer = BufWriter::new(&file);
        serde_json::to_writer(&mut writer, &event).map_err(HsmError::audit)?;
        writer.write_all(b"\n").map_err(HsmError::audit)?;
        writer.flush().map_err(HsmError::audit)?;
        file.sync_all().map_err(HsmError::audit)?;
        chain.last_hash = Some(hash);
        FileExt::unlock(&file).map_err(HsmError::audit)?;
        Ok(())
    }
}

/// SQLite-backed audit log with append-only semantics and automatic retention support.
pub struct SqliteAuditLog {
    conn: Mutex<Connection>,
    key: Option<Vec<u8>>,
    chain: Mutex<AuditChainState>,
}

impl SqliteAuditLog {
    pub fn new<P: AsRef<Path>>(path: P) -> HsmResult<Self> {
        let path = path.as_ref();
        if let Some(dir) = path.parent() {
            fs_utils::ensure_secure_dir(dir).map_err(HsmError::audit)?;
        }
        let conn = Connection::open(path).map_err(HsmError::audit)?;
        fs_utils::ensure_file_permissions(path).map_err(HsmError::audit)?;
        conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            CREATE TABLE IF NOT EXISTS audit_events (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                action TEXT NOT NULL,
                key_id TEXT,
                message TEXT NOT NULL,
                signature TEXT,
                prev_hash TEXT,
                hash TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp ON audit_events(timestamp);
            "#,
        )
        .map_err(HsmError::audit)?;
        Ok(Self {
            conn: Mutex::new(conn),
            key: None,
            chain: Mutex::new(AuditChainState::new()),
        })
    }

    pub fn with_signing_key(mut self, key: Vec<u8>) -> Self {
        self.key = Some(key);
        self
    }

    fn load_last_hash(conn: &Connection) -> HsmResult<Option<String>> {
        conn.query_row(
            "SELECT hash FROM audit_events ORDER BY timestamp DESC LIMIT 1",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(HsmError::audit)
    }

    pub fn tail(&self, limit: usize) -> HsmResult<Vec<AuditEvent>> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare(
                "SELECT id, timestamp, actor_id, session_id, action, key_id, message, signature, prev_hash, hash \
                 FROM audit_events ORDER BY timestamp DESC LIMIT ?1",
            )
            .map_err(HsmError::audit)?;
        let rows = stmt
            .query_map([limit as i64], |row| {
                let id: String = row.get(0)?;
                let timestamp: String = row.get(1)?;
                let actor_id: String = row.get(2)?;
                let session_id: String = row.get(3)?;
                let action_raw: String = row.get(4)?;
                let key_id: Option<String> = row.get(5)?;
                let message: String = row.get(6)?;
                let signature: Option<String> = row.get(7)?;
                let prev_hash: Option<String> = row.get(8)?;
                let hash: String = row.get(9)?;

                let record = AuditRecord {
                    id: Uuid::parse_str(&id).map_err(|_| rusqlite::Error::InvalidQuery)?,
                    timestamp: OffsetDateTime::parse(&timestamp, &Rfc3339)
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    actor_id,
                    session_id: Uuid::parse_str(&session_id)
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    action: serde_json::from_str(&action_raw)
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    key_id,
                    message,
                };

                Ok(AuditEvent {
                    record,
                    signature,
                    prev_hash,
                    hash,
                })
            })
            .map_err(HsmError::audit)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(HsmError::audit)?;
        Ok(rows)
    }

    pub fn purge_older_than(&self, cutoff: OffsetDateTime) -> HsmResult<u64> {
        let cutoff_str = cutoff.format(&Rfc3339).map_err(HsmError::audit)?;
        let conn = self.conn.lock();
        let affected = conn
            .execute(
                "DELETE FROM audit_events WHERE timestamp < ?1",
                params![cutoff_str],
            )
            .map_err(HsmError::audit)?;

        // reset cached hash if we might have deleted the tail
        if affected > 0 {
            let mut chain = self.chain.lock();
            chain.initialized = false;
            chain.last_hash = None;
        }

        Ok(affected as u64)
    }
}

impl AuditLog for SqliteAuditLog {
    fn record(&self, record: AuditRecord) -> HsmResult<()> {
        let signature = self
            .key
            .as_ref()
            .map(|key| crate::crypto::sign_audit_record(key, &record));

        let conn = self.conn.lock();
        let prev_hash = {
            let mut chain = self.chain.lock();
            if !chain.initialized {
                chain.last_hash = Self::load_last_hash(&conn)?;
                chain.initialized = true;
            }
            chain.last_hash.clone()
        };

        let hash = compute_event_hash(&record, signature.as_deref(), prev_hash.as_deref())?;

        let AuditRecord {
            id,
            timestamp,
            actor_id,
            session_id,
            action,
            key_id,
            message,
        } = record;

        let timestamp = timestamp.format(&Rfc3339).map_err(HsmError::audit)?;
        let action = serde_json::to_string(&action).map_err(HsmError::audit)?;

        conn.execute(
            "INSERT INTO audit_events (
                id, timestamp, actor_id, session_id, action, key_id, message, signature, prev_hash, hash
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                id.to_string(),
                timestamp,
                actor_id,
                session_id.to_string(),
                action,
                key_id,
                message,
                signature,
                prev_hash,
                hash.clone()
            ],
        )
        .map_err(HsmError::audit)?;

        let mut chain = self.chain.lock();
        chain.last_hash = Some(hash);
        chain.initialized = true;

        Ok(())
    }
}

pub fn compute_event_hash(
    record: &AuditRecord,
    signature: Option<&str>,
    prev_hash: Option<&str>,
) -> HsmResult<String> {
    #[derive(Serialize)]
    struct HashPayload<'a> {
        record: &'a AuditRecord,
        signature: Option<&'a str>,
        prev_hash: Option<&'a str>,
    }

    let payload = serde_json::to_vec(&HashPayload {
        record,
        signature,
        prev_hash,
    })
    .map_err(HsmError::audit)?;
    let mut hasher = Sha256::new();
    hasher.update(payload);
    Ok(hex::encode(hasher.finalize()))
}

#[derive(Default)]
struct AuditChainState {
    initialized: bool,
    last_hash: Option<String>,
}

impl AuditChainState {
    fn new() -> Self {
        Self::default()
    }
}
