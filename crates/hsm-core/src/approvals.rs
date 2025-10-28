use std::path::{Path, PathBuf};

use fs2::FileExt;
use parking_lot::Mutex;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use uuid::Uuid;

use crate::{
    error::{HsmError, HsmResult},
    fs_utils,
    rbac::Action,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRecord {
    pub id: Uuid,
    pub action: Action,
    pub subject: String,
    pub policy_tags: Vec<String>,
    pub requester: String,
    pub created_at: OffsetDateTime,
    pub approved_by: Option<String>,
    pub approved_at: Option<OffsetDateTime>,
}

impl ApprovalRecord {
    pub fn new(
        action: Action,
        subject: String,
        requester: String,
        policy_tags: Vec<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            action,
            subject,
            policy_tags,
            requester,
            created_at: OffsetDateTime::now_utc(),
            approved_by: None,
            approved_at: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingApprovalInfo {
    pub id: Uuid,
    pub action: Action,
    pub subject: String,
    pub requester: String,
    pub created_at: OffsetDateTime,
    pub approved_by: Option<String>,
    pub approved_at: Option<OffsetDateTime>,
}

pub trait ApprovalStore: Send + Sync {
    fn insert(&self, record: &ApprovalRecord) -> HsmResult<()>;
    fn save(&self, record: &ApprovalRecord) -> HsmResult<()>;
    fn fetch(&self, id: &Uuid) -> HsmResult<Option<ApprovalRecord>>;
    fn fetch_by_action_subject(
        &self,
        action: &Action,
        subject: &str,
    ) -> HsmResult<Option<ApprovalRecord>>;
    fn delete(&self, id: &Uuid) -> HsmResult<()>;
    fn list(&self) -> HsmResult<Vec<ApprovalRecord>>;
}

pub struct FileApprovalStore {
    dir: PathBuf,
    lock: Mutex<()>,
}

impl FileApprovalStore {
    pub fn new<P: AsRef<Path>>(dir: P) -> HsmResult<Self> {
        let dir = dir.as_ref().to_path_buf();
        fs_utils::ensure_secure_dir(&dir).map_err(HsmError::storage)?;
        Ok(Self {
            dir,
            lock: Mutex::new(()),
        })
    }

    fn record_path(&self, id: &Uuid) -> PathBuf {
        self.dir.join(format!("{}.json", id))
    }
}

impl ApprovalStore for FileApprovalStore {
    fn insert(&self, record: &ApprovalRecord) -> HsmResult<()> {
        self.save(record)
    }

    fn save(&self, record: &ApprovalRecord) -> HsmResult<()> {
        let _guard = self.lock.lock();
        let path = self.record_path(&record.id);
        let mut options = std::fs::OpenOptions::new();
        options.create(true).write(true).truncate(true);
        let file = fs_utils::open_secure(&path, &mut options).map_err(HsmError::storage)?;
        FileExt::lock_exclusive(&file).map_err(HsmError::storage)?;
        let writer = std::io::BufWriter::new(&file);
        serde_json::to_writer_pretty(writer, record).map_err(HsmError::storage)?;
        file.sync_all().map_err(HsmError::storage)?;
        FileExt::unlock(&file).map_err(HsmError::storage)?;
        Ok(())
    }

    fn fetch(&self, id: &Uuid) -> HsmResult<Option<ApprovalRecord>> {
        let path = self.record_path(id);
        if !path.exists() {
            return Ok(None);
        }
        fs_utils::ensure_file_permissions(&path).map_err(HsmError::storage)?;
        let file = std::fs::File::open(&path).map_err(HsmError::storage)?;
        let reader = std::io::BufReader::new(file);
        let record = serde_json::from_reader(reader).map_err(HsmError::storage)?;
        Ok(Some(record))
    }

    fn fetch_by_action_subject(
        &self,
        action: &Action,
        subject: &str,
    ) -> HsmResult<Option<ApprovalRecord>> {
        for record in self.list()? {
            if &record.action == action && record.subject == subject {
                return Ok(Some(record));
            }
        }
        Ok(None)
    }

    fn delete(&self, id: &Uuid) -> HsmResult<()> {
        let path = self.record_path(id);
        if path.exists() {
            std::fs::remove_file(&path).map_err(HsmError::storage)?;
        }
        Ok(())
    }

    fn list(&self) -> HsmResult<Vec<ApprovalRecord>> {
        let mut records = Vec::new();
        for entry in std::fs::read_dir(&self.dir).map_err(HsmError::storage)? {
            let entry = entry.map_err(HsmError::storage)?;
            if entry.file_type().map_err(HsmError::storage)?.is_file() {
                if let Some(stem) = entry.path().file_stem().and_then(|s| s.to_str()) {
                    if let Ok(id) = Uuid::parse_str(stem) {
                        if let Some(record) = self.fetch(&id)? {
                            records.push(record);
                        }
                    }
                }
            }
        }
        Ok(records)
    }
}

/// SQLite-backed approval store for durable dual-control workflows.
pub struct SqliteApprovalStore {
    conn: Mutex<Connection>,
}

impl SqliteApprovalStore {
    pub fn new<P: AsRef<Path>>(path: P) -> HsmResult<Self> {
        let path = path.as_ref();
        if let Some(dir) = path.parent() {
            fs_utils::ensure_secure_dir(dir).map_err(HsmError::storage)?;
        }
        let conn = Connection::open(path).map_err(HsmError::storage)?;
        fs_utils::ensure_file_permissions(path).map_err(HsmError::storage)?;
        conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            CREATE TABLE IF NOT EXISTS approvals (
                id TEXT PRIMARY KEY,
                action TEXT NOT NULL,
                subject TEXT NOT NULL,
                policy_tags TEXT NOT NULL,
                requester TEXT NOT NULL,
                created_at TEXT NOT NULL,
                approved_by TEXT,
                approved_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_approvals_action_subject ON approvals(action, subject);
            CREATE INDEX IF NOT EXISTS idx_approvals_created ON approvals(created_at);
            "#,
        )
        .map_err(HsmError::storage)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn serialize_tags(tags: &[String]) -> HsmResult<String> {
        serde_json::to_string(tags).map_err(HsmError::storage)
    }

    fn upsert(&self, record: &ApprovalRecord) -> HsmResult<()> {
        let conn = self.conn.lock();
        let action_raw = serde_json::to_string(&record.action).map_err(HsmError::storage)?;
        let tags_raw = Self::serialize_tags(&record.policy_tags)?;
        let created_at = record
            .created_at
            .format(&Rfc3339)
            .map_err(HsmError::storage)?;
        let approved_at = record
            .approved_at
            .map(|ts| ts.format(&Rfc3339).map_err(HsmError::storage))
            .transpose()?;
        conn.execute(
            "INSERT INTO approvals (
                id, action, subject, policy_tags, requester, created_at, approved_by, approved_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            ON CONFLICT(id) DO UPDATE SET
                action=excluded.action,
                subject=excluded.subject,
                policy_tags=excluded.policy_tags,
                requester=excluded.requester,
                created_at=excluded.created_at,
                approved_by=excluded.approved_by,
                approved_at=excluded.approved_at",
            params![
                record.id.to_string(),
                action_raw,
                record.subject.clone(),
                tags_raw,
                record.requester.clone(),
                created_at,
                record.approved_by.clone(),
                approved_at,
            ],
        )
        .map_err(HsmError::storage)?;
        Ok(())
    }

    fn map_row(row: &rusqlite::Row<'_>) -> Result<ApprovalRecord, rusqlite::Error> {
        let id: String = row.get(0)?;
        let action_raw: String = row.get(1)?;
        let subject: String = row.get(2)?;
        let policy_tags_raw: String = row.get(3)?;
        let requester: String = row.get(4)?;
        let created_at_raw: String = row.get(5)?;
        let approved_by: Option<String> = row.get(6)?;
        let approved_at_raw: Option<String> = row.get(7)?;

        Ok(ApprovalRecord {
            id: Uuid::parse_str(&id).map_err(|_| rusqlite::Error::InvalidQuery)?,
            action: serde_json::from_str(&action_raw).map_err(|_| rusqlite::Error::InvalidQuery)?,
            subject,
            policy_tags: serde_json::from_str(&policy_tags_raw)
                .map_err(|_| rusqlite::Error::InvalidQuery)?,
            requester,
            created_at: OffsetDateTime::parse(&created_at_raw, &Rfc3339)
                .map_err(|_| rusqlite::Error::InvalidQuery)?,
            approved_by,
            approved_at: match approved_at_raw {
                Some(val) => Some(
                    OffsetDateTime::parse(&val, &Rfc3339)
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                ),
                None => None,
            },
        })
    }

    pub fn purge_older_than(&self, cutoff: OffsetDateTime) -> HsmResult<u64> {
        let cutoff_str = cutoff.format(&Rfc3339).map_err(HsmError::storage)?;
        let conn = self.conn.lock();
        let affected = conn
            .execute(
                "DELETE FROM approvals WHERE approved_at IS NOT NULL AND approved_at < ?1",
                params![cutoff_str],
            )
            .map_err(HsmError::storage)?;
        Ok(affected as u64)
    }
}

impl ApprovalStore for SqliteApprovalStore {
    fn insert(&self, record: &ApprovalRecord) -> HsmResult<()> {
        self.upsert(record)
    }

    fn save(&self, record: &ApprovalRecord) -> HsmResult<()> {
        self.upsert(record)
    }

    fn fetch(&self, id: &Uuid) -> HsmResult<Option<ApprovalRecord>> {
        let conn = self.conn.lock();
        let result = conn
            .query_row(
                "SELECT id, action, subject, policy_tags, requester, created_at, approved_by, approved_at FROM approvals WHERE id = ?1",
                params![id.to_string()],
                Self::map_row,
            )
            .optional()
            .map_err(HsmError::storage)?;
        Ok(result)
    }

    fn fetch_by_action_subject(
        &self,
        action: &Action,
        subject: &str,
    ) -> HsmResult<Option<ApprovalRecord>> {
        let conn = self.conn.lock();
        let action_raw = serde_json::to_string(action).map_err(HsmError::storage)?;
        let result = conn
            .query_row(
                "SELECT id, action, subject, policy_tags, requester, created_at, approved_by, approved_at FROM approvals WHERE action = ?1 AND subject = ?2 LIMIT 1",
                params![action_raw, subject],
                Self::map_row,
            )
            .optional()
            .map_err(HsmError::storage)?;
        Ok(result)
    }

    fn delete(&self, id: &Uuid) -> HsmResult<()> {
        let conn = self.conn.lock();
        conn.execute(
            "DELETE FROM approvals WHERE id = ?1",
            params![id.to_string()],
        )
        .map_err(HsmError::storage)?;
        Ok(())
    }

    fn list(&self) -> HsmResult<Vec<ApprovalRecord>> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare(
                "SELECT id, action, subject, policy_tags, requester, created_at, approved_by, approved_at FROM approvals ORDER BY created_at DESC",
            )
            .map_err(HsmError::storage)?;
        let rows = stmt
            .query_map([], Self::map_row)
            .map_err(HsmError::storage)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(HsmError::storage)?;
        Ok(rows)
    }
}
