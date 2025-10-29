use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{BufReader, BufWriter, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use fs2::FileExt;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::attributes::AttributeSet;

use parking_lot::{Mutex as ParkingMutex, RwLock};
use rusqlite::{params, Connection, OptionalExtension};

use crate::{
    attributes::{AttributeId, AttributeTemplate, AttributeValue},
    error::{HsmError, HsmResult},
    fs_utils,
    models::{KeyId, KeyMaterialType, KeyMetadata},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedKeyMaterial {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub hmac: Vec<u8>,
    pub material_type: KeyMaterialType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRecord {
    pub metadata: KeyMetadata,
    pub sealed: SealedKeyMaterial,
}

pub trait KeyStore: Send + Sync {
    fn store(&self, record: KeyRecord) -> HsmResult<()>;
    fn fetch(&self, id: &KeyId) -> HsmResult<KeyRecord>;
    fn fetch_version(&self, id: &KeyId, version: u32) -> HsmResult<KeyRecord>;
    fn list(&self) -> HsmResult<Vec<KeyRecord>>;
    fn list_versions(&self, id: &KeyId) -> HsmResult<Vec<KeyRecord>>;
    fn delete(&self, id: &KeyId) -> HsmResult<()>;
    fn list_all_versions(&self) -> HsmResult<Vec<KeyRecord>>;
    fn update_version(&self, record: KeyRecord) -> HsmResult<()>;
    fn purge_version(&self, id: &KeyId, version: u32) -> HsmResult<PurgeReport>;
}

/// Tamper-evident key store that writes sealed key blobs to disk with exclusive locks and
/// durability guarantees.
pub struct FileKeyStore {
    dir: PathBuf,
    lock: ParkingMutex<()>,
    index: RwLock<AttributeIndex>,
}

#[derive(Debug, Clone)]
pub struct PurgeReport {
    pub bytes_overwritten: u64,
    pub data_hash: String,
}

impl FileKeyStore {
    pub fn new<P: AsRef<Path>>(dir: P) -> HsmResult<Self> {
        let dir = dir.as_ref().to_path_buf();
        fs_utils::ensure_secure_dir(&dir).map_err(HsmError::storage)?;
        let store = Self {
            dir,
            lock: ParkingMutex::new(()),
            index: RwLock::new(AttributeIndex::default()),
        };
        store.rebuild_index()?;
        Ok(store)
    }

    fn key_dir(&self, id: &KeyId) -> PathBuf {
        self.dir.join(id)
    }

    fn version_path(&self, id: &KeyId, version: u32) -> PathBuf {
        self.key_dir(id).join(format!("v{:08}.json", version))
    }

    fn current_path(&self, id: &KeyId) -> PathBuf {
        self.key_dir(id).join("current.json")
    }

    fn read_record(path: &Path) -> HsmResult<KeyRecord> {
        if path.exists() {
            fs_utils::ensure_file_permissions(path).map_err(HsmError::storage)?;
        }
        let file = File::open(path).map_err(|_| {
            let name = path
                .file_name()
                .and_then(|os| os.to_str())
                .unwrap_or_default()
                .to_string();
            HsmError::KeyNotFound(name)
        })?;
        let reader = BufReader::new(file);
        serde_json::from_reader(reader).map_err(HsmError::storage)
    }

    fn write_record(path: &Path, record: &KeyRecord) -> HsmResult<()> {
        let mut options = OpenOptions::new();
        options.create(true).write(true).truncate(true);
        let file = fs_utils::open_secure(path, &mut options).map_err(HsmError::storage)?;
        FileExt::lock_exclusive(&file).map_err(HsmError::storage)?;
        let writer = BufWriter::new(&file);
        serde_json::to_writer_pretty(writer, record).map_err(HsmError::storage)?;
        file.sync_all().map_err(HsmError::storage)?;
        FileExt::unlock(&file).map_err(HsmError::storage)?;
        Ok(())
    }

    fn highest_version(&self, id: &KeyId) -> HsmResult<Option<u32>> {
        let key_dir = self.key_dir(id);
        if !key_dir.exists() {
            return Ok(None);
        }
        let mut highest = None;
        for entry in fs::read_dir(&key_dir).map_err(HsmError::storage)? {
            let entry = entry.map_err(HsmError::storage)?;
            if entry.file_type().map_err(HsmError::storage)?.is_file() {
                if let Some(version) = Self::parse_version(entry.path()) {
                    let next = highest.map_or(version, |curr: u32| curr.max(version));
                    highest = Some(next);
                }
            }
        }
        Ok(highest)
    }

    fn parse_version(path: PathBuf) -> Option<u32> {
        let file_name = path.file_name()?.to_str()?;
        if let Some(stripped) = file_name.strip_prefix('v') {
            let number = stripped.strip_suffix(".json")?;
            return number.parse().ok();
        }
        None
    }

    pub fn find_by_attributes(&self, template: &AttributeTemplate) -> HsmResult<Vec<KeyRecord>> {
        if template.is_empty() {
            return self.list_all_versions();
        }
        let (attr_id, attr_value) = match template.entries().first() {
            Some(pair) => pair,
            None => return Ok(Vec::new()),
        };

        let candidates = {
            let index = self.index.read();
            index.lookup(*attr_id, attr_value)
        };

        let mut results = Vec::new();

        for (key_id, version) in candidates {
            if let Ok(record) = self.fetch_version(&key_id, version) {
                if record.metadata.attributes.matches_template(template) {
                    results.push(record);
                }
            }
        }
        Ok(results)
    }

    fn rebuild_index(&self) -> HsmResult<()> {
        let records = self.list_all_versions()?;
        let mut index = self.index.write();
        index.rebuild_from_iter(records.into_iter().map(|record| {
            (
                record.metadata.id.clone(),
                record.metadata.version,
                record.metadata.attributes.clone(),
            )
        }));
        Ok(())
    }
}

impl KeyStore for FileKeyStore {
    fn store(&self, record: KeyRecord) -> HsmResult<()> {
        {
            let _guard = self.lock.lock();
            let key_dir = self.key_dir(&record.metadata.id);
            fs_utils::ensure_secure_dir(&key_dir).map_err(HsmError::storage)?;

            let version_path = self.version_path(&record.metadata.id, record.metadata.version);
            let current_path = self.current_path(&record.metadata.id);

            if let Some(highest) = self.highest_version(&record.metadata.id)? {
                if record.metadata.version > highest + 1 {
                    return Err(HsmError::invalid(format!(
                        "version gap detected: current highest {highest}, attempted {}",
                        record.metadata.version
                    )));
                }
                if record.metadata.version < highest {
                    return Err(HsmError::invalid("cannot overwrite historical key version"));
                }
            } else if record.metadata.version != 1 {
                return Err(HsmError::invalid("first key version must be 1"));
            }

            Self::write_record(&version_path, &record)?;
            Self::write_record(&current_path, &record)?;
        }
        self.rebuild_index()?;
        Ok(())
    }

    fn fetch(&self, id: &KeyId) -> HsmResult<KeyRecord> {
        let current_path = self.current_path(id);
        if !current_path.exists() {
            return Err(HsmError::KeyNotFound(id.to_string()));
        }
        Self::read_record(&current_path)
    }

    fn fetch_version(&self, id: &KeyId, version: u32) -> HsmResult<KeyRecord> {
        let path = self.version_path(id, version);
        if !path.exists() {
            return Err(HsmError::KeyNotFound(format!("{id}@v{version}")));
        }
        Self::read_record(&path)
    }

    fn list(&self) -> HsmResult<Vec<KeyRecord>> {
        let mut records = Vec::new();
        for entry in fs::read_dir(&self.dir).map_err(HsmError::storage)? {
            let entry = entry.map_err(HsmError::storage)?;
            if entry.file_type().map_err(HsmError::storage)?.is_dir() {
                let id = entry.file_name().into_string().unwrap_or_default();
                if let Ok(record) = self.fetch(&id) {
                    records.push(record);
                }
            }
        }
        Ok(records)
    }

    fn list_versions(&self, id: &KeyId) -> HsmResult<Vec<KeyRecord>> {
        let key_dir = self.key_dir(id);
        if !key_dir.exists() {
            return Err(HsmError::KeyNotFound(id.to_string()));
        }
        let mut versions = Vec::new();
        let mut entries = fs::read_dir(&key_dir)
            .map_err(HsmError::storage)?
            .filter_map(|entry| entry.ok())
            .collect::<Vec<_>>();
        entries.sort_by_key(|entry| entry.path());
        for entry in entries {
            if entry.file_type().map_err(HsmError::storage)?.is_file() {
                if entry.file_name() == "current.json" {
                    continue;
                }
                if Self::parse_version(entry.path()).is_some() {
                    if let Ok(record) = Self::read_record(&entry.path()) {
                        versions.push(record);
                    }
                }
            }
        }
        versions.sort_by_key(|record| record.metadata.version);
        Ok(versions)
    }

    fn delete(&self, id: &KeyId) -> HsmResult<()> {
        let key_dir = self.key_dir(id);
        if key_dir.exists() {
            fs::remove_dir_all(&key_dir).map_err(HsmError::storage)?;
        }
        self.rebuild_index()?;
        Ok(())
    }

    fn list_all_versions(&self) -> HsmResult<Vec<KeyRecord>> {
        let mut records = Vec::new();
        for entry in fs::read_dir(&self.dir).map_err(HsmError::storage)? {
            let entry = entry.map_err(HsmError::storage)?;
            if entry.file_type().map_err(HsmError::storage)?.is_dir() {
                let id = entry.file_name().into_string().unwrap_or_default();
                let versions = self.list_versions(&id)?;
                for record in versions {
                    records.push(record);
                }
            }
        }
        Ok(records)
    }

    fn update_version(&self, record: KeyRecord) -> HsmResult<()> {
        {
            let _guard = self.lock.lock();
            let version_path = self.version_path(&record.metadata.id, record.metadata.version);
            if !version_path.exists() {
                return Err(HsmError::KeyNotFound(format!(
                    "{}@v{}",
                    record.metadata.id, record.metadata.version
                )));
            }
            Self::write_record(&version_path, &record)?;
            let current = self.fetch(&record.metadata.id)?;
            if current.metadata.version == record.metadata.version {
                let current_path = self.current_path(&record.metadata.id);
                Self::write_record(&current_path, &record)?;
            }
        }
        self.rebuild_index()?;
        Ok(())
    }

    fn purge_version(&self, id: &KeyId, version: u32) -> HsmResult<PurgeReport> {
        let report = {
            let _guard = self.lock.lock();
            let version_path = self.version_path(id, version);
            if !version_path.exists() {
                return Err(HsmError::KeyNotFound(format!("{id}@v{version}")));
            }

            let active = self.fetch(id)?;
            if active.metadata.version == version {
                return Err(HsmError::invalid("cannot purge active key version"));
            }

            // Validate file size to prevent resource exhaustion
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&version_path)
                .map_err(HsmError::storage)?;
            FileExt::lock_exclusive(&file).map_err(HsmError::storage)?;
            let size = file.metadata().map_err(HsmError::storage)?.len();

            // Limit maximum file size to prevent resource exhaustion during secure erase
            const MAX_ERASE_SIZE: u64 = 100 * 1024 * 1024; // 100MB limit
            if size > MAX_ERASE_SIZE {
                FileExt::unlock(&file).map_err(HsmError::storage)?;
                drop(file);
                return Err(HsmError::invalid("key file too large for secure erase"));
            }

            let mut writer = BufWriter::new(&file);
            writer.seek(SeekFrom::Start(0)).map_err(HsmError::storage)?;

            let mut hasher = Sha256::new();
            let mut remaining = size;
            let mut buffer = vec![0u8; 8192];
            while remaining > 0 {
                let chunk = remaining.min(buffer.len() as u64) as usize;
                OsRng.fill_bytes(&mut buffer[..chunk]);
                writer
                    .write_all(&buffer[..chunk])
                    .map_err(HsmError::storage)?;
                hasher.update(&buffer[..chunk]);
                remaining -= chunk as u64;
            }
            writer.flush().map_err(HsmError::storage)?;
            drop(writer);
            file.sync_all().map_err(HsmError::storage)?;
            FileExt::unlock(&file).map_err(HsmError::storage)?;
            drop(file);

            fs::remove_file(&version_path).map_err(HsmError::storage)?;

            PurgeReport {
                bytes_overwritten: size,
                data_hash: hex::encode(hasher.finalize()),
            }
        };
        self.rebuild_index()?;
        Ok(report)
    }
}

/// In-memory key store primarily for testing and ephemeral deployments.
pub struct MemoryKeyStore {
    records: RwLock<HashMap<KeyId, Vec<KeyRecord>>>,
    index: RwLock<AttributeIndex>,
}

impl Default for MemoryKeyStore {
    fn default() -> Self {
        Self {
            records: RwLock::new(HashMap::new()),
            index: RwLock::new(AttributeIndex::default()),
        }
    }
}

impl MemoryKeyStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn ensure_sequence(existing: &Vec<KeyRecord>, candidate: &KeyRecord) -> HsmResult<()> {
        if let Some(last) = existing.last() {
            if candidate.metadata.version > last.metadata.version + 1 {
                return Err(HsmError::invalid(format!(
                    "version gap detected: current highest {}, attempted {}",
                    last.metadata.version, candidate.metadata.version
                )));
            }
            if candidate.metadata.version <= last.metadata.version {
                return Err(HsmError::invalid("cannot overwrite historical key version"));
            }
        } else if candidate.metadata.version != 1 {
            return Err(HsmError::invalid("first key version must be 1"));
        }
        Ok(())
    }

    fn rebuild_index(&self, map: &HashMap<KeyId, Vec<KeyRecord>>) {
        let mut index = self.index.write();
        index.rebuild_from_iter(map.iter().flat_map(|(key_id, versions)| {
            versions.iter().map(move |record| {
                (
                    key_id.clone(),
                    record.metadata.version,
                    record.metadata.attributes.clone(),
                )
            })
        }));
    }

    pub fn find_by_attributes(&self, template: &AttributeTemplate) -> HsmResult<Vec<KeyRecord>> {
        let map = self.records.read();
        if template.is_empty() {
            return Ok(map.values().flat_map(|v| v.clone()).collect());
        }

        let (first_id, first_value) = match template.entries().first() {
            Some(entry) => entry,
            None => return Ok(vec![]),
        };

        let candidates = {
            let index = self.index.read();
            index.lookup(*first_id, first_value)
        };

        let mut results = Vec::new();
        for (key_id, version) in candidates {
            if let Some(versions) = map.get(&key_id) {
                if let Some(record) = versions.iter().find(|rec| rec.metadata.version == version) {
                    if record.metadata.attributes.matches_template(template) {
                        results.push(record.clone());
                    }
                }
            }
        }

        Ok(results)
    }
}

impl KeyStore for MemoryKeyStore {
    fn store(&self, record: KeyRecord) -> HsmResult<()> {
        let mut map = self.records.write();
        let entry = map.entry(record.metadata.id.clone()).or_default();
        Self::ensure_sequence(entry, &record)?;
        entry.push(record);
        self.rebuild_index(&*map);
        Ok(())
    }

    fn fetch(&self, id: &KeyId) -> HsmResult<KeyRecord> {
        let map = self.records.read();
        let versions = map
            .get(id)
            .ok_or_else(|| HsmError::KeyNotFound(id.to_string()))?;
        versions
            .last()
            .cloned()
            .ok_or_else(|| HsmError::KeyNotFound(id.to_string()))
    }

    fn fetch_version(&self, id: &KeyId, version: u32) -> HsmResult<KeyRecord> {
        let map = self.records.read();
        let versions = map
            .get(id)
            .ok_or_else(|| HsmError::KeyNotFound(id.to_string()))?;
        versions
            .iter()
            .find(|rec| rec.metadata.version == version)
            .cloned()
            .ok_or_else(|| HsmError::KeyNotFound(format!("{id}@v{version}")))
    }

    fn list(&self) -> HsmResult<Vec<KeyRecord>> {
        let map = self.records.read();
        Ok(map
            .values()
            .filter_map(|versions| versions.last().cloned())
            .collect())
    }

    fn list_versions(&self, id: &KeyId) -> HsmResult<Vec<KeyRecord>> {
        let map = self.records.read();
        let versions = map
            .get(id)
            .ok_or_else(|| HsmError::KeyNotFound(id.to_string()))?;
        Ok(versions.clone())
    }

    fn delete(&self, id: &KeyId) -> HsmResult<()> {
        let mut map = self.records.write();
        map.remove(id);
        self.rebuild_index(&*map);
        Ok(())
    }

    fn list_all_versions(&self) -> HsmResult<Vec<KeyRecord>> {
        let map = self.records.read();
        Ok(map.values().flat_map(|v| v.clone()).collect())
    }

    fn update_version(&self, record: KeyRecord) -> HsmResult<()> {
        let mut map = self.records.write();
        let versions = map
            .get_mut(&record.metadata.id)
            .ok_or_else(|| HsmError::KeyNotFound(record.metadata.id.clone()))?;
        if let Some(existing) = versions
            .iter_mut()
            .find(|rec| rec.metadata.version == record.metadata.version)
        {
            *existing = record;
            self.rebuild_index(&*map);
            Ok(())
        } else {
            Err(HsmError::KeyNotFound(format!(
                "{}@v{}",
                record.metadata.id, record.metadata.version
            )))
        }
    }

    fn purge_version(&self, id: &KeyId, version: u32) -> HsmResult<PurgeReport> {
        let mut map = self.records.write();
        let versions = map
            .get_mut(id)
            .ok_or_else(|| HsmError::KeyNotFound(id.to_string()))?;
        if let Some(active) = versions.last() {
            if active.metadata.version == version {
                return Err(HsmError::invalid("cannot purge active key version"));
            }
        }

        let index = versions
            .iter()
            .position(|rec| rec.metadata.version == version)
            .ok_or_else(|| HsmError::KeyNotFound(format!("{id}@v{version}")))?;
        let record = versions.remove(index);
        self.rebuild_index(&*map);
        let mut buffer = vec![0u8; record.sealed.ciphertext.len()];
        OsRng.fill_bytes(&mut buffer);
        let mut hasher = Sha256::new();
        hasher.update(&buffer);
        Ok(PurgeReport {
            bytes_overwritten: record.sealed.ciphertext.len() as u64,
            data_hash: hex::encode(hasher.finalize()),
        })
    }
}

#[derive(Default)]
struct AttributeIndex {
    map: HashMap<AttributeId, HashMap<AttributeValue, Vec<(KeyId, u32)>>>,
}

impl AttributeIndex {
    fn rebuild_from_iter<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = (KeyId, u32, AttributeSet)>,
    {
        self.map.clear();
        for (key_id, version, attributes) in iter {
            self.insert_entry(key_id, version, &attributes);
        }
    }

    fn insert_entry(&mut self, key_id: KeyId, version: u32, attributes: &AttributeSet) {
        for (attr_id, attr_value) in attributes.iter() {
            self.map
                .entry(*attr_id)
                .or_default()
                .entry(attr_value.clone())
                .or_default()
                .push((key_id.clone(), version));
        }
    }

    fn lookup(&self, id: AttributeId, value: &AttributeValue) -> Vec<(KeyId, u32)> {
        self.map
            .get(&id)
            .and_then(|by_value| by_value.get(value))
            .cloned()
            .unwrap_or_default()
    }
}

/// SQLite-backed key store enabling database deployments.
pub struct SqliteKeyStore {
    conn: ParkingMutex<Connection>,
    index: RwLock<AttributeIndex>,
}

impl SqliteKeyStore {
    pub fn new<P: AsRef<Path>>(path: P) -> HsmResult<Self> {
        let conn = Connection::open(path).map_err(HsmError::storage)?;
        conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            CREATE TABLE IF NOT EXISTS key_records (
                id TEXT NOT NULL,
                version INTEGER NOT NULL,
                record BLOB NOT NULL,
                PRIMARY KEY (id, version)
            );
            "#,
        )
        .map_err(HsmError::storage)?;
        let store = Self {
            conn: ParkingMutex::new(conn),
            index: RwLock::new(AttributeIndex::default()),
        };
        store.rebuild_index()?;
        Ok(store)
    }

    pub fn find_by_attributes(&self, template: &AttributeTemplate) -> HsmResult<Vec<KeyRecord>> {
        if template.is_empty() {
            return self.list_all_versions();
        }
        let (attr_id, attr_value) = match template.entries().first() {
            Some(pair) => pair,
            None => return Ok(Vec::new()),
        };

        let candidates = {
            let index = self.index.read();
            index.lookup(*attr_id, attr_value)
        };

        let mut results = Vec::new();
        for (key_id, version) in candidates {
            if let Ok(record) = self.fetch_version(&key_id, version) {
                if record.metadata.attributes.matches_template(template) {
                    results.push(record);
                }
            }
        }
        Ok(results)
    }

    fn rebuild_index(&self) -> HsmResult<()> {
        let records = self.list_all_versions()?;
        let mut index = self.index.write();
        index.rebuild_from_iter(records.into_iter().map(|record| {
            (
                record.metadata.id.clone(),
                record.metadata.version,
                record.metadata.attributes.clone(),
            )
        }));
        Ok(())
    }

    fn load_record(blob: &[u8]) -> HsmResult<KeyRecord> {
        serde_json::from_slice(blob).map_err(HsmError::storage)
    }

    fn store_internal(&self, conn: &Connection, record: &KeyRecord) -> HsmResult<()> {
        let highest: Option<u32> = conn
            .query_row(
                "SELECT MAX(version) FROM key_records WHERE id = ?1",
                params![record.metadata.id],
                |row| row.get(0),
            )
            .optional()
            .map_err(HsmError::storage)?
            .flatten();

        if let Some(highest) = highest {
            if record.metadata.version > highest + 1 {
                return Err(HsmError::invalid(format!(
                    "version gap detected: current highest {highest}, attempted {}",
                    record.metadata.version
                )));
            }
            if record.metadata.version <= highest {
                return Err(HsmError::invalid("cannot overwrite historical key version"));
            }
        } else if record.metadata.version != 1 {
            return Err(HsmError::invalid("first key version must be 1"));
        }

        let data = serde_json::to_vec(record).map_err(HsmError::storage)?;
        conn.execute(
            "INSERT INTO key_records (id, version, record) VALUES (?1, ?2, ?3)",
            params![record.metadata.id, record.metadata.version, data],
        )
        .map_err(HsmError::storage)?;
        Ok(())
    }

    fn fetch_latest(&self, conn: &Connection, id: &KeyId) -> HsmResult<KeyRecord> {
        let data: Vec<u8> = conn
            .query_row(
                "SELECT record FROM key_records WHERE id = ?1 ORDER BY version DESC LIMIT 1",
                params![id],
                |row| row.get(0),
            )
            .optional()
            .map_err(HsmError::storage)?
            .ok_or_else(|| HsmError::KeyNotFound(id.clone()))?;
        Self::load_record(&data)
    }

    fn fetch_version_internal(
        &self,
        conn: &Connection,
        id: &KeyId,
        version: u32,
    ) -> HsmResult<KeyRecord> {
        let data: Vec<u8> = conn
            .query_row(
                "SELECT record FROM key_records WHERE id = ?1 AND version = ?2",
                params![id, version],
                |row| row.get(0),
            )
            .optional()
            .map_err(HsmError::storage)?
            .ok_or_else(|| HsmError::KeyNotFound(format!("{id}@v{version}")))?;
        Self::load_record(&data)
    }
}

impl KeyStore for SqliteKeyStore {
    fn store(&self, record: KeyRecord) -> HsmResult<()> {
        let mut conn = self.conn.lock();
        let tx = conn.transaction().map_err(HsmError::storage)?;
        self.store_internal(&tx, &record)?;
        tx.commit().map_err(HsmError::storage)?;
        self.rebuild_index()?;
        Ok(())
    }

    fn fetch(&self, id: &KeyId) -> HsmResult<KeyRecord> {
        let conn = self.conn.lock();
        self.fetch_latest(&conn, id)
    }

    fn fetch_version(&self, id: &KeyId, version: u32) -> HsmResult<KeyRecord> {
        let conn = self.conn.lock();
        self.fetch_version_internal(&conn, id, version)
    }

    fn list(&self) -> HsmResult<Vec<KeyRecord>> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare("SELECT DISTINCT id FROM key_records")
            .map_err(HsmError::storage)?;
        let ids = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(HsmError::storage)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(HsmError::storage)?;
        ids.into_iter()
            .map(|id| self.fetch_latest(&conn, &id))
            .collect()
    }

    fn list_versions(&self, id: &KeyId) -> HsmResult<Vec<KeyRecord>> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare("SELECT record FROM key_records WHERE id = ?1 ORDER BY version ASC")
            .map_err(HsmError::storage)?;
        let rows = stmt
            .query_map(params![id], |row| row.get::<_, Vec<u8>>(0))
            .map_err(HsmError::storage)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(HsmError::storage)?;
        rows.into_iter()
            .map(|blob| Self::load_record(&blob))
            .collect()
    }

    fn delete(&self, id: &KeyId) -> HsmResult<()> {
        let conn = self.conn.lock();
        conn.execute("DELETE FROM key_records WHERE id = ?1", params![id])
            .map_err(HsmError::storage)?;
        drop(conn);
        self.rebuild_index()?;
        Ok(())
    }

    fn list_all_versions(&self) -> HsmResult<Vec<KeyRecord>> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare("SELECT record FROM key_records")
            .map_err(HsmError::storage)?;
        let rows = stmt
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .map_err(HsmError::storage)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(HsmError::storage)?;
        rows.into_iter()
            .map(|blob| Self::load_record(&blob))
            .collect()
    }

    fn update_version(&self, record: KeyRecord) -> HsmResult<()> {
        let conn = self.conn.lock();
        let data = serde_json::to_vec(&record).map_err(HsmError::storage)?;
        let rows = conn
            .execute(
                "UPDATE key_records SET record = ?3 WHERE id = ?1 AND version = ?2",
                params![record.metadata.id, record.metadata.version, data],
            )
            .map_err(HsmError::storage)?;
        if rows == 0 {
            return Err(HsmError::KeyNotFound(format!(
                "{}@v{}",
                record.metadata.id, record.metadata.version
            )));
        }
        drop(conn);
        self.rebuild_index()?;
        Ok(())
    }

    fn purge_version(&self, id: &KeyId, version: u32) -> HsmResult<PurgeReport> {
        let conn = self.conn.lock();
        let active = self.fetch_latest(&conn, id)?;
        if active.metadata.version == version {
            return Err(HsmError::invalid("cannot purge active key version"));
        }

        let record = self.fetch_version_internal(&conn, id, version)?;
        let mut buffer = vec![0u8; record.sealed.ciphertext.len()];
        OsRng.fill_bytes(&mut buffer);
        let mut hasher = Sha256::new();
        hasher.update(&buffer);
        conn.execute(
            "DELETE FROM key_records WHERE id = ?1 AND version = ?2",
            params![id, version],
        )
        .map_err(HsmError::storage)?;
        drop(conn);
        self.rebuild_index()?;
        Ok(PurgeReport {
            bytes_overwritten: record.sealed.ciphertext.len() as u64,
            data_hash: hex::encode(hasher.finalize()),
        })
    }
}

/// Trait describing remote/back-end specific semantics for cloud KMS adapters.
pub trait RemoteKeyVault: Send + Sync {
    fn put(&self, record: KeyRecord) -> HsmResult<()>;
    fn get_latest(&self, id: &KeyId) -> HsmResult<Option<KeyRecord>>;
    fn get_version(&self, id: &KeyId, version: u32) -> HsmResult<Option<KeyRecord>>;
    fn list_latest(&self) -> HsmResult<Vec<KeyRecord>>;
    fn list_versions(&self, id: &KeyId) -> HsmResult<Vec<KeyRecord>>;
    fn list_all_versions(&self) -> HsmResult<Vec<KeyRecord>>;
    fn delete_key(&self, id: &KeyId) -> HsmResult<()>;
    fn delete_version(&self, id: &KeyId, version: u32) -> HsmResult<()>;
}

/// Adapter that satisfies the `KeyStore` trait by delegating to a remote vault implementation.
pub struct RemoteKeyStore<V: RemoteKeyVault> {
    backend: V,
}

impl<V: RemoteKeyVault> RemoteKeyStore<V> {
    pub fn new(backend: V) -> Self {
        Self { backend }
    }
}

impl<V: RemoteKeyVault> KeyStore for RemoteKeyStore<V> {
    fn store(&self, record: KeyRecord) -> HsmResult<()> {
        self.backend.put(record)
    }

    fn fetch(&self, id: &KeyId) -> HsmResult<KeyRecord> {
        self.backend
            .get_latest(id)?
            .ok_or_else(|| HsmError::KeyNotFound(id.clone()))
    }

    fn fetch_version(&self, id: &KeyId, version: u32) -> HsmResult<KeyRecord> {
        self.backend
            .get_version(id, version)?
            .ok_or_else(|| HsmError::KeyNotFound(format!("{id}@v{version}")))
    }

    fn list(&self) -> HsmResult<Vec<KeyRecord>> {
        self.backend.list_latest()
    }

    fn list_versions(&self, id: &KeyId) -> HsmResult<Vec<KeyRecord>> {
        self.backend.list_versions(id)
    }

    fn delete(&self, id: &KeyId) -> HsmResult<()> {
        self.backend.delete_key(id)
    }

    fn list_all_versions(&self) -> HsmResult<Vec<KeyRecord>> {
        self.backend.list_all_versions()
    }

    fn update_version(&self, record: KeyRecord) -> HsmResult<()> {
        self.backend.put(record)
    }

    fn purge_version(&self, id: &KeyId, version: u32) -> HsmResult<PurgeReport> {
        if let Some(active) = self.backend.get_latest(id)? {
            if active.metadata.version == version {
                return Err(HsmError::invalid("cannot purge active key version"));
            }
        }
        self.backend.delete_version(id, version)?;
        Ok(PurgeReport {
            bytes_overwritten: 0,
            data_hash: "remote-managed".into(),
        })
    }
}
