use std::{
    collections::HashMap,
    fs::OpenOptions,
    io::{BufWriter, Write},
    path::{Path, PathBuf},
};

use fs2::FileExt;
use parking_lot::Mutex;
use serde::Deserialize;
use serde::Serialize;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::{
    error::{HsmError, HsmResult},
    fs_utils,
    models::{KeyMetadata, KeyState},
};

#[derive(Debug, Clone)]
pub struct RetentionPolicy {
    default: Duration,
    tags: HashMap<String, Duration>,
    overrides: Vec<RetentionOverride>,
}

#[derive(Debug, Clone)]
struct RetentionOverride {
    key_id: String,
    version: Option<u32>,
    duration: Duration,
}

#[derive(Debug, Deserialize)]
struct RawRetentionPolicy {
    #[serde(default = "default_default_days")]
    default_days: u64,
    #[serde(default)]
    tags: HashMap<String, u64>,
    #[serde(default)]
    overrides: Vec<RawRetentionOverride>,
}

#[derive(Debug, Deserialize)]
struct RawRetentionOverride {
    key_id: String,
    #[serde(default)]
    version: Option<u32>,
    days: u64,
}

fn default_default_days() -> u64 {
    365
}

impl RetentionPolicy {
    pub fn from_path<P: AsRef<Path>>(path: P) -> HsmResult<Self> {
        let path = path.as_ref();
        let contents = std::fs::read_to_string(path).map_err(HsmError::storage)?;
        let raw: RawRetentionPolicy = if path
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.eq_ignore_ascii_case("json"))
            .unwrap_or(false)
        {
            serde_json::from_str(&contents).map_err(HsmError::storage)?
        } else {
            serde_yaml::from_str(&contents).map_err(HsmError::storage)?
        };
        Self::from_raw(raw)
    }

    fn from_raw(raw: RawRetentionPolicy) -> HsmResult<Self> {
        let default = days_to_duration(raw.default_days)?;
        let tags = raw
            .tags
            .into_iter()
            .map(|(tag, days)| Ok((tag, days_to_duration(days)?)))
            .collect::<HsmResult<HashMap<_, _>>>()?;
        let overrides = raw
            .overrides
            .into_iter()
            .map(|ov| {
                Ok(RetentionOverride {
                    key_id: ov.key_id,
                    version: ov.version,
                    duration: days_to_duration(ov.days)?,
                })
            })
            .collect::<HsmResult<Vec<_>>>()?;
        Ok(Self {
            default,
            tags,
            overrides,
        })
    }

    pub fn retention_duration(&self, metadata: &KeyMetadata) -> Duration {
        let mut duration = self.default;

        for tag in &metadata.policy_tags {
            if let Some(tag_duration) = self.tags.get(tag) {
                if *tag_duration > duration {
                    duration = *tag_duration;
                }
            }
        }

        for override_entry in &self.overrides {
            if override_entry.key_id == metadata.id {
                match override_entry.version {
                    Some(version) if version == metadata.version => {
                        duration = override_entry.duration;
                        break;
                    }
                    None => {
                        if override_entry.duration > duration {
                            duration = override_entry.duration;
                        }
                    }
                    _ => {}
                }
            }
        }

        duration
    }

    pub fn retention_deadline(&self, metadata: &KeyMetadata) -> OffsetDateTime {
        metadata.created_at + self.retention_duration(metadata)
    }

    pub fn should_purge(&self, metadata: &KeyMetadata, now: OffsetDateTime) -> bool {
        matches!(metadata.state, KeyState::Revoked | KeyState::PurgeScheduled)
            && now >= self.retention_deadline(metadata)
    }
}

fn days_to_duration(days: u64) -> HsmResult<Duration> {
    let days = i64::try_from(days).map_err(|_| HsmError::invalid("retention days overflow"))?;
    Ok(Duration::days(days))
}

#[derive(Debug, Serialize)]
pub struct RetentionLedgerEntry {
    pub id: Uuid,
    pub timestamp: OffsetDateTime,
    pub key_id: String,
    pub version: u32,
    pub approval_id: Option<Uuid>,
    pub requester: Option<String>,
    pub approved_by: Option<String>,
    pub approved_at: Option<OffsetDateTime>,
    pub purged_at: OffsetDateTime,
    pub bytes_overwritten: u64,
    pub data_hash: String,
    pub method: String,
    pub notes: Option<String>,
}

pub struct RetentionLedger {
    path: PathBuf,
    lock: Mutex<()>,
}

impl RetentionLedger {
    pub fn new<P: AsRef<Path>>(path: P) -> HsmResult<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            fs_utils::ensure_secure_dir(parent).map_err(HsmError::storage)?;
        }
        Ok(Self {
            path,
            lock: Mutex::new(()),
        })
    }

    pub fn append(&self, entry: &RetentionLedgerEntry) -> HsmResult<()> {
        let _guard = self.lock.lock();
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        let file = fs_utils::open_secure(&self.path, &mut options).map_err(HsmError::storage)?;
        FileExt::lock_exclusive(&file).map_err(HsmError::storage)?;
        let mut writer = BufWriter::new(&file);
        serde_json::to_writer(&mut writer, entry).map_err(HsmError::storage)?;
        writer.write_all(b"\n").map_err(HsmError::storage)?;
        writer.flush().map_err(HsmError::storage)?;
        file.sync_all().map_err(HsmError::storage)?;
        FileExt::unlock(&file).map_err(HsmError::storage)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        attributes::AttributeSet,
        models::{KeyAlgorithm, KeyMetadata, KeyPurpose, KeyState, TamperStatus},
    };
    use std::collections::HashMap;

    fn base_metadata(tags: Vec<&str>, state: KeyState) -> KeyMetadata {
        KeyMetadata {
            id: "testing".into(),
            version: 1,
            algorithm: KeyAlgorithm::Aes256Gcm,
            usage: vec![KeyPurpose::Encrypt],
            description: None,
            created_at: OffsetDateTime::now_utc() - Duration::days(400),
            state,
            policy_tags: tags.into_iter().map(|s| s.to_string()).collect(),
            tamper_status: TamperStatus::Clean,
            attributes: AttributeSet::new(),
        }
    }

    #[test]
    fn selects_longest_tag_duration() {
        let policy = RetentionPolicy::from_raw(RawRetentionPolicy {
            default_days: 180,
            tags: HashMap::from([
                ("operational.default".into(), 180),
                ("operational.critical".into(), 365),
            ]),
            overrides: vec![],
        })
        .expect("policy");

        let metadata = base_metadata(
            vec!["operational.default", "operational.critical"],
            KeyState::Revoked,
        );
        let duration = policy.retention_duration(&metadata);
        assert_eq!(duration.whole_days(), 365);
    }

    #[test]
    fn override_by_version_takes_priority() {
        let policy = RetentionPolicy::from_raw(RawRetentionPolicy {
            default_days: 30,
            tags: HashMap::new(),
            overrides: vec![RawRetentionOverride {
                key_id: "testing".into(),
                version: Some(1),
                days: 720,
            }],
        })
        .expect("policy");

        let metadata = base_metadata(vec![], KeyState::Revoked);
        let duration = policy.retention_duration(&metadata);
        assert_eq!(duration.whole_days(), 720);
    }

    #[test]
    fn should_purge_when_deadline_passed() {
        let policy = RetentionPolicy::from_raw(RawRetentionPolicy {
            default_days: 30,
            tags: HashMap::new(),
            overrides: vec![],
        })
        .expect("policy");
        let metadata = base_metadata(vec![], KeyState::Revoked);
        assert!(policy.should_purge(&metadata, OffsetDateTime::now_utc()));
    }

    #[test]
    fn does_not_purge_active_keys() {
        let policy = RetentionPolicy::from_raw(RawRetentionPolicy {
            default_days: 30,
            tags: HashMap::new(),
            overrides: vec![],
        })
        .expect("policy");
        let metadata = base_metadata(vec![], KeyState::Active);
        assert!(!policy.should_purge(&metadata, OffsetDateTime::now_utc()));
    }
}
