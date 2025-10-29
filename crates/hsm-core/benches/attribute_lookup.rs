use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use hsm_core::{
    KeyMaterialType,
    attributes::{AttributeSet, AttributeTemplate, AttributeValue},
    models::{KeyAlgorithm, KeyMetadata, KeyPurpose, KeyState, TamperStatus},
    storage::{FileKeyStore, KeyRecord, MemoryKeyStore, SealedKeyMaterial},
};
use tempfile::TempDir;
use time::OffsetDateTime;

const LABEL_ATTR: u32 = 0x0000_0003;

fn make_record(id: &str, version: u32, label: &str) -> KeyRecord {
    let mut attributes = AttributeSet::new();
    attributes.insert(LABEL_ATTR, AttributeValue::Bytes(label.as_bytes().to_vec()));

    let metadata = KeyMetadata {
        id: id.to_string(),
        version,
        algorithm: KeyAlgorithm::Aes256Gcm,
        usage: vec![KeyPurpose::Encrypt],
        description: None,
        created_at: OffsetDateTime::now_utc(),
        state: KeyState::Active,
        policy_tags: Vec::new(),
        tamper_status: TamperStatus::Clean,
        attributes,
    };

    let sealed = SealedKeyMaterial {
        nonce: vec![0; 12],
        ciphertext: vec![0; 32],
        hmac: vec![0; 32],
        material_type: KeyMaterialType::Symmetric,
    };

    KeyRecord { metadata, sealed }
}

fn sample_records(count: usize) -> Vec<KeyRecord> {
    (0..count)
        .map(|i| {
            let id = format!("bench-key-{i:05}");
            make_record(&id, 1, &id)
        })
        .collect()
}

fn populate_memory_store(records: &[KeyRecord]) -> MemoryKeyStore {
    let store = MemoryKeyStore::new();
    for record in records {
        store.store(record.clone()).unwrap();
    }
    store
}

fn populate_file_store(records: &[KeyRecord]) -> (FileKeyStore, TempDir) {
    let tempdir = TempDir::new().expect("tempdir");
    let store = FileKeyStore::new(tempdir.path()).expect("file store");
    for record in records {
        store.store(record.clone()).unwrap();
    }
    (store, tempdir)
}

fn bench_attribute_lookup(c: &mut Criterion) {
    let records = sample_records(1_000);

    let memory_store = populate_memory_store(&records);
    let (file_store, _dir) = populate_file_store(&records);

    let target_label = records[records.len() / 2].metadata.id.clone();
    let mut template = AttributeTemplate::new();
    template.push(
        LABEL_ATTR,
        AttributeValue::Bytes(target_label.as_bytes().to_vec()),
    );

    let mut group = c.benchmark_group("attribute_lookup");
    group.bench_function(BenchmarkId::new("memory", records.len()), |b| {
        b.iter(|| {
            let results = memory_store.find_by_attributes(&template).unwrap();
            black_box(results.len());
        });
    });

    group.bench_function(BenchmarkId::new("file", records.len()), |b| {
        b.iter(|| {
            let results = file_store.find_by_attributes(&template).unwrap();
            black_box(results.len());
        });
    });
    group.finish();
}

criterion_group!(benches, bench_attribute_lookup);
criterion_main!(benches);
