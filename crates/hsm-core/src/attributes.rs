use crate::error::HsmError;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Identifier for a PKCS#11-style attribute (mirrors CK_ATTRIBUTE_TYPE numeric values).
pub type AttributeId = u32;

/// Supported attribute value representations.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(tag = "type", content = "value")]
pub enum AttributeValue {
    Bool(bool),
    Uint(u64),
    Bytes(Vec<u8>),
    Mechanisms(Vec<String>),
}

/// Template used when searching for objects via attribute matching.
#[derive(Clone, Debug, Default)]
pub struct AttributeTemplate {
    entries: Vec<(AttributeId, AttributeValue)>,
}

impl AttributeTemplate {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, id: AttributeId, value: AttributeValue) {
        self.entries.push((id, value));
    }

    pub fn entries(&self) -> &[(AttributeId, AttributeValue)] {
        &self.entries
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Collection of attributes persisted with a key.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttributeSet {
    #[serde(default)]
    entries: HashMap<AttributeId, AttributeValue>,
}

impl AttributeSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, id: AttributeId, value: AttributeValue) -> Option<AttributeValue> {
        self.entries.insert(id, value)
    }

    pub fn get(&self, id: AttributeId) -> Option<&AttributeValue> {
        self.entries.get(&id)
    }

    pub fn remove(&mut self, id: AttributeId) -> Option<AttributeValue> {
        self.entries.remove(&id)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&AttributeId, &AttributeValue)> {
        self.entries.iter()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Ensure all required attribute identifiers are present.
    pub fn validate_required(&self, required: &[AttributeId]) -> Result<(), HsmError> {
        for id in required {
            if !self.entries.contains_key(id) {
                return Err(HsmError::invalid(format!("missing attribute {id}")));
            }
        }
        Ok(())
    }

    /// Ensure no unexpected attributes beyond the allowed set are present.
    pub fn ensure_allowed(&self, allowed: &[AttributeId]) -> Result<(), HsmError> {
        let allowed: HashSet<AttributeId> = allowed.iter().copied().collect();
        for key in self.entries.keys() {
            if !allowed.contains(key) {
                return Err(HsmError::invalid(format!("unsupported attribute {key}")));
            }
        }
        Ok(())
    }

    /// Returns true when all entries in the template match the set exactly.
    pub fn matches_template(&self, template: &AttributeTemplate) -> bool {
        template
            .entries()
            .iter()
            .all(|(id, value)| self.get(*id).map_or(false, |candidate| candidate == value))
    }
}
