//! Slot and token management

use cryptoki::types::*;
use std::collections::HashMap;

/// Represents a PKCS#11 slot
#[derive(Clone)]
pub struct Slot {
    pub id: CK_SLOT_ID,
    pub token: Option<Token>,
}

/// Represents a token in a slot
#[derive(Clone)]
pub struct Token {
    pub label: String,
    pub serial_number: String,
    pub model: String,
    pub manufacturer: String,
    pub flags: CK_FLAGS,
}

/// Manages available slots
#[derive(Clone)]
pub struct SlotManager {
    slots: HashMap<CK_SLOT_ID, Slot>,
}

impl SlotManager {
    pub fn new() -> Self {
        Self {
            slots: HashMap::new(),
        }
    }

    pub fn add_slot(&mut self, slot: Slot) {
        self.slots.insert(slot.id, slot);
    }

    pub fn get_slots(&self) -> Vec<&Slot> {
        self.slots.values().collect()
    }

    pub fn get_slot(&self, slot_id: CK_SLOT_ID) -> Option<&Slot> {
        self.slots.get(&slot_id)
    }
}