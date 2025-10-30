//! Session management

use crate::slot::SlotManager;
use cryptoki::types::*;
use std::collections::HashMap;

/// Represents a PKCS#11 session
pub struct Session {
    pub id: CK_SESSION_HANDLE,
    pub slot_id: CK_SLOT_ID,
    pub state: CK_STATE,
    pub flags: CK_FLAGS,
}

/// Manages active sessions
pub struct SessionManager {
    sessions: HashMap<CK_SESSION_HANDLE, Session>,
    slot_manager: SlotManager,
    next_session_id: CK_SESSION_HANDLE,
}

impl SessionManager {
    pub fn new(slot_manager: SlotManager) -> Self {
        Self {
            sessions: HashMap::new(),
            slot_manager,
            next_session_id: 1,
        }
    }

    pub fn open_session(
        &mut self,
        slot_id: CK_SLOT_ID,
        flags: CK_FLAGS,
    ) -> Result<CK_SESSION_HANDLE, CK_RV> {
        // Check if slot exists
        if self.slot_manager.get_slot(slot_id).is_none() {
            return Err(CK_RV::CKR_SLOT_ID_INVALID);
        }

        let session_id = self.next_session_id;
        self.next_session_id += 1;

        let session = Session {
            id: session_id,
            slot_id,
            state: CK_STATE::CKS_RO_PUBLIC_SESSION,
            flags,
        };

        self.sessions.insert(session_id, session);
        Ok(session_id)
    }

    pub fn close_session(&mut self, session_handle: CK_SESSION_HANDLE) -> Result<(), CK_RV> {
        if self.sessions.remove(&session_handle).is_some() {
            Ok(())
        } else {
            Err(CK_RV::CKR_SESSION_HANDLE_INVALID)
        }
    }

    pub fn get_session(&self, session_handle: CK_SESSION_HANDLE) -> Option<&Session> {
        self.sessions.get(&session_handle)
    }
}