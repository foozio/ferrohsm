use crate::{
    attributes::{AttributeSet, AttributeTemplate},
    error::{HsmError, HsmResult},
    models::AuthContext,
};
use parking_lot::RwLock;
use std::{
    collections::{HashMap, VecDeque},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Instant,
};

pub type SlotId = u64;
pub type SessionHandle = u64;
pub type ObjectHandle = u64;

#[derive(Clone, Debug)]
pub struct SlotDescriptor {
    pub slot_id: SlotId,
    pub label: String,
    pub manufacturer: String,
    pub hardware_id: String,
}

pub trait HardwareAdapter: Send + Sync {
    fn id(&self) -> &'static str;
    fn supports_mechanism(&self, mechanism: &str) -> bool;
}

#[derive(Clone, Debug)]
pub enum SessionState {
    Public,
    User(AuthContext),
    SecurityOfficer(AuthContext),
}

#[derive(Clone, Debug)]
pub struct SessionInfo {
    pub slot_id: SlotId,
    pub read_only: bool,
    pub state: SessionState,
    pub opened_at: Instant,
    pub objects: Vec<ObjectHandle>,
    search: Option<SearchCursor>,
}

#[derive(Clone, Debug)]
pub struct ObjectDescriptor {
    pub handle: ObjectHandle,
    pub slot_id: SlotId,
    pub attributes: AttributeSet,
    pub token_object: bool,
    pub key_id: Option<String>,
}

impl ObjectDescriptor {
    pub fn token(slot_id: SlotId, attributes: AttributeSet, key_id: Option<String>) -> Self {
        Self {
            handle: 0,
            slot_id,
            attributes,
            token_object: true,
            key_id,
        }
    }

    pub fn session(slot_id: SlotId, attributes: AttributeSet, key_id: Option<String>) -> Self {
        Self {
            handle: 0,
            slot_id,
            attributes,
            token_object: false,
            key_id,
        }
    }
}

#[derive(Clone, Debug)]
struct SearchCursor {
    queue: VecDeque<ObjectHandle>,
}

struct SlotEntry {
    descriptor: SlotDescriptor,
    adapter: Arc<dyn HardwareAdapter>,
}

pub struct SessionManager {
    slots: HashMap<SlotId, SlotEntry>,
    sessions: RwLock<HashMap<SessionHandle, SessionInfo>>,
    objects: RwLock<HashMap<ObjectHandle, ObjectDescriptor>>,
    next_session: AtomicU64,
    next_object: AtomicU64,
}

impl SessionManager {
    pub fn new(slots: Vec<(SlotDescriptor, Arc<dyn HardwareAdapter>)>) -> Self {
        let slots_map = slots
            .into_iter()
            .map(|(descriptor, adapter)| {
                (
                    descriptor.slot_id,
                    SlotEntry {
                        descriptor,
                        adapter,
                    },
                )
            })
            .collect();
        Self {
            slots: slots_map,
            sessions: RwLock::new(HashMap::new()),
            objects: RwLock::new(HashMap::new()),
            next_session: AtomicU64::new(1),
            next_object: AtomicU64::new(1),
        }
    }

    pub fn list_slots(&self) -> Vec<SlotDescriptor> {
        self.slots
            .values()
            .map(|entry| entry.descriptor.clone())
            .collect()
    }

    pub fn open_session(&self, slot_id: SlotId, read_only: bool) -> HsmResult<SessionHandle> {
        if !self.slots.contains_key(&slot_id) {
            return Err(HsmError::invalid(format!("unknown slot {slot_id}")));
        }
        let handle = self.next_session.fetch_add(1, Ordering::Relaxed);
        let info = SessionInfo {
            slot_id,
            read_only,
            state: SessionState::Public,
            opened_at: Instant::now(),
            objects: Vec::new(),
            search: None,
        };
        self.sessions.write().insert(handle, info);
        Ok(handle)
    }

    pub fn close_session(&self, handle: SessionHandle) -> HsmResult<()> {
        let (objects_to_remove, slot) = {
            let mut guard = self.sessions.write();
            let session = guard
                .remove(&handle)
                .ok_or_else(|| HsmError::invalid(format!("session {handle} does not exist")))?;
            (session.objects, session.slot_id)
        };
        if !objects_to_remove.is_empty() {
            let mut registry = self.objects.write();
            for handle in objects_to_remove {
                registry.remove(&handle);
            }
        }
        self.teardown_search(slot);
        Ok(())
    }

    pub fn close_sessions_for_slot(&self, slot_id: SlotId) {
        let handles: Vec<SessionHandle> = {
            let guard = self.sessions.read();
            guard
                .iter()
                .filter_map(|(handle, info)| (info.slot_id == slot_id).then_some(*handle))
                .collect()
        };
        for handle in handles {
            let _ = self.close_session(handle);
        }
    }

    pub fn login(&self, handle: SessionHandle, state: SessionState) -> HsmResult<()> {
        let mut guard = self.sessions.write();
        let session = guard
            .get_mut(&handle)
            .ok_or_else(|| HsmError::invalid(format!("session {handle} not found")))?;
        if matches!(session.state, SessionState::Public) {
            session.state = state;
            Ok(())
        } else {
            Err(HsmError::invalid("session already logged in"))
        }
    }

    pub fn logout(&self, handle: SessionHandle) -> HsmResult<()> {
        let (objects_to_remove, slot_id) = {
            let mut guard = self.sessions.write();
            let session = guard
                .get_mut(&handle)
                .ok_or_else(|| HsmError::invalid(format!("session {handle} not found")))?;
            session.state = SessionState::Public;
            session.search = None;
            let objects = session.objects.clone();
            session.objects.clear();
            (objects, session.slot_id)
        };
        if !objects_to_remove.is_empty() {
            let mut registry = self.objects.write();
            for handle in objects_to_remove {
                registry.remove(&handle);
            }
        }
        self.teardown_search(slot_id);
        Ok(())
    }

    pub fn register_token_object(
        &self,
        mut descriptor: ObjectDescriptor,
    ) -> HsmResult<ObjectHandle> {
        if !self.slots.contains_key(&descriptor.slot_id) {
            return Err(HsmError::invalid("slot not registered"));
        }
        descriptor.token_object = true;
        Ok(self.insert_object(descriptor))
    }

    pub fn register_session_object(
        &self,
        session_handle: SessionHandle,
        attributes: AttributeSet,
        key_id: Option<String>,
    ) -> HsmResult<ObjectHandle> {
        let slot_id = {
            let guard = self.sessions.read();
            guard
                .get(&session_handle)
                .map(|session| session.slot_id)
                .ok_or_else(|| HsmError::invalid(format!("session {session_handle} not found")))?
        };

        let handle = self.insert_object(ObjectDescriptor::session(slot_id, attributes, key_id));
        let mut guard = self.sessions.write();
        let session = guard
            .get_mut(&session_handle)
            .ok_or_else(|| HsmError::invalid(format!("session {session_handle} not found")))?;
        session.objects.push(handle);
        Ok(handle)
    }

    pub fn find_objects_init(
        &self,
        session_handle: SessionHandle,
        template: AttributeTemplate,
    ) -> HsmResult<()> {
        let mut sessions = self.sessions.write();
        let session = sessions
            .get_mut(&session_handle)
            .ok_or_else(|| HsmError::invalid(format!("session {session_handle} not found")))?;

        let registry = self.objects.read();
        let mut matches = VecDeque::new();
        for descriptor in registry.values() {
            if descriptor.slot_id != session.slot_id {
                continue;
            }
            let visible = if descriptor.token_object {
                true
            } else {
                session.objects.contains(&descriptor.handle)
            };
            if !visible {
                continue;
            }
            if template.is_empty() || descriptor.attributes.matches_template(&template) {
                matches.push_back(descriptor.handle);
            }
        }
        session.search = Some(SearchCursor { queue: matches });
        Ok(())
    }

    pub fn find_objects(
        &self,
        session_handle: SessionHandle,
        max_objects: usize,
    ) -> HsmResult<Vec<ObjectHandle>> {
        let mut sessions = self.sessions.write();
        let session = sessions
            .get_mut(&session_handle)
            .ok_or_else(|| HsmError::invalid(format!("session {session_handle} not found")))?;
        let cursor = session
            .search
            .as_mut()
            .ok_or_else(|| HsmError::invalid("C_FindObjects called before C_FindObjectsInit"))?;
        let limit = max_objects.max(1);
        let mut results = Vec::new();
        for _ in 0..limit {
            if let Some(handle) = cursor.queue.pop_front() {
                results.push(handle);
            } else {
                break;
            }
        }
        Ok(results)
    }

    pub fn find_objects_final(&self, session_handle: SessionHandle) -> HsmResult<()> {
        let mut sessions = self.sessions.write();
        let session = sessions
            .get_mut(&session_handle)
            .ok_or_else(|| HsmError::invalid(format!("session {session_handle} not found")))?;
        session.search = None;
        Ok(())
    }

    pub fn adapter_for_object(&self, handle: ObjectHandle) -> Option<Arc<dyn HardwareAdapter>> {
        let registry = self.objects.read();
        let descriptor = registry.get(&handle)?;
        self.adapter_for_slot(descriptor.slot_id)
    }

    pub fn adapter_for_slot(&self, slot_id: SlotId) -> Option<Arc<dyn HardwareAdapter>> {
        self.slots
            .get(&slot_id)
            .map(|entry| Arc::clone(&entry.adapter))
    }

    pub fn session(&self, handle: SessionHandle) -> HsmResult<SessionInfo> {
        self.sessions
            .read()
            .get(&handle)
            .cloned()
            .ok_or_else(|| HsmError::invalid(format!("session {handle} not found")))
    }

    fn insert_object(&self, mut descriptor: ObjectDescriptor) -> ObjectHandle {
        let handle = self.next_object.fetch_add(1, Ordering::Relaxed);
        descriptor.handle = handle;
        self.objects.write().insert(handle, descriptor);
        handle
    }

    fn teardown_search(&self, slot_id: SlotId) {
        let mut sessions = self.sessions.write();
        for session in sessions.values_mut().filter(|s| s.slot_id == slot_id) {
            session.search = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        attributes::{AttributeSet, AttributeValue},
        rbac::Role,
    };

    struct StubAdapter;

    impl HardwareAdapter for StubAdapter {
        fn id(&self) -> &'static str {
            "stub"
        }

        fn supports_mechanism(&self, _mechanism: &str) -> bool {
            true
        }
    }

    fn make_slot_entry() -> (SlotDescriptor, Arc<dyn HardwareAdapter>) {
        (
            SlotDescriptor {
                slot_id: 1,
                label: "software".into(),
                manufacturer: "FerroHSM".into(),
                hardware_id: "soft".into(),
            },
            Arc::new(StubAdapter),
        )
    }

    fn auth(role: Role) -> AuthContext {
        AuthContext {
            actor_id: "tester".into(),
            session_id: uuid::Uuid::new_v4(),
            roles: vec![role],
            client_fingerprint: None,
            source_ip: None,
        }
    }

    #[test]
    fn open_and_close_session() {
        let manager = SessionManager::new(vec![make_slot_entry()]);
        let handle = manager.open_session(1, true).expect("session should open");
        assert!(manager.session(handle).is_ok());
        manager.close_session(handle).expect("close succeeds");
        assert!(manager.session(handle).is_err());
    }

    #[test]
    fn login_and_logout_transitions() {
        let manager = SessionManager::new(vec![make_slot_entry()]);
        let handle = manager.open_session(1, false).unwrap();
        manager
            .login(handle, SessionState::User(auth(Role::Operator)))
            .unwrap();
        manager.logout(handle).unwrap();
        let info = manager.session(handle).unwrap();
        assert!(matches!(info.state, SessionState::Public));
    }

    #[test]
    fn session_object_registration() {
        let manager = SessionManager::new(vec![make_slot_entry()]);
        let handle = manager.open_session(1, false).unwrap();
        let mut attrs = AttributeSet::new();
        attrs.insert(1, AttributeValue::Bool(true));
        let obj = manager
            .register_session_object(handle, attrs.clone(), None)
            .unwrap();
        assert_ne!(obj, 0);
        let info = manager.session(handle).unwrap();
        assert_eq!(info.objects.len(), 1);

        // token object remains after new session
        let token = manager
            .register_token_object(ObjectDescriptor::token(1, attrs, None))
            .unwrap();
        assert_ne!(token, 0);
    }

    #[test]
    fn find_objects_filters_by_attributes() {
        let manager = SessionManager::new(vec![make_slot_entry()]);
        let handle = manager.open_session(1, false).unwrap();
        let mut attrs = AttributeSet::new();
        attrs.insert(1, AttributeValue::Bool(true));
        let token_handle = manager
            .register_token_object(ObjectDescriptor::token(1, attrs.clone(), None))
            .unwrap();
        let mut template = AttributeTemplate::new();
        template.push(1, AttributeValue::Bool(true));
        manager
            .find_objects_init(handle, template)
            .expect("init search");
        let results = manager.find_objects(handle, 10).expect("search results");
        assert_eq!(results, vec![token_handle]);
        manager.find_objects_final(handle).unwrap();
    }

    #[test]
    fn adapter_routing_for_object() {
        let manager = SessionManager::new(vec![make_slot_entry()]);
        let mut attrs = AttributeSet::new();
        attrs.insert(1, AttributeValue::Uint(42));
        let handle = manager
            .register_token_object(ObjectDescriptor::token(1, attrs, None))
            .unwrap();
        let adapter = manager.adapter_for_object(handle).expect("adapter");
        assert_eq!(adapter.id(), "stub");
    }
}
