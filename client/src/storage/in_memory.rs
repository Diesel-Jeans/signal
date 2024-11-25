use super::generic::{ProtocolStore, SignalStore, Storage};
use crate::storage::generic::StorageType;
use axum::async_trait;
use libsignal_core::{Aci, Pni};
use libsignal_protocol::{
    IdentityKeyPair, InMemIdentityKeyStore, InMemKyberPreKeyStore, InMemPreKeyStore,
    InMemSenderKeyStore, InMemSessionStore, InMemSignedPreKeyStore,
};

#[derive(Debug)]
pub struct InMemory {
    password: String,
    aci: Aci,
    pni: Pni,
}

impl InMemory {
    fn new(password: String, aci: Aci, pni: Pni) -> Self {
        Self { password, aci, pni }
    }
}

impl Storage<InMemory> {
    pub fn new(
        password: String,
        aci: Aci,
        pni: Pni,
        protocol_store: ProtocolStore<InMemory>,
    ) -> Self {
        Self {
            inner: InMemory::new(password, aci, pni),
            protocol_store,
        }
    }
}

impl StorageType for InMemory {
    type IdentityKeyStore = InMemIdentityKeyStore;
    type PreKeyStore = InMemPreKeyStore;
    type SignedPreKeyStore = InMemSignedPreKeyStore;
    type KyberPreKeyStore = InMemKyberPreKeyStore;
    type SessionStore = InMemSessionStore;
    type SenderKeyStore = InMemSenderKeyStore;
}

#[async_trait]
impl SignalStore for Storage<InMemory> {
    async fn set_password(&mut self, new_password: String) {
        self.inner.password = new_password;
    }

    async fn get_password(&self) -> &str {
        &self.inner.password
    }

    async fn set_aci(&mut self, new_aci: Aci) {
        self.inner.aci = new_aci
    }

    async fn get_aci(&self) -> &Aci {
        &self.inner.aci
    }

    async fn set_pni(&mut self, new_pni: Pni) {
        self.inner.pni = new_pni
    }

    async fn get_pni(&self) -> &Pni {
        &self.inner.pni
    }
}

impl ProtocolStore<InMemory> {
    pub fn new(id_key_pair: IdentityKeyPair, aci_registration_id: u32) -> Self {
        Self {
            identity_key_store: InMemIdentityKeyStore::new(id_key_pair, aci_registration_id),
            pre_key_store: InMemPreKeyStore::new(),
            signed_pre_key_store: InMemSignedPreKeyStore::new(),
            kyber_pre_key_store: InMemKyberPreKeyStore::new(),
            session_store: InMemSessionStore::new(),
            sender_key_store: InMemSenderKeyStore::new(),
        }
    }
}
