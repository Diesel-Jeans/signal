use super::generic::{ProtocolStore, SignalStore, Storage};
use crate::{errors::SignalClientError, storage::generic::StorageType};
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
    type Error = SignalClientError;

    async fn set_password(&mut self, new_password: String) -> Result<(), Self::Error> {
        self.inner.password = new_password;
        Ok(())
    }

    async fn get_password(&self) -> Result<String, Self::Error> {
        Ok(self.inner.password.to_string())
    }

    async fn set_aci(&mut self, new_aci: Aci) -> Result<(), Self::Error> {
        self.inner.aci = new_aci;
        Ok(())
    }

    async fn get_aci(&self) -> Result<Aci, Self::Error> {
        Ok(self.inner.aci)
    }

    async fn set_pni(&mut self, new_pni: Pni) -> Result<(), Self::Error> {
        self.inner.pni = new_pni;
        Ok(())
    }

    async fn get_pni(&self) -> Result<Pni, Self::Error> {
        Ok(self.inner.pni)
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
