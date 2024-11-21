use libsignal_protocol::{
    InMemIdentityKeyStore, InMemKyberPreKeyStore, InMemPreKeyStore, InMemSenderKeyStore,
    InMemSessionStore, InMemSignedPreKeyStore,
};

use super::{protocol_store::GenericProtocolStore, storage_trait::Storage};

pub struct InMemoryStore {
    protocol_store: InMemoryProtocolStore,
}

impl
    Storage<
        InMemIdentityKeyStore,
        InMemPreKeyStore,
        InMemSignedPreKeyStore,
        InMemKyberPreKeyStore,
        InMemSessionStore,
        InMemSenderKeyStore,
    > for InMemoryStore
{
    fn set_password(&mut self, new_password: &str) {
        todo!()
    }

    fn get_password(&self) -> &str {
        todo!()
    }

    fn set_aci(&mut self, new_aci: &libsignal_core::Aci) {
        todo!()
    }

    fn get_aci(&self) -> &libsignal_core::Aci {
        todo!()
    }

    fn set_pni(&mut self, new_pni: &libsignal_core::Pni) {
        todo!()
    }

    fn get_pni(&self) -> &libsignal_core::Pni {
        todo!()
    }

    fn protocol_store(&mut self) -> &mut InMemoryProtocolStore {
        &mut self.protocol_store
    }
}

type InMemoryProtocolStore = GenericProtocolStore<
    InMemIdentityKeyStore,
    InMemPreKeyStore,
    InMemSignedPreKeyStore,
    InMemKyberPreKeyStore,
    InMemSessionStore,
    InMemSenderKeyStore,
>;
