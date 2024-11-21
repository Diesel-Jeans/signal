use crate::storage::protocol_store::GenericProtocolStore;
use libsignal_core::{Aci, Pni};
use libsignal_protocol::{
    IdentityKeyStore, KyberPreKeyStore, PreKeyStore, SenderKeyStore, SessionStore,
    SignedPreKeyStore,
};

pub trait Storage<ID, PK, SPK, KPK, SS, SKS>
where
    ID: IdentityKeyStore,
    PK: PreKeyStore,
    SPK: SignedPreKeyStore,
    KPK: KyberPreKeyStore,
    SS: SessionStore,
    SKS: SenderKeyStore,
{
    fn set_password(&mut self, new_password: &str);
    fn get_password(&self) -> &str;
    fn set_aci(&mut self, new_aci: &Aci);
    fn get_aci(&self) -> &Aci;
    fn set_pni(&mut self, new_pni: &Pni);
    fn get_pni(&self) -> &Pni;
    fn protocol_store(&mut self) -> &mut GenericProtocolStore<ID, PK, SPK, KPK, SS, SKS>;
}
