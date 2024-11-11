use std::borrow::Cow;
use std::collections::HashMap;
use std::{fs, u32};

use crate::errors::LoginError;

use super::protocol_store::ProtocolStore;
use super::serializations::{
    aci_serde, identity_key_pair_serde, identity_map_serde, kyber_pre_key_map_serde, pni_serde,
    pre_key_map_serde, private_key_serde, public_key_serde, sender_key_map_serde,
    session_map_serde, signed_pre_key_map_serde,
};
use bon::bon;
use http_client::async_trait;
use libsignal_core::{Aci, Pni, ProtocolAddress};
use libsignal_protocol::{
    Direction, IdentityKey, IdentityKeyPair, IdentityKeyStore, KyberPreKeyId, KyberPreKeyRecord,
    KyberPreKeyStore, PreKeyId, PreKeyRecord, PreKeyStore, PrivateKey, PublicKey, SenderKeyRecord,
    SenderKeyStore, SessionRecord, SessionStore, SignalProtocolError, SignedPreKeyId,
    SignedPreKeyRecord, SignedPreKeyStore,
};
use serde;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
pub struct DeviceProtocolStore {
    pub identity_key_store: DeviceIdentityKeyStore,
    pub pre_key_store: DevicePreKeyStore,
    pub signed_pre_key_store: DeviceSignedPreKeyStore,
    pub kyber_pre_key_store: DeviceKyberPreKeyStore,
    pub session_store: DeviceSessionStore,
    pub sender_key_store: DeviceSenderKeyStore,
}

impl DeviceProtocolStore {
    pub fn new(key_pair: IdentityKeyPair, registration_id: u32) -> Self {
        Self {
            identity_key_store: DeviceIdentityKeyStore::new(key_pair, registration_id),
            pre_key_store: DevicePreKeyStore::new(),
            signed_pre_key_store: DeviceSignedPreKeyStore::new(),
            kyber_pre_key_store: DeviceKyberPreKeyStore::new(),
            session_store: DeviceSessionStore::new(),
            sender_key_store: DeviceSenderKeyStore::new(),
        }
    }
}

impl
    ProtocolStore<
        DeviceIdentityKeyStore,
        DevicePreKeyStore,
        DeviceSignedPreKeyStore,
        DeviceKyberPreKeyStore,
        DeviceSessionStore,
        DeviceSenderKeyStore,
    > for DeviceProtocolStore
{
    fn identity_key_store(&self) -> &DeviceIdentityKeyStore {
        &self.identity_key_store
    }

    fn identity_key_store_mut(&mut self) -> &mut DeviceIdentityKeyStore {
        &mut self.identity_key_store
    }

    fn pre_key_store(&self) -> &DevicePreKeyStore {
        &self.pre_key_store
    }

    fn pre_key_store_mut(&mut self) -> &mut DevicePreKeyStore {
        &mut self.pre_key_store
    }

    fn signed_pre_key_store(&self) -> &DeviceSignedPreKeyStore {
        &self.signed_pre_key_store
    }

    fn signed_pre_key_store_mut(&mut self) -> &mut DeviceSignedPreKeyStore {
        &mut self.signed_pre_key_store
    }

    fn kyber_pre_key_store(&self) -> &DeviceKyberPreKeyStore {
        &self.kyber_pre_key_store
    }

    fn kyber_pre_key_store_mut(&mut self) -> &mut DeviceKyberPreKeyStore {
        &mut self.kyber_pre_key_store
    }

    fn session_store(&self) -> &DeviceSessionStore {
        &self.session_store
    }

    fn session_store_mut(&mut self) -> &mut DeviceSessionStore {
        &mut self.session_store
    }

    fn sender_key_store(&self) -> &DeviceSenderKeyStore {
        &self.sender_key_store
    }

    fn sender_key_store_mut(&mut self) -> &mut DeviceSenderKeyStore {
        &mut self.sender_key_store
    }
}

#[derive(Serialize, Deserialize)]
pub struct DeviceIdentityKeyStore {
    #[serde(with = "identity_key_pair_serde")]
    key_pair: IdentityKeyPair,
    registration_id: u32,
    #[serde(with = "identity_map_serde")]
    known_keys: HashMap<ProtocolAddress, IdentityKey>,
}

impl DeviceIdentityKeyStore {
    pub fn new(key_pair: IdentityKeyPair, registration_id: u32) -> Self {
        Self {
            key_pair,
            registration_id,
            known_keys: HashMap::new(),
        }
    }
}
#[async_trait(?Send)]
impl IdentityKeyStore for DeviceIdentityKeyStore {
    async fn get_identity_key_pair(&self) -> Result<IdentityKeyPair, SignalProtocolError> {
        Ok(self.key_pair)
    }

    async fn get_local_registration_id(&self) -> Result<u32, SignalProtocolError> {
        Ok(self.registration_id)
    }

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> Result<bool, SignalProtocolError> {
        match self.known_keys.get(address) {
            None => {
                self.known_keys.insert(address.clone(), *identity);
                Ok(false) // new key
            }
            Some(k) if k == identity => {
                Ok(false) // same key
            }
            Some(_k) => {
                self.known_keys.insert(address.clone(), *identity);
                Ok(true) // overwrite
            }
        }
    }

    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        _direction: Direction,
    ) -> Result<bool, SignalProtocolError> {
        match self.known_keys.get(address) {
            None => {
                Ok(true) // first use
            }
            Some(k) => Ok(k == identity),
        }
    }

    async fn get_identity(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<IdentityKey>, SignalProtocolError> {
        match self.known_keys.get(address) {
            None => Ok(None),
            Some(k) => Ok(Some(k.to_owned())),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct DevicePreKeyStore {
    #[serde(with = "pre_key_map_serde")]
    pre_keys: HashMap<PreKeyId, PreKeyRecord>,
}

impl DevicePreKeyStore {
    pub fn new() -> Self {
        Self {
            pre_keys: HashMap::new(),
        }
    }
}
#[async_trait(?Send)]
impl PreKeyStore for DevicePreKeyStore {
    async fn get_pre_key(&self, prekey_id: PreKeyId) -> Result<PreKeyRecord, SignalProtocolError> {
        Ok(self
            .pre_keys
            .get(&prekey_id)
            .ok_or(SignalProtocolError::InvalidPreKeyId)?
            .clone())
    }

    async fn save_pre_key(
        &mut self,
        prekey_id: PreKeyId,
        record: &PreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        self.pre_keys.insert(prekey_id, record.to_owned());
        Ok(())
    }

    async fn remove_pre_key(&mut self, prekey_id: PreKeyId) -> Result<(), SignalProtocolError> {
        self.pre_keys.remove(&prekey_id);
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
pub struct DeviceSignedPreKeyStore {
    #[serde(with = "signed_pre_key_map_serde")]
    signed_pre_keys: HashMap<SignedPreKeyId, SignedPreKeyRecord>,
}

impl DeviceSignedPreKeyStore {
    pub fn new() -> Self {
        Self {
            signed_pre_keys: HashMap::new(),
        }
    }
}
#[async_trait(?Send)]
impl SignedPreKeyStore for DeviceSignedPreKeyStore {
    async fn get_signed_pre_key(
        &self,
        id: SignedPreKeyId,
    ) -> Result<SignedPreKeyRecord, SignalProtocolError> {
        Ok(self
            .signed_pre_keys
            .get(&id)
            .ok_or(SignalProtocolError::InvalidSignedPreKeyId)?
            .clone())
    }

    async fn save_signed_pre_key(
        &mut self,
        id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        // This overwrites old values, which matches Java behavior, but is it correct?
        self.signed_pre_keys.insert(id, record.to_owned());
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
pub struct DeviceKyberPreKeyStore {
    #[serde(with = "kyber_pre_key_map_serde")]
    kyber_pre_keys: HashMap<KyberPreKeyId, KyberPreKeyRecord>,
}

impl DeviceKyberPreKeyStore {
    pub fn new() -> Self {
        Self {
            kyber_pre_keys: HashMap::new(),
        }
    }
}
#[async_trait(?Send)]
impl KyberPreKeyStore for DeviceKyberPreKeyStore {
    async fn get_kyber_pre_key(
        &self,
        kyber_prekey_id: KyberPreKeyId,
    ) -> Result<KyberPreKeyRecord, SignalProtocolError> {
        Ok(self
            .kyber_pre_keys
            .get(&kyber_prekey_id)
            .ok_or(SignalProtocolError::InvalidKyberPreKeyId)?
            .clone())
    }

    async fn save_kyber_pre_key(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        self.kyber_pre_keys
            .insert(kyber_prekey_id, record.to_owned());
        Ok(())
    }

    async fn mark_kyber_pre_key_used(
        &mut self,
        _kyber_prekey_id: KyberPreKeyId,
    ) -> Result<(), SignalProtocolError> {
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
pub struct DeviceSessionStore {
    #[serde(with = "session_map_serde")]
    sessions: HashMap<ProtocolAddress, SessionRecord>,
}

impl DeviceSessionStore {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }
}
#[async_trait(?Send)]
impl SessionStore for DeviceSessionStore {
    async fn load_session(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<SessionRecord>, SignalProtocolError> {
        match self.sessions.get(address) {
            None => Ok(None),
            Some(s) => Ok(Some(s.clone())),
        }
    }

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> Result<(), SignalProtocolError> {
        self.sessions.insert(address.clone(), record.clone());
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
pub struct DeviceSenderKeyStore {
    #[serde(with = "sender_key_map_serde")]
    keys: HashMap<(Cow<'static, ProtocolAddress>, Uuid), SenderKeyRecord>,
}

impl DeviceSenderKeyStore {
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }
}
#[async_trait(?Send)]
impl SenderKeyStore for DeviceSenderKeyStore {
    async fn store_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
        record: &SenderKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        self.keys.insert(
            (Cow::Owned(sender.clone()), distribution_id),
            record.clone(),
        );
        Ok(())
    }

    async fn load_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
    ) -> Result<Option<SenderKeyRecord>, SignalProtocolError> {
        Ok(self
            .keys
            .get(&(Cow::Borrowed(sender), distribution_id))
            .cloned())
    }
}

#[derive(Serialize, Deserialize)]
pub struct DeviceStorage {
    #[serde(with = "aci_serde")]
    aci: Aci,
    #[serde(with = "pni_serde")]
    pni: Pni,
    password: String,
    #[serde(with = "public_key_serde")]
    public_key: PublicKey,
    #[serde(with = "private_key_serde")]
    private_key: PrivateKey,
    aci_registration_id: u32,
    pni_registration_id: u32,
    pub protocol_store: DeviceProtocolStore,
}

#[bon]
impl DeviceStorage {
    pub fn load() -> Result<Self, LoginError> {
        fs::read("device_info.json")
            .map_err(|_| LoginError::NoAccountInformation)
            .map(|bytes| serde_json::from_slice(&bytes).map_err(|_| LoginError::LoadInfoError))?
    }
    #[builder]
    pub fn new(
        aci: Aci,
        pni: Pni,
        password: String,
        public_key: PublicKey,
        private_key: PrivateKey,
        aci_registration_id: u32,
        pni_registration_id: u32,
    ) -> Self {
        let storage = Self {
            aci,
            pni,
            password,
            public_key,
            private_key,
            aci_registration_id,
            pni_registration_id,
            protocol_store: DeviceProtocolStore::new(
                IdentityKeyPair::new(public_key.into(), private_key),
                aci_registration_id,
            ),
        };
        storage.write();
        storage
    }
    fn write(&self) {
        let data = serde_json::to_string_pretty(self).expect("Can serialize DeviceStorage");
        fs::write("device_info.json", data);
    }
}

pub trait Storage {
    fn set_password(&mut self, new_password: &str);
    fn get_password(&self) -> String;
    fn set_aci(&mut self, new_aci: &Aci);
    fn get_aci(&self) -> &Aci;
    fn set_pni(&mut self, new_pni: &Pni);
    fn get_pni(&self) -> &Pni;
    fn get_private_key(&self) -> &PrivateKey;
    fn set_private_key(&mut self, private_key: PrivateKey);
    fn get_public_key(&self) -> &PublicKey;
    fn set_public_key(&mut self, private_key: PublicKey);
    fn get_aci_registration_id(&self) -> u32;
    fn set_aci_registration_id(&mut self, id: u32);
    fn get_pni_registration_id(&self) -> u32;
    fn set_pni_registration_id(&mut self, id: u32);
}

impl Storage for DeviceStorage {
    fn set_password(&mut self, new_password: &str) {
        self.password = new_password.to_owned();
        self.write();
    }

    fn get_password(&self) -> String {
        self.password.clone()
    }

    fn set_aci(&mut self, new_aci: &Aci) {
        self.aci = new_aci.to_owned();
        self.write();
    }

    fn get_aci(&self) -> &Aci {
        &self.aci
    }

    fn set_pni(&mut self, new_pni: &Pni) {
        self.pni = new_pni.to_owned();
        self.write();
    }

    fn get_pni(&self) -> &Pni {
        &self.pni
    }

    fn get_private_key(&self) -> &PrivateKey {
        &self.private_key
    }

    fn set_private_key(&mut self, private_key: PrivateKey) {
        self.private_key = private_key;
        self.write();
    }

    fn get_public_key(&self) -> &PublicKey {
        &self.public_key
    }

    fn set_public_key(&mut self, public_key: PublicKey) {
        self.public_key = public_key;
        self.write();
    }

    fn get_aci_registration_id(&self) -> u32 {
        self.aci_registration_id
    }

    fn set_aci_registration_id(&mut self, id: u32) {
        self.aci_registration_id = id;
        self.write();
    }

    fn get_pni_registration_id(&self) -> u32 {
        self.pni_registration_id
    }

    fn set_pni_registration_id(&mut self, id: u32) {
        self.pni_registration_id = id;
        self.write();
    }
}
