use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
};

use common::pre_key::PreKeyType;
use libsignal_protocol::{
    kem, GenericSignedPreKey, IdentityKeyStore, InMemSignalProtocolStore, KeyPair, KyberPreKeyId,
    KyberPreKeyRecord, KyberPreKeyStore, PreKeyId, PreKeyRecord, PreKeyStore, SignalProtocolError,
    SignedPreKeyId, SignedPreKeyRecord, SignedPreKeyStore, Timestamp,
};
use rand::{CryptoRng, Rng};
use surf::utils::async_trait;

pub struct InMemoryKeyManager {
    store: InMemSignalProtocolStore,
    key_incrementer_map: HashMap<PreKeyType, u32>,
}

impl InMemoryKeyManager {
    pub fn new(store: InMemSignalProtocolStore) -> Self {
        Self {
            store,
            key_incrementer_map: HashMap::from([
                (PreKeyType::Signed, 0u32),
                (PreKeyType::Kyber, 0u32),
                (PreKeyType::OneTime, 0u32),
            ]),
        }
    }
    fn get_new_key_id(&mut self, key_type: &PreKeyType) -> u32 {
        let id = *self.key_incrementer_map.get(key_type).unwrap();
        *self.key_incrementer_map.get_mut(key_type).unwrap() += 1u32;
        id
    }
}

type Signature = Box<[u8]>;

#[async_trait(?Send)]
pub trait KeyManager<Key, KeyId> {
    async fn store(&mut self, key: &Key) -> Result<(), SignalProtocolError>;
    async fn generate<R: Rng + CryptoRng>(
        &mut self,
        csprng: &mut R,
    ) -> Result<Key, SignalProtocolError>;
}

fn time_now() -> Timestamp {
    Timestamp::from_epoch_millis(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Now is later than epoch")
            .as_millis()
            .try_into()
            .expect("Living in the future is not allowed"),
    )
}

#[async_trait(?Send)]
impl KeyManager<SignedPreKeyRecord, SignedPreKeyId> for InMemoryKeyManager {
    async fn store(&mut self, key: &SignedPreKeyRecord) -> Result<(), SignalProtocolError> {
        self.store
            .save_signed_pre_key(key.id().expect("Can always get ID"), key)
            .await
    }

    async fn generate<R: Rng + CryptoRng>(
        &mut self,
        csprng: &mut R,
    ) -> Result<SignedPreKeyRecord, SignalProtocolError> {
        let signed_pre_key_pair = KeyPair::generate(csprng);
        let signature = self
            .store
            .get_identity_key_pair()
            .await?
            .private_key()
            .calculate_signature(&signed_pre_key_pair.public_key.serialize(), csprng)?;
        let id = self.get_new_key_id(&PreKeyType::Signed).into();
        let record = SignedPreKeyRecord::new(id, time_now(), &signed_pre_key_pair, &signature);

        self.store.save_signed_pre_key(id, &record).await?;

        Ok(record)
    }
}

#[async_trait(?Send)]
impl KeyManager<KyberPreKeyRecord, KyberPreKeyId> for InMemoryKeyManager {
    async fn store(&mut self, key: &KyberPreKeyRecord) -> Result<(), SignalProtocolError> {
        todo!()
    }
    async fn generate<R: Rng + CryptoRng>(
        &mut self,
        csprng: &mut R,
    ) -> Result<KyberPreKeyRecord, SignalProtocolError> {
        let id = self.get_new_key_id(&PreKeyType::Kyber).into();
        let record = KyberPreKeyRecord::generate(
            kem::KeyType::Kyber1024,
            id,
            self.store.get_identity_key_pair().await?.private_key(),
        )?;

        self.store.save_kyber_pre_key(id, &record);
        Ok(record)
    }
}

#[async_trait(?Send)]
impl KeyManager<PreKeyRecord, PreKeyId> for InMemoryKeyManager {
    async fn store(&mut self, key: &PreKeyRecord) -> Result<(), SignalProtocolError> {
        todo!()
    }
    async fn generate<R: Rng + CryptoRng>(
        &mut self,
        csprng: &mut R,
    ) -> Result<PreKeyRecord, SignalProtocolError> {
        let id = self.get_new_key_id(&PreKeyType::Kyber).into();

        let key_pair = KeyPair::generate(csprng);
        let record = PreKeyRecord::new(id, &key_pair);
        self.store.save_pre_key(id, &record).await?;
        Ok(record)
    }
}
