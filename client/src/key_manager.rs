use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
};

use libsignal_protocol::{
    kem, GenericSignedPreKey, IdentityKeyStore, KeyPair, KyberPreKeyRecord, KyberPreKeyStore,
    PreKeyRecord, PreKeyStore, SignalProtocolError, SignedPreKeyRecord, SignedPreKeyStore,
    Timestamp,
};
use rand::{CryptoRng, Rng};

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub enum PreKeyType {
    Signed,
    Kyber,
    OneTime,
}

pub struct KeyManager {
    key_incrementer_map: HashMap<PreKeyType, u32>,
}

impl KeyManager {
    pub fn new() -> Self {
        Self {
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
    pub async fn generate_pre_key<R: Rng + CryptoRng, PK: PreKeyStore>(
        &mut self,
        pre_key_store: &mut PK,
        csprng: &mut R,
    ) -> Result<PreKeyRecord, SignalProtocolError> {
        let id = self.get_new_key_id(&PreKeyType::Kyber).into();

        let key_pair = KeyPair::generate(csprng);
        let record = PreKeyRecord::new(id, &key_pair);
        pre_key_store.save_pre_key(id, &record).await?;
        Ok(record)
    }
    pub async fn generate_signed_pre_key<
        R: Rng + CryptoRng,
        IK: IdentityKeyStore,
        SPK: SignedPreKeyStore,
    >(
        &mut self,
        identity_key_store: &mut IK,
        signed_pre_key_store: &mut SPK,
        csprng: &mut R,
    ) -> Result<SignedPreKeyRecord, SignalProtocolError> {
        let id = self.get_new_key_id(&PreKeyType::Signed).into();
        let signed_pre_key_pair = KeyPair::generate(csprng);
        let signature = identity_key_store
            .get_identity_key_pair()
            .await?
            .private_key()
            .calculate_signature(&signed_pre_key_pair.public_key.serialize(), csprng)?;

        let record = SignedPreKeyRecord::new(id, time_now(), &signed_pre_key_pair, &signature);
        signed_pre_key_store
            .save_signed_pre_key(id, &record)
            .await?;

        Ok(record)
    }

    pub async fn generate_kyber_pre_key<IK: IdentityKeyStore, KPK: KyberPreKeyStore>(
        &mut self,
        identity_key_store: &mut IK,
        kyber_pre_key_store: &mut KPK,
    ) -> Result<KyberPreKeyRecord, SignalProtocolError> {
        let id = self.get_new_key_id(&PreKeyType::Kyber).into();
        let record = KyberPreKeyRecord::generate(
            kem::KeyType::Kyber1024,
            id,
            identity_key_store
                .get_identity_key_pair()
                .await?
                .private_key(),
        )?;

        kyber_pre_key_store.save_kyber_pre_key(id, &record).await?;
        Ok(record)
    }
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
