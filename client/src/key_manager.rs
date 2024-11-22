use std::collections::HashMap;

use common::{pre_key::PreKeyType, utils::time_now};
use libsignal_protocol::{
    kem, GenericSignedPreKey as _, IdentityKeyStore, KeyPair, KyberPreKeyRecord, KyberPreKeyStore,
    PreKeyRecord, PreKeyStore, SignalProtocolError, SignedPreKeyRecord, SignedPreKeyStore,
};
use rand::{CryptoRng, Rng};

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

    pub async fn generate_prekey<R: Rng + CryptoRng, PK: PreKeyStore>(
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
    pub async fn generate_signed_prekey<
        R: Rng + CryptoRng,
        ID: IdentityKeyStore,
        SPK: SignedPreKeyStore,
    >(
        &mut self,
        identity_key_store: &mut ID,
        signed_pre_key_store: &mut SPK,
        csprng: &mut R,
    ) -> Result<SignedPreKeyRecord, SignalProtocolError> {
        let signed_pre_key_pair = KeyPair::generate(csprng);
        let signature = identity_key_store
            .get_identity_key_pair()
            .await?
            .private_key()
            .calculate_signature(&signed_pre_key_pair.public_key.serialize(), csprng)?;
        let id = self.get_new_key_id(&PreKeyType::Signed).into();
        let record = SignedPreKeyRecord::new(id, time_now(), &signed_pre_key_pair, &signature);

        signed_pre_key_store
            .save_signed_pre_key(id, &record)
            .await?;

        Ok(record)
    }
    pub async fn generate_kyber_prekey<ID: IdentityKeyStore, KPK: KyberPreKeyStore>(
        &mut self,
        identity_key_store: &mut ID,
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
    fn get_new_key_id(&mut self, key_type: &PreKeyType) -> u32 {
        let id = *self.key_incrementer_map.get(key_type).unwrap();
        *self.key_incrementer_map.get_mut(key_type).unwrap() += 1u32;
        id
    }
}
