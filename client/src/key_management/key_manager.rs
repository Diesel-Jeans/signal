use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
};

use common::pre_key::PreKeyType;
use libsignal_protocol::{
    kem, GenericSignedPreKey, IdentityKeyStore, KeyPair, KyberPreKeyRecord, KyberPreKeyStore,
    PreKeyRecord, PreKeyStore, SenderKeyStore, SessionStore, SignalProtocolError,
    SignedPreKeyRecord, SignedPreKeyStore, Timestamp,
};
use rand::{CryptoRng, Rng};

use crate::storage::protocol_store::{GenericProtocolStore};

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

pub struct KeyManager<'a> {
    identity_key_store: &'a mut dyn IdentityKeyStore,
    pre_key_store: &'a mut dyn PreKeyStore,
    signed_pre_key_store: &'a mut dyn SignedPreKeyStore,
    kyber_pre_key_store: &'a mut dyn KyberPreKeyStore,
    key_incrementer_map: HashMap<PreKeyType, u32>,
}

impl<'a> KeyManager<'a> {
    pub fn new<
        ID: IdentityKeyStore,
        PK: PreKeyStore,
        SPK: SignedPreKeyStore,
        KPK: KyberPreKeyStore,
        SS: SessionStore,
        SKS: SenderKeyStore,
    >(
        protocol_store: &'a mut GenericProtocolStore<ID, PK, SPK, KPK, SS, SKS>,
    ) -> Self {
        Self {
            identity_key_store: &mut protocol_store.identity_key_store,
            pre_key_store: &mut protocol_store.pre_key_store,
            signed_pre_key_store: &mut protocol_store.signed_pre_key_store,
            kyber_pre_key_store: &mut protocol_store.kyber_pre_key_store,
            key_incrementer_map: HashMap::from([
                (PreKeyType::Signed, 0u32),
                (PreKeyType::Kyber, 0u32),
                (PreKeyType::OneTime, 0u32),
            ]),
        }
    }

    pub async fn generate_prekey<R: Rng + CryptoRng>(
        &mut self,
        csprng: &mut R,
    ) -> Result<PreKeyRecord, SignalProtocolError> {
        let id = self.get_new_key_id(&PreKeyType::Kyber).into();

        let key_pair = KeyPair::generate(csprng);
        let record = PreKeyRecord::new(id, &key_pair);
        self.pre_key_store.save_pre_key(id, &record).await?;
        Ok(record)
    }
    pub async fn generate_signed_prekey<R: Rng + CryptoRng>(
        &mut self,
        csprng: &mut R,
    ) -> Result<SignedPreKeyRecord, SignalProtocolError> {
        let signed_pre_key_pair = KeyPair::generate(csprng);
        let signature = self
            .identity_key_store
            .get_identity_key_pair()
            .await?
            .private_key()
            .calculate_signature(&signed_pre_key_pair.public_key.serialize(), csprng)?;
        let id = self.get_new_key_id(&PreKeyType::Signed).into();
        let record = SignedPreKeyRecord::new(id, time_now(), &signed_pre_key_pair, &signature);

        self.signed_pre_key_store
            .save_signed_pre_key(id, &record)
            .await?;

        Ok(record)
    }
    pub async fn generate_kyber_prekey(
        &mut self,
    ) -> Result<KyberPreKeyRecord, SignalProtocolError> {
        let id = self.get_new_key_id(&PreKeyType::Kyber).into();
        let record = KyberPreKeyRecord::generate(
            kem::KeyType::Kyber1024,
            id,
            self.identity_key_store
                .get_identity_key_pair()
                .await?
                .private_key(),
        )?;

        self.kyber_pre_key_store
            .save_kyber_pre_key(id, &record)
            .await?;
        Ok(record)
    }
    fn get_new_key_id(&mut self, key_type: &PreKeyType) -> u32 {
        let id = *self.key_incrementer_map.get(key_type).unwrap();
        *self.key_incrementer_map.get_mut(key_type).unwrap() += 1u32;
        id
    }
}
