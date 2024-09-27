use anyhow::Result;
use libsignal_protocol::*;
use rand::{CryptoRng, Rng};
use std::collections::HashMap;
use std::ops::Deref;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Hash, Eq, PartialEq)]
pub enum PreKey {
    Signed,
    Kyber,
    OneTime,
}

pub enum KeyType {
    KemKey(kem::KeyPair),
    KeyPair(KeyPair),
}

pub struct KeyManager {
    key_incrementer_map: HashMap<PreKey, u32>,
}

impl KeyManager {
    pub fn new() -> KeyManager {
        let mut key_incrementer_map = HashMap::new();
        key_incrementer_map.insert(PreKey::Signed, 0);
        key_incrementer_map.insert(PreKey::Kyber, 0);
        key_incrementer_map.insert(PreKey::OneTime, 0);
        Self {
            key_incrementer_map,
        }
    }

    fn get_new_key_id(&mut self, key_type: &PreKey) -> u32 {
        let id = self.key_incrementer_map.get_mut(key_type).unwrap().deref() + 1u32;
        id - 1
    }

    async fn compute_signature<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        store: &InMemSignalProtocolStore,
        serialized_public_key: Box<[u8]>,
    ) -> Result<Box<[u8]>> {
        Ok(store
            .get_identity_key_pair()
            .await?
            .private_key()
            .calculate_signature(&serialized_public_key, rng)?)
    }

    pub async fn generate_key<R: Rng + CryptoRng>(
        &mut self,
        mut rng: R,
        store: &mut InMemSignalProtocolStore,
        key_type: PreKey,
    ) -> Result<(KeyType, Option<Box<[u8]>>)> {
        match key_type {
            PreKey::Kyber => {
                let kyper_pre_key_pair = kem::KeyPair::generate(kem::KeyType::Kyber1024);
                let signature = self
                    .compute_signature(&mut rng, &store, kyper_pre_key_pair.public_key.serialize())
                    .await?;
                let id = self.get_new_key_id(&key_type);

                store
                    .save_kyber_pre_key(
                        id.into(),
                        &KyberPreKeyRecord::new(
                            id.into(),
                            Timestamp::from_epoch_millis(
                                SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .unwrap()
                                    .as_millis()
                                    .try_into()?,
                            ),
                            &kyper_pre_key_pair,
                            &signature,
                        ),
                    )
                    .await?;

                Ok((KeyType::KemKey(kyper_pre_key_pair), Some(signature)))
            }
            PreKey::Signed => {
                let signed_pre_key_pair = KeyPair::generate(&mut rng);
                let signature = self
                    .compute_signature(&mut rng, &store, signed_pre_key_pair.public_key.serialize())
                    .await?;
                let id = self.get_new_key_id(&key_type);

                store
                    .save_signed_pre_key(
                        id.into(),
                        &SignedPreKeyRecord::new(
                            id.into(),
                            Timestamp::from_epoch_millis(
                                SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .unwrap()
                                    .as_millis()
                                    .try_into()?,
                            ),
                            &signed_pre_key_pair,
                            &signature,
                        ),
                    )
                    .await?;

                Ok((KeyType::KeyPair(signed_pre_key_pair), Some(signature)))
            }
            PreKey::OneTime => {
                let onetime_pre_key_pair = KeyPair::generate(&mut rng);
                let id = self.get_new_key_id(&key_type);

                store
                    .save_pre_key(
                        id.into(),
                        &PreKeyRecord::new(id.into(), &onetime_pre_key_pair),
                    )
                    .await?;

                Ok((KeyType::KeyPair(onetime_pre_key_pair), None))
            }
        }
    }
}

#[cfg(test)]
mod key_manager_tests {
    use super::*;
    use core::panic;
    use rand::rngs::OsRng;

    fn store(reg: u32) -> InMemSignalProtocolStore {
        let mut rng = OsRng;
        let p = KeyPair::generate(&mut rng).into();
        InMemSignalProtocolStore::new(p, reg).unwrap()
    }

    #[tokio::test]
    async fn generate_kyper_key() {
        let rng = OsRng;
        let mut store = store(0);
        let mut manager = KeyManager::new();
        let (key, sign) = manager
            .generate_key(rng, &mut store, PreKey::Kyber)
            .await
            .unwrap();

        assert!(matches!(key, KeyType::KemKey(_)));

        let stored_sign = store
            .get_kyber_pre_key(store.all_kyber_pre_key_ids().next().unwrap().to_owned())
            .await
            .unwrap()
            .signature()
            .unwrap();

        assert_eq!(sign.unwrap().to_vec(), stored_sign);
    }

    #[tokio::test]
    async fn generate_signed_key() {
        let rng = OsRng;
        let mut store = store(0);
        let mut manager = KeyManager::new();
        let (key, sign) = manager
            .generate_key(rng, &mut store, PreKey::Signed)
            .await
            .unwrap();

        assert!(matches!(key, KeyType::KeyPair(_)));

        let stored_sign = store
            .get_signed_pre_key(store.all_signed_pre_key_ids().next().unwrap().to_owned())
            .await
            .unwrap()
            .signature()
            .unwrap();

        assert_eq!(sign.unwrap().to_vec(), stored_sign);
    }

    #[tokio::test]
    async fn generate_onetime_key() {
        let rng = OsRng;
        let mut store = store(0);
        let mut manager = KeyManager::new();
        let (key, _) = manager
            .generate_key(rng, &mut store, PreKey::OneTime)
            .await
            .unwrap();

        let key_pair = if let KeyType::KeyPair(x) = key {
            x
        } else {
            panic!()
        };

        let stored_key_pair = store
            .get_pre_key(store.all_pre_key_ids().next().unwrap().to_owned())
            .await
            .unwrap()
            .key_pair()
            .unwrap();
        assert_eq!(key_pair.public_key, stored_key_pair.public_key);
    }
}
