use anyhow::{anyhow, bail, Result};
use common::pre_key::PreKeyType;
use libsignal_core::ProtocolAddress;
use libsignal_protocol::{
    kem, GenericSignedPreKey, IdentityKey, IdentityKeyStore, InMemSignalProtocolStore, KeyPair,
    KyberPreKeyRecord, KyberPreKeyStore, PreKeyRecord, PreKeyStore, SignedPreKeyRecord,
    SignedPreKeyStore, Timestamp,
};
use rand::{CryptoRng, Rng};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

pub enum KeyType {
    KemKey(kem::KeyPair),
    KeyPair(KeyPair),
}

struct KeyManager {
    address: ProtocolAddress,
    key_incrementer_map: HashMap<PreKeyType, u32>,
}

impl KeyManager {
    pub fn new(address: ProtocolAddress) -> KeyManager {
        Self {
            address,
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

    pub async fn generate_key<R: Rng + CryptoRng>(
        &mut self,
        mut rng: R,
        store: &mut InMemSignalProtocolStore,
        key_type: PreKeyType,
    ) -> Result<(KeyType, Option<Box<[u8]>>)> {
        match key_type {
            PreKeyType::Kyber => {
                let kyper_pre_key_pair = kem::KeyPair::generate(kem::KeyType::Kyber1024);
                let signature = self
                    .compute_signature(&mut rng, store, kyper_pre_key_pair.public_key.serialize())
                    .await?;

                self.store_kyper_key(store, &kyper_pre_key_pair, &signature)
                    .await?;

                Ok((KeyType::KemKey(kyper_pre_key_pair), Some(signature)))
            }
            PreKeyType::Signed => {
                let signed_pre_key_pair = KeyPair::generate(&mut rng);
                let signature = self
                    .compute_signature(&mut rng, store, signed_pre_key_pair.public_key.serialize())
                    .await?;

                self.store_ec_key(store, &key_type, &signed_pre_key_pair, Some(&signature))
                    .await?;

                Ok((KeyType::KeyPair(signed_pre_key_pair), Some(signature)))
            }
            PreKeyType::OneTime => {
                let onetime_pre_key_pair = KeyPair::generate(&mut rng);

                self.store_ec_key(store, &key_type, &onetime_pre_key_pair, None)
                    .await?;

                Ok((KeyType::KeyPair(onetime_pre_key_pair), None))
            }
            PreKeyType::Identity => {
                let identity_key = KeyPair::generate(&mut rng);

                self.store_ec_key(store, &key_type, &identity_key, None);

                Ok((KeyType::KeyPair(identity_key), None))
            }
        }
    }

    async fn compute_signature<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        store: &InMemSignalProtocolStore,
        serialized_public_key: Box<[u8]>,
    ) -> Result<Box<[u8]>> {
        store
            .get_identity_key_pair()
            .await?
            .private_key()
            .calculate_signature(&serialized_public_key, rng)
            .map_err(|err| err.into())
    }

    async fn store_kyper_key(
        &mut self,
        store: &mut InMemSignalProtocolStore,
        key: &kem::KeyPair,
        signature: &[u8],
    ) -> Result<()> {
        let id = self.get_new_key_id(&PreKeyType::Kyber);
        store
            .save_kyber_pre_key(
                id.into(),
                &KyberPreKeyRecord::new(id.into(), self.time_now()?, key, signature),
            )
            .await
            .map_err(|err| err.into())
    }

    async fn store_ec_key(
        &mut self,
        store: &mut InMemSignalProtocolStore,
        key_type: &PreKeyType,
        key: &KeyPair,
        signature: Option<&[u8]>,
    ) -> Result<()> {
        let id = self.get_new_key_id(key_type);
        match key_type {
            PreKeyType::Signed => {
                store
                    .save_signed_pre_key(
                        id.into(),
                        &SignedPreKeyRecord::new(
                            id.into(),
                            self.time_now()?,
                            key,
                            signature.ok_or_else(|| {
                                anyhow!("Must supply signature to store a signed key")
                            })?,
                        ),
                    )
                    .await?;
            }
            PreKeyType::OneTime => {
                store
                    .save_pre_key(id.into(), &PreKeyRecord::new(id.into(), key))
                    .await?;
            }
            PreKeyType::Identity => {
                store
                    .save_identity(&self.address, &IdentityKey::new(key.public_key))
                    .await?;
            }
            _ => bail!("You cannot supply a non-eliptic curve key"),
        }
        Ok(())
    }

    fn time_now(&self) -> Result<Timestamp> {
        Ok(Timestamp::from_epoch_millis(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)?
                .as_millis()
                .try_into()?,
        ))
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

    #[test]
    fn get_id_test() {
        let mut manager = KeyManager::new(ProtocolAddress::new("0".into(), 0.into()));
        let id0 = manager.get_new_key_id(&PreKeyType::OneTime);
        assert_eq!(id0, 0);
        let id1 = manager.get_new_key_id(&PreKeyType::OneTime);
        assert_eq!(id1, 1);
    }

    #[tokio::test]
    async fn generate_kyper_key() {
        let rng = OsRng;
        let mut store = store(0);
        let mut manager = KeyManager::new(ProtocolAddress::new("0".into(), 0.into()));
        let (key, sign) = manager
            .generate_key(rng, &mut store, PreKeyType::Kyber)
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
        let mut manager = KeyManager::new(ProtocolAddress::new("0".into(), 0.into()));
        let (key, sign) = manager
            .generate_key(rng, &mut store, PreKeyType::Signed)
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
        let mut manager = KeyManager::new(ProtocolAddress::new("0".into(), 0.into()));
        let (key, _) = manager
            .generate_key(rng, &mut store, PreKeyType::OneTime)
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
