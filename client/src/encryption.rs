use crate::contact_manager::{Contact, Device};
use libsignal_protocol::*;
use rand::{CryptoRng, Rng};
use std::collections::HashMap;
use std::time::SystemTime;

pub async fn encrypt(
    store: &mut InMemSignalProtocolStore,
    to: &Contact,
    msg: &[u8],
) -> HashMap<u32, Result<CiphertextMessage, SignalProtocolError>> {
    let mut msgs: HashMap<u32, Result<CiphertextMessage, SignalProtocolError>> = HashMap::new();
    for (id, device) in to.devices.iter() {
        let res = message_encrypt(
            msg,
            &device.address,
            &mut store.session_store,
            &mut store.identity_store,
            SystemTime::now(),
        )
        .await;

        match res {
            Ok(x) => {
                msgs.insert(*id, Ok(x));
            }
            Err(y) => {
                msgs.insert(*id, Err(y));
            }
        }
    }
    msgs
}

pub async fn decrypt<R: Rng + CryptoRng>(
    store: &mut InMemSignalProtocolStore,
    rng: &mut R,
    from_device: &Device,
    msg: &CiphertextMessage,
) -> Result<Vec<u8>, SignalProtocolError> {
    message_decrypt(
        msg,
        &from_device.address,
        &mut store.session_store,
        &mut store.identity_store,
        &mut store.pre_key_store,
        &store.signed_pre_key_store,
        &mut store.kyber_pre_key_store,
        rng,
    )
    .await
}

#[cfg(test)]
pub(crate) mod test {
    use crate::contact_manager::{Contact, ContactManager, Device};
    use crate::encryption::{decrypt, encrypt};
    use crate::key_management::bundle::KeyBundleContent;
    use libsignal_protocol::*;
    use rand::rngs::OsRng;
    use rand::{CryptoRng, Rng};
    use std::sync::{Arc, Mutex};
    use std::time::SystemTime;
    use uuid::Uuid;

    pub fn store(reg: u32) -> InMemSignalProtocolStore {
        let mut rng = OsRng;
        let p = KeyPair::generate(&mut rng).into();

        InMemSignalProtocolStore::new(p, reg).unwrap()
    }

    pub fn signal_bundle_to_our_bundle(bundle: PreKeyBundle) -> KeyBundleContent {
        KeyBundleContent::new(
            bundle.registration_id().unwrap(),
            bundle.device_id().unwrap(),
            Some((
                bundle.pre_key_id().unwrap().unwrap(),
                bundle.pre_key_public().unwrap().unwrap(),
            )),
            (
                bundle.signed_pre_key_id().unwrap(),
                bundle.signed_pre_key_public().unwrap(),
            ),
            bundle.signed_pre_key_signature().unwrap().to_vec(),
            bundle.identity_key().unwrap().to_owned(),
            Some((
                bundle.kyber_pre_key_id().unwrap().unwrap(),
                bundle.kyber_pre_key_public().unwrap().unwrap().to_owned(),
                bundle.kyber_pre_key_signature().unwrap().unwrap().to_vec(),
            )),
        )
    }

    #[tokio::test]
    async fn test_encryption() {
        let mut alice_store = store(1);
        let mut bob_store = store(0);

        let alice_id = Uuid::new_v4().to_string();
        let bob_id = Uuid::new_v4().to_string();

        let mut manager = ContactManager::new();

        let _ = manager.add_contact(&alice_id);
        let _ = manager.add_contact(&bob_id);

        let mut rng = OsRng;

        let alice_bundle = create_pre_key_bundle(&mut alice_store, 0, &mut rng)
            .await
            .unwrap();

        //Shitty hack to stuff a signal prekey bundle into our KeyBundle.
        let alice_bundle_content = signal_bundle_to_our_bundle(alice_bundle.clone());

        let bob_bundle = create_pre_key_bundle(&mut bob_store, 1, &mut rng)
            .await
            .unwrap();

        //Another garbage hack to force Signal's shit into ours
        let bob_bundle_content = signal_bundle_to_our_bundle(bob_bundle.clone());

        let _ = manager.update_contact(&alice_id, vec![(0, alice_bundle_content)]);
        let _ = manager.update_contact(&bob_id, vec![(1, bob_bundle_content)]);

        let bob = manager.get_contact(&bob_id).unwrap();
        let bob_device = bob.devices.get(&1).unwrap();
        let bob_pre_key_bundle = bob_device.bundle.clone().create_key_bundle().unwrap();

        let _ = process_prekey_bundle(
            &bob_device.address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            &bob_pre_key_bundle,
            SystemTime::now(),
            &mut rng,
        )
        .await;

        let msg_map = encrypt(&mut alice_store, bob, "Hello Bob".as_bytes()).await;

        let to_bob_msg = msg_map.get(&1).unwrap().as_ref().unwrap();

        let alice_device = manager
            .get_contact(&alice_id)
            .unwrap()
            .devices
            .get(&0)
            .unwrap();

        let bob_msg = decrypt(&mut bob_store, &mut rng, alice_device, &to_bob_msg)
            .await
            .unwrap();

        assert!(String::from_utf8(bob_msg).unwrap() == "Hello Bob".to_string())
    }

    pub async fn create_pre_key_bundle<R: Rng + CryptoRng>(
        store: &mut dyn ProtocolStore,
        device_id: u32,
        mut csprng: &mut R,
    ) -> Result<PreKeyBundle, SignalProtocolError> {
        // z is random
        let pre_key_pair = KeyPair::generate(&mut csprng); // OPK - only one but should be more -> publish

        let signed_pre_key_pair = KeyPair::generate(&mut csprng); // SPKB - changes periodically -> publish
        let kyber_pre_key_pair = kem::KeyPair::generate(kem::KeyType::Kyber1024); // PQSPKB - changes periodically -> publish

        let signed_pre_key_signature = store // Sig(IKB, EncodeEC(SPKB), ZSPK) - changes periodically -> publish
            .get_identity_key_pair() // IKB - Bob only needs to upload his identity key to the server once -> publish
            .await?
            .private_key()
            .calculate_signature(&signed_pre_key_pair.public_key.serialize(), &mut csprng)?;

        let kyber_pre_key_signature = store // Sig(IKB, EncodeKEM(PQSPKB), ZPQSPK) - changes periodically -> publish
            .get_identity_key_pair()
            .await?
            .private_key()
            .calculate_signature(&kyber_pre_key_pair.public_key.serialize(), &mut csprng)?;

        let pre_key_id: u32 = csprng.gen(); // IdEC(OPKB1) -> publish
        let signed_pre_key_id: u32 = csprng.gen(); // IdEC(SPKB) -> publish
        let kyber_pre_key_id: u32 = csprng.gen(); // IdKEM(PQSPKB) -> publish

        // <-- publish -->
        // one-time pqkem prekeys - these are not generated and should be, so users can verify integrity
        // should also generate signatures for each of the keys - (Sig(IKB, EncodeKEM(PQOPKB), Z1)
        // this can be used: kem::KeyPair::generate(kem::KeyType::Kyber1024)

        let pre_key_bundle = PreKeyBundle::new(
            store.get_local_registration_id().await?, // the users unique id
            device_id.into(),
            Some((pre_key_id.into(), pre_key_pair.public_key)),
            signed_pre_key_id.into(),
            signed_pre_key_pair.public_key,
            signed_pre_key_signature.to_vec(),
            *store.get_identity_key_pair().await?.identity_key(),
        )?;
        let pre_key_bundle = pre_key_bundle.with_kyber_pre_key(
            kyber_pre_key_id.into(),
            kyber_pre_key_pair.public_key.clone(),
            kyber_pre_key_signature.to_vec(),
        );

        store
            .save_pre_key(
                pre_key_id.into(),
                &PreKeyRecord::new(pre_key_id.into(), &pre_key_pair),
            )
            .await?;

        let timestamp = Timestamp::from_epoch_millis(csprng.gen());

        store
            .save_signed_pre_key(
                signed_pre_key_id.into(),
                &SignedPreKeyRecord::new(
                    signed_pre_key_id.into(),
                    timestamp,
                    &signed_pre_key_pair,
                    &signed_pre_key_signature,
                ),
            )
            .await?;

        store
            .save_kyber_pre_key(
                kyber_pre_key_id.into(),
                &KyberPreKeyRecord::new(
                    kyber_pre_key_id.into(),
                    Timestamp::from_epoch_millis(43),
                    &kyber_pre_key_pair,
                    &kyber_pre_key_signature,
                ),
            )
            .await?;
        Ok(pre_key_bundle)
    }
}
