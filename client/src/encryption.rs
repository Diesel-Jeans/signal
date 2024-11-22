use crate::contact_manager::Contact;
use libsignal_core::{DeviceId, ProtocolAddress};
use libsignal_protocol::{
    message_decrypt, message_encrypt, CiphertextMessage, IdentityKeyStore,
    InMemSignalProtocolStore, SessionStore, SignalProtocolError,
};
use rand::{CryptoRng, Rng};
use std::error::Error;
use std::fmt::Display;
use std::vec;
use std::{collections::HashMap, time::SystemTime};

pub async fn encrypt(
    session_store: &mut dyn SessionStore,
    identity_store: &mut dyn IdentityKeyStore,
    target: &Contact,
    msg: &[u8],
    timestamp: SystemTime,
) -> HashMap<DeviceId, Result<CiphertextMessage, SignalProtocolError>> {
    let mut msgs = HashMap::new();
    for id in target.device_ids.iter() {
        let addr = target.get_address(&id);
        let res = match addr {
            Err(err) => Err(err),
            Ok(ref addr) => {
                message_encrypt(msg, addr, session_store, identity_store, timestamp).await
            }
        };
        msgs.insert(id.to_owned(), res);
    }

    msgs
}

pub async fn decrypt<R: Rng + CryptoRng>(
    store: &mut InMemSignalProtocolStore,
    rng: &mut R,
    from_address: &ProtocolAddress,
    msg: &CiphertextMessage,
) -> Result<Vec<u8>, SignalProtocolError> {
    message_decrypt(
        msg,
        from_address,
        &mut store.session_store,
        &mut store.identity_store,
        &mut store.pre_key_store,
        &store.signed_pre_key_store,
        &mut store.kyber_pre_key_store,
        rng,
    )
    .await
}

#[derive(Debug)]
pub enum PaddingError {
    UnpadError,
}

impl Display for PaddingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Could not unpad message - missing termination char 0x80")
    }
}

impl Error for PaddingError {}

fn get_padded_message_length(length: usize) -> usize {
    let message_length_with_terminator = length + 1;
    let mut message_part_count = message_length_with_terminator.div_euclid(160);

    if message_length_with_terminator % 160 != 0 {
        message_part_count += 1;
    }

    message_part_count * 160
}

pub fn pad_message(message: &[u8]) -> Vec<u8> {
    let len = get_padded_message_length(message.len() + 1) - 1;
    let mut plaintext = vec![0u8; len];
    for i in 0..message.len() {
        plaintext[i] = message[i];
    }
    plaintext[message.len()] = 0x80;

    plaintext
}

pub fn unpad_message(message: &[u8]) -> Result<Vec<u8>, PaddingError> {
    for i in 0..message.len() {
        if message[i] == 0x80 {
            return Ok(message[0..i].to_vec());
        }
    }
    Err(PaddingError::UnpadError)
}

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::{
        contact_manager::ContactManager,
        encryption::{decrypt, encrypt},
        test_utils::user::{new_device_id, new_service_id},
    };
    use libsignal_protocol::{
        kem, process_prekey_bundle, GenericSignedPreKey, KeyPair, KyberPreKeyRecord, PreKeyBundle,
        PreKeyRecord, ProtocolStore, SignedPreKeyRecord, Timestamp,
    };
    use rand::{rngs::OsRng, CryptoRng, Rng};
    use std::time::SystemTime;

    pub fn store(reg: u32) -> InMemSignalProtocolStore {
        let mut rng = OsRng;
        let p = KeyPair::generate(&mut rng).into();

        InMemSignalProtocolStore::new(p, reg).unwrap()
    }

    pub async fn create_pre_key_bundle<R: Rng + CryptoRng>(
        store: &mut dyn ProtocolStore,
        device_id: DeviceId,
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

    #[test]
    fn test_padding() {
        let msg = [5u8; 32];
        let padded = pad_message(&msg);

        assert_eq!(padded.len(), 159);

        let unpadded = unpad_message(padded.as_ref()).unwrap();

        assert_eq!(msg.to_vec(), unpadded);
    }

    #[tokio::test]
    async fn test_encryption() {
        let alice_id = new_service_id();
        let bob_id = new_service_id();
        let alice_device = new_device_id();
        let bob_device = new_device_id();

        let mut manager = ContactManager::new();
        let _ = manager.add_contact(&alice_id, alice_device);
        let _ = manager.add_contact(&bob_id, bob_device);

        let mut alice_store = store(1);
        let mut bob_store = store(0);

        let mut rng = OsRng;

        let bob_bundle_content = create_pre_key_bundle(&mut bob_store, bob_device, &mut rng)
            .await
            .unwrap();

        let bob = manager.get_contact(&bob_id).unwrap();

        let _ = process_prekey_bundle(
            &manager
                .get_contact(&bob_id)
                .expect("Bob was not added")
                .get_address(&bob_device)
                .expect("Bob device id not added to contact"),
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            &bob_bundle_content,
            SystemTime::now(),
            &mut rng,
        )
        .await;

        let ts = SystemTime::now();
        let msg_map = encrypt(
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            bob,
            "Hello Bob".as_bytes(),
            ts,
        )
        .await;

        let to_bob_msg = msg_map.get(&bob_device).unwrap().as_ref().unwrap();

        let alice_address = manager
            .get_contact(&alice_id)
            .unwrap()
            .get_address(&alice_device)
            .unwrap();

        let bob_msg = decrypt(&mut bob_store, &mut rng, &alice_address, to_bob_msg)
            .await
            .unwrap();

        assert!(String::from_utf8(bob_msg).unwrap() == *"Hello Bob")
    }
}
