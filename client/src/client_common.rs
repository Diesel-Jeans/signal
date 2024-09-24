use libsignal_protocol::*;
use rand::{CryptoRng, Rng};

pub async fn create_pre_key_bundle<R: Rng + CryptoRng>(
    store: &mut dyn ProtocolStore,
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

    let device_id: u32 = csprng.gen();
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
