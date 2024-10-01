use anyhow::Result;
use libsignal_protocol::*;

pub struct KeyBundleContent {
    registration_id: u32,
    device_id: DeviceId,
    onetime_public_key: Option<(PreKeyId, PublicKey)>,
    signed_public_key_id: SignedPreKeyId,
    signed_public_key: PublicKey,
    signed_signature: Vec<u8>,
    identity_key: IdentityKey,
    kyper_key_essentials: Option<(KyberPreKeyId, kem::PublicKey, Vec<u8>)>,
}

impl KeyBundleContent {
    pub fn new(
        registration_id: u32,
        device_id: DeviceId,
        onetime_public_key: Option<(PreKeyId, PublicKey)>,
        signed_public_key: (SignedPreKeyId, PublicKey),
        signed_signature: Vec<u8>,
        identity_key: IdentityKey,
        kyber_public_id_key_signature: Option<(KyberPreKeyId, kem::PublicKey, Vec<u8>)>,
    ) -> KeyBundleContent {
        Self {
            registration_id,
            device_id,
            onetime_public_key,
            signed_public_key_id: signed_public_key.0,
            signed_public_key: signed_public_key.1,
            signed_signature,
            identity_key,
            kyper_key_essentials: kyber_public_id_key_signature,
        }
    }
    pub fn create_key_bundle(self) -> Result<PreKeyBundle> {
        let pre_key_bundle = PreKeyBundle::new(
            self.registration_id,
            self.device_id,
            self.onetime_public_key,
            self.signed_public_key_id,
            self.signed_public_key,
            self.signed_signature,
            self.identity_key,
        )?;
        match self.kyper_key_essentials {
            Some((id, key, sign)) => Ok(PreKeyBundle::with_kyber_pre_key(
                pre_key_bundle,
                id,
                key,
                sign,
            )),
            None => Ok(pre_key_bundle),
        }
    }
}
