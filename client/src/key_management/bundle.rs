use anyhow::Result;
use libsignal_protocol::*;
use serde::{Deserialize, Serialize, Serializer};

#[derive(Clone)]
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

    pub fn serialize(&self) -> PrimitiveKeyBundleContent {
        PrimitiveKeyBundleContent::new(
            self.registration_id,
            self.device_id.into(),
            Some(self.onetime_public_key.unwrap().0.into()),
            self.onetime_public_key.unwrap().1.serialize().into(),
            self.signed_public_key_id.into(),
            self.signed_public_key.serialize(),
            self.signed_signature.clone(),
            self.identity_key.serialize(),
            Some(self.kyper_key_essentials.clone().unwrap().0.into()),
            self.kyper_key_essentials
                .clone()
                .unwrap()
                .1
                .serialize()
                .into(),
            self.kyper_key_essentials.clone().unwrap().2.into(),
        )
    }
}

#[derive(Clone, Debug, Eq, PartialOrd, PartialEq, Serialize, Deserialize)]
pub struct PrimitiveKeyBundleContent {
    registration_id: u32,
    device_id: u32,
    onetime_public_key_id: Option<u32>,
    onetime_public_key: Option<Box<[u8]>>,
    signed_public_key_id: u32,
    signed_public_key: Box<[u8]>,
    signed_signature: Vec<u8>,
    identity_key: Box<[u8]>,
    kyper_pre_key_id: Option<u32>,
    kyper_public_key: Option<Box<[u8]>>,
    kyper_signature: Vec<u8>,
}
impl PrimitiveKeyBundleContent {
    pub fn new(
        registration_id: u32,
        device_id: u32,
        onetime_public_key_id: Option<u32>,
        onetime_public_key: Option<Box<[u8]>>,
        signed_public_key_id: u32,
        signed_public_key: Box<[u8]>,
        signed_signature: Vec<u8>,
        identity_key: Box<[u8]>,
        kyper_pre_key_id: Option<u32>,
        kyper_public_key: Option<Box<[u8]>>,
        kyper_signature: Vec<u8>,
    ) -> Self {
        PrimitiveKeyBundleContent {
            registration_id,
            device_id,
            onetime_public_key_id,
            onetime_public_key,
            signed_public_key_id,
            signed_public_key,
            signed_signature,
            identity_key,
            kyper_pre_key_id,
            kyper_public_key,
            kyper_signature,
        }
    }

    pub fn create_key_bundle_content(&self) -> KeyBundleContent {
        KeyBundleContent::new(
            self.registration_id.into(),
            self.device_id.into(),
            Some((
                self.onetime_public_key_id.clone().unwrap().into(),
                PublicKey::deserialize(
                    self.onetime_public_key
                        .clone()
                        .unwrap()
                        .into_vec()
                        .as_slice(),
                )
                .unwrap(),
            )),
            (
                self.signed_public_key_id.clone().into(),
                PublicKey::deserialize(&(*self.signed_public_key))
                    .unwrap(),
            ),
            self.signed_signature.clone(),
            IdentityKey::decode(&(*self.identity_key)).unwrap(),
            Some((
                self.kyper_pre_key_id.unwrap().into(),
                kem::PublicKey::deserialize(
                    &(*self.kyper_public_key.clone().unwrap()),
                )
                .expect("desrialize pk"),
                self.kyper_signature.clone().into(),
            )),
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::contact_manager::Device;
    use crate::encryption::test::{create_pre_key_bundle, signal_bundle_to_our_bundle, store};
    use libsignal_protocol::*;
    use rand::rngs::OsRng;
    use serde::*;
    use serde_json;
    use uuid::Uuid;

    #[tokio::test]
    async fn test_serialize_bundle_data() {
        let alice = Uuid::new_v4().to_string();
        let device_id = 42069;
        let mut store = store(device_id);

        let bundle = create_pre_key_bundle(&mut store, device_id, &mut OsRng)
            .await
            .unwrap();

        let device = Device::new(alice, device_id, signal_bundle_to_our_bundle(bundle));
        let out = serde_json::to_string(&device.bundle.serialize()).unwrap();
        let deserialized = serde_json::from_str(&out).unwrap();

        assert_eq!(device.bundle.serialize(), deserialized);
    }
}
