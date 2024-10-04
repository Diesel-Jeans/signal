use anyhow::Result;
use libsignal_protocol::*;
use serde::{Deserialize, Serialize, Serializer};

#[derive(Clone, Eq, PartialEq)]
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
        let one_time_key: (u32, Box<[u8]>) = if (self.onetime_public_key.is_none()) {
            (0, Box::new([0]))
        } else {
            let (prekey_id, public_key) = self.onetime_public_key.unwrap();
            (prekey_id.into(), public_key.serialize())
        };

        let kyber_key: (u32, Box<[u8]>, Vec<u8>) = if (self.kyper_key_essentials.is_none()) {
            (0, Box::new([0]), vec![0])
        } else {
            let (kyber_id, kyber_key, vec) = self.kyper_key_essentials.to_owned().unwrap();
            (kyber_id.into(), kyber_key.serialize(), vec)
        };

        PrimitiveKeyBundleContent::new(
            self.registration_id,
            self.device_id.into(),
            Some(one_time_key.0),
            Some(one_time_key.1),
            self.signed_public_key_id.into(),
            self.signed_public_key.serialize(),
            self.signed_signature.clone(),
            self.identity_key.serialize(),
            Some(kyber_key.0),
            Some(kyber_key.1),
            Some(kyber_key.2),
        )
    }

    pub fn deserialize(bundle: &PrimitiveKeyBundleContent) -> KeyBundleContent {
        let one_time_key: Option<(PreKeyId, PublicKey)> =
            if (bundle.onetime_public_key_id.is_none()
                || bundle.onetime_public_key.is_none()
                || bundle
                    .onetime_public_key_id
                    .expect("One time pre key id is somehow None after a none check - kill me")
                    == 0)
            {
                None
            } else {
                Some((
                    bundle
                        .onetime_public_key_id
                        .expect("Public key id not found")
                        .into(),
                    PublicKey::deserialize(
                        &(*bundle
                            .onetime_public_key
                            .to_owned()
                            .expect("Public key not found")),
                    )
                    .expect("Cannot create public key"),
                ))
            };

        let kyber: Option<(KyberPreKeyId, kem::PublicKey, Vec<u8>)> =
            if (bundle.kyper_pre_key_id.is_none()
                || bundle.kyper_public_key.is_none()
                || bundle.kyper_signature.is_none()
                || bundle
                    .kyper_pre_key_id
                    .expect("None checks are fucked if this happens")
                    == 0)
            {
                None
            } else {
                Some((
                    bundle
                        .kyper_pre_key_id
                        .expect("Kyber pre key id not found")
                        .into(),
                    kem::PublicKey::deserialize(
                        &(*bundle
                            .kyper_public_key
                            .to_owned()
                            .expect("Public key not found")),
                    )
                    .expect("Public kyber key gen failed"),
                    bundle
                        .kyper_signature
                        .to_owned()
                        .expect("Kyber signature is missing"),
                ))
            };

        KeyBundleContent::new(
            bundle.registration_id,
            bundle.device_id.into(),
            one_time_key,
            (
                bundle.signed_public_key_id.into(),
                PublicKey::deserialize(&(*bundle.signed_public_key))
                    .expect("Cannot generate public key"),
            ),
            bundle.signed_signature.to_owned(),
            IdentityKey::decode(&(*bundle.identity_key)).expect("Identity key gen failed"),
            kyber,
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
    kyper_signature: Option<Vec<u8>>,
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
        kyper_signature: Option<Vec<u8>>,
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
