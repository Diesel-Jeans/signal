pub mod authorization;

use base64::{prelude::BASE64_STANDARD, Engine};
use libsignal_protocol::{
    kem::{self},
    DeviceId, GenericSignedPreKey, IdentityKey, KyberPreKeyRecord, PreKeyBundle, PreKeyId,
    PreKeyRecord, PublicKey, SignedPreKeyRecord,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DeviceCapabilities {
    pub storage: bool,
    pub transfer: bool,
    pub payment_activation: bool,
    pub delete_sync: bool,
    pub versioned_expiration_timer: bool,
}

impl DeviceCapabilities {
    pub fn new(
        storage: bool,
        transfer: bool,
        payment_activation: bool,
        delete_sync: bool,
        versioned_expiration_timer: bool,
    ) -> Self {
        Self {
            storage,
            transfer,
            payment_activation,
            delete_sync,
            versioned_expiration_timer,
        }
    }
}

impl Default for DeviceCapabilities {
    fn default() -> Self {
        // Default settings for Signal Desktop.
        Self::new(true, false, false, true, true)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AccountAttributes {
    pub name: String,
    pub fetches_messages: bool,
    pub registration_id: u32,
    pub pni_registration_id: u32,
    pub capabilities: DeviceCapabilities,
    pub unidentified_access_key: Box<[u8]>,
}

impl AccountAttributes {
    pub fn new(
        name: String,
        fetches_messages: bool,
        registration_id: u32,
        pni_registration_id: u32,
        capabilities: DeviceCapabilities,
        unidentified_access_key: Box<[u8]>,
    ) -> Self {
        Self {
            name,
            fetches_messages,
            registration_id,
            pni_registration_id,
            capabilities,
            unidentified_access_key,
        }
    }
}

mod id_key {
    use libsignal_protocol::IdentityKey;
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(key: &IdentityKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Convert IdentityKey to bytes and serialize them
        serializer.serialize_bytes(&key.serialize())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<IdentityKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        let bytes = Vec::<u8>::deserialize(deserializer)?;

        IdentityKey::decode(&bytes)
            .map_err(|e| Error::custom(format!("Failed to decode IdentityKey: {}", e)))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ApnToken {
    apn_registration_id: String,
    voip_registration_id: String,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct GcmToken {
    gcm_registration_id: String,
}

/// A request to register an account.
#[derive(Debug, Serialize, Deserialize)]
pub struct RegistrationRequest {
    session_id: String,
    recovery_password: String,
    account_attributes: AccountAttributes,
    require_atomic: bool,
    skip_device_transfer: bool,
    #[serde(with = "id_key")]
    aci_identity_key: IdentityKey,
    #[serde(with = "id_key")]
    pni_identity_key: IdentityKey,
    aci_signed_pre_key: UploadSignedPreKey,
    pni_signed_pre_key: UploadSignedPreKey,
    aci_pq_last_resort_pre_key: UploadSignedPreKey,
    pni_pq_last_resort_pre_key: UploadSignedPreKey,
    apn_token: Option<ApnToken>,
    gcm_token: Option<GcmToken>,
}

impl RegistrationRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_id: String,
        recovery_password: String,
        account_attributes: AccountAttributes,
        require_atomic: bool,
        skip_device_transfer: bool,
        aci_identity_key: IdentityKey,
        pni_identity_key: IdentityKey,
        aci_signed_pre_key: UploadSignedPreKey,
        pni_signed_pre_key: UploadSignedPreKey,
        aci_pq_last_resort_pre_key: UploadSignedPreKey,
        pni_pq_last_resort_pre_key: UploadSignedPreKey,
        apn_token: Option<ApnToken>,
        gcm_token: Option<GcmToken>,
    ) -> Self {
        Self {
            session_id,
            recovery_password,
            account_attributes,
            require_atomic,
            skip_device_transfer,
            aci_identity_key,
            pni_identity_key,
            aci_signed_pre_key,
            pni_signed_pre_key,
            aci_pq_last_resort_pre_key,
            pni_pq_last_resort_pre_key,
            apn_token,
            gcm_token,
        }
    }
    pub fn session_id(&self) -> &String {
        &self.session_id
    }
    pub fn account_attributes(&self) -> &AccountAttributes {
        &self.account_attributes
    }
    pub fn require_atomic(&self) -> bool {
        self.require_atomic
    }
    pub fn skip_device_transfer(&self) -> bool {
        self.skip_device_transfer
    }
    pub fn aci_identity_key(&self) -> &IdentityKey {
        &self.aci_identity_key
    }
    pub fn pni_identity_key(&self) -> &IdentityKey {
        &self.pni_identity_key
    }
    pub fn aci_signed_pre_key(&self) -> &UploadSignedPreKey {
        &self.aci_signed_pre_key
    }
    pub fn pni_signed_pre_key(&self) -> &UploadSignedPreKey {
        &self.pni_signed_pre_key
    }
    pub fn aci_pq_last_resort_pre_key(&self) -> &UploadSignedPreKey {
        &self.aci_pq_last_resort_pre_key
    }
    pub fn pni_pq_last_resort_pre_key(&self) -> &UploadSignedPreKey {
        &self.pni_pq_last_resort_pre_key
    }
}

/// When you register an account, the server will send an [AccountIdentityResponse].
pub type RegistrationResponse = AccountIdentityResponse;

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AccountIdentityResponse {
    pub uuid: Uuid,
    pub number: String,
    pub pni: Uuid,
    pub username_hash: Option<Box<[u8]>>,
    pub storage_capable: bool,
}

/// Used to upload any type of prekey along with a signature that is used
/// to verify the authenticity of the prekey.
#[derive(Debug, Serialize, Deserialize, Clone, Hash, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UploadSignedPreKey {
    pub key_id: u32,
    pub public_key: Box<[u8]>, // TODO: Make this a PublicKey and implement Serialize
    pub signature: Box<[u8]>,  // TODO: Make this a PublicKey and implement Serialize
}

impl From<SignedPreKeyRecord> for UploadSignedPreKey {
    fn from(value: SignedPreKeyRecord) -> Self {
        UploadSignedPreKey {
            key_id: value.id().expect("Can get ID").into(),
            public_key: value.public_key().expect("Can get public_key").serialize(),
            signature: value.signature().expect("Can get signature").into(),
        }
    }
}

impl From<KyberPreKeyRecord> for UploadSignedPreKey {
    fn from(value: KyberPreKeyRecord) -> Self {
        UploadSignedPreKey {
            key_id: value.id().expect("Can get ID").into(),
            public_key: value.public_key().expect("Can get public_key").serialize(),
            signature: value.signature().expect("Can get signature").into(),
        }
    }
}

impl From<PreKeyRecord> for UploadPreKey {
    fn from(value: PreKeyRecord) -> Self {
        UploadPreKey {
            key_id: value.id().expect("Can get ID").into(),
            public_key: value.public_key().expect("Can get public_key").serialize(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UploadPreKey {
    pub key_id: u32,
    pub public_key: Box<[u8]>,
}

/// Used to upload a new prekeys.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct UploadKeys {
    identity_key: Box<[u8]>,
    // If a field is not provided, the server won't update its data.
    pre_keys: Option<UploadSignedPreKey>,
    pq_pre_keys: Option<UploadSignedPreKey>,
    pq_last_resort_pre_key: Option<UploadSignedPreKey>,
    signed_pre_key: Option<UploadSignedPreKey>,
}
impl UploadKeys {
    pub fn new(
        identity_key: Box<[u8]>,
        pre_keys: Option<UploadSignedPreKey>,
        pq_pre_keys: Option<UploadSignedPreKey>,
        pq_last_resort_pre_key: Option<UploadSignedPreKey>,
        signed_pre_key: Option<UploadSignedPreKey>,
    ) -> Self {
        Self {
            identity_key,
            pre_keys,
            pq_pre_keys,
            pq_last_resort_pre_key,
            signed_pre_key,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DevicePreKeyBundle {
    pub aci_signed_pre_key: UploadSignedPreKey,
    pub pni_signed_pre_key: UploadSignedPreKey,
    pub aci_pq_pre_key: UploadSignedPreKey,
    pub pni_pq_pre_key: UploadSignedPreKey,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SetKeyRequest {
    pub pre_key: Option<Vec<UploadPreKey>>,
    pub signed_pre_key: Option<UploadSignedPreKey>,
    pub pq_pre_key: Option<Vec<UploadSignedPreKey>>,
    pub pq_last_resort_pre_key: Option<UploadSignedPreKey>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreKeyResponse {
    identity_key: String, // Base64 endcoded
    keys: Vec<PreKeyResponseItem>,
}

impl PreKeyResponse {
    pub fn new(identity_key: IdentityKey, keys: Vec<PreKeyResponseItem>) -> Self {
        Self {
            identity_key: BASE64_STANDARD.encode(identity_key.serialize()),
            keys,
        }
    }

    pub fn identity_key(&self) -> &str {
        &self.identity_key
    }
    pub fn keys(&self) -> &Vec<PreKeyResponseItem> {
        &self.keys
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreKeyResponseItem {
    device_id: u32,
    registration_id: u32,
    pre_key: Option<UploadPreKey>,
    pq_pre_key: UploadSignedPreKey,
    signed_pre_key: UploadSignedPreKey,
}

impl PreKeyResponseItem {
    pub fn new(
        device_id: DeviceId,
        registration_id: u32,
        pre_key: Option<UploadPreKey>,
        pq_pre_key: UploadSignedPreKey,
        signed_pre_key: UploadSignedPreKey,
    ) -> Self {
        Self {
            device_id: device_id.into(),
            registration_id,
            pre_key,
            pq_pre_key,
            signed_pre_key,
        }
    }
    pub fn device_id(&self) -> DeviceId {
        self.device_id.into()
    }
    pub fn registration_id(&self) -> u32 {
        self.registration_id
    }
    pub fn pre_key(&self) -> &Option<UploadPreKey> {
        &self.pre_key
    }
    pub fn pq_pre_key(&self) -> &UploadSignedPreKey {
        &self.pq_pre_key
    }
    pub fn signed_pre_key(&self) -> &UploadSignedPreKey {
        &self.signed_pre_key
    }
}

impl TryFrom<PreKeyResponse> for Vec<PreKeyBundle> {
    type Error = String;

    fn try_from(items: PreKeyResponse) -> Result<Vec<PreKeyBundle>, Self::Error> {
        let identity_key = IdentityKey::decode(
            BASE64_STANDARD
                .decode(items.identity_key())
                .map_err(|_| "Failed decoding identity key")?
                .as_slice(),
        )
        .map_err(|_| "Failed decoding identity key")?;

        let mut bundles = Vec::new();
        for pre_key_items in items.keys() {
            let pre_key = if let Some(pre_key) = pre_key_items.pre_key() {
                Some((
                    pre_key.key_id.into(),
                    PublicKey::deserialize(&pre_key.public_key)
                        .map_err(|_| "Failed decoding pre key")?,
                ))
            } else {
                None
            };
            let bundle = PreKeyBundle::new(
                pre_key_items.registration_id(),
                pre_key_items.device_id(),
                pre_key,
                pre_key_items.signed_pre_key().key_id.into(),
                PublicKey::deserialize(&pre_key_items.signed_pre_key().public_key)
                    .map_err(|_| "Failed decoding signed pre key key")?,
                pre_key_items.signed_pre_key().signature.to_vec(),
                identity_key,
            )
            .map_err(|_| "Creation of key bundle failed")?;

            bundles.push(
                bundle.with_kyber_pre_key(
                    pre_key_items.pq_pre_key().key_id.into(),
                    kem::PublicKey::deserialize(&pre_key_items.pq_pre_key().public_key)
                        .map_err(|_| "Failed decoding kem pre key key")?,
                    pre_key_items.pq_pre_key().signature.to_vec(),
                ),
            )
        }
        Ok(bundles)
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SignalMessages {
    pub messages: Vec<SignalMessage>,
    pub online: bool,
    pub urgent: bool,
    pub timestamp: u64,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SignalMessage {
    pub r#type: i32,
    pub destination_device_id: u32,
    pub destination_registration_id: u32,
    pub content: String,
}

#[cfg(test)]
mod api_structs_tests {
    use libsignal_protocol::{kem, IdentityKeyPair, KeyPair, PreKeyBundle};
    use rand::rngs::OsRng;

    use super::{PreKeyResponse, PreKeyResponseItem, UploadPreKey, UploadSignedPreKey};

    #[test]
    fn test_try_from_pre_key_response() {
        let identity_key = IdentityKeyPair::generate(&mut OsRng);
        let prekey = KeyPair::generate(&mut OsRng);
        let pq_pre_key = kem::KeyPair::generate(kem::KeyType::Kyber1024);

        let mut keys = Vec::new();
        keys.push(PreKeyResponseItem::new(
            1.into(),
            1,
            Some(UploadPreKey {
                key_id: 1,
                public_key: prekey.public_key.serialize(),
            }),
            UploadSignedPreKey {
                key_id: 1,
                public_key: pq_pre_key.public_key.serialize(),
                signature: Box::new([1, 2, 3, 4]),
            },
            UploadSignedPreKey {
                key_id: 1,
                public_key: prekey.public_key.serialize(),
                signature: Box::new([1, 2, 3, 4]),
            },
        ));

        let res = PreKeyResponse::new(*identity_key.identity_key(), keys);
        let _: Vec<PreKeyBundle> = res.try_into().unwrap();
    }
}
