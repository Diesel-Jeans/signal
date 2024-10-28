pub mod authorization;
use std::{fmt, num::ParseIntError, str::FromStr};

use crate::signal_protobuf::Envelope;
use anyhow::{anyhow, bail, Error};
use libsignal_protocol::{DeviceId, IdentityKey, ServiceId};
use serde::{
    de::{self, MapAccess, Visitor},
    ser::SerializeStruct,
    Deserialize, Deserializer, Serialize,
};
use uuid::Uuid;

use crate::pre_key;

/// All information required to create an account.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAccountOptions {
    pub session_id: String,
    pub number: String,
    pub code: String,
    pub new_password: String,
    pub registration_id: u32,
    pub pni_registration_id: u32,
    pub access_key: Box<[u8]>,
    pub aci_public_key: Box<[u8]>,
    pub pni_public_key: Box<[u8]>,
    pub aci_signed_pre_key: UploadSignedPreKey,
    pub pni_signed_pre_key: UploadSignedPreKey,
    pub aci_pq_last_resort_pre_key: UploadSignedPreKey,
    pub pni_pq_last_resort_pre_key: UploadSignedPreKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceCapabilities {
    storage: bool,
    transfer: bool,
    payment_activation: bool,
    delete_sync: bool,
    versioned_expiration_timer: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountAttributes {
    fetches_messages: bool,
    registration_id: i32,
    pni_registration_id: i32,
    capabilities: DeviceCapabilities,
    unidentified_access_key: Box<[u8]>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizationHeader {
    username: String,
    device_id: u32,
    password: String,
}

impl AuthorizationHeader {
    pub fn new(username: String, device_id: u32, password: String) -> Self {
        Self {
            username,
            device_id,
            password,
        }
    }
    pub fn username(&self) -> &String {
        &self.username
    }
    pub fn device_id(&self) -> u32 {
        self.device_id
    }
    pub fn password(&self) -> &String {
        &self.password
    }
}

impl FromStr for AuthorizationHeader {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let index1 = s.find(":").unwrap();
        let index2 = s.find(".").unwrap();
        let (address_part, password) = s.split_at(index1);
        let (username_part, device_part) = address_part.split_at(index2);
        let device_id = device_part.strip_suffix(":").unwrap().parse().unwrap();
        let username = username_part.strip_suffix(".").unwrap();
        Ok(AuthorizationHeader::new(
            username.to_owned(),
            device_id,
            password.to_owned(),
        ))
    }
}

/// A request to register an account.
#[derive(Debug)]
pub struct RegistrationRequest {
    session_id: String,
    account_attributes: AccountAttributes,
    require_atomic: bool,
    skip_device_transfer: bool,
    aci_identity_key: IdentityKey,
    pni_identity_key: IdentityKey,
    aci_signed_pre_key: UploadSignedPreKey,
    pni_signed_pre_key: UploadSignedPreKey,
    aci_pq_last_resort_pre_key: UploadSignedPreKey,
    pni_pq_last_resort_pre_key: UploadSignedPreKey,
}

impl Serialize for RegistrationRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("RegistrationRequest", 10)?;
        state.serialize_field("sessionId", &self.session_id)?;
        state.serialize_field("accountAttributes", &self.account_attributes)?;
        state.serialize_field("requireAtomic", &self.require_atomic)?;
        state.serialize_field("skipDeviceTransfer", &self.skip_device_transfer)?;
        state.serialize_field("aciIdentityKey", &(self.aci_identity_key.serialize()))?;
        state.serialize_field("pniIdentityKey", &(self.pni_identity_key.serialize()))?;
        state.serialize_field("aciSignedPreKey", &self.aci_signed_pre_key)?;
        state.serialize_field("pniSignedPreKey", &self.pni_signed_pre_key)?;
        state.serialize_field("aciPqLastResortPreKey", &self.aci_pq_last_resort_pre_key)?;
        state.serialize_field("pniPqLastResortPreKey", &self.pni_pq_last_resort_pre_key)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for RegistrationRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Use a visitor to manually handle field deserialization
        struct RegistrationRequestVisitor;

        impl<'de> Visitor<'de> for RegistrationRequestVisitor {
            type Value = RegistrationRequest;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct RegistrationRequest")
            }

            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut session_id = None;
                let mut account_attributes = None;
                let mut require_atomic = None;
                let mut skip_device_transfer = None;
                let mut aci_identity_key = None;
                let mut pni_identity_key = None;
                let mut aci_signed_pre_key = None;
                let mut pni_signed_pre_key = None;
                let mut aci_pq_last_resort_pre_key = None;
                let mut pni_pq_last_resort_pre_key = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        "session_id" => session_id = Some(map.next_value()?),
                        "account_attributes" => account_attributes = Some(map.next_value()?),
                        "require_atomic" => require_atomic = Some(map.next_value()?),
                        "skip_device_transfer" => skip_device_transfer = Some(map.next_value()?),
                        "aci_identity_key" => aci_identity_key = Some(map.next_value()?),
                        "pni_identity_key" => pni_identity_key = Some(map.next_value()?),
                        "aci_signed_pre_key" => aci_signed_pre_key = Some(map.next_value()?),
                        "pni_signed_pre_key" => pni_signed_pre_key = Some(map.next_value()?),
                        "aci_pq_last_resort_pre_key" => {
                            aci_pq_last_resort_pre_key = Some(map.next_value()?)
                        }
                        "pni_pq_last_resort_pre_key" => {
                            pni_pq_last_resort_pre_key = Some(map.next_value()?)
                        }
                        _ => {}
                    }
                }

                Ok(RegistrationRequest {
                    session_id: session_id.ok_or_else(|| de::Error::missing_field("session_id"))?,
                    account_attributes: account_attributes
                        .ok_or_else(|| de::Error::missing_field("account_attributes"))?,
                    require_atomic: require_atomic
                        .ok_or_else(|| de::Error::missing_field("require_atomic"))?,
                    skip_device_transfer: skip_device_transfer
                        .ok_or_else(|| de::Error::missing_field("skip_device_transfer"))?,
                    aci_identity_key: aci_identity_key
                        .map(IdentityKey::decode)
                        .ok_or_else(|| de::Error::missing_field("aci_identity_key"))?
                        .map_err(|_| de::Error::custom("Could not decode aciIdentityKey"))?,
                    pni_identity_key: pni_identity_key
                        .map(IdentityKey::decode)
                        .ok_or_else(|| de::Error::missing_field("pni_identity_key"))?
                        .map_err(|_| de::Error::custom("Could not decode pniIdentityKey"))?,
                    aci_signed_pre_key: aci_signed_pre_key
                        .ok_or_else(|| de::Error::missing_field("aci_signed_pre_key"))?,
                    pni_signed_pre_key: pni_signed_pre_key
                        .ok_or_else(|| de::Error::missing_field("pni_signed_pre_key"))?,
                    aci_pq_last_resort_pre_key: aci_pq_last_resort_pre_key
                        .ok_or_else(|| de::Error::missing_field("aci_pq_last_resort_pre_key"))?,
                    pni_pq_last_resort_pre_key: pni_pq_last_resort_pre_key
                        .ok_or_else(|| de::Error::missing_field("pni_pq_last_resort_pre_key"))?,
                })
            }
        }

        deserializer.deserialize_struct(
            "RegistrationRequest",
            &[
                "session_id",
                "account_attributes",
                "require_atomic",
                "skip_device_transfer",
                "aci_identity_key",
                "pni_identity_key",
                "aci_signed_pre_key",
                "pni_signed_pre_key",
                "aci_pq_last_resort_pre_key",
                "pni_pq_last_resort_pre_key",
            ],
            RegistrationRequestVisitor,
        )
    }
}
impl RegistrationRequest {
    fn new(
        session_id: String,
        account_attributes: AccountAttributes,
        require_atomic: bool,
        skip_device_transfer: bool,
        aci_identity_key: IdentityKey,
        pni_identity_key: IdentityKey,
        aci_signed_pre_key: UploadSignedPreKey,
        pni_signed_pre_key: UploadSignedPreKey,
        aci_pq_last_resort_pre_key: UploadSignedPreKey,
        pni_pq_last_resort_pre_key: UploadSignedPreKey,
    ) -> Self {
        Self {
            session_id,
            account_attributes,
            require_atomic,
            skip_device_transfer,
            aci_identity_key,
            pni_identity_key,
            aci_signed_pre_key,
            pni_signed_pre_key,
            aci_pq_last_resort_pre_key,
            pni_pq_last_resort_pre_key,
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

/// Used to upload any type of prekey along with a signature that is used
/// to verify the authenticity of the prekey.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct UploadSignedPreKey {
    pub key_id: u32,
    pub public_key: Box<[u8]>, // TODO: Make this a PublicKey and implement Serialize
    pub signature: Box<[u8]>,  // TODO: Make this a PublicKey and implement Serialize
}

#[derive(Debug, Serialize, Deserialize, Clone)]
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

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DevicePreKeyBundle {
    pub aci_signed_pre_key: UploadSignedPreKey,
    pub pni_signed_pre_key: UploadSignedPreKey,
    pub aci_pq_pre_key: UploadSignedPreKey,
    pub pni_pq_pre_key: UploadSignedPreKey,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetKeyRequest {
    pub pre_key: Option<UploadPreKey>,
    pub signed_pre_key: Option<UploadSignedPreKey>,
    pub pq_pre_key: Option<UploadSignedPreKey>,
}

#[derive(Debug)]
pub struct PreKeyResponse {
    identity_key: IdentityKey,
    keys: Vec<PreKeyResponseItem>,
}

impl PreKeyResponse {
    pub fn new(identity_key: IdentityKey, keys: Vec<PreKeyResponseItem>) -> Self {
        Self { identity_key, keys }
    }
}

#[derive(Debug)]
pub struct PreKeyResponseItem {
    device_id: DeviceId, // Make a version which is serializable, then implement serde on the
    // object
    registration_id: u32,
    pre_key: UploadPreKey,
    pq_pre_key: UploadSignedPreKey,
    signed_pre_key: UploadSignedPreKey,
}

impl PreKeyResponseItem {
    pub fn new(
        device_id: DeviceId,
        registration_id: u32,
        pre_key: UploadPreKey,
        pq_pre_key: UploadSignedPreKey,
        signed_pre_key: UploadSignedPreKey,
    ) -> Self {
        Self {
            device_id,
            registration_id,
            pre_key,
            pq_pre_key,
            signed_pre_key,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SignalMessages {
    pub destination: uuid::Uuid,
    pub timestamp: u64,
    pub messages: Vec<SignalMessage>,
    pub online: bool,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SignalMessage {
    pub r#type: u32,
    pub destination_device_id: u32,
    pub destination_registration_id: u32,
    pub content: String,
}
