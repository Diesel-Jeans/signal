use std::str::FromStr;

use anyhow::Error;
use libsignal_protocol::{DeviceId, IdentityKey, ServiceId};
use serde::{Deserialize, Serialize};

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

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceCapabilities {
    storage: bool,
    transfer: bool,
    payment_activation: bool,
    delete_sync: bool,
    versioned_expiration_timer: bool,
}

#[derive(Debug, Serialize, Deserialize)]
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
        return &self.username;
    }
    pub fn device_id(&self) -> u32 {
        return self.device_id;
    }
    pub fn password(&self) -> &String {
        return &self.password;
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
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationRequest {
    session_id: String,
    account_attributes: AccountAttributes,
    require_atomic: bool,
    skip_device_transfer: bool,
    aci_identity_key: Box<[u8]>,
    pni_identity_key: Box<[u8]>,
    aci_signed_pre_key: UploadSignedPreKey,
    pni_signed_pre_key: UploadSignedPreKey,
    aci_pq_last_resort_pre_key: UploadSignedPreKey,
    pni_pq_last_resort_pre_key: UploadSignedPreKey,
}

/// Used to upload any type of prekey along with a signature that is used
/// to verify the authenticity of the prekey.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct UploadSignedPreKey {
    pub key_id: u32,
    pub public_key: Box<[u8]>,
    pub signature: Box<[u8]>,
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
    pub aci_pq_last_resort_pre_key: UploadSignedPreKey,
    pub pni_pq_last_resort_pre_key: UploadSignedPreKey,
}

#[derive(Debug, Hash, PartialEq, Eq, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Device {
    pub device_id: u32,
    pub name: String,
    pub last_seen: u32,
    pub created: u32,
}

impl Device {
    pub fn device_id(&self) -> DeviceId {
        self.device_id.into()
    }
}
