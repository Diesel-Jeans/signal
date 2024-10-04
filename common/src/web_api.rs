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
