use serde::Deserialize;
#[derive(Deserialize)]
pub struct PutV1MessageParams {
    pub story: bool,
}

#[derive(Deserialize)]
pub struct CheckKeysRequest {
    pub identity_type: String,
    pub user_digest: [u8; 32],
}
