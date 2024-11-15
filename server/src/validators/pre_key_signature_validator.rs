use anyhow::{Ok, Result};
use base64::{prelude::BASE64_STANDARD, Engine as _};
use common::web_api::UploadSignedPreKey;
use libsignal_protocol::{GenericSignedPreKey, IdentityKey};

pub struct PreKeySignatureValidator;

impl PreKeySignatureValidator {
    pub fn validate_pre_key_signatures(
        identity_key: &IdentityKey,
        signed_pre_keys: &[UploadSignedPreKey],
    ) -> bool {
        signed_pre_keys.iter().all(|signed_pre_key| {
            identity_key
                .public_key()
                .verify_signature(&signed_pre_key.public_key, &signed_pre_key.signature)
                .unwrap_or_default()
        })
    }
}
