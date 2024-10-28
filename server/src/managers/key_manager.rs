use axum::http::StatusCode;
use common::web_api::{PreKeyResponse, PreKeyResponseItem, SetKeyRequest};
use libsignal_core::{DeviceId, ProtocolAddress, ServiceId};
use libsignal_protocol::PreKeyBundle;
use sha2::{Digest, Sha256};

use crate::{database::SignalDatabase, error::ApiError};

#[derive(Debug, Default, Clone)]
pub struct KeyManager {}

impl KeyManager {
    pub fn new() -> Self {
        Self {}
    }
    async fn handle_put_keys<S: SignalDatabase>(
        database: S,
        address: &ProtocolAddress,
        bundle: SetKeyRequest,
    ) -> Result<(), ApiError> {
        todo!()
    }

    async fn handle_get_keys<S: SignalDatabase>(
        database: S,
        service_id: &ServiceId,
        address_and_registration_ids: Vec<(ProtocolAddress, u32)>,
    ) -> Result<PreKeyResponse, ApiError> {
        async fn get_key<S: SignalDatabase>(
            database: &S,
            service_id: &ServiceId,
            device_id: DeviceId,
            registration_id: u32,
            address: ProtocolAddress,
        ) -> Result<PreKeyResponseItem, ApiError> {
            let bundle = database
                .get_key_bundle(&address)
                .await
                .map_err(|_| ApiError {
                    status_code: StatusCode::INTERNAL_SERVER_ERROR,
                    message: "Could not fetch user key bundle".into(),
                })?;

            let (pq_pre_key, signed_pre_key) = match service_id {
                ServiceId::Aci(_) => (bundle.aci_pq_pre_key, bundle.aci_signed_pre_key),
                ServiceId::Pni(_) => (bundle.pni_pq_pre_key, bundle.pni_signed_pre_key),
            };

            let prekey = database
                .get_one_time_pre_key(&address)
                .await
                .map_err(|_| ApiError {
                    status_code: StatusCode::INTERNAL_SERVER_ERROR,
                    message: "Could not fetch user pre key".into(),
                })?;

            Ok(PreKeyResponseItem::new(
                device_id,
                registration_id,
                prekey,
                pq_pre_key,
                signed_pre_key,
            ))
        }

        let mut keys = Vec::new();
        for (address, registration_id) in address_and_registration_ids {
            keys.push(
                get_key(
                    &database,
                    service_id,
                    address.device_id(),
                    registration_id,
                    address,
                )
                .await?,
            )
        }

        let account = database
            .get_account(service_id)
            .await
            .map_err(|_| ApiError {
                status_code: StatusCode::INTERNAL_SERVER_ERROR,
                message: "Could not fetch user account".into(),
            })?;

        let identity_key = match service_id {
            ServiceId::Aci(_) => account.aci_identity_key(),
            ServiceId::Pni(_) => account.pni_identity_key(),
        };

        Ok(PreKeyResponse::new(identity_key, keys))
    }

    // The Signal endpoint /v2/keys/check says that a u64 id is needed, however their ids, such as
    // KyperPreKeyID only supports u32. Here only a u32 is used and therefore only a 4 byte size
    // instead of the sugested u64.
    async fn handle_post_keycheck<S: SignalDatabase>(
        database: S,
        service_id: &ServiceId,
        address: ProtocolAddress,
        usr_digest: [u8; 32],
    ) -> Result<bool, ApiError> {
        let mut digest = Sha256::new();
        let account = database
            .get_account(service_id)
            .await
            .map_err(|_| ApiError {
                status_code: StatusCode::INTERNAL_SERVER_ERROR,
                message: "Could not fetch user account".into(),
            })?;
        let bundle = database
            .get_key_bundle(&address)
            .await
            .map_err(|_| ApiError {
                status_code: StatusCode::INTERNAL_SERVER_ERROR,
                message: "Could not fetch user key bundle".into(),
            })?;

        match service_id {
            ServiceId::Aci(_) => {
                digest.update(
                    account
                        .aci_identity_key()
                        .public_key()
                        .public_key_bytes()
                        .map_err(|_| ApiError {
                            status_code: StatusCode::INTERNAL_SERVER_ERROR,
                            message: "Could not convert key to bytes".into(),
                        })?,
                );
                digest.update(bundle.aci_signed_pre_key.key_id.to_be_bytes());
                digest.update(&bundle.aci_signed_pre_key.public_key);
                digest.update(bundle.aci_pq_pre_key.key_id.to_be_bytes());
                digest.update(&bundle.aci_pq_pre_key.public_key);
            }
            ServiceId::Pni(_) => {
                digest.update(
                    account
                        .pni_identity_key()
                        .public_key()
                        .public_key_bytes()
                        .map_err(|_| ApiError {
                            status_code: StatusCode::INTERNAL_SERVER_ERROR,
                            message: "Could not convert key to bytes".into(),
                        })?,
                );
                digest.update(bundle.pni_signed_pre_key.key_id.to_be_bytes());
                digest.update(&bundle.pni_signed_pre_key.public_key);
                digest.update(bundle.pni_pq_pre_key.key_id.to_be_bytes());
                digest.update(&bundle.pni_pq_pre_key.public_key);
            }
        }

        let server_digest: [u8; 32] = digest.finalize().into();

        Ok(server_digest == usr_digest)
    }
}
