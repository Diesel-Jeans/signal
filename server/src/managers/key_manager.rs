use crate::{
    account::{self, AuthenticatedDevice},
    database::SignalDatabase,
    error::ApiError,
};
use anyhow::Result;
use axum::http::StatusCode;
use common::{
    pre_key,
    web_api::{
        DevicePreKeyBundle, PreKeyResponse, PreKeyResponseItem, SetKeyRequest, UploadPreKey,
        UploadSignedPreKey,
    },
};
use libsignal_core::{DeviceId, ProtocolAddress, ServiceId, ServiceIdKind};
use sha2::{Digest, Sha256};

#[derive(Debug, Default, Clone)]
pub struct KeyManager {}

impl KeyManager {
    pub fn new() -> Self {
        Self {}
    }
    pub async fn handle_put_keys<S: SignalDatabase>(
        &self,
        database: &S,
        checked_device: &AuthenticatedDevice,
        bundle: SetKeyRequest,
        kind: ServiceIdKind,
    ) -> Result<(), ApiError> {
        let identity_key = match kind {
            ServiceIdKind::Aci => checked_device.account().aci_identity_key(),
            ServiceIdKind::Pni => checked_device.account().pni_identity_key(),
        };

        let address = checked_device.get_protocol_address(kind);

        if let Some(prekeys) = bundle.pre_key {
            database
                .store_one_time_ec_pre_keys(prekeys, &address)
                .await
                .map_err(|_| ApiError {
                    status_code: StatusCode::INTERNAL_SERVER_ERROR,
                    message: "Database fault".into(),
                });
        }

        if let Some(ref prekey) = bundle.signed_pre_key {
            if !identity_key
                .public_key()
                .verify_signature(&prekey.public_key, &prekey.signature)
                .unwrap()
            {
                return Err(ApiError {
                    status_code: StatusCode::BAD_REQUEST,
                    message: "Could not verify signature for signed prekey".into(),
                });
            }

            database
                .store_signed_pre_key(prekey, &address)
                .await
                .map_err(|_| ApiError {
                    status_code: StatusCode::INTERNAL_SERVER_ERROR,
                    message: "Database fault".into(),
                });
        }

        if let Some(prekeys) = bundle.pq_pre_key {
            for prekey in prekeys.iter() {
                if !identity_key
                    .public_key()
                    .verify_signature(&prekey.public_key, &prekey.signature)
                    .unwrap()
                {
                    return Err(ApiError {
                        status_code: StatusCode::BAD_REQUEST,
                        // Important not to tell end user that this is not the last resort key
                        message: "Could not verify signature for kem prekey".into(),
                    });
                }
            }

            database
                .store_one_time_pq_pre_keys(prekeys, &address)
                .await
                .map_err(|_| ApiError {
                    status_code: StatusCode::INTERNAL_SERVER_ERROR,
                    message: "Database fault".into(),
                });
        }

        if let Some(ref prekey) = bundle.pq_last_resort_pre_key {
            if !identity_key
                .public_key()
                .verify_signature(&prekey.public_key, &prekey.signature)
                .unwrap()
            {
                return Err(ApiError {
                    status_code: StatusCode::BAD_REQUEST,
                    // Important not to tell the end user that this is the last resort kem key
                    message: "Could not verify signature for signed prekey".into(),
                });
            }
            database
                .store_pq_signed_pre_key(prekey, &address)
                .await
                .map_err(|_| ApiError {
                    status_code: StatusCode::INTERNAL_SERVER_ERROR,
                    message: "Database fault".into(),
                });
        }

        Ok(())
    }

    pub async fn handle_get_keys<S: SignalDatabase>(
        &self,
        database: &S,
        auth_device: &AuthenticatedDevice,
        target_service_id: ServiceId,
        target_device_id: Option<DeviceId>,
    ) -> Result<PreKeyResponse, ApiError> {
        async fn get_key<S: SignalDatabase>(
            database: &S,
            service_id: &ServiceId,
            address: &ProtocolAddress,
            registration_id: u32,
            device_id: u32,
        ) -> Result<PreKeyResponseItem, ApiError> {
            let bundle = database
                .get_key_bundle(address)
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
                .get_one_time_ec_pre_key(address)
                .await
                .map_err(|_| ApiError {
                    status_code: StatusCode::INTERNAL_SERVER_ERROR,
                    message: "Could not fetch user pre key".into(),
                })?;

            Ok(PreKeyResponseItem::new(
                address.device_id(),
                registration_id,
                prekey,
                pq_pre_key,
                signed_pre_key,
            ))
        }

        let target_account = database
            .get_account(&target_service_id)
            .await
            .map_err(|_| ApiError {
                status_code: StatusCode::BAD_REQUEST,
                message: format!(
                    "Could not find account for service id: {}",
                    target_service_id.service_id_string()
                ),
            })?;

        let devices = match target_device_id {
            None => database
                .get_all_devices(&target_service_id)
                .await
                .map_err(|_| ApiError {
                    status_code: StatusCode::INTERNAL_SERVER_ERROR,
                    message: "Could not get all targets devices".into(),
                })?,
            Some(device_id) => {
                vec![database
                    .get_device(&target_service_id, device_id.into())
                    .await
                    .map_err(|_| ApiError {
                        status_code: StatusCode::BAD_REQUEST,
                        message: format!("Device id does not exist: {}", device_id),
                    })?]
            }
        };

        let device_addresses = devices.iter().map(|device| {
            ProtocolAddress::new(target_service_id.service_id_string(), device.device_id())
        });

        let keys = Vec::new();
        for (device, ref address) in devices.iter().zip(device_addresses.into_iter()) {
            get_key(
                database,
                &target_service_id,
                address,
                device.registration_id(),
                device.device_id().into(),
            )
            .await?;
        }

        Ok(PreKeyResponse::new(
            match target_service_id {
                ServiceId::Aci(_) => target_account.aci_identity_key(),
                ServiceId::Pni(_) => target_account.pni_identity_key(),
            },
            keys,
        ))
    }

    // The Signal endpoint /v2/keys/check says that a u64 id is needed, however their ids, such as
    // KyperPreKeyID only supports u32. Here only a u32 is used and therefore only a 4 byte size
    // instead of the sugested u64.
    pub async fn handle_post_keycheck<S: SignalDatabase>(
        &self,
        database: &S,
        auth_device: &AuthenticatedDevice,
        kind: ServiceIdKind, // In Signal this is called IdentityType
        usr_digest: [u8; 32],
    ) -> Result<bool, ApiError> {
        let service_id = match kind {
            ServiceIdKind::Aci => auth_device.account().aci().into(),
            ServiceIdKind::Pni => auth_device.account().pni().into(),
        };
        let address = auth_device.get_protocol_address(kind);
        let bundle = database
            .get_key_bundle(&address)
            .await
            .map_err(|_| ApiError {
                status_code: StatusCode::INTERNAL_SERVER_ERROR,
                message: "Could not fetch user key bundle".into(),
            })?;

        let mut digest = Sha256::new();
        match service_id {
            ServiceId::Aci(_) => {
                digest.update(
                    auth_device
                        .account()
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
                    auth_device
                        .account()
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

    pub async fn get_one_time_pre_key_count<T: SignalDatabase>(
        &self,
        db: &T,
        service_id: &ServiceId,
    ) -> Result<(u32, u32)> {
        Ok((
            db.get_one_time_ec_pre_key_count(service_id).await?,
            db.get_one_time_pq_pre_key_count(service_id).await?,
        ))
    }
}
