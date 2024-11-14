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
use libsignal_protocol::IdentityKey;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Default)]
pub struct KeyManager {}

impl KeyManager {
    pub fn new() -> Self {
        Self {}
    }
    pub async fn handle_put_keys<S: SignalDatabase>(
        &self,
        database: &S,
        auth_device: &AuthenticatedDevice,
        bundle: SetKeyRequest,
        kind: ServiceIdKind,
    ) -> Result<(), ApiError> {
        let address = auth_device.get_protocol_address(kind);
        let identity_key = match kind {
            ServiceIdKind::Aci => auth_device.account().aci_identity_key(),
            ServiceIdKind::Pni => auth_device.account().pni_identity_key(),
        };

        if let Some(prekeys) = bundle.pre_key {
            database
                .store_one_time_ec_pre_keys(prekeys, &address)
                .await
                .map_err(|_| ApiError {
                    status_code: StatusCode::INTERNAL_SERVER_ERROR,
                    message: "Database fault".into(),
                });
        }

        let verify_key = |prekey: &UploadSignedPreKey, msg: &str| -> Result<(), ApiError> {
            if !identity_key
                .public_key()
                .verify_signature(&prekey.public_key, &prekey.signature)
                .unwrap()
            {
                return Err(ApiError {
                    status_code: StatusCode::BAD_REQUEST,
                    message: msg.into(),
                });
            }
            Ok(())
        };

        if let Some(ref prekey) = bundle.signed_pre_key {
            verify_key(prekey, "Could not verify signature for signed prekey")?;

            database
                .store_signed_pre_key(prekey, &address)
                .await
                .map_err(|_| ApiError {
                    status_code: StatusCode::INTERNAL_SERVER_ERROR,
                    message: "Database fault".into(),
                });
        }

        if let Some(prekeys) = bundle.pq_pre_key {
            prekeys.iter().try_for_each(|prekey| {
                verify_key(prekey, "Could not verify signature for kem prekey")
            })?;

            database
                .store_one_time_pq_pre_keys(prekeys, &address)
                .await
                .map_err(|_| ApiError {
                    status_code: StatusCode::INTERNAL_SERVER_ERROR,
                    message: "Database fault".into(),
                });
        }

        if let Some(ref prekey) = bundle.pq_last_resort_pre_key {
            verify_key(prekey, "Could not verify signature for kem prekey")?;

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
                .map_err(|err| ApiError {
                    status_code: StatusCode::INTERNAL_SERVER_ERROR,
                    message: format!("Could not fetch user key bundle: {}", err),
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

        let mut keys = Vec::new();
        for device in devices.iter() {
            keys.push(
                get_key(
                    database,
                    &target_service_id,
                    &ProtocolAddress::new(
                        target_service_id.service_id_string(),
                        device.device_id(),
                    ),
                    device.registration_id(),
                    device.device_id().into(),
                )
                .await?,
            );
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

#[cfg(test)]
mod key_manager_tests {
    use account::{Account, Device};
    use common::web_api::{AccountAttributes, DeviceCapabilities};
    use libsignal_core::{Aci, Pni};
    use libsignal_protocol::{IdentityKey, KeyPair, PublicKey};
    use rand::rngs::OsRng;
    use sha2::{Digest, Sha256};
    use uuid::Uuid;

    use crate::postgres::PostgresDatabase;
    use crate::test_utils::key::new_device_pre_key_bundle;
    use crate::test_utils::key::new_upload_pre_keys;
    use crate::test_utils::key::new_upload_signed_pre_key;

    use super::*;
    use crate::test_utils::database::*;
    use crate::test_utils::user::*;

    pub fn new_account_from_identity_key(identity_key: IdentityKey) -> Account {
        Account::new(
            Pni::from(Uuid::new_v4()),
            new_device(),
            identity_key,
            identity_key,
            Uuid::new_v4().into(),
            new_account_attributes(),
        )
    }

    #[tokio::test]
    async fn get_keys_test() {
        let km = KeyManager::new();
        let database = database_connect().await;

        let target = new_account();
        let target_device = target.devices()[0].clone();
        let target_address =
            &ProtocolAddress::new(target.aci().service_id_string(), target_device.device_id());

        let key_bundle = new_device_pre_key_bundle();
        let one_time = new_upload_pre_keys(1);

        database.add_account(&target).await;

        database
            .store_key_bundle(&key_bundle, target_address)
            .await
            .unwrap();
        database
            .store_one_time_ec_pre_keys(one_time.clone(), target_address)
            .await
            .unwrap();

        let auth_device1 = new_authenticated_device();

        let keys = km
            .handle_get_keys(
                &database,
                &auth_device1,
                target.aci().into(),
                Some(target_device.device_id()),
            )
            .await
            .unwrap();

        let device_bundle = keys.keys();

        database.delete_account(&target.aci().into()).await.unwrap();

        assert_eq!(keys.identity_key().clone(), target.aci_identity_key());
        assert!(device_bundle.len() == 1);

        assert_eq!(
            device_bundle[0].device_id().clone(),
            target_device.device_id()
        );
        assert_eq!(
            device_bundle[0].registration_id(),
            target_device.registration_id()
        );
        assert_eq!(device_bundle[0].pre_key().clone(), one_time[0]);
        assert_eq!(
            device_bundle[0].signed_pre_key().clone(),
            key_bundle.pni_signed_pre_key
        );
        assert_eq!(
            device_bundle[0].pq_pre_key().clone(),
            key_bundle.pni_pq_pre_key
        );
    }

    #[tokio::test]
    async fn put_keys_test() {
        let km = KeyManager::new();
        let database = database_connect().await;

        let mut csprng = OsRng;
        let identity_key = KeyPair::generate(&mut csprng);
        let account = new_account_from_identity_key(IdentityKey::from(identity_key.public_key));
        let device = account.devices()[0].clone();
        let auth_device = AuthenticatedDevice::new(account, device);

        let target_device_id = auth_device.device().device_id();
        let target_service_id = auth_device.account().pni();
        let address = auth_device.get_protocol_address(ServiceIdKind::Pni);

        let key = Box::new([1, 2, 3, 4]);
        let sign = identity_key
            .private_key
            .calculate_signature(&*key, &mut csprng)
            .unwrap();

        let prekey = new_upload_pre_keys(1);
        let signed_pre_key = new_upload_signed_pre_key(Some(identity_key.private_key));
        let pq_pre_key = new_upload_signed_pre_key(Some(identity_key.private_key));
        let pq_last_resort_pre_key = new_upload_signed_pre_key(Some(identity_key.private_key));

        let request = SetKeyRequest {
            pre_key: Some(prekey.clone()),
            signed_pre_key: Some(signed_pre_key.clone()),
            pq_pre_key: Some(vec![pq_pre_key.clone()]),
            pq_last_resort_pre_key: Some(pq_last_resort_pre_key.clone()),
        };

        database.add_account(auth_device.account()).await.unwrap();

        km.handle_put_keys(&database, &auth_device, request.clone(), ServiceIdKind::Pni)
            .await
            .unwrap();

        let prekey_db = database.get_one_time_ec_pre_key(&address).await.unwrap();
        let signed_pre_key_db = get_ec_pni_signed_pre_key(
            &database,
            request.signed_pre_key.unwrap().key_id,
            &ServiceId::Pni(target_service_id),
            target_device_id.into(),
        )
        .await
        .unwrap();
        let pq_pre_key_db = database.get_one_time_pq_pre_key(&address).await.unwrap();
        let pq_last_resort_pre_key_db = get_pq_last_resort_pre_key(
            &database,
            request.pq_last_resort_pre_key.unwrap().key_id,
            &ServiceId::Pni(target_service_id),
            target_device_id.into(),
        )
        .await
        .unwrap();

        database
            .delete_account(&ServiceId::Pni(target_service_id))
            .await
            .unwrap();

        assert_eq!(prekey[0], prekey_db);
        assert_eq!(signed_pre_key, signed_pre_key_db);
        assert_eq!(pq_pre_key, pq_pre_key_db);
        assert_eq!(pq_last_resort_pre_key, pq_last_resort_pre_key_db);
    }
    #[tokio::test]
    async fn check_keys_test() {
        let database = database_connect().await;
        let auth_device = new_authenticated_device();
        database.add_account(auth_device.account()).await;

        let key_bundle = new_device_pre_key_bundle();
        let signed_pre_key = key_bundle.pni_signed_pre_key.clone();
        let pq_last_resort_pre_key = key_bundle.pni_pq_pre_key.clone();

        database
            .store_key_bundle(
                &key_bundle,
                &auth_device.get_protocol_address(ServiceIdKind::Pni),
            )
            .await
            .unwrap();

        let mut usr_digest = Sha256::new();
        usr_digest.update(
            auth_device
                .account()
                .pni_identity_key()
                .public_key()
                .public_key_bytes()
                .unwrap(),
        );
        usr_digest.update(signed_pre_key.key_id.to_be_bytes());
        usr_digest.update(signed_pre_key.public_key);
        usr_digest.update(pq_last_resort_pre_key.key_id.to_be_bytes());
        usr_digest.update(pq_last_resort_pre_key.public_key);

        let res = KeyManager::new()
            .handle_post_keycheck(
                &database,
                &auth_device,
                ServiceIdKind::Pni,
                usr_digest.finalize().into(),
            )
            .await
            .unwrap();

        database
            .delete_account(&ServiceId::Pni(auth_device.account().pni()))
            .await
            .unwrap();

        assert!(res);
    }
}
