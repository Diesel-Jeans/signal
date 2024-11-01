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

#[derive(Debug, Clone, Default)]
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

        let device_addresses = devices.iter().map(|device| {
            ProtocolAddress::new(target_service_id.service_id_string(), device.device_id())
        });

        let mut keys = Vec::new();
        for (device, ref address) in devices.iter().zip(device_addresses.into_iter()) {
            keys.push(
                get_key(
                    database,
                    &target_service_id,
                    address,
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
    use uuid::Uuid;

    use crate::postgres::PostgresDatabase;

    use super::*;
    async fn create_authenticated_device(
        device_id: DeviceId,
        registration_id: u32,
        identity_key: IdentityKey,
    ) -> AuthenticatedDevice {
        let device = Device::new(
            device_id,
            "test".to_owned(),
            0,
            0,
            Vec::<u8>::new(),
            "salt".to_owned(),
            registration_id,
        );
        let device_capabilities = DeviceCapabilities {
            storage: false,
            transfer: false,
            payment_activation: false,
            delete_sync: false,
            versioned_expiration_timer: false,
        };
        let account_attr = AccountAttributes {
            fetches_messages: false,
            registration_id: registration_id.try_into().unwrap(),
            pni_registration_id: registration_id.try_into().unwrap(),
            capabilities: device_capabilities,
            unidentified_access_key: <Box<[u8]>>::default(),
        };
        let account = Account::new(
            Pni::from(Uuid::new_v4()),
            device.clone(),
            identity_key,
            identity_key,
            "12354678".to_owned(),
            account_attr,
        );
        AuthenticatedDevice::new(account, device)
    }

    async fn add_target<S: SignalDatabase>(
        database: &S,
        target_device_id: &DeviceId,
        target_service_id: &Pni,
        target_identity_key: &IdentityKey,
    ) -> () {
        let device_capabilities = DeviceCapabilities {
            storage: false,
            transfer: false,
            payment_activation: false,
            delete_sync: false,
            versioned_expiration_timer: false,
        };
        let account_attr = AccountAttributes {
            fetches_messages: false,
            registration_id: 1,
            pni_registration_id: 1,
            capabilities: device_capabilities,
            unidentified_access_key: <Box<[u8]>>::default(),
        };

        let device = Device::new(
            target_device_id.clone(),
            "name".into(),
            0,
            0,
            "no token".into(),
            "no salt".into(),
            1,
        );

        database
            .add_account(&Account::new(
                target_service_id.clone(),
                device,
                target_identity_key.clone(),
                target_identity_key.clone(),
                Uuid::new_v4().to_string().into(),
                account_attr,
            ))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn get_keys_test() {
        let km = KeyManager::new();
        let database = PostgresDatabase::connect("DATABASE_URL_TEST".into())
            .await
            .unwrap();

        let target_device_id = DeviceId::from(111);
        let target_service_id = Pni::from(Uuid::new_v4());
        let identity_key = IdentityKey::from(KeyPair::generate(&mut OsRng).public_key);
        add_target(
            &database,
            &target_device_id,
            &target_service_id,
            &identity_key,
        )
        .await;

        let key_bundle = DevicePreKeyBundle {
            aci_signed_pre_key: UploadSignedPreKey {
                key_id: 1,
                public_key: Box::new([1, 2, 3, 4]),
                signature: Box::new([1, 2, 3, 4]),
            },
            pni_signed_pre_key: UploadSignedPreKey {
                key_id: 1,
                public_key: Box::new([1, 2, 3, 4]),
                signature: Box::new([1, 2, 3, 4]),
            },
            aci_pq_pre_key: UploadSignedPreKey {
                key_id: 1,
                public_key: Box::new([1, 2, 3, 4]),
                signature: Box::new([1, 2, 3, 4]),
            },
            pni_pq_pre_key: UploadSignedPreKey {
                key_id: 1,
                public_key: Box::new([1, 2, 3, 4]),
                signature: Box::new([1, 2, 3, 4]),
            },
        };
        let target_address =
            &ProtocolAddress::new(target_service_id.service_id_string(), target_device_id);
        database
            .store_key_bundle(&key_bundle, target_address)
            .await
            .unwrap();

        let one_time = UploadPreKey {
            key_id: 1,
            public_key: Box::new([1, 2, 3, 4]),
        };
        database
            .store_one_time_ec_pre_keys(vec![one_time.clone()], target_address)
            .await
            .unwrap();

        let auth_device1 = create_authenticated_device(0.into(), 0, identity_key).await;

        let keys = km
            .handle_get_keys(
                &database,
                &auth_device1,
                target_service_id.into(),
                Some(target_device_id),
            )
            .await
            .unwrap();

        let device_bundle = keys.keys();

        database
            .delete_account(&target_service_id.into())
            .await
            .unwrap();

        assert_eq!(keys.identity_key().clone(), identity_key);
        assert!(device_bundle.len() == 1);

        assert_eq!(device_bundle[0].device_id().clone(), target_device_id);
        assert_eq!(device_bundle[0].registration_id(), 1);
        assert_eq!(device_bundle[0].pre_key().clone(), one_time);
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
        let database = PostgresDatabase::connect("DATABASE_URL_TEST".into())
            .await
            .unwrap();

        let target_device_id = DeviceId::from(112);
        let target_service_id = Pni::from(Uuid::new_v4());
        let identity_key = IdentityKey::from(KeyPair::generate(&mut OsRng).public_key);
        let auth_device = create_authenticated_device(target_device_id, 0, identity_key).await;

        let prekey = UploadPreKey {
            key_id: 1,
            public_key: Box::new([1, 2, 3, 4]),
        };
        let signed_pre_key = UploadSignedPreKey {
            key_id: 1,
            public_key: Box::new([1, 2, 3, 4]),
            signature: Box::new([1, 2, 3, 4]),
        };
        let pq_pre_key = UploadSignedPreKey {
            key_id: 1,
            public_key: Box::new([1, 2, 3, 4]),
            signature: Box::new([1, 2, 3, 4]),
        };
        let pq_last_resort_pre_key = UploadSignedPreKey {
            key_id: 1,
            public_key: Box::new([1, 2, 3, 4]),
            signature: Box::new([1, 2, 3, 4]),
        };

        let request = SetKeyRequest {
            pre_key: Some(vec![prekey]),
            signed_pre_key: Some(signed_pre_key),
            pq_pre_key: Some(vec![pq_pre_key]),
            pq_last_resort_pre_key: Some(pq_last_resort_pre_key),
        };

        km.handle_put_keys(&database, &auth_device, request, ServiceIdKind::Aci)
            .await
            .unwrap();

        database.
    }
    #[tokio::test]
    async fn check_keys_test() {}
}
