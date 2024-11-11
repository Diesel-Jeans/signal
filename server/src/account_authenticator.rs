use std::fmt::Debug;

use axum::{
    async_trait,
    extract::{FromRequestParts, State},
    http::{request::Parts, StatusCode},
    Error,
};
use axum_extra::{
    headers::{authorization::Basic, Authorization},
    typed_header::TypedHeaderRejectionReason,
    TypedHeader,
};
use libsignal_core::{DeviceId, ServiceId};

use crate::{
    account::{Account, AuthenticatedDevice, Device},
    database::SignalDatabase,
    error::ApiError,
    managers::{state::SignalServerState, websocket::wsstream::WSStream},
};

#[async_trait]
impl<T: SignalDatabase, U: WSStream + Debug> FromRequestParts<SignalServerState<T, U>> for AuthenticatedDevice
where
    T: Sync + Send,
{
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &SignalServerState<T, U>,
    ) -> Result<Self, Self::Rejection> {
        let TypedHeader(Authorization(basic)) =
            TypedHeader::<Authorization<Basic>>::from_request_parts(parts, state)
                .await
                .map_err(|err| match err.reason() {
                    TypedHeaderRejectionReason::Missing => ApiError {
                        status_code: StatusCode::UNAUTHORIZED,
                        message: "Authorization header is missing".to_owned(),
                    },
                    _ => ApiError {
                        status_code: StatusCode::INTERNAL_SERVER_ERROR,
                        message: "Error parsing Authorization header".to_owned(),
                    },
                })?;

        if let Some(v) = basic.username().find('.') {
            let service_id: ServiceId = ServiceId::parse_from_service_id_string(
                &basic.username()[..v],
            )
            .ok_or(ApiError {
                status_code: StatusCode::INTERNAL_SERVER_ERROR,
                message: "Error parsing service id".to_owned(),
            })?;
            let device_id = basic.username()[(v + 1)..]
                .parse::<u32>()
                .map_err(|_| ApiError {
                    status_code: StatusCode::INTERNAL_SERVER_ERROR,
                    message: "Error parsing device id".to_owned(),
                })?;
            authenticate_device(state, &service_id, device_id, basic.password()).await
        } else {
            let service_id: ServiceId = ServiceId::parse_from_service_id_string(basic.username())
                .ok_or(ApiError {
                status_code: StatusCode::INTERNAL_SERVER_ERROR,
                message: "Error parsing service id".to_owned(),
            })?;
            authenticate_device(state, &service_id, 1, basic.password()).await
        }
    }
}

async fn authenticate_device<T: SignalDatabase, U: WSStream + Debug>(
    state: &SignalServerState<T, U>,
    service_id: &ServiceId,
    device_id: u32,
    password: &str,
) -> Result<AuthenticatedDevice, ApiError> {
    let account: Account = state.get_account(service_id).await.map_err(|_| ApiError {
        status_code: StatusCode::INTERNAL_SERVER_ERROR,
        message: "Error getting account".to_owned(),
    })?;

    let device: Device = account
        .devices()
        .iter()
        .find(|&d| d.device_id() == device_id.into())
        .ok_or(ApiError {
            status_code: StatusCode::NOT_FOUND,
            message: "Device not found".to_owned(),
        })?
        .to_owned();

    if verify_password(device.auth_token(), device.salt(), password).await? {
        Ok(AuthenticatedDevice::new(account, device))
    } else {
        Err(ApiError {
            status_code: StatusCode::UNAUTHORIZED,
            message: "Wrong password".to_owned(),
        })
    }
}

async fn verify_password(auth_token: &[u8], salt: &str, password: &str) -> Result<bool, ApiError> {
    let password_hash = HKDF_DeriveSecrets(
        32,
        password.as_bytes(),
        Some("authtoken".as_bytes()),
        Some(salt.as_bytes()),
    )?;
    Ok(password_hash == *auth_token)
}

//Function taken from libsignal-bridge
#[allow(nonstandard_style)]
fn HKDF_DeriveSecrets(
    output_length: u32,
    ikm: &[u8],
    label: Option<&[u8]>,
    salt: Option<&[u8]>,
) -> Result<Vec<u8>, ApiError> {
    let label = label.unwrap_or(&[]);
    let mut buffer = vec![0; output_length as usize];
    hkdf::Hkdf::<sha2::Sha256>::new(salt, ikm)
        .expand(label, &mut buffer)
        .map_err(|_| ApiError {
            status_code: StatusCode::INTERNAL_SERVER_ERROR,
            message: format!("output too long ({})", output_length),
        })?;
    Ok(buffer)
}
