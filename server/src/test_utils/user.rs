use crate::{
    account::{Account, AuthenticatedDevice, Device},
    postgres::PostgresDatabase,
};
use common::web_api::{AccountAttributes, DeviceCapabilities};
use libsignal_core::{Pni, ProtocolAddress};
use libsignal_protocol::{IdentityKey, KeyPair, PublicKey};
use rand::{
    rngs::{OsRng, StdRng},
    Rng, SeedableRng,
};
use uuid::Uuid;

pub fn new_authenticated_device() -> AuthenticatedDevice {
    let acc = new_account();
    let device = acc.devices()[0].clone();
    AuthenticatedDevice::new(acc, device)
}

pub fn new_account() -> Account {
    let mut csprng = OsRng;
    let identity_key = KeyPair::generate(&mut csprng);

    Account::new(
        Pni::from(Uuid::new_v4()),
        new_device(),
        IdentityKey::new(identity_key.public_key),
        IdentityKey::new(identity_key.public_key),
        Uuid::new_v4().into(),
        new_account_attributes(),
    )
}
pub fn new_device() -> Device {
    Device::builder()
        .device_id(StdRng::from_entropy().gen::<u32>().into())
        .name("device".into())
        .last_seen(0)
        .created(0)
        .auth_token("bob_token".into())
        .salt("bob_salt".into())
        .registration_id(StdRng::from_entropy().gen::<u32>().into())
        .pni_registration_id(StdRng::from_entropy().gen::<u32>().into())
        .build()
}

pub fn new_account_attributes() -> AccountAttributes {
    AccountAttributes {
        name: "name".into(),
        fetches_messages: true,
        registration_id: 1,
        pni_registration_id: 1,
        capabilities: DeviceCapabilities {
            storage: true,
            transfer: true,
            payment_activation: true,
            delete_sync: true,
            versioned_expiration_timer: true,
        },
        unidentified_access_key: Box::new([1u8, 2u8, 3u8]),
    }
}

pub fn new_protocol_address() -> ProtocolAddress {
    let name = Pni::from(Uuid::new_v4());
    let device_id = StdRng::from_entropy().gen::<u32>().into();
    ProtocolAddress::new(name.service_id_string(), device_id)
}
