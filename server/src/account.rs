use anyhow::Result;
use libsignal_core::{Aci, DeviceId, Pni, ServiceId};
use libsignal_protocol::IdentityKey;
use uuid::Uuid;

/*
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Account {
    pub aci: Option<String>,
    pub pni: Option<String>,
    pub auth_token: String,
    pub identity_key: IdentityKey,
    pub attributes: AccountAttributes,
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct AccountAttributes {
    pub aci_registration_id: i64,
    pub pni_registration_id: i64,
}

impl Account {
    /// Get the service id for this account.
    ///
    /// An account has an ACI (Account Identifier), or
    /// a PNI (Phone Number Identifier) or both.
    pub fn service_id(&self) -> ServiceId {
        let id = self
            .aci
            .as_ref()
            .or(self.pni.as_ref())
            .expect("An account must have an Aci, a Pni or both");
        ServiceId::parse_from_service_id_string(id).unwrap()
    }
}
*/

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Account {
    pni: Pni,
    aci: Aci,
    aci_identity_key: IdentityKey,
    pni_identity_key: IdentityKey,
    devices: Vec<Device>,
}

impl Account {
    pub fn new(
        pni: Pni,
        device: Device,
        pni_identity_key: IdentityKey,
        aci_identity_key: IdentityKey,
    ) -> Self {
        Self {
            pni,
            aci: Uuid::new_v4().into(),
            devices: vec![device],
            pni_identity_key,
            aci_identity_key,
        }
    }

    pub fn from_db(
        pni: Pni,
        aci: Aci,
        pni_identity_key: IdentityKey,
        aci_identity_key: IdentityKey,
        devices: Vec<Device>,
    ) -> Self {
        Self {
            pni,
            aci,
            pni_identity_key,
            aci_identity_key,
            devices,
        }
    }

    pub fn pni(&self) -> Pni {
        self.pni
    }

    pub fn aci(&self) -> Aci {
        self.aci
    }

    pub fn aci_identity_key(&self) -> IdentityKey {
        self.aci_identity_key
    }

    pub fn pni_identity_key(&self) -> IdentityKey {
        self.pni_identity_key
    }

    pub fn devices(&self) -> &Vec<Device> {
        &self.devices
    }

    pub fn add_device(&mut self, device: Device) -> Result<()> {
        // TODO: Do some check to see if device is not in devices
        self.devices.push(device);
        Ok(())
    }
}

#[derive(Debug, Hash, PartialEq, Eq, Clone)]
pub struct Device {
    device_id: DeviceId,
    name: String,
    last_seen: u32,
    created: u32,
    auth_token: Vec<u8>,
    salt: String,
}

impl Device {
    pub fn new(
        device_id: DeviceId,
        name: String,
        last_seen: u32,
        created: u32,
        auth_token: Vec<u8>,
        salt: String,
    ) -> Self {
        Self {
            device_id,
            name,
            last_seen,
            created,
            auth_token,
            salt,
        }
    }
    pub fn device_id(&self) -> DeviceId {
        self.device_id
    }
    pub fn name(&self) -> &String {
        &self.name
    }
    pub fn last_seen(&self) -> u32 {
        self.last_seen
    }
    pub fn created(&self) -> u32 {
        self.created
    }

    pub fn auth_token(&self) -> &Vec<u8> {
        &self.auth_token
    }

    pub fn salt(&self) -> &String {
        &self.salt
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AuthenticatedDevice {
    account: Account,
    device: Device,
}

impl AuthenticatedDevice {
    pub fn new(
        account: Account,
        device: Device,
    ) -> Self {
        Self {
            account,
            device,
        }
    }

    pub fn account(&self) -> &Account {
        &self.account
    }

    pub fn device(&self) -> &Device {
        &self.device
    }
}
