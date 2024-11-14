use anyhow::Result;
use common::web_api::{AccountAttributes, UploadSignedPreKey};
use libsignal_core::{Aci, DeviceId, Pni, ProtocolAddress, ServiceId, ServiceIdKind};
use libsignal_protocol::IdentityKey;
use uuid::Uuid;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Account {
    pni: Pni,
    aci: Aci,
    aci_identity_key: IdentityKey,
    pni_identity_key: IdentityKey,
    devices: Vec<Device>,
    phone_number: String,
    account_attr: AccountAttributes,
}

impl Account {
    pub fn new(
        pni: Pni,
        device: Device,
        pni_identity_key: IdentityKey,
        aci_identity_key: IdentityKey,
        phone_number: String,
        account_attr: AccountAttributes,
    ) -> Self {
        Self {
            pni,
            aci: Uuid::new_v4().into(),
            devices: vec![device],
            pni_identity_key,
            aci_identity_key,
            phone_number,
            account_attr,
        }
    }

    pub fn from_db(
        pni: Pni,
        aci: Aci,
        pni_identity_key: IdentityKey,
        aci_identity_key: IdentityKey,
        devices: Vec<Device>,
        phone_number: String,
        account_attr: AccountAttributes,
    ) -> Self {
        Self {
            pni,
            aci,
            pni_identity_key,
            aci_identity_key,
            devices,
            phone_number,
            account_attr,
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

    pub fn devices(&self) -> &[Device] {
        &self.devices
    }

    pub fn add_device(&mut self, device: Device) -> Result<()> {
        // TODO: Do some check to see if device is not in devices
        self.devices.push(device);
        Ok(())
    }

    pub fn phone_number(&self) -> &str {
        &self.phone_number
    }

    pub fn account_attr(&self) -> &AccountAttributes {
        &self.account_attr
    }
}

#[derive(Debug, Hash, PartialEq, Eq, Clone, bon::Builder)]
pub struct Device {
    device_id: DeviceId,
    name: String,
    last_seen: u64,
    created: u64,
    auth_token: String,
    salt: String,
    registration_id: u32,
    pni_registration_id: u32,
}
impl Device {
    pub fn device_id(&self) -> DeviceId {
        self.device_id
    }
    pub fn name(&self) -> &String {
        &self.name
    }
    pub fn last_seen(&self) -> u64 {
        self.last_seen
    }
    pub fn created(&self) -> u64 {
        self.created
    }

    pub fn auth_token(&self) -> &String {
        &self.auth_token
    }

    pub fn salt(&self) -> &str {
        &self.salt
    }

    pub fn registration_id(&self) -> u32 {
        self.registration_id
    }

    pub fn pni_registration_id(&self) -> u32 {
        self.pni_registration_id
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AuthenticatedDevice {
    account: Account,
    device: Device,
}

impl AuthenticatedDevice {
    pub fn new(account: Account, device: Device) -> Self {
        Self { account, device }
    }

    pub fn account(&self) -> &Account {
        &self.account
    }

    pub fn device(&self) -> &Device {
        &self.device
    }

    pub fn get_protocol_address(&self, kind: ServiceIdKind) -> ProtocolAddress {
        ProtocolAddress::new(
            match kind {
                ServiceIdKind::Aci => self.account().aci.service_id_string(),
                ServiceIdKind::Pni => self.account().pni.service_id_string(),
            },
            self.device().device_id(),
        )
    }
}
