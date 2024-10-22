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
}

#[derive(Debug, Hash, PartialEq, Eq, Clone)]
pub struct Device {
    device_id: DeviceId,
    name: String,
    last_seen: u32,
    created: u32,
}

impl Device {
    pub fn new(device_id: DeviceId, name: String, last_seen: u32, created: u32) -> Self {
        Self {
            device_id,
            name,
            last_seen,
            created,
        }
    }
    pub fn device_id(&self) -> DeviceId {
        self.device_id.into()
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
}
