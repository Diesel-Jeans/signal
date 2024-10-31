use crate::contact_manager::Device;
use crate::key_management::bundle::PrimitiveKeyBundleContent;
use libsignal_core::{Aci, Pni};
use libsignal_protocol::{
    IdentityKeyPair, IdentityKeyStore, InMemIdentityKeyStore, InMemKyberPreKeyStore,
    InMemPreKeyStore, InMemSignalProtocolStore, KyberPreKeyStore, PreKeyId, PreKeyStore,
    ProtocolStore,
};
use serde::*;
use serde_json::*;
use std::collections::HashMap;
use std::fs;
use uuid::Uuid;

#[derive(Serialize, Deserialize, Default)]
pub struct DeviceStorage {
    aci: Option<Uuid>,
    pni: Option<Uuid>,
    password: Option<String>,
}

impl DeviceStorage {
    pub fn new() -> Self {
        fs::read("device_info.json")
            .map_err(|_| ())
            .and_then(|bytes| serde_json::from_slice(&bytes).map_err(|_| ()))
            .unwrap_or_default()
    }
    fn write(&self) {
        let data = serde_json::to_string_pretty(self).expect("Can serialize DeviceStorage");
        fs::write("device_info.json", data);
    }
}

pub trait Storage {
    fn set_password(&mut self, new_password: &str);
    fn get_password(&self) -> Option<String>;
    fn set_aci(&mut self, new_aci: &Aci);
    fn get_aci(&self) -> Option<Aci>;
    fn set_pni(&mut self, new_pni: &Pni);
    fn get_pni(&self) -> Option<Pni>;
}

impl Storage for DeviceStorage {
    fn set_password(&mut self, new_password: &str) {
        self.password = Some(new_password.to_owned());
        self.write();
    }

    fn get_password(&self) -> Option<String> {
        self.password.clone()
    }

    fn set_aci(&mut self, new_aci: &Aci) {
        self.aci = Some(new_aci.to_owned().into());
        self.write();
    }

    fn get_aci(&self) -> Option<Aci> {
        self.aci.map(|aci| aci.into())
    }

    fn set_pni(&mut self, new_pni: &Pni) {
        self.pni = Some(new_pni.to_owned().into());
        self.write();
    }

    fn get_pni(&self) -> Option<Pni> {
        self.pni.map(|pni| pni.into())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Info {
    uuid: String,
    device_id: u32,
    bundle: PrimitiveKeyBundleContent,
}

pub fn store_device_data(device: &Device) -> std::io::Result<()> {
    let data = Info {
        uuid: device.address.name().to_string(),
        device_id: device.address.device_id().into(),
        bundle: device.bundle.serialize(),
    };

    let json = to_string(&data)?;
    fs::write("device_info.json", json)?;
    Ok(())
}

pub fn retrive_device_data() -> Result<(Info)> {
    let content = fs::read_to_string("device_info.json").unwrap();
    let info: Info = from_str(&content).unwrap();
    Ok(info)
}

#[cfg(test)]
mod tests {
    use crate::contact_manager::Device;
    use crate::encryption::test::{create_pre_key_bundle, store};
    use crate::storage::{retrive_device_data, store_device_data};
    use libsignal_protocol::*;
    use rand::rngs::OsRng;
    use serde::de::IntoDeserializer;

    use uuid::Uuid;

    #[tokio::test]
    async fn test_store_bundle_data() {
        let alice = Uuid::new_v4().to_string();
        let device_id = 42069;
        let mut store = store(device_id);

        let bundle = create_pre_key_bundle(&mut store, device_id, &mut OsRng)
            .await
            .unwrap();

        let device = Device::new(alice, device_id, bundle.try_into().unwrap());

        store_device_data(&device).unwrap();

        let result = retrive_device_data().unwrap();
        let device_id: u32 = device.address.device_id().into();
        assert_eq!(result.device_id, device_id);
        assert_eq!(result.bundle, device.bundle.serialize());
    }
}
