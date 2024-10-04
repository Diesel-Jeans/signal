use crate::contact_manager::Device;
use crate::key_management::bundle::PrimitiveKeyBundleContent;
use libsignal_protocol::*;
use serde::*;
use serde_json::*;
use std::fs;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
struct Info {
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
    use serde_json;
    use uuid::Uuid;

    #[tokio::test]
    async fn test_store_bundle_data() {
        let alice = Uuid::new_v4().to_string();
        let device_id = 42069;
        let mut store = store(device_id);

        let bundle = create_pre_key_bundle(&mut store, device_id, &mut OsRng)
            .await
            .unwrap();

        let device = Device::new(alice, device_id, bundle.into());

        store_device_data(&device).unwrap();

        let result = retrive_device_data().unwrap();
        let device_id: u32 = device.address.device_id().into();
        assert_eq!(result.device_id, device_id);
        assert_eq!(result.bundle, device.bundle.serialize());
    }
}
