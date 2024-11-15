use crate::errors::{LoginError, MissingFieldError};
use libsignal_core::{Aci, Pni};
use libsignal_protocol::{PrivateKey, PublicKey};
use serde::{Deserialize, Serialize};
use std::fs;
use uuid::Uuid;

mod public_key_serde {
    use libsignal_protocol::{PrivateKey, PublicKey};
    use serde::{self, de, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(key: &PublicKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Convert IdentityKey to bytes and serialize them
        let key_bytes = key.serialize();
        serializer.serialize_bytes(&key_bytes)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<PublicKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        let bytes = Vec::<u8>::deserialize(deserializer)?;

        PublicKey::deserialize(&bytes)
            .map_err(|e| Error::custom(format!("Failed to decode IdentityKey: {}", e)))
    }
}

mod private_key_serde {
    use libsignal_protocol::PrivateKey;
    use serde::{Deserialize, Deserializer, Serializer};

    /// Convert IdentityKey to bytes and serialize them
    pub fn serialize<S>(key: &PrivateKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&key.serialize())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<PrivateKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        let bytes = Vec::<u8>::deserialize(deserializer)?;

        PrivateKey::deserialize(&bytes)
            .map_err(|e| Error::custom(format!("Failed to decode IdentityKey: {}", e)))
    }
}

mod aci_serde {
    use libsignal_protocol::Aci;
    use serde::{Deserialize, Deserializer, Serializer};
    use uuid::Uuid;

    pub fn serialize<S>(key: &Aci, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Convert IdentityKey to bytes and serialize them
        let id: Uuid = key.to_owned().into();
        serializer.serialize_bytes(&id.into_bytes())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Aci, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        let bytes = Vec::<u8>::deserialize(deserializer)?
            .try_into()
            .map_err(|_| Error::custom("Failed to decode ACI".to_owned()))?;

        Ok(Uuid::from_bytes(bytes).into())
    }
}

mod pni_serde {
    use libsignal_core::Pni;
    use serde::{Deserialize, Deserializer, Serializer};
    use uuid::Uuid;

    pub fn serialize<S>(key: &Pni, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Convert IdentityKey to bytes and serialize them
        let id: Uuid = key.to_owned().into();
        serializer.serialize_bytes(&id.into_bytes())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Pni, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        let bytes = Vec::<u8>::deserialize(deserializer)?
            .try_into()
            .map_err(|_| Error::custom("Failed to decode PNI".to_owned()))?;

        Ok(Uuid::from_bytes(bytes).into())
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceStorage {
    #[serde(with = "aci_serde")]
    aci: Aci,
    #[serde(with = "pni_serde")]
    pni: Pni,
    password: String,
    #[serde(with = "public_key_serde")]
    public_key: PublicKey,
    #[serde(with = "private_key_serde")]
    private_key: PrivateKey,
    aci_registration_id: u32,
    pni_registration_id: u32,
}

#[derive(Default)]
pub struct DeviceStorageBuilder {
    aci: Option<Aci>,
    pni: Option<Pni>,
    password: Option<String>,
    public_key: Option<PublicKey>,
    private_key: Option<PrivateKey>,
    aci_registration_id: Option<u32>,
    pni_registration_id: Option<u32>,
}

impl DeviceStorageBuilder {
    pub fn set_password(mut self, password: String) -> Self {
        self.password = Some(password);
        self
    }
    pub fn set_aci(mut self, aci: Aci) -> Self {
        self.aci = Some(aci);
        self
    }
    pub fn set_pni(mut self, pni: Pni) -> Self {
        self.pni = Some(pni);
        self
    }
    pub fn set_private_key(mut self, private_key: PrivateKey) -> Self {
        self.private_key = Some(private_key);
        self
    }
    pub fn set_public_key(mut self, public_key: PublicKey) -> Self {
        self.public_key = Some(public_key);
        self
    }
    pub fn set_aci_registration_id(mut self, id: u32) -> Self {
        self.aci_registration_id = Some(id);
        self
    }
    pub fn set_pni_registration_id(mut self, id: u32) -> Self {
        self.pni_registration_id = Some(id);
        self
    }
}

impl TryFrom<DeviceStorageBuilder> for DeviceStorage {
    type Error = MissingFieldError;

    fn try_from(value: DeviceStorageBuilder) -> Result<Self, Self::Error> {
        Ok(Self::new(
            value.aci.ok_or("aci")?,
            value.pni.ok_or("pni")?,
            value.password.ok_or("password")?,
            value.public_key.ok_or("public_key")?,
            value.private_key.ok_or("private_key")?,
            value.aci_registration_id.ok_or("aci_registration_id")?,
            value.pni_registration_id.ok_or("pni_registration_id")?,
        ))
    }
}

impl DeviceStorage {
    pub fn builder() -> DeviceStorageBuilder {
        DeviceStorageBuilder::default()
    }
    pub fn load() -> Result<Self, LoginError> {
        fs::read("device_info.json")
            .map_err(|_| LoginError::NoAccountInformation)
            .map(|bytes| serde_json::from_slice(&bytes).map_err(|_| LoginError::LoadInfoError))?
    }
    pub fn new(
        aci: Aci,
        pni: Pni,
        password: String,
        public_key: PublicKey,
        private_key: PrivateKey,
        aci_registration_id: u32,
        pni_registration_id: u32,
    ) -> Self {
        let storage = Self {
            aci,
            pni,
            password,
            public_key,
            private_key,
            aci_registration_id,
            pni_registration_id,
        };
        storage.write();
        storage
    }
    fn write(&self) {
        let data = serde_json::to_string_pretty(self).expect("Can serialize DeviceStorage");
        fs::write("device_info.json", data);
    }
}

pub trait Storage {
    fn set_password(&mut self, new_password: &str);
    fn get_password(&self) -> String;
    fn set_aci(&mut self, new_aci: &Aci);
    fn get_aci(&self) -> &Aci;
    fn set_pni(&mut self, new_pni: &Pni);
    fn get_pni(&self) -> &Pni;
    fn get_private_key(&self) -> &PrivateKey;
    fn set_private_key(&mut self, private_key: PrivateKey);
    fn get_public_key(&self) -> &PublicKey;
    fn set_public_key(&mut self, private_key: PublicKey);
    fn get_aci_registration_id(&self) -> u32;
    fn set_aci_registration_id(&mut self, id: u32);
    fn get_pni_registration_id(&self) -> u32;
    fn set_pni_registration_id(&mut self, id: u32);
}

impl Storage for DeviceStorage {
    fn set_password(&mut self, new_password: &str) {
        self.password = new_password.to_owned();
        self.write();
    }

    fn get_password(&self) -> String {
        self.password.clone()
    }

    fn set_aci(&mut self, new_aci: &Aci) {
        self.aci = new_aci.to_owned();
        self.write();
    }

    fn get_aci(&self) -> &Aci {
        &self.aci
    }

    fn set_pni(&mut self, new_pni: &Pni) {
        self.pni = new_pni.to_owned();
        self.write();
    }

    fn get_pni(&self) -> &Pni {
        &self.pni
    }

    fn get_private_key(&self) -> &PrivateKey {
        &self.private_key
    }

    fn set_private_key(&mut self, private_key: PrivateKey) {
        self.private_key = private_key;
        self.write();
    }

    fn get_public_key(&self) -> &PublicKey {
        &self.public_key
    }

    fn set_public_key(&mut self, public_key: PublicKey) {
        self.public_key = public_key;
        self.write();
    }

    fn get_aci_registration_id(&self) -> u32 {
        self.aci_registration_id
    }

    fn set_aci_registration_id(&mut self, id: u32) {
        self.aci_registration_id = id;
        self.write();
    }

    fn get_pni_registration_id(&self) -> u32 {
        self.pni_registration_id
    }

    fn set_pni_registration_id(&mut self, id: u32) {
        self.pni_registration_id = id;
        self.write();
    }
}
