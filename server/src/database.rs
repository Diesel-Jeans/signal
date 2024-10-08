use axum::async_trait;

use common::signal_protobuf::Envelope;
use common::web_api::UploadSignedPreKey;

pub type Username = String;
pub type DeviceID = u32;
pub type UserID = u32;
pub type ErrorMessage = String;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Device {
    pub id: u32,
    pub owner: u32,
}
pub type Error = String;

impl TryFrom<String> for Device {
    fn try_from(value: String) -> std::result::Result<Self, self::Error> {
        let ids = value.split_at(
            value
                .find(".")
                .ok_or("Could not parse address. Address did not contain '.'")?,
        );
        let id = ids.0.parse::<u32>().map_err(|e| format!("{}", e))?;

        let owner = ids.1.parse::<u32>().map_err(|e| format!("{}", e))?;
        Ok(Device { id, owner })
    }

    type Error = Error;
}

#[derive(Debug, Eq, PartialEq)]
pub struct User {
    pub id: i32,
    pub username: String,
    pub password: String,
}

pub type PreKeyBundle = String;

#[async_trait]
pub trait SignalDatabase: Clone {
    async fn add_user(&self, username: &str, password: &str) -> Result<(), String>;

    async fn get_user(&self, username: &str) -> Result<User, String>;

    async fn update_user_username(
        &self,
        old_username: &str,
        new_username: &str,
    ) -> Result<(), Error>;

    async fn update_user_password(&self, username: &str, new_password: &str) -> Result<(), Error>;

    async fn delete_user(&self, username: &str) -> Result<(), Error>;

    async fn add_device(&self, owner: &UserID, device: Device) -> Result<(), Error>;

    async fn get_devices(&self, owner: &User) -> Result<Vec<Device>, Error>;

    async fn delete_device(&self, owner: &User, id: i32) -> Result<(), Error>;

    async fn push_msg_queue(&self, reciver: &Device, msg: Envelope) -> Result<(), Error>;

    async fn pop_msg_queue(&self, reciver: &Device) -> Result<Vec<Envelope>, Error>;

    async fn store_key_bundle(&self, data: PreKeyBundle, owner: &Device) -> Result<(), Error>;

    async fn get_key_bundle(&self, owner: &Device) -> Result<PreKeyBundle, Error>;

    async fn get_one_time_pre_key_count(&self, user: &UserID) -> Result<u32, Error>;

    async fn store_one_time_pre_keys(
        &self,
        otpks: Vec<UploadSignedPreKey>,
        owner: &Device,
    ) -> Result<(), Error>;

    async fn get_one_time_pre_key(&self, owner: &Device) -> Result<UploadSignedPreKey, Error>;
}
