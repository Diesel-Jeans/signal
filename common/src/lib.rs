pub mod web_api;
pub mod device;
pub mod key_bundle;
pub mod user;

pub mod signal_protobuf {
    tonic::include_proto!("textsecure"); // The string specified here must match the proto package name
}

pub mod signal_protocol_messages {
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, Debug)]
    pub struct RegistrationRequest {
        pub aci: String,
    }
}
pub mod pre_key;
