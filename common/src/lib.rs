#![allow(unused)]
pub mod web_api;

pub mod signal_protobuf {
    tonic::include_proto!("textsecure"); // The string specified here must match the proto package name
    tonic::include_proto!("signalservice");
}

pub mod signal_protocol_messages {
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, Debug)]
    pub struct RegistrationRequest {
        pub aci: String,
    }
}
pub mod pre_key;
