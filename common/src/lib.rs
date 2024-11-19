#![allow(unused)]
pub mod web_api;
pub mod websocket;

pub mod signal_protobuf {
    tonic::include_proto!("textsecure"); // The string specified here must match the proto package name
    tonic::include_proto!("signalservice");
}

pub mod pre_key;
