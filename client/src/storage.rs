use std::collections::HashMap;
use serde_json::*;
use serde::*;
use crate::contact_manager::Device;
use libsignal_protocol::*;
use std::fs;

pub fn store_device_data(device: &Device) -> std::io::Result<()> {
    /*let json = serialize_device(device);
    fs::write("device_info.json", json)?;*/
    Ok(())
}

//This is pure trash but I have no fucking idea how to serialize it better

pub fn retrive_device_data() {


}





