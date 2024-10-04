use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct PreKey {
    pub key_id: i32,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct PreKeyBundle {
    pub aci_signed_pre_key: PreKey,
    pub pni_signed_pre_key: PreKey,
    pub aci_pq_last_resort_pre_key: PreKey,
    pub pni_pq_last_resort_pre_key: PreKey,
}
