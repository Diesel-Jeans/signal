use common::web_api::{DevicePreKeyBundle, UploadPreKey, UploadSignedPreKey};
use libsignal_protocol::{PrivateKey, PublicKey};
use rand::{
    rngs::{OsRng, StdRng},
    Rng, SeedableRng,
};

pub fn new_device_pre_key_bundle() -> DevicePreKeyBundle {
    DevicePreKeyBundle {
        aci_signed_pre_key: UploadSignedPreKey {
            key_id: 1,
            public_key: Box::new([1, 2, 3, 4]),
            signature: Box::new([1, 2, 3, 4]),
        },
        pni_signed_pre_key: UploadSignedPreKey {
            key_id: 1,
            public_key: Box::new([1, 2, 3, 4]),
            signature: Box::new([1, 2, 3, 4]),
        },
        aci_pq_pre_key: UploadSignedPreKey {
            key_id: 1,
            public_key: Box::new([1, 2, 3, 4]),
            signature: Box::new([1, 2, 3, 4]),
        },
        pni_pq_pre_key: UploadSignedPreKey {
            key_id: 1,
            public_key: Box::new([1, 2, 3, 4]),
            signature: Box::new([1, 2, 3, 4]),
        },
    }
}

pub fn new_upload_pre_keys(amount: u32) -> Vec<UploadPreKey> {
    let mut keys = Vec::new();
    for n in 0..amount {
        keys.push(UploadPreKey {
            key_id: n,
            public_key: Box::new([1, 2, 3, 4]),
        })
    }
    keys
}

pub fn new_upload_signed_pre_key(signer: Option<PrivateKey>) -> UploadSignedPreKey {
    let key = Box::new([1, 2, 3, 4]);
    match signer {
        Some(signer) => UploadSignedPreKey {
            key_id: StdRng::from_entropy().gen::<u32>().into(),
            public_key: key.clone(),
            signature: signer.calculate_signature(&*key, &mut OsRng).unwrap(),
        },
        None => UploadSignedPreKey {
            key_id: StdRng::from_entropy().gen::<u32>().into(),
            public_key: key.clone(),
            signature: key.clone(),
        },
    }
}
