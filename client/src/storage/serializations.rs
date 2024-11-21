pub(crate) mod public_key_serde {
    use libsignal_protocol::PublicKey;
    use serde::{self, Deserialize, Deserializer, Serializer};

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

pub(crate) mod private_key_serde {
    use libsignal_protocol::PrivateKey;
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(key: &PrivateKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Convert IdentityKey to bytes and serialize them
        let key_bytes = key.serialize();
        serializer.serialize_bytes(&key_bytes)
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
pub(crate) mod aci_serde {
    use libsignal_protocol::Aci;
    use serde::{self, Deserialize, Deserializer, Serializer};
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

pub(crate) mod pni_serde {
    use libsignal_core::Pni;
    use serde::{self, Deserialize, Deserializer, Serializer};
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

pub(crate) mod identity_key_pair_serde {
    use libsignal_protocol::IdentityKeyPair;
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(key: &IdentityKeyPair, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Convert IdentityKey to bytes and serialize them
        serializer.serialize_bytes(&key.serialize())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<IdentityKeyPair, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        let bytes = Vec::<u8>::deserialize(deserializer)?;

        IdentityKeyPair::try_from(bytes.as_ref())
            .map_err(|_| Error::custom("Failed to decode IdentityKeyPair"))
    }
}

pub(crate) mod identity_map_serde {
    use core::fmt;
    use std::collections::HashMap;

    use common::protocol_address::parse_protocol_address;
    use libsignal_core::ProtocolAddress;
    use libsignal_protocol::IdentityKey;
    use serde::{
        self,
        de::{MapAccess, Visitor},
        ser::SerializeMap,
        Deserializer, Serializer,
    };

    pub fn serialize<S>(
        key: &HashMap<ProtocolAddress, IdentityKey>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Convert IdentityKey to bytes and serialize them
        let mut map = serializer.serialize_map(Some(key.len()))?;
        for (k, v) in key {
            let k = format!("{k}");
            map.serialize_key(&k)?;
            map.serialize_entry(&k, &v.serialize())?;
        }
        map.end()
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<HashMap<ProtocolAddress, IdentityKey>, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        struct MapVisitor;

        impl<'de> Visitor<'de> for MapVisitor {
            type Value = HashMap<ProtocolAddress, IdentityKey>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a map with string keys and byte array values")
            }

            fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut map = HashMap::new();

                // Process each key-value pair
                while let Some((key, value)) = access.next_entry::<String, Vec<u8>>()? {
                    map.insert(
                        parse_protocol_address(&key).map_err(|err| {
                            Error::custom(format!("Could not deserialize protocol_address: {err}"))
                        })?,
                        IdentityKey::decode(value.as_ref()).map_err(|err| {
                            Error::custom(format!("Could not decode IdentityKey: {err}"))
                        })?,
                    );
                }

                Ok(map)
            }
        }

        deserializer.deserialize_map(MapVisitor)
    }
}

pub(crate) mod pre_key_map_serde {
    use core::fmt;
    use std::{collections::HashMap, u32};

    use libsignal_protocol::{PreKeyId, PreKeyRecord};
    use serde::{
        self,
        de::{MapAccess, Visitor},
        ser::{Error, SerializeMap},
        Deserializer, Serializer,
    };

    pub fn serialize<S>(
        key: &HashMap<PreKeyId, PreKeyRecord>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Convert IdentityKey to bytes and serialize them
        let mut map = serializer.serialize_map(Some(key.len()))?;
        for (k, v) in key {
            let k = u32::from(k.to_owned());
            map.serialize_key(&k)?;
            map.serialize_entry(
                &k,
                &v.serialize()
                    .map_err(|err| Error::custom(format!("Could not serialize PreKeyRecord: {err}")))?,
            )?;
        }
        map.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<HashMap<PreKeyId, PreKeyRecord>, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        struct MapVisitor;

        impl<'de> Visitor<'de> for MapVisitor {
            type Value = HashMap<PreKeyId, PreKeyRecord>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a map with string keys and byte array values")
            }

            fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut map = HashMap::new();

                // Process each key-value pair
                while let Some((key, value)) = access.next_entry::<u32, Vec<u8>>()? {
                    map.insert(
                        key.into(),
                        PreKeyRecord::deserialize(value.as_ref()).map_err(|err| {
                            Error::custom(format!("Could not derserialize PreKeyRecord: {err}"))
                        })?,
                    );
                }

                Ok(map)
            }
        }

        deserializer.deserialize_map(MapVisitor)
    }
}

pub(crate) mod signed_pre_key_map_serde {
    use core::fmt;
    use std::{collections::HashMap, u32};

    use libsignal_protocol::{GenericSignedPreKey, SignedPreKeyId, SignedPreKeyRecord};
    use serde::{
        self,
        de::{MapAccess, Visitor},
        ser::{Error, SerializeMap},
        Deserializer, Serializer,
    };

    pub fn serialize<S>(
        key: &HashMap<SignedPreKeyId, SignedPreKeyRecord>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Convert IdentityKey to bytes and serialize them
        let mut map = serializer.serialize_map(Some(key.len()))?;
        for (k, v) in key {
            let k = u32::from(k.to_owned());
            map.serialize_key(&k)?;
            map.serialize_entry(
                &k,
                &v.serialize().map_err(|err| {
                    Error::custom(format!("Could not serialize SignedPreKeyRecord: {err}"))
                })?,
            )?;
        }
        map.end()
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<HashMap<SignedPreKeyId, SignedPreKeyRecord>, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        struct MapVisitor;

        impl<'de> Visitor<'de> for MapVisitor {
            type Value = HashMap<SignedPreKeyId, SignedPreKeyRecord>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a map with string keys and byte array values")
            }

            fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut map = HashMap::new();

                // Process each key-value pair
                while let Some((key, value)) = access.next_entry::<u32, Vec<u8>>()? {
                    map.insert(
                        key.into(),
                        SignedPreKeyRecord::deserialize(value.as_ref()).map_err(|err| {
                            Error::custom(format!(
                                "Could not derserialize SignedPreKeyRecord: {err}"
                            ))
                        })?,
                    );
                }

                Ok(map)
            }
        }

        deserializer.deserialize_map(MapVisitor)
    }
}

pub(crate) mod kyber_pre_key_map_serde {
    use core::fmt;
    use std::{collections::HashMap, u32};

    use libsignal_protocol::{GenericSignedPreKey, KyberPreKeyId, KyberPreKeyRecord};
    use serde::{
        self,
        de::{MapAccess, Visitor},
        ser::{Error, SerializeMap},
        Deserializer, Serializer,
    };

    pub fn serialize<S>(
        key: &HashMap<KyberPreKeyId, KyberPreKeyRecord>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Convert IdentityKey to bytes and serialize them
        let mut map = serializer.serialize_map(Some(key.len()))?;
        for (k, v) in key {
            let k = u32::from(k.to_owned());
            map.serialize_key(&k)?;
            map.serialize_entry(
                &k,
                &v.serialize().map_err(|err| {
                    Error::custom(format!("Could not serialize KyberPreKeyRecord: {err}"))
                })?,
            )?;
        }
        map.end()
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<HashMap<KyberPreKeyId, KyberPreKeyRecord>, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        struct MapVisitor;

        impl<'de> Visitor<'de> for MapVisitor {
            type Value = HashMap<KyberPreKeyId, KyberPreKeyRecord>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a map with string keys and byte array values")
            }

            fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut map = HashMap::new();

                // Process each key-value pair
                while let Some((key, value)) = access.next_entry::<u32, Vec<u8>>()? {
                    map.insert(
                        key.into(),
                        KyberPreKeyRecord::deserialize(value.as_ref()).map_err(|err| {
                            Error::custom("Could not derserialize KyberPreKeyRecord".to_string())
                        })?,
                    );
                }

                Ok(map)
            }
        }

        deserializer.deserialize_map(MapVisitor)
    }
}

pub(crate) mod session_map_serde {
    use core::fmt;
    use std::collections::HashMap;

    use common::protocol_address::parse_protocol_address;
    use libsignal_core::ProtocolAddress;
    use libsignal_protocol::SessionRecord;
    use serde::{
        self,
        de::{MapAccess, Visitor},
        ser::{Error, SerializeMap},
        Deserializer, Serializer,
    };

    pub fn serialize<S>(
        key: &HashMap<ProtocolAddress, SessionRecord>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Convert IdentityKey to bytes and serialize them
        let mut map = serializer.serialize_map(Some(key.len()))?;
        for (k, v) in key {
            let k = format!("{k}");
            map.serialize_key(&k)?;
            map.serialize_entry(
                &k,
                &v.serialize().map_err(|err| {
                    Error::custom(format!("Could not serialize SessionRecord: {err}"))
                })?,
            )?;
        }
        map.end()
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<HashMap<ProtocolAddress, SessionRecord>, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        struct MapVisitor;

        impl<'de> Visitor<'de> for MapVisitor {
            type Value = HashMap<ProtocolAddress, SessionRecord>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a map with string keys and byte array values")
            }

            fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut map = HashMap::new();

                // Process each key-value pair
                while let Some((key, value)) = access.next_entry::<String, Vec<u8>>()? {
                    map.insert(
                        parse_protocol_address(&key).map_err(|err| {
                            Error::custom(format!("Could not deserialize protocol_address: {err}"))
                        })?,
                        SessionRecord::deserialize(value.as_ref()).map_err(|err| {
                            Error::custom(format!("Could not deserialize SessionRecord: {err}"))
                        })?,
                    );
                }

                Ok(map)
            }
        }

        deserializer.deserialize_map(MapVisitor)
    }
}

pub(crate) mod sender_key_map_serde {
    use core::fmt;
    use std::{borrow::Cow, collections::HashMap};

    use common::protocol_address::parse_protocol_address;
    use libsignal_core::ProtocolAddress;
    use libsignal_protocol::SenderKeyRecord;
    use serde::{
        self,
        de::{MapAccess, Visitor},
        ser::{Error, SerializeMap},
        Deserializer, Serializer,
    };
    use uuid::Uuid;

    pub fn serialize<S>(
        key: &HashMap<(Cow<'static, ProtocolAddress>, Uuid), SenderKeyRecord>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Convert IdentityKey to bytes and serialize them
        let mut map = serializer.serialize_map(Some(key.len()))?;
        for ((s, uuid), v) in key {
            let k = format!("{}", Cow::Borrowed(s));
            map.serialize_key(&(&k, uuid))?;
            map.serialize_entry(
                &k,
                &v.serialize().map_err(|err| {
                    Error::custom(format!("Could not serialize SenderKeyRecord: {err}"))
                })?,
            )?;
        }
        map.end()
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<HashMap<(Cow<'static, ProtocolAddress>, Uuid), SenderKeyRecord>, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        struct MapVisitor;

        impl<'de> Visitor<'de> for MapVisitor {
            type Value = HashMap<(Cow<'static, ProtocolAddress>, Uuid), SenderKeyRecord>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a map with string keys and byte array values")
            }

            fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut map = HashMap::new();

                // Process each key-value pair
                while let Some(((s, uuid), value)) =
                    access.next_entry::<(String, Uuid), Vec<u8>>()?
                {
                    map.insert(
                        (
                            Cow::Owned(
                                parse_protocol_address(&s)
                                    .map_err(|err| Error::custom(format!("{err}")))?,
                            ),
                            uuid,
                        ),
                        SenderKeyRecord::deserialize(value.as_ref()).map_err(|err| {
                            Error::custom(format!("Could not decode SenderKeyRecord: {err}"))
                        })?,
                    );
                }

                Ok(map)
            }
        }

        deserializer.deserialize_map(MapVisitor)
    }
}
