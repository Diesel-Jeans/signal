use crate::errors::Result;
use crate::{
    contact_manager::ContactManager,
    encryption::{encrypt, pad_message, unpad_message},
    errors::{ProcessPreKeyBundleError, ReceiveMessageError},
    key_manager::KeyManager,
    server::{SignalServer, SignalServerAPI},
    storage::{
        generic::{ProtocolStore, Storage, StorageType},
        in_memory::InMemory,
    },
};
use base64::{prelude::BASE64_STANDARD, Engine as _};
use common::{
    signalservice::{envelope, Content, DataMessage},
    web_api::{
        AccountAttributes, DeviceCapabilities, RegistrationRequest, SignalMessage, SignalMessages,
    },
};
use core::str;
use libsignal_core::{Aci, Pni, ProtocolAddress, ServiceId};
use libsignal_protocol::{
    message_decrypt, process_prekey_bundle, CiphertextMessage, CiphertextMessageType,
    IdentityKeyPair, SignalProtocolError,
};
use prost::Message;
use rand::{rngs::OsRng, Rng};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct Client<ST: StorageType, SSA: SignalServerAPI> {
    pub aci: Aci,
    #[allow(unused)]
    pub pni: Pni,
    contact_manager: ContactManager,
    server_api: SSA,
    key_manager: KeyManager,
    pub storage: Storage<ST>,
}

const PROFILE_KEY_LENGTH: usize = 32;
const MASTER_KEY_LENGTH: usize = 32;
const PASSWORD_LENGTH: usize = 16;

impl<ST: StorageType, SSA: SignalServerAPI> Client<ST, SSA> {
    fn new(
        aci: Aci,
        pni: Pni,
        contact_manager: ContactManager,
        server_api: SSA,
        key_manager: KeyManager,
        storage: Storage<ST>,
    ) -> Self {
        Client {
            aci,
            pni,
            contact_manager,
            server_api,
            key_manager,
            storage,
        }
    }

    /// Register a new account with the server.
    /// `phone_number` must be unique.
    pub async fn register(
        name: &str,
        phone_number: String,
        server_url: &str,
        cert_path: &str,
    ) -> Result<Client<InMemory, SignalServer>> {
        let mut csprng = OsRng;
        let aci_registration_id = OsRng.gen_range(1..16383);
        let pni_registration_id = OsRng.gen_range(1..16383);
        let aci_id_key_pair = IdentityKeyPair::generate(&mut csprng);
        let pni_id_key_pair = IdentityKeyPair::generate(&mut csprng);

        let mut proto_storage = ProtocolStore::new(aci_id_key_pair, aci_registration_id);
        let mut key_manager = KeyManager::new();

        let aci_signed_pk = key_manager
            .generate_signed_pre_key(
                &mut proto_storage.identity_key_store,
                &mut proto_storage.signed_pre_key_store,
                &mut csprng,
            )
            .await?;

        let pni_signed_pk = key_manager
            .generate_signed_pre_key(
                &mut proto_storage.identity_key_store,
                &mut proto_storage.signed_pre_key_store,
                &mut csprng,
            )
            .await?;

        let aci_pq_last_resort = key_manager
            .generate_kyber_pre_key(
                &mut proto_storage.identity_key_store,
                &mut proto_storage.kyber_pre_key_store,
            )
            .await?;

        let pni_pq_last_resort = key_manager
            .generate_kyber_pre_key(
                &mut proto_storage.identity_key_store,
                &mut proto_storage.kyber_pre_key_store,
            )
            .await?;

        let mut password = [0u8; PASSWORD_LENGTH];
        csprng.fill(&mut password);
        let password = BASE64_STANDARD.encode(password);
        let password = password[0..password.len() - 2].to_owned();

        let mut profile_key = [0u8; PROFILE_KEY_LENGTH];
        csprng.fill(&mut profile_key);

        let access_key = [0u8; 16]; // This should be derived from profile_key

        let mut master_key = [0u8; MASTER_KEY_LENGTH];
        csprng.fill(&mut master_key);

        let capabilities = DeviceCapabilities::default();

        let account_attributes = AccountAttributes::new(
            name.into(),
            true,
            aci_registration_id,
            pni_registration_id,
            capabilities,
            Box::new(access_key),
        );
        let mut server_api = SignalServer::new(cert_path, server_url);

        let req = RegistrationRequest::new(
            "".into(),
            "".into(),
            account_attributes,
            true, // Require atomic is always true
            true, // Skip device transfer is always true
            aci_id_key_pair.identity_key().clone(),
            pni_id_key_pair.identity_key().clone(),
            aci_signed_pk.into(),
            pni_signed_pk.into(),
            aci_pq_last_resort.into(),
            pni_pq_last_resort.into(),
            None,
            None,
        );

        let response = server_api
            .register_client(phone_number, password.clone(), req, None)
            .await?;

        let aci: Aci = response.uuid.into();
        let pni: Pni = response.pni.into();

        server_api.create_auth_header(aci, password.clone(), 1.into());

        let contact_manager = ContactManager::new();
        let mut storage = Storage::new(password.clone(), aci, pni, proto_storage);
        let key_bundle = key_manager
            .generate_key_bundle(&mut storage.protocol_store)
            .await?;

        server_api.publish_pre_key_bundle(key_bundle).await?;

        server_api
            .connect(&aci.service_id_string(), &password, server_url, cert_path)
            .await?;

        Ok(Client::new(
            aci,
            pni,
            contact_manager,
            server_api,
            key_manager,
            storage,
        ))
    }

    pub async fn login() -> Result<Self> {
        todo!("Implement when Storage<Device> is done")
    }

    pub async fn send_message(&mut self, message: &str, service_id: &ServiceId) -> Result<()> {
        let content = Content::builder()
            .data_message(
                DataMessage::builder()
                    .body(message.to_owned())
                    .contact(vec![])
                    .body_ranges(vec![])
                    .preview(vec![])
                    .attachments(vec![])
                    .build(),
            )
            .build();

        let timestamp = SystemTime::now();

        // Update the contact.
        let to = match self.contact_manager.get_contact(service_id) {
            Err(_) => {
                self.contact_manager
                    .add_contact(service_id, 1.into())
                    .expect("Can add contact that does not exist yet");
                let bundles = self.server_api.fetch_pre_key_bundles(service_id).await?;

                let mut device_ids = Vec::new();
                let time = SystemTime::now();
                for ref bundle in bundles {
                    // Device id is safe to unwrap.
                    let device_id = bundle.device_id().unwrap();
                    device_ids.push(device_id);
                    process_prekey_bundle(
                        &ProtocolAddress::new(service_id.service_id_string(), device_id),
                        &mut self.storage.protocol_store.session_store,
                        &mut self.storage.protocol_store.identity_key_store,
                        bundle,
                        time,
                        &mut OsRng,
                    )
                    .await
                    .map_err(|err| ProcessPreKeyBundleError(err))?;
                }

                self.contact_manager
                    .get_contact(service_id)
                    .expect("Can get contact that was just added.")
            }
            Ok(contact) => contact,
        };

        let msgs = encrypt(
            &mut self.storage.protocol_store.identity_key_store,
            &mut self.storage.protocol_store.session_store,
            to,
            pad_message(content.encode_to_vec().as_ref()).as_ref(),
            timestamp,
        )
        .await?;

        // Put messages into structure ready.
        let msgs = SignalMessages {
            messages: msgs
                .into_iter()
                .map(|(id, msg)| SignalMessage {
                    r#type: match msg.1 {
                        CiphertextMessage::SignalMessage(_) => envelope::Type::Ciphertext.into(),
                        CiphertextMessage::SenderKeyMessage(_) => {
                            envelope::Type::KeyExchange.into()
                        }
                        CiphertextMessage::PreKeySignalMessage(_) => {
                            envelope::Type::PrekeyBundle.into()
                        }
                        CiphertextMessage::PlaintextContent(_) => {
                            envelope::Type::PlaintextContent.into()
                        }
                    },
                    destination_device_id: id.into(),
                    destination_registration_id: msg.0,
                    content: BASE64_STANDARD.encode(msg.1.serialize()),
                })
                .collect(),
            online: false,
            urgent: true,
            timestamp: timestamp
                .duration_since(UNIX_EPOCH)
                .expect("can get the time since epoch")
                .as_secs(),
        };

        self.server_api.send_msg(msgs, service_id).await
    }

    pub async fn receive_message(&mut self) -> Result<String> {
        // I get Envelope from Server.
        let envelope = self
            .server_api
            .get_message()
            .await
            .ok_or(ReceiveMessageError::NoMessageReceived)?;

        // Envelope contains a ciphertext message; a so called `encrypted [Content]`
        let ciphertext_content = envelope.content();

        // The content of the envelope is base64 encoded.
        let bytes = ciphertext_content.to_vec();

        // The envelope contains information about which message type is received.
        let _type = match envelope.r#type() {
            envelope::Type::Ciphertext => Ok(CiphertextMessageType::Whisper),
            envelope::Type::PrekeyBundle => Ok(CiphertextMessageType::PreKey),
            envelope::Type::PlaintextContent => Ok(CiphertextMessageType::Plaintext),
            _ => Err(ReceiveMessageError::InvalidMessageTypeInEnvelope),
        }?;

        // Use the information from envelope to construct a CiphertextMessage.
        let ciphertext =
            decode_ciphertext(bytes, _type).map_err(ReceiveMessageError::CiphertextDecodeError)?;

        let address = ProtocolAddress::new(
            envelope.source_service_id().to_string(),
            envelope.source_device().into(),
        );

        let mut csprng = OsRng;
        let store = &mut self.storage.protocol_store;

        // Decrypt the message.
        let plaintext = message_decrypt(
            &ciphertext,
            &address,
            &mut store.session_store,
            &mut store.identity_key_store,
            &mut store.pre_key_store,
            &mut store.signed_pre_key_store,
            &mut store.kyber_pre_key_store,
            &mut csprng,
        )
        .await
        .map_err(ReceiveMessageError::DecryptMessageError)?;

        // The final message is stored within a DataMessage inside a Content.
        Ok(
            Content::decode(unpad_message(plaintext.as_ref()).unwrap().as_ref())
                .map_err(ReceiveMessageError::ProtobufDecodeContentError)?
                .data_message
                .ok_or_else(|| ReceiveMessageError::InvalidMessageContent)?
                .body()
                .to_owned(),
        )
    }
}

fn decode_ciphertext(
    bytes: Vec<u8>,
    _type: CiphertextMessageType,
) -> std::result::Result<CiphertextMessage, SignalProtocolError> {
    match _type {
        CiphertextMessageType::Whisper => {
            Ok(CiphertextMessage::SignalMessage((&*bytes).try_into()?))
        }
        CiphertextMessageType::PreKey => Ok(CiphertextMessage::PreKeySignalMessage(
            (&*bytes).try_into()?,
        )),
        CiphertextMessageType::SenderKey => {
            Ok(CiphertextMessage::SenderKeyMessage((&*bytes).try_into()?))
        }
        CiphertextMessageType::Plaintext => {
            Ok(CiphertextMessage::PlaintextContent((&*bytes).try_into()?))
        }
    }
}
