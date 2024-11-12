use crate::account::{Account, Device};
use crate::database::SignalDatabase;
use anyhow::{anyhow, Result};
use axum::async_trait;
use axum::extract::ws::Message;
use axum::Error;
use common::pre_key::PreKeyType;
use common::signal_protobuf::Envelope;
use common::web_api::{DevicePreKeyBundle, UploadPreKey, UploadSignedPreKey};
use libsignal_core::{Aci, DeviceId, Pni, ProtocolAddress, ServiceId};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::Mutex;

use crate::managers::websocket::wsstream::WSStream;

#[cfg(test)]
#[derive(Clone)]
pub struct MockDB {}

#[cfg(test)]
#[async_trait]
impl SignalDatabase for MockDB {
    async fn store_signed_pre_key(
        &self,
        spk: &UploadSignedPreKey,
        address: &ProtocolAddress,
    ) -> Result<()> {
        todo!()
    }

    async fn store_pq_signed_pre_key(
        &self,
        pq_spk: &UploadSignedPreKey,
        address: &ProtocolAddress,
    ) -> Result<()> {
        todo!()
    }
    async fn add_device(&self, service_id: &ServiceId, device: &Device) -> Result<()> {
        todo!()
    }
    async fn get_all_devices(&self, service_id: &ServiceId) -> Result<Vec<Device>> {
        todo!()
    }
    async fn get_device(&self, service_id: &ServiceId, device_id: u32) -> Result<Device> {
        todo!()
    }
    async fn delete_device(&self, service_id: &ServiceId, device_id: u32) -> Result<()> {
        todo!()
    }

    async fn add_account(&self, account: &Account) -> Result<()> {
        todo!()
    }
    async fn get_account(&self, service_id: &ServiceId) -> Result<Account> {
        todo!()
    }
    async fn update_account_aci(&self, service_id: &ServiceId, new_aci: Aci) -> Result<()> {
        todo!()
    }
    async fn update_account_pni(&self, service_id: &ServiceId, new_pni: Pni) -> Result<()> {
        todo!()
    }

    async fn delete_account(&self, service_id: &ServiceId) -> Result<()> {
        todo!()
    }

    async fn push_message_queue(
        &self,
        address: &ProtocolAddress,
        messages: Vec<Envelope>,
    ) -> Result<()> {
        todo!()
    }
    async fn pop_msg_queue(&self, address: &ProtocolAddress) -> Result<Vec<Envelope>> {
        todo!()
    }
    async fn store_key_bundle(
        &self,
        data: &DevicePreKeyBundle,
        owner_address: &ProtocolAddress,
    ) -> Result<()> {
        todo!()
    }
    async fn get_key_bundle(&self, address: &ProtocolAddress) -> Result<DevicePreKeyBundle> {
        todo!()
    }

    async fn get_one_time_ec_pre_key_count(&self, service_id: &ServiceId) -> Result<u32> {
        todo!()
    }

    async fn get_one_time_pq_pre_key_count(&self, service_id: &ServiceId) -> Result<u32> {
        todo!()
    }

    async fn store_one_time_ec_pre_keys(
        &self,
        otpks: Vec<UploadPreKey>,
        owner_address: &ProtocolAddress,
    ) -> Result<()> {
        todo!()
    }

    async fn store_one_time_pq_pre_keys(
        &self,
        otpks: Vec<UploadSignedPreKey>,
        owner_address: &ProtocolAddress,
    ) -> Result<()> {
        todo!()
    }

    async fn get_one_time_ec_pre_key(
        &self,
        owner_address: &ProtocolAddress,
    ) -> Result<UploadPreKey> {
        todo!()
    }

    async fn get_one_time_pq_pre_key(
        &self,
        owner_address: &ProtocolAddress,
    ) -> Result<UploadSignedPreKey> {
        todo!()
    }

    async fn count_messages(&self, address: &ProtocolAddress) -> Result<u32> {
        todo!()
    }

    async fn get_messages(&self, address: &ProtocolAddress) -> Result<Vec<Envelope>> {
        todo!()
    }

    async fn delete_messages(&self, address: &ProtocolAddress) -> Result<Vec<Envelope>> {
        todo!()
    }
}

#[derive(Debug)]
pub struct MockSocket {
    client_sender: Receiver<Result<Message, Error>>,
    client_receiver: Sender<Message>,
}

impl MockSocket {
    pub fn new() -> (Self, Sender<Result<Message, Error>>, Receiver<Message>) {
        let (send_to_socket, client_sender) = channel(10); // Queue for test -> socket
        let (client_receiver, receive_from_socket) = channel(10); // Queue for socket -> test

        (
            Self {
                client_sender,
                client_receiver,
            },
            send_to_socket,
            receive_from_socket,
        )
    }
}

#[async_trait::async_trait]
impl WSStream for MockSocket {
    async fn recv(&mut self) -> Option<Result<Message, Error>> {
        self.client_sender.recv().await
    }

    async fn send(&mut self, msg: Message) -> Result<(), Error> {
        self.client_receiver
            .send(msg)
            .await
            .map_err(|_| Error::new("Send failed".to_string()))
    }

    async fn close(self) -> Result<(), Error> {
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::MockSocket;
    use super::WSStream;
    use axum::extract::ws::Message;
    #[tokio::test]
    async fn test_mock() {
        let (mut mock, mut sender, mut receiver) = MockSocket::new();

        tokio::spawn(async move {
            if let Some(Ok(Message::Text(x))) = mock.recv().await {
                mock.send(Message::Text(x)).await
            } else {
                panic!("Expected Text Message");
            }
        });

        sender.send(Ok(Message::Text("hello".to_string()))).await;

        match receiver.recv().await.unwrap() {
            Message::Text(x) => assert!(x == "hello", "Expected 'hello' in test_mock"),
            _ => panic!("Did not receive text message"),
        }
    }
}
