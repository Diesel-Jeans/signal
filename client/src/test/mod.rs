use crate::server::Server;

struct MockServer {}

impl Server for MockServer {
    async fn connect(&mut self) -> anyhow::Result<()> {
        todo!()
    }

    async fn publish_bundle(
        &self,
        uuid: String, //registration_id: u32,
                      //bundle: &PreKeyBundle,
    ) -> anyhow::Result<surf::Response, Box<dyn std::error::Error>> {
        todo!()
    }

    async fn fetch_bundle(
        &self,
        uuid: String,
    ) -> anyhow::Result<surf::Response, Box<dyn std::error::Error>> {
        todo!()
    }

    async fn register_client(
        &self,
        phone_number: String,
        password: String,
        registration_request: common::web_api::RegistrationRequest,
        session: Option<&crate::client::VerifiedSession>,
    ) -> anyhow::Result<surf::Response, Box<dyn std::error::Error>> {
        todo!()
    }

    async fn register_device(
        &self,
        client_info: &crate::contact_manager::Contact,
    ) -> anyhow::Result<surf::Response, Box<dyn std::error::Error>> {
        todo!()
    }

    async fn send_msg(
        &self,
        msg: common::web_api::SignalMessages,
        user_id: libsignal_core::ServiceId,
    ) -> anyhow::Result<common::signalservice::WebSocketResponseMessage> {
        todo!()
    }

    async fn update_client(
        &self,
        new_client: &crate::contact_manager::Contact,
    ) -> anyhow::Result<surf::Response, Box<dyn std::error::Error>> {
        todo!()
    }

    async fn delete_client(
        &self,
        uuid: String,
    ) -> anyhow::Result<surf::Response, Box<dyn std::error::Error>> {
        todo!()
    }

    async fn delete_device(
        &self,
        uuid: String,
    ) -> anyhow::Result<surf::Response, Box<dyn std::error::Error>> {
        todo!()
    }
}
