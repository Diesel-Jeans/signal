use crate::contact_manager::ContactManager;
use crate::encryption::encrypt;
use crate::server::{Server, ServerAPI};
use surf::http::mime::JSON;
use tokio_tungstenite::tungstenite::http::response;

pub struct Client {
    contact_manager: ContactManager,
    server_api: ServerAPI,
}

impl Client {
    pub fn new() -> Self {
        Client {
            contact_manager: ContactManager::new(),
            server_api: ServerAPI::new().unwrap(),
        }
    }
    pub async fn send_message(&self, message: &str) -> Result<(), Box<dyn std::error::Error>> {
        let res = self
            .server_api
            .send_msg(message.to_owned(), "bob".to_owned(), 0);
        println!("Sent message: {}", message);
        match res.await {
            Ok(response) => {
                println!("Got response: {:?}", response.status());
            }
            Err(error) => {
                println!("Got error: {:?}", error);
            }
        }
        Ok(())
    }
}
