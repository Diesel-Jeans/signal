use crate::contact_manager::ContactManager;
use crate::server::{Server, ServerAPI};

pub struct Client {
    contact_manager: ContactManager,
    server_api: ServerAPI,
}

impl Client {
    pub fn new() -> Self {
        Client {
            contact_manager: ContactManager::new(),
            server_api: ServerAPI::new(),
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
