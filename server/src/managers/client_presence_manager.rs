use crate::message_cache::WebsocketConnection;
use anyhow::Result;
use deadpool_redis::{Config, Runtime};
use libsignal_core::DeviceId;
use redis::cmd;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

const PRESENCE_EXPIRATION_SECONDS: u16 = 660;

/**
 * A displaced presence listener is notified when a specific client's presence has been displaced because the same
 * client opened a newer connection to the Signal service.
 */
trait DisplacedPresenceListener {
    fn handle_displacement(&self);
}

impl DisplacedPresenceListener for WebsocketConnection {
    fn handle_displacement(&self) {
        todo!()
    }
}

#[derive(Clone, Debug)]
struct ClientPresenceManager {
    displacement_listeners: HashMap<String, Arc<Mutex<WebsocketConnection>>>,
    pool: deadpool_redis::Pool,
    manager_id: String,
}

impl ClientPresenceManager {
    fn connect() -> Result<ClientPresenceManager> {
        let _ = dotenv::dotenv();
        let redis_url = std::env::var("REDIS_URL").expect("Unable to read REDIS_URL .env var");
        let mut redis_config = Config::from_url(redis_url);
        let redis_pool: deadpool_redis::Pool = redis_config.create_pool(Some(Runtime::Tokio1))?;

        Ok(ClientPresenceManager {
            displacement_listeners: HashMap::new(),
            pool: redis_pool,
            manager_id: Uuid::new_v4().to_string(),
        })
    }

    async fn set_present(
        &mut self,
        account_uuid: &str,
        device_id: DeviceId,
        displacement_listener: Arc<Mutex<WebsocketConnection>>,
    ) -> Result<()> {
        let presence_key = ClientPresenceManager::get_presence_key(account_uuid, device_id.into());

        if self.displacement_listeners.contains_key(&presence_key) {
            self.displace_presence(&presence_key, true);
        }

        self.displacement_listeners
            .insert(presence_key.clone(), displacement_listener);

        let mut connection = self.pool.get().await?;
        let set_key = ClientPresenceManager::get_set_key(self.manager_id.as_str());

        cmd("SADD")
            .arg(&set_key)
            .arg(&presence_key)
            .query_async::<()>(&mut connection)
            .await?;

        cmd("SET")
            .arg(&presence_key)
            .arg(&self.manager_id)
            .arg("EX")
            .arg(PRESENCE_EXPIRATION_SECONDS)
            .query_async::<()>(&mut connection)
            .await?;

        Ok(())
    }

    async fn renew_presence(&self, account_uuid: &str, device_id: DeviceId) -> Result<()> {
        let presence_key = ClientPresenceManager::get_presence_key(account_uuid, device_id.into());
        let mut connection = self.pool.get().await?;

        // If there is no presence key connected to the manager, we cannot renew it.
        if cmd("GET")
            .arg(&presence_key)
            .query_async::<String>(&mut connection)
            .await?
            == self.manager_id
        {
            cmd("EXPIRE")
                .arg(&presence_key)
                .arg(PRESENCE_EXPIRATION_SECONDS)
                .query_async::<()>(&mut connection)
                .await?;
        }
        Ok(())
    }

    async fn clear_presence(&mut self, presence_key: &str) -> Result<bool> {
        self.displacement_listeners.remove(presence_key);

        let removed: bool;
        let mut connection = self.pool.get().await?;

        if let Some(key) = cmd("GET")
            .arg(presence_key)
            .query_async::<Option<String>>(&mut connection)
            .await?
        {
            cmd("DEL")
                .arg(presence_key)
                .query_async::<String>(&mut connection)
                .await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn disconnect_all_presence(
        &mut self,
        account_uuid: &str,
        device_ids: Vec<DeviceId>,
    ) -> Result<u8> {
        let mut connection = self.pool.get().await?;
        let mut presence_keys: Vec<String> = Vec::new();

        for device_id in device_ids {
            let presence_key =
                ClientPresenceManager::get_presence_key(account_uuid, device_id.into());
            if (self.is_locally_present(&presence_key)) {
                self.displace_presence(&presence_key, false);
            }
            presence_keys.push(presence_key.to_string());
        }

        let deleted_keys = cmd("DEL")
            .arg(&presence_keys)
            .query_async::<u8>(&mut connection)
            .await?;
        Ok(deleted_keys)
    }

    fn is_locally_present(&self, presence_key: &str) -> bool {
        self.displacement_listeners.contains_key(presence_key)
    }

    async fn disconnect_presence(&mut self, account_uuid: &str, device_id: DeviceId) -> Result<u8> {
        self.disconnect_all_presence(account_uuid, vec![device_id])
            .await
    }

    async fn displace_presence(
        &mut self,
        presence_key: &str,
        connected_elsewhere: bool,
    ) -> Result<bool> {
        if let Some(displacement_listener) = self.displacement_listeners.get(presence_key) {
            displacement_listener.lock().await.handle_displacement();
        }

        self.clear_presence(presence_key).await
    }

    async fn is_present(&mut self, account_id: &str, device_id: DeviceId) -> Result<bool> {
        let mut connection = self.pool.get().await?;
        let is_present = cmd("EXISTS")
            .arg(ClientPresenceManager::get_presence_key(
                account_id,
                device_id.into(),
            ))
            .query_async::<bool>(&mut connection)
            .await?;
        Ok(is_present)
    }

    fn get_presence_key(account_uuid: &str, device_id: u32) -> String {
        format!("presence::{{{}::{}}}", account_uuid, device_id)
    }

    fn get_set_key(manager_id: &str) -> String {
        format!("presence::clients::{}", manager_id)
    }
}

#[cfg(test)]
mod client_presence_manager_test {
    use super::*;
    use crate::message_cache::message_cache_tests::{generate_uuid, teardown};
    use serial_test::serial;

    #[tokio::test]
    #[serial]
    async fn test_set_present() {
        let mut manager: ClientPresenceManager = ClientPresenceManager::connect().unwrap();
        let mut connection = manager.pool.get().await.unwrap();
        let websocket = Arc::new(Mutex::new(WebsocketConnection));
        let account_id = generate_uuid();
        let device_id = DeviceId::from(2);

        manager.set_present(account_id.as_str(), device_id, websocket);

        let presence_keys = cmd("SMEMBERS")
            .arg(ClientPresenceManager::get_set_key(account_id.as_str()))
            .query_async::<Vec<String>>(&mut connection)
            .await
            .unwrap();

        for presence_key in presence_keys {
            assert_eq!(
                presence_key,
                ClientPresenceManager::get_presence_key(account_id.as_str(), device_id.into())
            );
        }

        teardown(connection);
    }

    #[tokio::test]
    #[serial]
    async fn test_disconnect_all_presence() {
        let mut manager: ClientPresenceManager = ClientPresenceManager::connect().unwrap();
        let mut connection = manager.pool.get().await.unwrap();

        let websocket = Arc::new(Mutex::new(WebsocketConnection));
        let account_id = Uuid::new_v4().to_string();
        let device_id = DeviceId::from(1);

        manager
            .set_present(account_id.as_str(), device_id, websocket)
            .await;

        let removed = manager
            .disconnect_all_presence(account_id.as_str(), vec![device_id])
            .await
            .unwrap();

        assert_eq!(removed, 1);
        teardown(connection);
    }

    #[tokio::test]
    #[serial]
    async fn test_is_present() {
        let mut manager: ClientPresenceManager = ClientPresenceManager::connect().unwrap();
        let mut connection = manager.pool.get().await.unwrap();
        let websocket = Arc::new(Mutex::new(WebsocketConnection));
        let account_id = Uuid::new_v4().to_string();
        let device_id = DeviceId::from(1);

        manager
            .set_present(account_id.as_str(), device_id, websocket)
            .await;

        let is_present = manager
            .is_present(account_id.as_str(), device_id)
            .await
            .unwrap();

        assert!(is_present);
        teardown(connection);
    }
}
