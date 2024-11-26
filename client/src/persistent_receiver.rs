use tokio::sync::{broadcast, mpsc};

pub struct PersistentReceiver<T>(mpsc::UnboundedReceiver<T>);

impl <T: Clone + Send + 'static> PersistentReceiver<T>{
    pub fn new<F>(mut r: broadcast::Receiver<T>, filter: Option<F>) -> Self
    where F: Fn(&T) -> Option<T> + Send + Sync + 'static{
        let (tx, rx) = mpsc::unbounded_channel::<T>();
        tokio::spawn(async move {
            if let Some(f) = &filter {
                while let Ok(msg) = r.recv().await {
                    let _ = match f(&msg) {
                        Some(x) => tx.send(x),
                        None => continue
                    }.map_err(|e| println!("PersistentEnvelopeReceiver Error: {}", e));
                }
            } else {
                while let Ok(msg) = r.recv().await {
                    let _ = tx.send(msg).map_err(|e| println!("PersistentEnvelopeReceiver Error: {}", e));
                }
            }
            
        });
        Self (rx)
    }

    pub async fn recv(&mut self) -> Option<T> {
        self.0.recv().await
    }

    pub async fn is_empty(&mut self) -> bool {
        self.0.is_empty()
    }
}

#[cfg(test)]
mod test { 
    use std::time::Duration;

    use super::PersistentReceiver;
    use tokio::sync::broadcast;

    #[tokio::test]
    async fn test_filter_recv(){
        let (tx, rx) = broadcast::channel::<String>(5);
        let mut r = PersistentReceiver::new(rx, Some(|s: &String| {
            if s.starts_with("x"){
                None
            } else {
                Some(s.clone())
            }
        }));
        tx.send("hello".to_string()).unwrap();
        assert!(r.recv().await.unwrap() == "hello");
        tx.send("xhello".to_string()).unwrap();
        let x = tokio::time::timeout(Duration::from_millis(100), r.recv()).await;
        assert!(x.is_err())
    }

    #[tokio::test]
    async fn test_recv(){
        let (tx, rx) = broadcast::channel::<String>(5);
        let mut r = PersistentReceiver::<String>::new::<fn(&String) -> Option<String>>(rx, None);
        tx.send("hello".to_string()).unwrap();
        assert!(r.recv().await.unwrap() == "hello");
        tx.send("xhello".to_string()).unwrap();
        assert!(r.recv().await.unwrap() == "xhello");
        
    }

}