use async_trait::async_trait;
use dashmap::DashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[async_trait]
#[allow(dead_code)]
pub trait SessionStore: Send + Sync {
    async fn get(&self, id: &str) -> Result<Option<Vec<u8>>, String>;
    async fn put(&self, id: &str, payload: Vec<u8>, ttl: Duration) -> Result<(), String>;
    async fn delete(&self, id: &str) -> Result<(), String>;
}

#[allow(dead_code)]
pub struct InMemorySessionStore {
    entries: DashMap<String, (Vec<u8>, Instant)>,
}

impl InMemorySessionStore {
    #[allow(dead_code)]
    pub fn new(shard_amount: usize) -> Arc<Self> {
        Arc::new(Self {
            entries: DashMap::with_shard_amount(shard_amount),
        })
    }
}

#[async_trait]
impl SessionStore for InMemorySessionStore {
    async fn get(&self, id: &str) -> Result<Option<Vec<u8>>, String> {
        let now = Instant::now();
        let expired = match self.entries.get(id) {
            Some(entry) if entry.value().1 > now => return Ok(Some(entry.value().0.clone())),
            Some(_) => true,
            None => false,
        };
        if expired {
            self.entries.remove(id);
        }
        Ok(None)
    }

    async fn put(&self, id: &str, payload: Vec<u8>, ttl: Duration) -> Result<(), String> {
        self.entries
            .insert(id.to_string(), (payload, Instant::now() + ttl));
        Ok(())
    }

    async fn delete(&self, id: &str) -> Result<(), String> {
        self.entries.remove(id);
        Ok(())
    }
}

#[allow(dead_code)]
pub struct RedisSessionStore {
    _url: String,
}

impl RedisSessionStore {
    #[allow(dead_code)]
    pub fn new(url: String) -> Arc<Self> {
        Arc::new(Self { _url: url })
    }
}

#[async_trait]
impl SessionStore for RedisSessionStore {
    async fn get(&self, _id: &str) -> Result<Option<Vec<u8>>, String> {
        Err("redis session store is not connected".to_string())
    }

    async fn put(&self, _id: &str, _payload: Vec<u8>, _ttl: Duration) -> Result<(), String> {
        Err("redis session store is not connected".to_string())
    }

    async fn delete(&self, _id: &str) -> Result<(), String> {
        Err("redis session store is not connected".to_string())
    }
}
