use super::StateStore;
use serde::{de::DeserializeOwned, Serialize};
use std::collections::HashMap;

#[derive(Default)]
pub struct MemoryStore {
    m: HashMap<String, Vec<u8>>,
}

impl MemoryStore {
    #[must_use]
    pub fn new() -> Self {
        Self { m: HashMap::new() }
    }
}

impl StateStore for MemoryStore {
    fn save<T: Serialize>(&mut self, name: &str, value: &T) -> anyhow::Result<()> {
        let b = bincode::serialize(value)?;
        self.m.insert(name.to_string(), b);
        Ok(())
    }
    fn load<T: DeserializeOwned>(&mut self, name: &str) -> anyhow::Result<Option<T>> {
        if let Some(b) = self.m.get(name) {
            Ok(Some(bincode::deserialize::<T>(b)?))
        } else {
            Ok(None)
        }
    }
    fn remove(&mut self, name: &str) -> anyhow::Result<()> {
        self.m.remove(name);
        Ok(())
    }
}
