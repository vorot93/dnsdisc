use super::Backend;
use async_trait::async_trait;
use std::collections::HashMap;

#[async_trait]
impl Backend for HashMap<String, String> {
    async fn get_record(&self, fqdn: String) -> anyhow::Result<Option<String>> {
        println!("resolving {}", fqdn);
        if let Some(v) = self.get(&fqdn) {
            println!("resolved {} to {}", fqdn, v);
            return Ok(Some(v.clone()));
        }

        Ok(None)
    }
}
