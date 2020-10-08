use super::Backend;
use crate::DnsRecord;
use async_trait::async_trait;
use std::collections::HashMap;

#[async_trait]
impl Backend for HashMap<String, String> {
    async fn get_record(&self, fqdn: String) -> anyhow::Result<Option<DnsRecord>> {
        if let Some(v) = self.get(&fqdn) {
            return Ok(Some(v.parse()?));
        }

        Ok(None)
    }
}
