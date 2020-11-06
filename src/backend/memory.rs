use super::Backend;
use crate::DnsRecord;
use async_trait::async_trait;
use enr::EnrKeyUnambiguous;
use std::collections::HashMap;

#[async_trait]
impl Backend for HashMap<String, String> {
    async fn get_record<K: EnrKeyUnambiguous>(
        &self,
        fqdn: String,
    ) -> anyhow::Result<Option<DnsRecord<K>>> {
        if let Some(v) = self.get(&fqdn) {
            return Ok(Some(v.parse()?));
        }

        Ok(None)
    }
}
