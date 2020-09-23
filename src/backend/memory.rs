use super::Backend;
use crate::{DnsRecord, StdError};
use async_trait::async_trait;
use std::collections::HashMap;

#[async_trait]
impl Backend for HashMap<String, String> {
    async fn get_record(&self, fqdn: String) -> Result<Option<DnsRecord>, StdError> {
        if let Some(v) = self.get(&fqdn) {
            return Ok(Some(v.parse()?));
        }

        Ok(None)
    }
}
