use super::Backend;
use crate::{DnsRecord, StdError};
use async_trait::async_trait;
use std::collections::HashMap;

#[async_trait]
impl Backend for HashMap<(String, String), String> {
    async fn get_record(&self, subdomain: String, domain: String) -> Result<DnsRecord, StdError> {
        Ok(self
            .get(&(subdomain.clone(), domain.clone()))
            .ok_or_else(|| StdError::from(format!("No record for {}.{}", subdomain, domain)))?
            .parse()?)
    }
}
