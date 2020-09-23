use super::{DnsRecord, StdError};
use async_trait::async_trait;
use std::sync::Arc;

pub mod memory;

#[cfg(feature = "trust-dns")]
pub mod trust_dns;

#[async_trait]
pub trait Backend: Send + Sync + 'static {
    async fn get_record(&self, subdomain: String, host: String) -> Result<DnsRecord, StdError>;
}

#[async_trait]
impl Backend for Arc<dyn Backend> {
    async fn get_record(&self, subdomain: String, host: String) -> Result<DnsRecord, StdError> {
        (**self).get_record(subdomain, host).await
    }
}
