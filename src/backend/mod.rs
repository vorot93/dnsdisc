use super::DnsRecord;
use async_trait::async_trait;
use std::sync::Arc;

pub mod memory;

#[cfg(feature = "trust-dns")]
pub mod trust_dns;

#[async_trait]
pub trait Backend: Send + Sync + 'static {
    async fn get_record(&self, fqdn: String) -> anyhow::Result<Option<DnsRecord>>;
}

#[async_trait]
impl Backend for Arc<dyn Backend> {
    async fn get_record(&self, fqdn: String) -> anyhow::Result<Option<DnsRecord>> {
        (**self).get_record(fqdn).await
    }
}
