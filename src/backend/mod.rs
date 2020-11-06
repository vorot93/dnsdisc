use super::DnsRecord;
use async_trait::async_trait;
use auto_impl::auto_impl;
use enr::EnrKeyUnambiguous;

pub mod memory;

#[cfg(feature = "trust-dns")]
pub mod trust_dns;

#[async_trait]
#[auto_impl(&, Box, Arc)]
pub trait Backend: Send + Sync + 'static {
    async fn get_record<K: EnrKeyUnambiguous>(
        &self,
        fqdn: String,
    ) -> anyhow::Result<Option<DnsRecord<K>>>;
}
