use super::Backend;
use crate::DnsRecord;
use async_trait::async_trait;
use enr::EnrKeyUnambiguous;
use tokio_compat_02::FutureExt;
use tracing::*;
use trust_dns_resolver::{
    error::ResolveErrorKind, proto::DnsHandle, AsyncResolver, ConnectionProvider,
};

#[async_trait]
impl<C, P> Backend for AsyncResolver<C, P>
where
    C: DnsHandle,
    P: ConnectionProvider<Conn = C>,
{
    async fn get_record<K: EnrKeyUnambiguous>(
        &self,
        fqdn: String,
    ) -> anyhow::Result<Option<DnsRecord<K>>> {
        trace!("Resolving FQDN {}", fqdn);
        Ok(match self.txt_lookup(format!("{}.", fqdn)).compat().await {
            Err(e) => {
                if let ResolveErrorKind::NoRecordsFound { .. } = e.kind() {
                    None
                } else {
                    return Err(e.into());
                }
            }
            Ok(v) => {
                if let Some(txt) = v.into_iter().next() {
                    if let Some(txt_entry) = txt.iter().next() {
                        return Ok(Some(std::str::from_utf8(&*txt_entry)?.parse()?));
                    }
                }

                None
            }
        })
    }
}
