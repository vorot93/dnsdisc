use super::Backend;
use crate::{DnsRecord, StdError};
use async_trait::async_trait;
use trust_dns_resolver::{proto::DnsHandle, AsyncResolver, ConnectionProvider};

#[async_trait]
impl<C, P> Backend for AsyncResolver<C, P>
where
    C: DnsHandle,
    P: ConnectionProvider<Conn = C>,
{
    async fn get_record(&self, subdomain: String, host: String) -> Result<DnsRecord, StdError> {
        let fqdn = format!("{}.{}.", subdomain, host);
        let err = || StdError::from(format!("No records found for {}", fqdn));
        Ok(String::from_utf8(
            self.txt_lookup(fqdn.clone())
                .await?
                .iter()
                .next()
                .ok_or_else(err)?
                .iter()
                .next()
                .ok_or_else(err)?
                .to_vec(),
        )?
        .parse()?)
    }
}
