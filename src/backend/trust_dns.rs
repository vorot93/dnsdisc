use super::Backend;
use crate::{DnsRecord, StdError};
use async_trait::async_trait;
use log::*;
use trust_dns_resolver::{
    error::ResolveErrorKind, proto::DnsHandle, AsyncResolver, ConnectionProvider,
};

#[async_trait]
impl<C, P> Backend for AsyncResolver<C, P>
where
    C: DnsHandle,
    P: ConnectionProvider<Conn = C>,
{
    async fn get_record(&self, fqdn: String) -> Result<Option<DnsRecord>, StdError> {
        trace!("Resolving FQDN {}", fqdn);
        let err = || StdError::from(format!("No records found for {}", fqdn));

        Ok(match self.txt_lookup(fqdn.clone()).await {
            Err(e) => {
                if let ResolveErrorKind::NoRecordsFound { .. } = e.kind() {
                    None
                } else {
                    return Err(e.into());
                }
            }
            Ok(v) => Some(
                String::from_utf8(
                    v.iter()
                        .next()
                        .ok_or_else(err)?
                        .iter()
                        .next()
                        .ok_or_else(err)?
                        .to_vec(),
                )?
                .parse()?,
            ),
        })
    }
}
