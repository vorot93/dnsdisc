use std::sync::Arc;
use tokio::stream::StreamExt;
use tracing::*;
use tracing_subscriber::EnvFilter;
use trust_dns_resolver::{config::*, TokioAsyncResolver};

const DNS_ROOT: &str = "all.mainnet.ethdisco.net";

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("query=info".parse().unwrap()))
        .init();

    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default())
        .await
        .unwrap();

    let mut st = dnsdisc::Resolver::new(Arc::new(resolver)).query(DNS_ROOT, None);
    let mut total = 0;
    while let Some(record) = st.try_next().await.unwrap() {
        info!("Got record: {}", record);
        total += 1;
    }
    info!("Resolved {} records", total);
}
