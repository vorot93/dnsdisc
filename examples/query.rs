use k256::ecdsa::SigningKey;
use std::{sync::Arc, time::Instant};
use tokio::stream::StreamExt;
use tokio_compat_02::FutureExt;
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
        .compat()
        .await
        .unwrap();

    let mut st = dnsdisc::Resolver::<_, SigningKey>::new(Arc::new(resolver)).query(DNS_ROOT, None);
    let mut total = 0;
    let start = Instant::now();
    while let Some(record) = st.try_next().await.unwrap() {
        info!("Got record: {}", record);
        total += 1;
    }

    let dur = Instant::now() - start;
    info!(
        "Resolved {} records in {}.{} seconds",
        total,
        dur.as_secs(),
        dur.as_millis()
    );
}
