use k256::ecdsa::SigningKey;
use std::{sync::Arc, time::Instant};
use tokio_stream::StreamExt;
use tracing::*;
use tracing_subscriber::EnvFilter;
use trust_dns_resolver::{config::*, TokioAsyncResolver};

const DNS_ROOT: &str =
    "enrtree://AKA3AM6LPBYEUDMVNU3BSVQJ5AD45Y7YPOHJLEF6W26QOE4VTUDPE@all.mainnet.ethdisco.net";

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let resolver =
        TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default()).unwrap();

    let mut st = dnsdisc::Resolver::<_, SigningKey>::new(Arc::new(resolver)).query_tree(DNS_ROOT);
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
