use std::sync::Arc;
use tokio::stream::StreamExt;
use trust_dns_resolver::{config::*, TokioAsyncResolver};

#[tokio::main]
async fn main() {
    env_logger::init();

    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default())
        .await
        .unwrap();

    let mut st = dnsdisc::Resolver::new(Arc::new(resolver))
        .query("all.mainnet.ethdisco.net".to_string(), None);
    let mut total = 0;
    while let Some(record) = st.try_next().await.unwrap() {
        println!("Got record: {}", record);
        total += 1;
    }
    println!("Resolved {} records", total);
}
