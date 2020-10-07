use arrayvec::ArrayString;
use async_stream::{stream, try_stream};
use data_encoding::*;
use derive_more::{Deref, Display};
use k256::{
    ecdsa::{recoverable::Signature, signature::Signature as _, SigningKey, VerifyKey},
    EncodedPoint,
};
use maplit::hashset;
use std::{
    collections::{HashMap, HashSet},
    fmt,
    fmt::{Display, Formatter},
    pin::Pin,
    str::FromStr,
    sync::Arc,
};
use task_group::TaskGroup;
use tokio::stream::{Stream, StreamExt};
use tracing::*;

mod backend;
pub use crate::backend::Backend;

pub type StdError = Box<dyn std::error::Error + Send + Sync>;
pub type StdResult<T> = Result<T, StdError>;

pub type Enr = enr::Enr<SigningKey>;
type Base32Hash = ArrayString<[u8; BASE32_HASH_LEN]>;

pub type QueryStream = Pin<Box<dyn Stream<Item = StdResult<Enr>> + Send + 'static>>;

pub const BASE32_HASH_LEN: usize = 26;
pub const ROOT_PREFIX: &str = "enrtree-root:v1";
pub const LINK_PREFIX: &str = "enrtree://";
pub const BRANCH_PREFIX: &str = "enrtree-branch:";
pub const ENR_PREFIX: &str = "enr:";

#[derive(Clone, Debug, Deref)]
pub struct RootRecord {
    #[deref]
    base: UnsignedRoot,
    signature: Signature,
}

#[derive(Clone, Debug, Display)]
#[display(
    fmt = "{} e={} l={} seq={}",
    ROOT_PREFIX,
    enr_root,
    link_root,
    sequence
)]
pub struct UnsignedRoot {
    enr_root: Base32Hash,
    link_root: Base32Hash,
    sequence: usize,
}

impl RootRecord {
    fn verify(&self, pk: &VerifyKey) -> Result<bool, StdError> {
        Ok(self
            .signature
            .recover_verify_key(self.to_string().as_bytes())?
            == *pk)
    }
}

impl Display for RootRecord {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} sig={}",
            self.base,
            BASE64.encode(self.signature.as_ref())
        )
    }
}

#[derive(Clone, Debug)]
pub enum DnsRecord {
    Root(RootRecord),
    Link {
        public_key: VerifyKey,
        domain: String,
    },
    Branch {
        children: HashSet<Base32Hash>,
    },
    Enr {
        record: Enr,
    },
}

impl Display for DnsRecord {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Root(root_record) => write!(f, "{}", root_record),
            Self::Link { public_key, domain } => write!(
                f,
                "{}{}@{}",
                LINK_PREFIX,
                BASE32_NOPAD.encode(&public_key.to_bytes()),
                domain
            ),
            Self::Branch { children } => write!(
                f,
                "{}{}",
                BRANCH_PREFIX,
                children
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            Self::Enr { record } => write!(f, "{}", record.to_base64()),
        }
    }
}

impl FromStr for DnsRecord {
    type Err = StdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        trace!("Parsing record {}", s);
        if let Some(root) = s.strip_prefix(ROOT_PREFIX) {
            let mut e = None;
            let mut l = None;
            let mut seq = None;
            let mut sig = None;
            for entry in root.trim().split_whitespace() {
                if let Some(v) = entry.strip_prefix("e=") {
                    trace!("Extracting ENR root: {:?}", v);
                    e = Some(v.parse()?);
                } else if let Some(v) = entry.strip_prefix("l=") {
                    trace!("Extracting link root: {:?}", v);
                    l = Some(v.parse()?);
                } else if let Some(v) = entry.strip_prefix("seq=") {
                    trace!("Extracting sequence: {:?}", v);
                    seq = Some(v.parse()?);
                } else if let Some(v) = entry.strip_prefix("sig=") {
                    trace!("Extracting signature: {:?}", v);
                    let v = BASE64URL_NOPAD.decode(v.as_bytes())?;
                    sig = Some(Signature::from_bytes(&v)?);
                } else {
                    return Err(format!("Invalid string: {}", entry).into());
                }
            }

            let v = RootRecord {
                base: UnsignedRoot {
                    enr_root: e.ok_or_else(|| StdError::from("ENR root absent"))?,
                    link_root: l.ok_or_else(|| StdError::from("Link root absent"))?,
                    sequence: seq.ok_or_else(|| StdError::from("Sequence not found"))?,
                },
                signature: sig.ok_or_else(|| StdError::from("Signature not found"))?,
            };

            trace!("Successfully parsed {:?}", v);

            return Ok(DnsRecord::Root(v));
        }

        if let Some(link) = s.strip_prefix(LINK_PREFIX) {
            let mut it = link.split('@');
            let public_key = VerifyKey::from_encoded_point(&EncodedPoint::from_bytes(
                &BASE32_NOPAD.decode(
                    &it.next()
                        .ok_or_else(|| StdError::from("Public key not found"))?
                        .as_bytes(),
                )?,
            )?)?;
            let domain = it
                .next()
                .ok_or_else(|| StdError::from("Domain not found"))?
                .to_string();

            return Ok(DnsRecord::Link { public_key, domain });
        }

        if let Some(branch) = s.strip_prefix(BRANCH_PREFIX) {
            let children = branch
                .trim()
                .split(',')
                .filter_map(|h| match h.parse::<Base32Hash>() {
                    Ok(v) => {
                        if v.is_empty() {
                            None
                        } else {
                            Some(Ok(v))
                        }
                    }
                    Err(e) => Some(Err(StdError::from(e))),
                })
                .collect::<Result<_, StdError>>()?;

            return Ok(DnsRecord::Branch { children });
        }

        if s.starts_with(ENR_PREFIX) {
            let record = s.parse::<Enr>()?;

            return Ok(DnsRecord::Enr { record });
        }

        Err(format!("Invalid string: {}", s).into())
    }
}

fn domain_is_allowed(
    whitelist: &Option<Arc<HashMap<String, VerifyKey>>>,
    domain: &str,
    public_key: &VerifyKey,
) -> bool {
    whitelist.as_ref().map_or(true, |whitelist| {
        whitelist.get(domain).map_or(false, |pk| *pk == *public_key)
    })
}

#[derive(Clone, Debug)]
enum BranchKind {
    Enr,
    Link {
        remote_whitelist: Option<Arc<HashMap<String, VerifyKey>>>,
    },
}

fn resolve_branch<B: Backend>(
    task_group: Arc<TaskGroup>,
    backend: Arc<B>,
    host: String,
    children: HashSet<Base32Hash>,
    kind: BranchKind,
) -> QueryStream {
    let (tx, mut branches_res) = tokio::sync::mpsc::channel(1);
    for subdomain in &children {
        let fqdn = format!("{}.{}", subdomain, host);
        task_group.spawn_with_name(
            {
                let subdomain = *subdomain;
                let mut tx = tx.clone();
                let backend = backend.clone();
                let host = host.clone();
                let kind = kind.clone();
                let fqdn = fqdn.clone();
                let task_group = task_group.clone();
                async move {
                    if let Err(e) = {
                        let mut tx = tx.clone();
                        async move {
                            let record = backend.get_record(fqdn).await?;
                            if let Some(record) = record {
                                trace!("Resolved record {}: {:?}", subdomain, record);
                                match record {
                                    DnsRecord::Branch { children } => {
                                        let mut t = resolve_branch(
                                            task_group, backend, host, children, kind,
                                        );
                                        while let Some(item) = t.try_next().await? {
                                            let _ = tx.send(Ok(item)).await;
                                        }

                                        return Ok(());
                                    }
                                    DnsRecord::Link { public_key, domain } => {
                                        if let BranchKind::Link { remote_whitelist } = &kind {
                                            if domain_is_allowed(
                                                &remote_whitelist,
                                                &domain,
                                                &public_key,
                                            ) {
                                                let mut t = resolve_tree(
                                                    Some(task_group),
                                                    backend,
                                                    domain,
                                                    Some(public_key),
                                                    None,
                                                    remote_whitelist.clone(),
                                                );
                                                while let Some(item) = t.try_next().await? {
                                                    let _ = tx.send(Ok(item)).await;
                                                }
                                            } else {
                                                trace!(
                                                    "Skipping subtree for forbidden domain: {}",
                                                    domain
                                                );
                                            }
                                            return Ok(());
                                        } else {
                                            return Err(StdError::from(format!(
                                                "Unexpected link record in ENR tree: {}",
                                                subdomain
                                            )));
                                        }
                                    }
                                    DnsRecord::Enr { record } => {
                                        if let BranchKind::Enr = &kind {
                                            let _ = tx.send(Ok(record)).await;

                                            return Ok(());
                                        } else {
                                            return Err(StdError::from(format!(
                                                "Unexpected ENR record in link tree: {}",
                                                subdomain
                                            )));
                                        }
                                    }
                                    DnsRecord::Root { .. } => {
                                        return Err(StdError::from(format!(
                                            "Unexpected root record: {}",
                                            subdomain
                                        )));
                                    }
                                }
                            } else {
                                warn!("Child {} is empty", subdomain);
                            }

                            Ok(())
                        }
                    }
                    .await
                    {
                        let _ = tx.send(Err(e)).await;
                    }
                }
            },
            format!("DNS discovery: {}", fqdn),
        );
    }

    Box::pin(stream! {
        trace!("Resolving branch {:?}", children);
        while let Some(v) = branches_res.next().await {
            yield v;
        }
        trace!("Branch {:?} resolution complete", children);
    })
}

fn resolve_tree<B: Backend>(
    task_group: Option<Arc<TaskGroup>>,
    backend: Arc<B>,
    host: String,
    public_key: Option<VerifyKey>,
    seen_sequence: Option<usize>,
    remote_whitelist: Option<Arc<HashMap<String, VerifyKey>>>,
) -> QueryStream {
    Box::pin(try_stream! {
        let task_group = task_group.unwrap_or_default();
        let record = backend.get_record(host.clone()).await?;
        if let Some(record) = &record {
            if let DnsRecord::Root(record) = &record {
                if let Some(pk) = public_key {
                    if !record.verify(&pk)? {
                        Err(StdError::from("Public key does not match"))?;
                    }
                }

                let UnsignedRoot { enr_root, link_root, sequence } = &record.base;

                if let Some(seen) = seen_sequence {
                    if *sequence <= seen {
                        // We have already seen this record.
                        return;
                    }
                }

                let mut s = resolve_branch(task_group.clone(), backend.clone(), host.clone(), hashset![ *link_root ], BranchKind::Link { remote_whitelist });
                while let Some(record) = s.try_next().await? {
                    yield record;
                }

                let mut s = resolve_branch(task_group.clone(),backend.clone(), host.clone(), hashset![ *enr_root ], BranchKind::Enr);
                while let Some(record) = s.try_next().await? {
                    yield record;
                }
            } else {
                Err(StdError::from(format!("Expected root, got {:?}", record)))?;
            }
            trace!("Resolution of tree at {} complete", host);
        } else {
            warn!("No records found for tree {}", host);
        }
    })
}

pub struct Resolver<B> {
    backend: Arc<B>,
    task_group: Option<Arc<TaskGroup>>,
    seen_sequence: Option<usize>,
    remote_whitelist: Option<Arc<HashMap<String, VerifyKey>>>,
}

impl<B> Resolver<B> {
    pub fn new(backend: Arc<B>) -> Self {
        Self {
            backend,
            task_group: None,
            seen_sequence: None,
            remote_whitelist: None,
        }
    }

    pub fn with_task_group(&mut self, task_group: Arc<TaskGroup>) -> &mut Self {
        self.task_group = Some(task_group);
        self
    }

    pub fn with_seen_sequence(&mut self, seen_sequence: usize) -> &mut Self {
        self.seen_sequence = Some(seen_sequence);
        self
    }

    pub fn with_remote_whitelist(
        &mut self,
        remote_whitelist: Arc<HashMap<String, VerifyKey>>,
    ) -> &mut Self {
        self.remote_whitelist = Some(remote_whitelist);
        self
    }
}

impl<B: Backend> Resolver<B> {
    pub fn query(&self, host: impl Display, public_key: Option<VerifyKey>) -> QueryStream {
        resolve_tree(
            self.task_group.clone(),
            self.backend.clone(),
            host.to_string(),
            public_key,
            self.seen_sequence,
            self.remote_whitelist.clone(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maplit::hashmap;
    use std::collections::{HashMap, HashSet};
    use tracing_subscriber::EnvFilter;

    #[tokio::test]
    async fn eip_example() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .try_init();

        const DOMAIN: &str = "mynodes.org";
        const TEST_RECORDS: &[(Option<&str>, &str)] = &[
            (
                None,
                "enrtree-root:v1 e=JWXYDBPXYWG6FX3GMDIBFA6CJ4 l=C7HRFPF3BLGF3YR4DY5KX3SMBE seq=1 sig=o908WmNp7LibOfPsr4btQwatZJ5URBr2ZAuxvK4UWHlsB9sUOTJQaGAlLPVAhM__XJesCHxLISo94z5Z2a463gA"
            ), (
                Some("C7HRFPF3BLGF3YR4DY5KX3SMBE"),
                "enrtree://AM5FCQLWIZX2QFPNJAP7VUERCCRNGRHWZG3YYHIUV7BVDQ5FDPRT2@morenodes.example.org"
            ), (
                Some("JWXYDBPXYWG6FX3GMDIBFA6CJ4"),
                "enrtree-branch:2XS2367YHAXJFGLZHVAWLQD4ZY,H4FHT4B454P6UXFD7JCYQ5PWDY,MHTDO6TMUBRIA2XWG5LUDACK24",
            ), (
                Some("2XS2367YHAXJFGLZHVAWLQD4ZY"),
                "enr:-HW4QOFzoVLaFJnNhbgMoDXPnOvcdVuj7pDpqRvh6BRDO68aVi5ZcjB3vzQRZH2IcLBGHzo8uUN3snqmgTiE56CH3AMBgmlkgnY0iXNlY3AyNTZrMaECC2_24YYkYHEgdzxlSNKQEnHhuNAbNlMlWJxrJxbAFvA"
            ), (
                Some("H4FHT4B454P6UXFD7JCYQ5PWDY"),
                "enr:-HW4QAggRauloj2SDLtIHN1XBkvhFZ1vtf1raYQp9TBW2RD5EEawDzbtSmlXUfnaHcvwOizhVYLtr7e6vw7NAf6mTuoCgmlkgnY0iXNlY3AyNTZrMaECjrXI8TLNXU0f8cthpAMxEshUyQlK-AM0PW2wfrnacNI"
            ), (
                Some("MHTDO6TMUBRIA2XWG5LUDACK24"),
                "enr:-HW4QLAYqmrwllBEnzWWs7I5Ev2IAs7x_dZlbYdRdMUx5EyKHDXp7AV5CkuPGUPdvbv1_Ms1CPfhcGCvSElSosZmyoqAgmlkgnY0iXNlY3AyNTZrMaECriawHKWdDRk2xeZkrOXBQ0dfMFLHY4eENZwdufn1S1o"
            )
        ];

        let data = TEST_RECORDS
            .iter()
            .map(|(sub, entry)| {
                (
                    format!(
                        "{}{}",
                        sub.map(|s| format!("{}.", s)).unwrap_or_default(),
                        DOMAIN.to_string()
                    ),
                    entry.to_string(),
                )
            })
            .collect::<HashMap<_, _>>();

        let mut s = Resolver::new(Arc::new(data))
            .with_remote_whitelist(Arc::new(hashmap!{
                "morenodes.example.org".to_string() => VerifyKey::from_encoded_point(&EncodedPoint::from_bytes(&hex::decode("049f88229042fef9200246f49f94d9b77c4e954721442714e85850cb6d9e5daf2d880ea0e53cb3ac1a75f9923c2726a4f941f7d326781baa6380754a360de5c2b6").unwrap()).unwrap()).unwrap()
            }))
            .query(DOMAIN.to_string(), None);
        let mut out = HashSet::new();
        while let Some(record) = s.try_next().await.unwrap() {
            assert!(out.insert(record.to_base64()));
        }
        assert_eq!(
            out,
            hashset![
                "enr:-HW4QOFzoVLaFJnNhbgMoDXPnOvcdVuj7pDpqRvh6BRDO68aVi5ZcjB3vzQRZH2IcLBGHzo8uUN3snqmgTiE56CH3AMBgmlkgnY0iXNlY3AyNTZrMaECC2_24YYkYHEgdzxlSNKQEnHhuNAbNlMlWJxrJxbAFvA",
                "enr:-HW4QAggRauloj2SDLtIHN1XBkvhFZ1vtf1raYQp9TBW2RD5EEawDzbtSmlXUfnaHcvwOizhVYLtr7e6vw7NAf6mTuoCgmlkgnY0iXNlY3AyNTZrMaECjrXI8TLNXU0f8cthpAMxEshUyQlK-AM0PW2wfrnacNI",
                "enr:-HW4QLAYqmrwllBEnzWWs7I5Ev2IAs7x_dZlbYdRdMUx5EyKHDXp7AV5CkuPGUPdvbv1_Ms1CPfhcGCvSElSosZmyoqAgmlkgnY0iXNlY3AyNTZrMaECriawHKWdDRk2xeZkrOXBQ0dfMFLHY4eENZwdufn1S1o",
            ].into_iter().map(ToString::to_string).collect()
        );
    }
}
