use arrayvec::ArrayString;
use async_stream::try_stream;
use async_trait::async_trait;
use data_encoding::*;
use derive_more::{Deref, Display};
use log::*;
use maplit::hashset;
use secp256k1::{Message, PublicKey, PublicKeyFormat, RecoveryId, SecretKey, Signature};
use sha3::{Digest, Keccak256};
use std::{
    collections::{BTreeSet, HashMap, HashSet},
    fmt,
    fmt::{Display, Formatter},
    pin::Pin,
    str::FromStr,
    sync::Arc,
};
use tokio::stream::{Stream, StreamExt};

pub type StdError = Box<dyn std::error::Error + Send + Sync>;
pub type Enr = enr::Enr<SecretKey>;
pub type Base32Hash = ArrayString<[u8; BASE32_HASH_LEN]>;

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
    recovery_id: RecoveryId,
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

impl UnsignedRoot {
    fn message(&self) -> Message {
        Message::parse_slice(&*Keccak256::digest(self.to_string().as_bytes())).unwrap()
    }
}

impl RootRecord {
    fn verify(&self, pk: &PublicKey) -> Result<bool, StdError> {
        Ok(secp256k1::recover(&self.base.message(), &self.signature, &self.recovery_id)? == *pk)
    }
}

impl Display for RootRecord {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut sig = [0_u8; 65];
        sig.copy_from_slice(&self.signature.serialize());
        sig[64] = self.recovery_id.serialize();
        write!(f, "{} sig={}", self.base, BASE64.encode(&sig))
    }
}

#[derive(Clone, Debug)]
pub enum DnsRecord {
    Root(RootRecord),
    Link {
        public_key: PublicKey,
        domain: String,
    },
    Branch {
        children: BTreeSet<Base32Hash>,
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
                BASE32_NOPAD.encode(&public_key.serialize_compressed()),
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
        if let Some(root) = s.strip_prefix(ROOT_PREFIX) {
            trace!("Parsing root entry {}", root);
            let mut e = None;
            let mut l = None;
            let mut seq = None;
            let mut sig = None;
            let mut rec = None;
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
                    sig =
                        Some(Signature::parse_slice(v.get(..64).ok_or_else(|| {
                            StdError::from("Signature body not found")
                        })?)?);
                    rec = Some(RecoveryId::parse(
                        *v.get(64)
                            .ok_or_else(|| StdError::from("Recovery ID not found"))?,
                    )?);
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
                recovery_id: rec.ok_or_else(|| StdError::from("Recovery ID not found"))?,
            };

            trace!("Successfully parsed {:?}", v);

            return Ok(DnsRecord::Root(v));
        }

        if let Some(link) = s.strip_prefix(LINK_PREFIX) {
            let mut it = link.split('@');
            let public_key = PublicKey::parse_slice(
                &BASE32_NOPAD.decode(
                    &it.next()
                        .ok_or_else(|| StdError::from("Public key not found"))?
                        .as_bytes(),
                )?,
                Some(PublicKeyFormat::Compressed),
            )?;
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
                .map(|h| h.parse::<Base32Hash>().map_err(StdError::from))
                .collect::<Result<BTreeSet<_>, StdError>>()?;

            return Ok(DnsRecord::Branch { children });
        }

        if s.starts_with(ENR_PREFIX) {
            let record = s.parse::<Enr>()?;

            return Ok(DnsRecord::Enr { record });
        }

        Err(format!("Invalid string: {}", s).into())
    }
}

#[async_trait]
pub trait Backend: Send + Sync {
    async fn get_record(&self, subdomain: String, host: String) -> Result<DnsRecord, StdError>;
}

#[async_trait]
impl Backend for Arc<dyn Backend> {
    async fn get_record(&self, subdomain: String, host: String) -> Result<DnsRecord, StdError> {
        (**self).get_record(subdomain, host).await
    }
}

pub fn domain_is_allowed(
    whitelist: &Option<HashMap<String, PublicKey>>,
    domain: &str,
    public_key: &PublicKey,
) -> bool {
    whitelist.as_ref().map_or(true, |whitelist| {
        whitelist.get(domain).map_or(false, |pk| *pk == *public_key)
    })
}

pub fn resolve_branch(
    backend: Arc<dyn Backend>,
    host: String,
    branch: HashSet<Base32Hash>,
    remote_whitelist: Option<HashMap<String, PublicKey>>,
) -> Pin<Box<dyn Stream<Item = Result<Enr, StdError>> + Send + 'static>> {
    Box::pin(try_stream! {
        trace!("Resolving branch {:?}", branch);
        for subdomain in branch {
            let record = backend.get_record(subdomain.to_string(), host.clone()).await?;
            trace!("Resolved record {}: {:?}", subdomain, record);
            match record {
                DnsRecord::Root { .. } => {
                    Err(StdError::from("Unexpected root"))?;
                }
                DnsRecord::Link {
                    public_key,
                    domain,
                } => {
                    if domain_is_allowed(&remote_whitelist, &domain, &public_key) {
                        let mut t = resolve_tree(backend.clone(), domain, Some(public_key), None, remote_whitelist.clone());
                        while let Some(item) = t.try_next().await? {
                            yield item;
                        }
                    }
                }
                DnsRecord::Branch {
                    children
                } => {
                    let mut t = resolve_branch(backend.clone(), host.clone(), children.into_iter().collect(), remote_whitelist.clone());
                    while let Some(item) = t.try_next().await? {
                        yield item;
                    }
                }
                DnsRecord::Enr {
                    record
                } => {
                    yield record;
                }
            }
        }
        trace!("Resolution complete");
    })
}

pub fn resolve_tree(
    backend: Arc<dyn Backend>,
    host: String,
    public_key: Option<PublicKey>,
    seen_sequence: Option<usize>,
    remote_whitelist: Option<HashMap<String, PublicKey>>,
) -> Pin<Box<dyn Stream<Item = Result<Enr, StdError>> + Send + 'static>> {
    Box::pin(try_stream! {
        let record = backend.get_record("@".into(), host.clone()).await?;
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

            let mut s = resolve_branch(backend.clone(), host.clone(), hashset![ *link_root ], remote_whitelist.clone());
            while let Some(record) = s.try_next().await? {
                yield record;
            }

            let mut s = resolve_branch(backend.clone(), host.clone(), hashset![ *enr_root ], remote_whitelist.clone());
            while let Some(record) = s.try_next().await? {
                yield record;
            }
        } else {
            Err(StdError::from(format!("Expected root, got {:?}", record)))?;
        }

        trace!("Tree resolution complete");
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use maplit::hashmap;
    use std::collections::{HashMap, HashSet};

    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    struct Addr {
        subdomain: String,
        domain: String,
    }

    #[async_trait]
    impl Backend for HashMap<Addr, String> {
        async fn get_record(
            &self,
            subdomain: String,
            domain: String,
        ) -> Result<DnsRecord, StdError> {
            Ok(self
                .get(&{
                    let domain = domain.clone();
                    let subdomain = subdomain.clone();
                    Addr { subdomain, domain }
                })
                .ok_or_else(|| StdError::from(format!("No record for {}.{}", subdomain, domain)))?
                .parse()?)
        }
    }

    #[tokio::test]
    async fn eip_example() {
        env_logger::init();

        const DOMAIN: &str = "mynodes.org";
        const TEST_RECORDS: &[(&str, &str)] = &[
            (
                "@",
                "enrtree-root:v1 e=JWXYDBPXYWG6FX3GMDIBFA6CJ4 l=C7HRFPF3BLGF3YR4DY5KX3SMBE seq=1 sig=o908WmNp7LibOfPsr4btQwatZJ5URBr2ZAuxvK4UWHlsB9sUOTJQaGAlLPVAhM__XJesCHxLISo94z5Z2a463gA"
            ), (
                "C7HRFPF3BLGF3YR4DY5KX3SMBE",
                "enrtree://AM5FCQLWIZX2QFPNJAP7VUERCCRNGRHWZG3YYHIUV7BVDQ5FDPRT2@morenodes.example.org"
            ), (
                "JWXYDBPXYWG6FX3GMDIBFA6CJ4",
                "enrtree-branch:2XS2367YHAXJFGLZHVAWLQD4ZY,H4FHT4B454P6UXFD7JCYQ5PWDY,MHTDO6TMUBRIA2XWG5LUDACK24",
            ), (
                "2XS2367YHAXJFGLZHVAWLQD4ZY",
                "enr:-HW4QOFzoVLaFJnNhbgMoDXPnOvcdVuj7pDpqRvh6BRDO68aVi5ZcjB3vzQRZH2IcLBGHzo8uUN3snqmgTiE56CH3AMBgmlkgnY0iXNlY3AyNTZrMaECC2_24YYkYHEgdzxlSNKQEnHhuNAbNlMlWJxrJxbAFvA"
            ), (
                "H4FHT4B454P6UXFD7JCYQ5PWDY",
                "enr:-HW4QAggRauloj2SDLtIHN1XBkvhFZ1vtf1raYQp9TBW2RD5EEawDzbtSmlXUfnaHcvwOizhVYLtr7e6vw7NAf6mTuoCgmlkgnY0iXNlY3AyNTZrMaECjrXI8TLNXU0f8cthpAMxEshUyQlK-AM0PW2wfrnacNI"
            ), (
                "MHTDO6TMUBRIA2XWG5LUDACK24",
                "enr:-HW4QLAYqmrwllBEnzWWs7I5Ev2IAs7x_dZlbYdRdMUx5EyKHDXp7AV5CkuPGUPdvbv1_Ms1CPfhcGCvSElSosZmyoqAgmlkgnY0iXNlY3AyNTZrMaECriawHKWdDRk2xeZkrOXBQ0dfMFLHY4eENZwdufn1S1o"
            )
        ];

        let data = TEST_RECORDS
            .iter()
            .map(|(sub, entry)| {
                (
                    Addr {
                        subdomain: sub.to_string(),
                        domain: DOMAIN.to_string(),
                    },
                    entry.to_string(),
                )
            })
            .collect::<HashMap<_, _>>();

        let mut s = resolve_tree(
            Arc::new(data),
            DOMAIN.to_string(),
            None,
            None,
            Some(hashmap! {}),
        );
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
