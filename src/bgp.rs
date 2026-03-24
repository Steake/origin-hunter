/// BGP Prefix Enumeration
///
/// Resolves the domain's current A record → looks up its ASN via BGPView →
/// fetches all IPv4 prefixes announced by that ASN.
///
/// This reveals the full IP range of the organisation hosting the origin,
/// which can then be fed into the verifier to find the exact backend.
///
/// Uses BGPView public API (no auth required):
///   https://bgpview.docs.apiary.io/

use reqwest::Client;
use serde::Deserialize;
use std::collections::HashSet;
use std::time::Duration;
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};

pub struct BgpScanner {
    client: Client,
}

// ── BGPView /ip/<ip> response ────────────────────────────────────────────────

#[derive(Deserialize, Debug)]
struct IpResponse {
    status: String,
    data: Option<IpData>,
}

#[derive(Deserialize, Debug)]
struct IpData {
    prefixes: Vec<IpPrefix>,
}

#[derive(Deserialize, Debug)]
struct IpPrefix {
    asn: Option<AsnInfo>,
}

#[derive(Deserialize, Debug)]
struct AsnInfo {
    asn: u32,
}

// ── BGPView /asn/<asn>/prefixes response ─────────────────────────────────────

#[derive(Deserialize, Debug)]
struct AsnPrefixResponse {
    status: String,
    data: Option<AsnPrefixData>,
}

#[derive(Deserialize, Debug)]
struct AsnPrefixData {
    ipv4_prefixes: Vec<PrefixEntry>,
}

#[derive(Deserialize, Debug)]
struct PrefixEntry {
    prefix: String,
    #[serde(rename = "ip")]
    _ip: Option<String>,
    #[serde(rename = "cidr")]
    _cidr: Option<u32>,
}

impl BgpScanner {
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(20))
            .user_agent("WAF-Origin-Hunter/2.0")
            .build()
            .unwrap();
        Self { client }
    }

    /// Resolve `domain` → IP → ASN → all IPv4 CIDR prefixes for that ASN.
    /// Returns the set of CIDR strings (not individual IPs — too many to enumerate).
    /// The caller is expected to pass these to the verifier as probe targets.
    pub async fn find_asn_prefixes(&self, domain: &str) -> (Option<u32>, HashSet<String>) {
        let mut prefixes = HashSet::new();

        // 1. Resolve the domain to an IP
        let resolver = match TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default()) {
            r => r,
        };

        let ip = match resolver.ipv4_lookup(domain).await.ok().and_then(|l| l.iter().next().map(|a| a.to_string())) {
            Some(ip) => ip,
            None => return (None, prefixes),
        };

        // 2. Look up the ASN for that IP
        let asn = match self.asn_for_ip(&ip).await {
            Some(a) => a,
            None => return (None, prefixes),
        };

        // 3. Fetch all prefixes announced by that ASN
        prefixes = self.prefixes_for_asn(asn).await;

        (Some(asn), prefixes)
    }

    async fn asn_for_ip(&self, ip: &str) -> Option<u32> {
        let url = format!("https://api.bgpview.io/ip/{}", ip);
        let resp = self.client.get(&url).send().await.ok()?;
        if !resp.status().is_success() {
            return None;
        }
        let data: IpResponse = resp.json().await.ok()?;
        if data.status != "ok" {
            return None;
        }
        data.data?
            .prefixes
            .into_iter()
            .find_map(|p| p.asn.map(|a| a.asn))
    }

    async fn prefixes_for_asn(&self, asn: u32) -> HashSet<String> {
        let mut out = HashSet::new();
        let url = format!("https://api.bgpview.io/asn/{}/prefixes", asn);
        if let Ok(resp) = self.client.get(&url).send().await {
            if resp.status().is_success() {
                if let Ok(data) = resp.json::<AsnPrefixResponse>().await {
                    if data.status == "ok" {
                        if let Some(d) = data.data {
                            for p in d.ipv4_prefixes {
                                out.insert(p.prefix);
                            }
                        }
                    }
                }
            }
        }
        out
    }
}
