use anyhow::Result;
use serde::Deserialize;
use reqwest::Client;
use std::collections::HashSet;
use std::time::Duration;

pub struct SslScanner {
    client: Client,
    api_id: Option<String>,
    api_secret: Option<String>,
}

// ── Censys v2 response structs ────────────────────────────────────────────────

#[derive(Deserialize, Debug)]
struct CensysSearchResponse {
    result: Option<CensysResult>,
}

#[derive(Deserialize, Debug)]
struct CensysResult {
    hits: Vec<CensysHit>,
    links: Option<CensysLinks>,
}

#[derive(Deserialize, Debug)]
struct CensysHit {
    ip: String,
}

#[derive(Deserialize, Debug)]
struct CensysLinks {
    next: Option<String>,
}

#[derive(serde::Serialize)]
struct CensysSearchRequest<'a> {
    q: &'a str,
    per_page: u32,
    cursor: Option<String>,
}

impl SslScanner {
    pub fn new(api_id: Option<String>, api_secret: Option<String>) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("Mozilla/5.0 (compatible; WAF-Origin-Hunter)")
            .build()
            .unwrap();
        Self { client, api_id, api_secret }
    }

    /// Query Censys v2 hosts/search API for TLS certs containing `domain`.
    /// Paginates up to 3 pages (300 results) to avoid runaway queries.
    pub async fn find_by_censys(&self, domain: &str) -> Result<HashSet<String>> {
        let mut ips = HashSet::new();

        let id = match &self.api_id {
            Some(i) => i.clone(),
            None => return Ok(ips),
        };
        let secret = match &self.api_secret {
            Some(s) => s.clone(),
            None => return Ok(ips),
        };

        let url = "https://search.censys.io/api/v2/hosts/search";
        let query = format!("services.tls.certificates.leaf_data.names: {}", domain);

        let mut cursor: Option<String> = None;
        let max_pages = 3u32;

        for _ in 0..max_pages {
            let body = CensysSearchRequest {
                q: &query,
                per_page: 100,
                cursor: cursor.clone(),
            };

            let resp = self
                .client
                .post(url)
                .basic_auth(&id, Some(&secret))
                .json(&body)
                .send()
                .await?;

            if !resp.status().is_success() {
                break;
            }

            let data: CensysSearchResponse = resp.json().await?;

            if let Some(result) = data.result {
                for hit in &result.hits {
                    ips.insert(hit.ip.clone());
                }
                // Follow next-page cursor if present
                if let Some(links) = result.links {
                    cursor = links.next;
                    if cursor.is_none() {
                        break;
                    }
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        Ok(ips)
    }
}
