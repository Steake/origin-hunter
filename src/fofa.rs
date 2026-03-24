/// FOFA API Integration
///
/// Queries FOFA for hosts matching `cert="<domain>"`.
/// Requires `FOFA_EMAIL` and `FOFA_KEY` environment variables.
///
/// FOFA API docs: https://en.fofa.info/api

use base64::{engine::general_purpose::STANDARD, Engine as _};
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashSet;
use std::time::Duration;

pub struct FofaScanner {
    client: Client,
    email: String,
    key: String,
}

#[derive(Deserialize, Debug)]
struct FofaResponse {
    error: Option<bool>,
    results: Option<Vec<Vec<String>>>,
}

impl FofaScanner {
    pub fn new(email: String, key: String) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("Mozilla/5.0 (compatible; WAF-Origin-Hunter)")
            .build()
            .unwrap();
        Self { client, email, key }
    }

    /// Search FOFA for `cert="<domain>"` and return IPs.
    pub async fn find_ips(&self, domain: &str) -> HashSet<String> {
        let mut ips = HashSet::new();

        // FOFA requires the query to be base64-encoded
        let query = format!("cert=\"{}\"", domain);
        let qbase64 = STANDARD.encode(query.as_bytes());

        let url = format!(
            "https://fofa.info/api/v1/search/all?email={}&key={}&qbase64={}&fields=ip&size=100&full=false",
            self.email, self.key, qbase64
        );

        match self.client.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => {
                if let Ok(data) = resp.json::<FofaResponse>().await {
                    if data.error == Some(true) {
                        return ips;
                    }
                    if let Some(results) = data.results {
                        for row in results {
                            if let Some(ip) = row.first() {
                                // Strip port if present (e.g. "1.2.3.4:443")
                                let ip_clean = ip.split(':').next().unwrap_or(ip);
                                ips.insert(ip_clean.to_string());
                            }
                        }
                    }
                }
            }
            _ => {}
        }

        ips
    }
}
