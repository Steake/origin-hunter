/// Shodan Search API Integration
///
/// Queries Shodan for hosts matching SSL/TLS certificate names.
/// Requires `SHODAN_API_KEY` environment variable (or --shodan-key flag).
///
/// Queries run:
///   - ssl:"<domain>"           → hosts presenting cert for this domain
///   - hostname:"<domain>"      → hosts with matching hostname metadata

use reqwest::Client;
use serde::Deserialize;
use std::collections::HashSet;
use std::time::Duration;

pub struct ShodanScanner {
    client: Client,
    api_key: String,
}

#[derive(Deserialize, Debug)]
struct ShodanSearchResponse {
    matches: Vec<ShodanMatch>,
}

#[derive(Deserialize, Debug)]
struct ShodanMatch {
    ip_str: String,
}

impl ShodanScanner {
    pub fn new(api_key: String) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("Mozilla/5.0 (compatible; WAF-Origin-Hunter)")
            .build()
            .unwrap();
        Self { client, api_key }
    }

    /// Search Shodan for hosts related to `domain`. Returns a set of IP strings.
    pub async fn find_ips(&self, domain: &str) -> HashSet<String> {
        let mut ips = HashSet::new();

        let queries = vec![
            format!("ssl:\"{}\"", domain),
            format!("hostname:\"{}\"", domain),
        ];

        for query in queries {
            let url = format!(
                "https://api.shodan.io/shodan/host/search?key={}&query={}&minify=true",
                self.api_key,
                urlencoding::encode(&query),
            );

            match self.client.get(&url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    if let Ok(data) = resp.json::<ShodanSearchResponse>().await {
                        for m in data.matches {
                            ips.insert(m.ip_str);
                        }
                    }
                }
                _ => {}
            }
        }

        ips
    }
}

/// URL-encode a string (simple percent-encoding for query params)
mod urlencoding {
    pub fn encode(s: &str) -> String {
        let mut out = String::with_capacity(s.len() * 3);
        for byte in s.bytes() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' |
                b'-' | b'_' | b'.' | b'~' => out.push(byte as char),
                _ => {
                    out.push('%');
                    out.push_str(&format!("{:02X}", byte));
                }
            }
        }
        out
    }
}
