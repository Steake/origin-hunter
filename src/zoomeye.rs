/// ZoomEye API Integration
///
/// Queries ZoomEye for hosts with `ssl:"<domain>"` or `hostname:"<domain>"`.
/// Requires `ZOOMEYE_API_KEY` environment variable.
///
/// ZoomEye API docs: https://www.zoomeye.org/doc

use reqwest::Client;
use serde::Deserialize;
use std::collections::HashSet;
use std::time::Duration;

pub struct ZoomEyeScanner {
    client: Client,
    api_key: String,
}

#[derive(Deserialize, Debug)]
struct ZoomEyeResponse {
    matches: Option<Vec<ZoomEyeMatch>>,
}

#[derive(Deserialize, Debug)]
struct ZoomEyeMatch {
    ip: String,
}

impl ZoomEyeScanner {
    pub fn new(api_key: String) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("Mozilla/5.0 (compatible; WAF-Origin-Hunter)")
            .build()
            .unwrap();
        Self { client, api_key }
    }

    /// Search ZoomEye for hosts associated with `domain`.
    pub async fn find_ips(&self, domain: &str) -> HashSet<String> {
        let mut ips = HashSet::new();

        let queries = vec![
            format!("ssl:\"{}\"", domain),
            format!("hostname:\"{}\"", domain),
        ];

        for query in queries {
            let url = format!(
                "https://api.zoomeye.org/host/search?query={}&page=1",
                percent_encode(&query),
            );

            match self
                .client
                .get(&url)
                .header("Authorization", format!("JWT {}", self.api_key))
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => {
                    if let Ok(data) = resp.json::<ZoomEyeResponse>().await {
                        if let Some(matches) = data.matches {
                            for m in matches {
                                ips.insert(m.ip);
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        ips
    }
}

fn percent_encode(s: &str) -> String {
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
