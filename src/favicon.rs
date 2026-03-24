/// Favicon Hashing module.
///
/// Fetches the target's favicon.ico, base64-encodes it in the Shodan-specific format
/// (76-char line-wrapped), and computes MurmurHash3 (x86_32) to produce a Shodan/Censys
/// compatible hash.
///
/// The resulting integer can be queried on Shodan with: http.favicon.hash:<HASH>

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use murmur3::murmur3_32;
use reqwest::Client;
use std::io::Cursor;
use std::time::Duration;

pub struct FaviconHasher {
    client: Client,
}

impl FaviconHasher {
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(15))
            .danger_accept_invalid_certs(true)
            .user_agent("Mozilla/5.0 (compatible; WAF-Origin-Hunter)")
            .build()
            .unwrap();
        Self { client }
    }

    /// Fetch and hash the favicon for `domain`. Returns the Shodan-compatible
    /// MurmurHash3 integer and the raw hash as a signed integer (Shodan uses signed).
    pub async fn hash(&self, domain: &str) -> Result<(i32, String)> {
        // Try HTTPS first, fall back to HTTP
        let favicon_bytes = self.fetch_favicon(domain).await?;

        // Base64-encode with 76-char line wrapping (Shodan's specific format)
        let b64 = STANDARD.encode(&favicon_bytes);
        let wrapped = b64
            .chars()
            .collect::<Vec<char>>()
            .chunks(76)
            .map(|c| c.iter().collect::<String>())
            .collect::<Vec<String>>()
            .join("\n")
            + "\n";

        // MurmurHash3 x86_32 with seed 0
        let hash = murmur3_32(&mut Cursor::new(wrapped.as_bytes()), 0)?;

        // Shodan stores as signed int32
        let signed_hash = hash as i32;
        let shodan_url = format!(
            "https://www.shodan.io/search?query=http.favicon.hash%3A{}",
            signed_hash
        );

        Ok((signed_hash, shodan_url))
    }

    async fn fetch_favicon(&self, domain: &str) -> Result<Vec<u8>> {
        // Try /favicon.ico directly on both schemas
        for scheme in &["https", "http"] {
            let url = format!("{}://{}/favicon.ico", scheme, domain);
            if let Ok(resp) = self.client.get(&url).send().await {
                if resp.status().is_success() {
                    if let Ok(bytes) = resp.bytes().await {
                        if !bytes.is_empty() {
                            return Ok(bytes.to_vec());
                        }
                    }
                }
            }
        }
        Err(anyhow::anyhow!("Could not fetch favicon from {}", domain))
    }
}
