/// VHost Validator with multi-port, HTTPS, and DOM similarity heuristics.
///
/// Strategy:
///  1. Fetch the real site via proxy and extract baseline title + body fingerprint.
///  2. For each candidate IP, scan ports: 80 (HTTP), 443 (HTTPS), 8080, 8443, 2083.
///  3. Send HOST header and compare responses for:
///     - Exact title match
///     - String similarity >= 0.75 (Jaro-Winkler via `strsim`)
///     - Domain string presence in body

use reqwest::{Client, header};
use scraper::{Html, Selector};
use strsim::jaro_winkler;
use std::time::Duration;

const PORTS: &[(u16, &str)] = &[
    (80, "http"),
    (443, "https"),
    (8080, "http"),
    (8443, "https"),
    (2083, "https"),
];

pub struct VHostValidator {
    /// Standard client for normal browsing requests (with cert validation)
    client: Client,
    /// Permissive client that ignores invalid TLS certs (for direct IP access)
    raw_client: Client,
}

/// Result of a single candidate IP validation attempt.
#[derive(Debug)]
pub struct ValidationResult {
    pub ip: String,
    pub port: u16,
    pub scheme: &'static str,
    pub similarity: f64,
    pub title_match: bool,
}

impl VHostValidator {
    pub fn new() -> Self {
        let raw_client = Client::builder()
            .timeout(Duration::from_secs(8))
            .danger_accept_invalid_certs(true)
            .user_agent("Mozilla/5.0 (compatible; WAF-Origin-Hunter)")
            .build()
            .unwrap();
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent("Mozilla/5.0 (compatible; WAF-Origin-Hunter)")
            .build()
            .unwrap();
        Self { client, raw_client }
    }

    /// Fetch the real proxied site and extract a baseline fingerprint.
    pub async fn build_baseline(&self, domain: &str) -> Option<Baseline> {
        let url = format!("https://{}", domain);
        let resp = self.client.get(&url).send().await.ok()?;
        let body = resp.text().await.ok()?;
        let title = extract_title(&body);
        Some(Baseline {
            title,
            body_sample: body.chars().take(8000).collect(),
        })
    }

    /// Validate a single candidate IP across all PORTS.
    /// Returns the best-matching `ValidationResult` if any port passes threshold.
    pub async fn validate(
        &self,
        ip: &str,
        domain: &str,
        baseline: Option<&Baseline>,
    ) -> Option<ValidationResult> {
        let domain_lc = domain.to_lowercase();
        let mut best: Option<ValidationResult> = None;

        for &(port, scheme) in PORTS {
            let url = format!("{}://{}:{}", scheme, ip, port);
            let result = self
                .raw_client
                .get(&url)
                .header(header::HOST, domain)
                .send()
                .await;

            let resp = match result {
                Ok(r) => r,
                Err(_) => continue,
            };

            let body = match resp.text().await {
                Ok(b) => b,
                Err(_) => continue,
            };

            let body_lc = body.to_lowercase();
            let title = extract_title(&body);

            // Heuristic 1: domain name appears in body
            let domain_in_body = body_lc.contains(&domain_lc);

            // Heuristic 2: title match against baseline
            let title_match = baseline
                .and_then(|b| b.title.as_ref())
                .zip(title.as_ref())
                .map(|(bt, t)| bt.to_lowercase() == t.to_lowercase())
                .unwrap_or(false);

            // Heuristic 3: Jaro-Winkler similarity on body samples
            let similarity = if let Some(base) = baseline {
                let sample: String = body.chars().take(8000).collect();
                jaro_winkler(&base.body_sample, &sample)
            } else {
                if domain_in_body { 0.8 } else { 0.0 }
            };

            // Accept if similarity >= 0.75, exact title match, or domain in body
            let passes = similarity >= 0.75 || title_match || domain_in_body;

            if passes {
                let result = ValidationResult {
                    ip: ip.to_string(),
                    port,
                    scheme,
                    similarity,
                    title_match,
                };
                match &best {
                    None => best = Some(result),
                    Some(prev) if result.similarity > prev.similarity => best = Some(result),
                    _ => {}
                }
            }
        }

        best
    }
}

pub struct Baseline {
    pub title: Option<String>,
    pub body_sample: String,
}

fn extract_title(html: &str) -> Option<String> {
    let doc = Html::parse_document(html);
    let sel = Selector::parse("title").ok()?;
    doc.select(&sel)
        .next()
        .map(|el| el.text().collect::<String>().trim().to_string())
        .filter(|s| !s.is_empty())
}
