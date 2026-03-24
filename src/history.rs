/// Historical DNS IP Scraper
///
/// Silently scrapes multiple free third-party services for historical A records
/// that may expose an origin IP from before Cloudflare was configured.
///
/// Sources:
///   - viewdns.info/iphistory/
///   - SecurityTrails public UI API
///   - VirusTotal public UI subdomains API
///   - HackerTarget hostsearch API (free, no auth)
///   - RapidDNS subdomain search (HTML scrape)

use regex::Regex;
use reqwest::{Client, header};
use std::collections::HashSet;
use std::time::Duration;

pub struct HistoryScanner {
    client: Client,
}

impl HistoryScanner {
    pub fn new() -> Self {
        let mut headers = header::HeaderMap::new();
        headers.insert(
            header::USER_AGENT,
            header::HeaderValue::from_static(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 \
                 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            ),
        );
        let client = Client::builder()
            .timeout(Duration::from_secs(20))
            .default_headers(headers)
            .build()
            .unwrap();
        Self { client }
    }

    /// Collect historical IPs from all available free sources.
    pub async fn collect(&self, domain: &str) -> HashSet<String> {
        let mut ips = HashSet::new();

        // Spawn all scrapers concurrently
        let (viewdns, sectrails, vt, hackertarget, rapiddns) = tokio::join!(
            self.scrape_viewdns(domain),
            self.scrape_securitytrails(domain),
            self.scrape_virustotal(domain),
            self.scrape_hackertarget(domain),
            self.scrape_rapiddns(domain),
        );

        for set in [viewdns, sectrails, vt, hackertarget, rapiddns] {
            ips.extend(set);
        }

        ips
    }

    /// viewdns.info/iphistory/ — scrape A record history table
    async fn scrape_viewdns(&self, domain: &str) -> HashSet<String> {
        let url = format!("https://viewdns.info/iphistory/?domain={}", domain);
        let ip_re = Regex::new(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b").unwrap();
        let mut ips = HashSet::new();

        if let Ok(resp) = self.client.get(&url).send().await {
            if let Ok(text) = resp.text().await {
                for cap in ip_re.captures_iter(&text) {
                    ips.insert(cap[1].to_string());
                }
            }
        }
        ips
    }

    /// SecurityTrails public UI history endpoint
    async fn scrape_securitytrails(&self, domain: &str) -> HashSet<String> {
        let url = format!(
            "https://securitytrails.com/app/api/v1/history/{}/dns/a?page=1",
            domain
        );
        let ip_re = Regex::new(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b").unwrap();
        let mut ips = HashSet::new();

        if let Ok(resp) = self
            .client
            .get(&url)
            .header("Accept", "application/json")
            .send()
            .await
        {
            if let Ok(text) = resp.text().await {
                for cap in ip_re.captures_iter(&text) {
                    ips.insert(cap[1].to_string());
                }
            }
        }
        ips
    }

    /// VirusTotal public UI subdomains endpoint — resolves IPs from subdomain list
    async fn scrape_virustotal(&self, domain: &str) -> HashSet<String> {
        let url = format!(
            "https://www.virustotal.com/ui/domains/{}/subdomains?limit=40",
            domain
        );
        let ip_re = Regex::new(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b").unwrap();
        let mut ips = HashSet::new();

        if let Ok(resp) = self
            .client
            .get(&url)
            .header("Accept", "application/json")
            .send()
            .await
        {
            if let Ok(text) = resp.text().await {
                for cap in ip_re.captures_iter(&text) {
                    ips.insert(cap[1].to_string());
                }
            }
        }
        ips
    }

    /// HackerTarget hostsearch — returns CSV of "hostname,ip" lines
    async fn scrape_hackertarget(&self, domain: &str) -> HashSet<String> {
        let url = format!(
            "https://api.hackertarget.com/hostsearch/?q={}",
            domain
        );
        let ip_re = Regex::new(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b").unwrap();
        let mut ips = HashSet::new();

        if let Ok(resp) = self.client.get(&url).send().await {
            if let Ok(text) = resp.text().await {
                // Response is "subdomain.example.com,1.2.3.4\n..."
                // Reject API-error responses
                if text.starts_with("error") || text.contains("API count exceeded") {
                    return ips;
                }
                for cap in ip_re.captures_iter(&text) {
                    ips.insert(cap[1].to_string());
                }
            }
        }
        ips
    }

    /// RapidDNS full subdomain search — HTML page scrape
    async fn scrape_rapiddns(&self, domain: &str) -> HashSet<String> {
        let url = format!("https://rapiddns.io/s/{}?full=1", domain);
        let ip_re = Regex::new(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b").unwrap();
        let mut ips = HashSet::new();

        if let Ok(resp) = self.client.get(&url).send().await {
            if let Ok(text) = resp.text().await {
                for cap in ip_re.captures_iter(&text) {
                    ips.insert(cap[1].to_string());
                }
            }
        }
        ips
    }
}
