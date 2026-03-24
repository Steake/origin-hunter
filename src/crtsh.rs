use anyhow::Result;
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashSet;
use std::time::Duration;

#[derive(Deserialize)]
struct CrtShEntry {
    name_value: String,
}

pub struct CrtShScanner {
    client: Client,
}

impl CrtShScanner {
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap();
        Self { client }
    }

    pub async fn fetch_subdomains(&self, domain: &str) -> Result<HashSet<String>> {
        let url = format!("https://crt.sh/?q=%25.{}&output=json", domain);
        
        let res = self.client.get(&url).send().await?;
        
        if !res.status().is_success() {
            return Err(anyhow::anyhow!("crt.sh returned status: {}", res.status()));
        }

        let entries: Vec<CrtShEntry> = res.json().await?;
        let mut subs = HashSet::new();

        for entry in entries {
            // crt.sh name_value can contain multiple domains separated by newlines
            for name in entry.name_value.split('\n') {
                let name = name.trim().to_lowercase();
                if name.ends_with(domain) && !name.contains('*') {
                    subs.insert(name);
                }
            }
        }

        Ok(subs)
    }
}
