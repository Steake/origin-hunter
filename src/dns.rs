use anyhow::Result;
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use std::collections::HashSet;

pub struct DnsScanner {
    resolver: TokioAsyncResolver,
}

impl DnsScanner {
    pub async fn new() -> Result<Self> {
        let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
        Ok(Self { resolver })
    }

    pub async fn find_origin_ips(&self, domain: &str) -> Result<HashSet<String>> {
        let mut ips = HashSet::new();

        // 1. Direct A record (often points to CF, but good for baseline)
        if let Ok(lookup) = self.resolver.ipv4_lookup(domain).await {
            for ip in lookup.iter() {
                ips.insert(ip.to_string());
            }
        }

        // 2. AAAA records (IPv6 — sometimes the origin forgets to proxify these)
        if let Ok(lookup) = self.resolver.ipv6_lookup(domain).await {
            for ip in lookup.iter() {
                ips.insert(ip.to_string());
            }
        }

        // 3. MX records (often point to origin or related infra)
        if let Ok(mx_lookup) = self.resolver.mx_lookup(domain).await {
            for mx in mx_lookup.iter() {
                let exchange = mx.exchange().to_string();
                if let Ok(lookup) = self.resolver.ipv4_lookup(&exchange).await {
                    for ip in lookup.iter() {
                        ips.insert(ip.to_string());
                    }
                }
                // Also try AAAA for MX hosts
                if let Ok(lookup) = self.resolver.ipv6_lookup(&exchange).await {
                    for ip in lookup.iter() {
                        ips.insert(ip.to_string());
                    }
                }
            }
        }

        // 4. NS record resolution — nameserver IPs reveal origin ASN
        if let Ok(ns_lookup) = self.resolver.ns_lookup(domain).await {
            for ns in ns_lookup.iter() {
                let ns_name = ns.0.to_string();
                if let Ok(lookup) = self.resolver.ipv4_lookup(&ns_name).await {
                    for ip in lookup.iter() {
                        ips.insert(ip.to_string());
                    }
                }
            }
        }

        // 5. TXT records — SPF, DMARC, DKIM
        if let Ok(txt_lookup) = self.resolver.txt_lookup(domain).await {
            for txt in txt_lookup.iter() {
                for data in txt.txt_data() {
                    let record = String::from_utf8_lossy(data);
                    if record.contains("v=spf1") {
                        for part in record.split_whitespace() {
                            if part.starts_with("ip4:") {
                                ips.insert(part[4..].to_string());
                            } else if part.starts_with("ip6:") {
                                ips.insert(part[4..].to_string());
                            }
                        }
                    }
                }
            }
        }

        // 6. DMARC TXT record (_dmarc.<domain>)
        let dmarc_host = format!("_dmarc.{}", domain);
        if let Ok(txt_lookup) = self.resolver.txt_lookup(&dmarc_host).await {
            for txt in txt_lookup.iter() {
                for data in txt.txt_data() {
                    let record = String::from_utf8_lossy(data);
                    // DMARC records may include rua/ruf mail endpoints
                    // Extract any embedded IPs (rare but possible in includes)
                    for part in record.split(';') {
                        let part = part.trim();
                        if part.starts_with("ip4:") {
                            ips.insert(part[4..].trim().to_string());
                        }
                    }
                }
            }
        }

        // 7. Default DKIM selector TXT (_domainkey zone)
        // Try common selectors: default, google, mail, dkim, k1
        for selector in &["default", "google", "mail", "dkim", "k1", "selector1", "selector2"] {
            let dkim_host = format!("{}._domainkey.{}", selector, domain);
            if let Ok(txt_lookup) = self.resolver.txt_lookup(&dkim_host).await {
                for txt in txt_lookup.iter() {
                    for data in txt.txt_data() {
                        let record = String::from_utf8_lossy(data);
                        let _ = record; // suppress unused warning
                    }
                }
            }
        }

        // 8. Common subdomains (minimal core list)
        let commons = vec!["direct", "ftp", "mail", "cpanel", "webmail", "portal", "dev", "staging"];
        for sub in commons {
            let sub_domain = format!("{}.{}", sub, domain);
            if let Ok(lookup) = self.resolver.ipv4_lookup(&sub_domain).await {
                for ip in lookup.iter() {
                    ips.insert(ip.to_string());
                }
            }
        }

        Ok(ips)
    }

    pub async fn resolve_hostnames(&self, hostnames: &HashSet<String>) -> HashSet<String> {
        let mut ips = HashSet::new();
        let mut handles = vec![];

        for host in hostnames {
            let host_clone = host.clone();
            let resolver = self.resolver.clone();

            let handle = tokio::spawn(async move {
                let mut local_ips = HashSet::new();
                if let Ok(lookup) = resolver.ipv4_lookup(host_clone.as_str()).await {
                    for ip in lookup.iter() {
                        local_ips.insert(ip.to_string());
                    }
                }
                // Also try AAAA
                if let Ok(lookup) = resolver.ipv6_lookup(host_clone.as_str()).await {
                    for ip in lookup.iter() {
                        local_ips.insert(ip.to_string());
                    }
                }
                local_ips
            });
            handles.push(handle);
        }

        for handle in handles {
            if let Ok(local_ips) = handle.await {
                ips.extend(local_ips);
            }
        }

        ips
    }
}
