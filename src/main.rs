mod asn;
mod bgp;
mod crtsh;
mod dns;
mod favicon;
mod fofa;
mod history;
mod shodan;
mod ssl;
mod vhost;
mod zoomeye;

use anyhow::Result;
use asn::is_cdn_ip;
use bgp::BgpScanner;
use clap::Parser;
use colored::*;
use crtsh::CrtShScanner;
use dns::DnsScanner;
use favicon::FaviconHasher;
use fofa::FofaScanner;
use history::HistoryScanner;
use shodan::ShodanScanner;
use ssl::SslScanner;
use vhost::VHostValidator;
use zoomeye::ZoomEyeScanner;
use indicatif::{ProgressBar, ProgressStyle};
use std::{env, collections::HashSet};
use tokio::fs;

#[derive(Parser)]
#[command(
    author,
    version,
    about = "Discover origin IPs of websites behind Cloudflare/WAF",
    long_about = None
)]
struct Args {
    #[arg(help = "The target domain (e.g., example.com)")]
    domain: String,

    #[arg(short, long, help = "Verify discovered IPs by sending Host headers (multi-port)")]
    verify: bool,

    #[arg(long, help = "Path to a subdomain wordlist file for brute-forcing")]
    wordlist: Option<String>,

    #[arg(long, help = "Compute and display favicon MurmurHash3 (Shodan-compatible)")]
    favicon: bool,

    #[arg(long = "no-history", help = "Skip historical DNS scraping (faster)")]
    no_history: bool,

    #[arg(long, help = "Smart Mode: Run ALL discovery methods, APIs, and auto-verify")]
    smart: bool,

    #[arg(long = "no-verify", help = "Disable auto-verification in Smart Mode")]
    no_verify: bool,

    #[arg(long, help = "Censys API ID")]
    api_id: Option<String>,

    #[arg(long, help = "Censys API Secret")]
    api_secret: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    dotenv::dotenv().ok();

    let api_id = args.api_id.or(env::var("CENSYS_API_ID").ok());
    let api_secret = args.api_secret.or(env::var("CENSYS_API_SECRET").ok());

    let shodan_key = env::var("SHODAN_API_KEY").ok();
    let fofa_email = env::var("FOFA_EMAIL").ok();
    let fofa_key = env::var("FOFA_KEY").ok();
    let zoomeye_key = env::var("ZOOMEYE_API_KEY").ok();

    println!("\n{}", "WAF-Origin-Hunter v2.0.0".bold().bright_cyan());
    println!("{} {}\n", "Target:".dimmed(), args.domain.bold());

    let is_smart = args.smart;
    if is_smart {
        println!("{}", "\u{26a1} SMART MODE ENHANCED RECON \u{26a1}".bold().bright_magenta());
        println!();
    }

    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")?,
    );

    let mut ips: HashSet<String> = HashSet::new();

    // ── 1. Core DNS Recon ────────────────────────────────────────────────────
    pb.set_message("Scanning DNS records (A, MX, SPF, subdomains)...");
    let dns_scanner = DnsScanner::new().await?;
    ips.extend(dns_scanner.find_origin_ips(&args.domain).await?);

    // ── 2. crt.sh certificate transparency ──────────────────────────────────
    pb.set_message("Scraping crt.sh certificate transparency logs...");
    let crt_scanner = CrtShScanner::new();
    if let Ok(subs) = crt_scanner.fetch_subdomains(&args.domain).await {
        if !subs.is_empty() {
            pb.set_message(format!("Resolving {} subdomains from crt.sh...", subs.len()));
            ips.extend(dns_scanner.resolve_hostnames(&subs).await);
        }
    }

    // ── 3. Wordlist subdomain brute-force ────────────────────────────────────
    if let Some(wordlist_path) = &args.wordlist {
        pb.set_message(format!("Loading wordlist: {}...", wordlist_path));
        match fs::read_to_string(wordlist_path).await {
            Ok(content) => {
                let words: HashSet<String> = content
                    .lines()
                    .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
                    .map(|w| format!("{}.{}", w.trim(), args.domain))
                    .collect();
                pb.set_message(format!("Resolving {} wordlist subdomains...", words.len()));
                ips.extend(dns_scanner.resolve_hostnames(&words).await);
            }
            Err(e) => {
                pb.println(format!(
                    "  {} Failed to read wordlist '{}': {}",
                    "[!]".yellow(),
                    wordlist_path,
                    e
                ));
            }
        }
    }

    // ── 4. Historical DNS scraping ───────────────────────────────────────────
    if !args.no_history {
        pb.set_message("Scraping historical DNS records (ViewDNS, SecurityTrails, VT)...");
        let history_scanner = HistoryScanner::new();
        let history_ips = history_scanner.collect(&args.domain).await;
        if !history_ips.is_empty() {
            pb.println(format!(
                "  {} Found {} IPs from DNS history sources.",
                "[+]".green(),
                history_ips.len()
            ));
            ips.extend(history_ips);
        }
    }

    // ── 5. Censys SSL recon (optional, requires API keys) ───────────────────
    if api_id.is_some() && api_secret.is_some() {
        pb.set_message("Querying Censys for SSL certificate matches...");
        let ssl_scanner = SslScanner::new(api_id, api_secret);
        if let Ok(ssl_ips) = ssl_scanner.find_by_censys(&args.domain).await {
            if is_smart && !ssl_ips.is_empty() {
                pb.println(format!("  {} Censys found {} IPs.", "[+]".green(), ssl_ips.len()));
            }
            ips.extend(ssl_ips);
        }
    } else {
        if is_smart {
            pb.println(format!("  {} Censys: Missing API keys.", "[SKIP]".dimmed()));
        } else {
            pb.println(format!("  {} Censys API keys not found. Skipping SSL recon.", "[!]".yellow()));
        }
    }

    let mut bgp_prefixes = HashSet::new();

    // ── Smart Mode Extras ────────────────────────────────────────────────────
    if is_smart {
        pb.set_message("Running advanced OSINT API queries...");

        // 6. Shodan
        if let Some(key) = shodan_key {
            let shodan = ShodanScanner::new(key);
            let s_ips = shodan.find_ips(&args.domain).await;
            pb.println(format!("  {} Shodan found {} IPs.", "[+]".green(), s_ips.len()));
            ips.extend(s_ips);
        } else {
            pb.println(format!("  {} Shodan: Missing SHODAN_API_KEY.", "[SKIP]".dimmed()));
        }

        // 7. FOFA
        if let (Some(email), Some(key)) = (fofa_email, fofa_key) {
            let fofa = FofaScanner::new(email, key);
            let f_ips = fofa.find_ips(&args.domain).await;
            pb.println(format!("  {} FOFA found {} IPs.", "[+]".green(), f_ips.len()));
            ips.extend(f_ips);
        } else {
            pb.println(format!("  {} FOFA: Missing FOFA_EMAIL or FOFA_KEY.", "[SKIP]".dimmed()));
        }

        // 8. ZoomEye
        if let Some(key) = zoomeye_key {
            let zoomeye = ZoomEyeScanner::new(key);
            let z_ips = zoomeye.find_ips(&args.domain).await;
            pb.println(format!("  {} ZoomEye found {} IPs.", "[+]".green(), z_ips.len()));
            ips.extend(z_ips);
        } else {
            pb.println(format!("  {} ZoomEye: Missing ZOOMEYE_API_KEY.", "[SKIP]".dimmed()));
        }

        // 9. BGP Prefix Enumeration
        pb.set_message("Locating ASNs and enumerating BGP IPv4 prefixes...");
        let bgp = BgpScanner::new();
        let (asn, prefixes) = bgp.find_asn_prefixes(&args.domain).await;
        if let Some(a) = asn {
            pb.println(format!("  {} BGP: Target maps to AS{}", "[+]".green(), a));
            if !prefixes.is_empty() {
                pb.println(format!("  {} Discovered {} routed IPv4 prefixes for origin org.", "[+]".green(), prefixes.len()));
                bgp_prefixes = prefixes;
            }
        }
    }

    // ── 6. CDN/ASN Filtering ─────────────────────────────────────────────────
    let before = ips.len();
    ips.retain(|ip| !is_cdn_ip(ip));
    let filtered = before - ips.len();
    if filtered > 0 {
        pb.println(format!(
            "  {} Filtered {} known CDN IPs (Cloudflare/Fastly/CloudFront).",
            "[~]".dimmed(),
            filtered
        ));
    }

    pb.finish_and_clear();
    println!("{} Found {} candidate origin IPs.\n", "[\u{2713}]".green(), ips.len());

    // ── 7. Favicon Hash ──────────────────────────────────────────────────────
    if args.favicon {
        print!("{} Computing favicon hash... ", "[*]".cyan());
        let hasher = FaviconHasher::new();
        match hasher.hash(&args.domain).await {
            Ok((hash, shodan_url)) => {
                println!();
                println!("  {} Favicon MurmurHash3: {}", "Hash:".bold(), hash.to_string().bright_yellow());
                println!("  {} {}", "Shodan:".bold(), shodan_url.bright_blue());
            }
            Err(e) => println!("{} {}", "[!]".yellow(), e),
        }
        println!();
    }

    // ── 8. Verification (multi-port + DOM heuristics) ───────────────────────
    let do_verify = args.verify || (is_smart && !args.no_verify);

    if do_verify && (!ips.is_empty() || !bgp_prefixes.is_empty()) {
        println!("{}", "Verifying candidate IPs (multi-port + DOM similarity)...".bold());
        println!();

        // Fetch baseline from the proxied site once
        let validator = VHostValidator::new();
        let baseline = validator.build_baseline(&args.domain).await;
        if baseline.is_some() {
            println!(
                "  {} Baseline fingerprint captured from {}.",
                "[+]".green(),
                args.domain
            );
        }

        let mut confirmed: Vec<vhost::ValidationResult> = Vec::new();
        let ip_list: Vec<String> = ips.into_iter().collect();

        let pb2 = ProgressBar::new(ip_list.len() as u64);
        pb2.set_style(
            ProgressStyle::default_bar()
                .template("  {spinner:.green} [{bar:30.cyan/blue}] {pos}/{len} {msg}")?
                .progress_chars("#>-"),
        );

        for ip in &ip_list {
            pb2.set_message(format!("Checking {}...", ip));
            match validator.validate(ip, &args.domain, baseline.as_ref()).await {
                Some(res) => {
                    pb2.println(format!(
                        "  {} {} -> {}:{} (similarity: {:.0}%{})",
                        "[\u{2713}] CONFIRMED".green().bold(),
                        ip.bright_white(),
                        res.scheme,
                        res.port,
                        res.similarity * 100.0,
                        if res.title_match { ", title match" } else { "" }
                    ));
                    confirmed.push(res);
                }
                None => {
                    pb2.println(format!("  {} {}", "[-]".dimmed(), ip));
                }
            }
            pb2.inc(1);
        }
        pb2.finish_and_clear();

        println!();
        if confirmed.is_empty() {
            println!("{} No confirmed origin IPs found.", "[!]".yellow());
            println!(
                "{}",
                "[TIP] Try --wordlist <file> or check for HTTPS-only origins.".dimmed()
            );
        } else {
            println!("{} {} confirmed origin IP(s):", "[\u{2713}]".green().bold(), confirmed.len());
            for r in &confirmed {
                println!(
                    "  {} {}://{}:{}",
                    "\u{2192}".bright_green(),
                    r.scheme, r.ip, r.port
                );
            }
        }
    } else if !do_verify {
        // Print all unverified IPs
        let ip_list: Vec<String> = ips.into_iter().collect();
        println!("{}", "Discovered IPs (Unverified):".bold());
        for ip in &ip_list {
            println!("  {} {}", "-".dimmed(), ip);
        }
        println!();
        println!(
            "{}",
            "[TIP] Run with --verify to validate these IPs across ports 80/443/8080/8443.".dimmed()
        );
    }

    Ok(())
}
