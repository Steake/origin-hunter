# origin-hunter

[![Crates.io](https://img.shields.io/crates/v/origin-hunter.svg)](https://crates.io/crates/origin-hunter)
[![Build](https://github.com/Steake/origin-hunter/actions/workflows/ci.yml/badge.svg)](https://github.com/Steake/origin-hunter/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-unlicensed-blue.svg)](#)

Fast, async Rust CLI for discovering the real origin IP of websites hiding behind Cloudflare and other WAFs. Chains passive enumeration, certificate transparency, historical DNS, OSINT APIs, and active verification into one sweep.

```
origin-hunter bugcrowd.com --smart
```

---

## Install

**Homebrew (macOS / Linux)**
```bash
brew tap Steake/origin-hunter
brew install origin-hunter
```

**cargo**
```bash
cargo install origin-hunter
```

**Pre-built binaries** — grab the latest from [Releases](https://github.com/Steake/origin-hunter/releases) for Linux x86_64, macOS (Apple Silicon + Intel), and Windows.

**Build from source**
```bash
git clone https://github.com/Steake/origin-hunter
cd origin-hunter
cargo build --release
# binary → ./target/release/origin-hunter
```

---

## Usage

```
origin-hunter [OPTIONS] <DOMAIN>
```

| Flag | Description |
|------|-------------|
| `<DOMAIN>` | Target domain, e.g. `example.com` |
| `--smart` | **Smart Mode** — runs every discovery method, all OSINT APIs, BGP enumeration, and auto-verifies results |
| `-v, --verify` | Active verification: sends `Host` headers across ports 80/443/8080/8443/2083 and scores DOM similarity |
| `--wordlist <FILE>` | Subdomain wordlist for async brute-force DNS resolution |
| `--favicon` | Compute favicon MurmurHash3 (Shodan-compatible) and print search URL |
| `--no-history` | Skip historical DNS scraping — faster, lower noise |
| `--no-verify` | Disable auto-verification when using `--smart` |
| `--api-id <ID>` | Censys API ID (or `CENSYS_API_ID` env var) |
| `--api-secret <SECRET>` | Censys API Secret (or `CENSYS_API_SECRET` env var) |

---

## Examples

Passive recon only, no API keys needed:
```bash
origin-hunter target.com
```

Full kitchen-sink sweep with everything enabled:
```bash
origin-hunter target.com --smart
```

Wordlist brute-force + active verification:
```bash
origin-hunter target.com --wordlist ~/wordlists/subdomains.txt --verify
```

Favicon hash for Shodan pivoting:
```bash
origin-hunter target.com --favicon
```

Fast run, skip DNS history:
```bash
origin-hunter target.com --no-history --verify
```

---

## How it works

Each run chains these steps in order, filtering CDN IPs at every stage:

1. **DNS records** — A, AAAA, MX, SPF, and a sweep of common forgotten subdomains (`direct`, `mail`, `cpanel`, etc.)
2. **Certificate transparency** — scrapes [crt.sh](https://crt.sh) for every SSL cert ever issued for the domain, resolves all discovered subdomains
3. **Subdomain brute-force** — async DNS resolution against a user-supplied wordlist
4. **Historical DNS** — queries ViewDNS, SecurityTrails, and VirusTotal public endpoints for pre-Cloudflare A records
5. **CDN/ASN filtering** — drops IPs belonging to Cloudflare, Fastly, and AWS CloudFront before wasting time on them
6. **Censys SSL matching** *(optional)* — finds hosts presenting certs for your domain that Censys has seen
7. **Smart Mode extras:**
   - **Shodan** — searches for the domain across Shodan's banner data
   - **FOFA** — queries FOFA for hosts referencing the domain
   - **ZoomEye** — ZoomEye cross-reference
   - **BGP prefix enumeration** — resolves the target's ASN and enumerates all routed IPv4 prefixes for the owning org
8. **Favicon MurmurHash3** — fetches `/favicon.ico`, computes Shodan-compatible hash, prints ready-to-use search link
9. **Verification** — captures a baseline fingerprint of the real proxied site, then for each candidate IP: tries every port, spoofs `Host` header, scores DOM similarity with Jaro-Winkler, reports confirmed origins with similarity %, port, and scheme

---

## API keys

All integrations are optional and degrade gracefully. Copy `.env.example` to `.env` or export directly:

```bash
cp .env.example .env
# then fill in what you have
```

| Variable | Source |
|----------|--------|
| `CENSYS_API_ID` / `CENSYS_API_SECRET` | [search.censys.io/account/api](https://search.censys.io/account/api) |
| `SHODAN_API_KEY` | [account.shodan.io](https://account.shodan.io) |
| `FOFA_EMAIL` / `FOFA_KEY` | [fofa.info/userInfo](https://fofa.info/userInfo) |
| `ZOOMEYE_API_KEY` | [zoomeye.hk/profile](https://www.zoomeye.hk/profile) |

Without any API keys, origin-hunter still runs all free methods (DNS, crt.sh, DNS history, CDN filtering, verification) — the paid integrations just get skipped with a `[SKIP]` notice.

---

## Contributing

PRs welcome. `cargo clippy` and `cargo test` should be clean before opening one.
