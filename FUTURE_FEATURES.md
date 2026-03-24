# WAF-Origin-Hunter: Future Feature Roadmap

Based on testing and WAF bypass methodologies, here are advanced features that would significantly increase the effectiveness and accuracy of `WAF-Origin-Hunter`.

## 1. Multi-Protocol & Port Validation
**Problem**: The current `VHostValidator` only tests `http://ip:80`. If an origin server rejects port 80 or strictly requires HTTPS, the validation fails (e.g., `error sending request for url`).
**Solution**:
- Blindly try `https://` requests and ignore invalid certificate errors (`danger_accept_invalid_certs(true)` is already implemented).
- Support scanning common backend and alternate HTTP ports: `8080`, `8443`, `2082`, `2083` (cPanel), and `8880`.

## 2. Advanced Origin Verification (Heuristics)
**Problem**: The current verification checks if the `target_domain` string exists in the HTML body of the IP's response. This produces false negatives if the origin server serves valid content without mentioning the domain name explicitly in the source.
**Solution**:
- **DOM/Hash Similarity**: Fetch the real proxied site through Cloudflare. Generate a structural similarity hash (like SSDeep or a basic DOM structure hash). Fetch the candidate IP's response and compare the hashes. Anything `>90%` similarity is a guaranteed match.
- **Title Extraction**: Parse the `<title>` tag from both the proxy and the candidate IP. If they match exactly, it's highly likely the origin.

## 3. Subdomain Wordlist Bruteforcing
**Problem**: We currently only check 8 hardcoded subdomains (`direct`, `mail`, `cpanel`, etc.) and rely on `crt.sh` logs. 
**Solution**:
- Add a `--wordlist <FILE>` argument.
- Use `tokio` to concurrently resolve thousands of common developer subdomains (e.g., `staging`, `dev`, `backend-api`, `old-site`). This often finds active development servers that devs forgot to proxy through Cloudflare.

## 4. Favicon Hashing (Shodan Integration)
**Problem**: Developers rarely change the default `favicon.ico` when configuring new backend servers, which creates a highly reliable tracking signature.
**Solution**:
- Fetch the `favicon.ico` from the target domain.
- Compute its `MurmurHash3` value (the standard format used by security search engines).
- Query Shodan or Censys for servers across the internet presenting that exact hash: `http.favicon.hash:<HASH>`.
- Extremely low false-positive rate.

## 5. Intelligent CDN & ASN Filtering
**Problem**: DNS history often returns IPs that belong to AWS CloudFront, Fastly, StackPath, or other older CDNs that the target used historically. Scanning these wastes time and produces false positives.
**Solution**:
- Integrate a lightweight IP-to-ASN check before verification.
- Drop any discovered IPs that belong to known CDN ranges (e.g., Cloudflare's own IP ranges, Fastly, Akamai).