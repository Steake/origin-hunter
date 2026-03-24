/// CDN / ASN Filtering - discards IPs belonging to Cloudflare, Fastly, AWS CloudFront,
/// and other known CDNs so we don't waste time verifying false positives.
///
/// CIDR lists sourced from:
///   - https://www.cloudflare.com/ips-v4
///   - https://ip-ranges.amazonaws.com/ip-ranges.json (CloudFront prefix sample)
///   - https://api.fastly.com/public-ip-list

/// Known CDN CIDR blocks. Compact static list for zero-dependency filtering.
const CDN_CIDRS: &[&str] = &[
    // Cloudflare
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "108.162.192.0/18",
    "131.0.72.0/22",
    "141.101.64.0/18",
    "162.158.0.0/15",
    "172.64.0.0/13",
    "173.245.48.0/20",
    "188.114.96.0/20",
    "190.93.240.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    // Fastly (sample)
    "23.235.32.0/20",
    "43.249.72.0/22",
    "103.244.50.0/24",
    "103.245.222.0/23",
    "103.245.224.0/24",
    "104.156.80.0/20",
    "146.75.0.0/16",
    "151.101.0.0/16",
    "157.52.64.0/18",
    "167.82.0.0/17",
    "167.82.128.0/20",
    "167.82.160.0/20",
    "167.82.224.0/20",
    "172.111.64.0/18",
    "185.31.16.0/22",
    "199.27.72.0/21",
    "199.232.0.0/16",
    // AWS CloudFront (common ranges)
    "13.32.0.0/15",
    "13.35.0.0/16",
    "52.46.0.0/18",
    "52.84.0.0/15",
    "54.182.0.0/16",
    "54.192.0.0/16",
    "54.230.0.0/16",
    "54.239.128.0/18",
    "54.239.192.0/19",
    "64.252.64.0/18",
    "70.132.0.0/18",
    "71.152.0.0/17",
    "99.84.0.0/16",
    "204.246.164.0/22",
    "204.246.168.0/22",
    "204.246.174.0/23",
    "204.246.176.0/20",
    "205.251.192.0/19",
    "205.251.249.0/24",
    "205.251.250.0/23",
    "205.251.252.0/23",
    "205.251.254.0/24",
    "216.137.32.0/19",
];

/// Parse an IP string and CIDR string into integer ranges and test membership.
fn ip_in_cidr(ip: &str, cidr: &str) -> bool {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return false;
    }
    let prefix_len: u32 = match parts[1].parse() {
        Ok(n) => n,
        Err(_) => return false,
    };
    let ip_int = match ip_to_u32(ip) {
        Some(n) => n,
        None => return false,
    };
    let net_int = match ip_to_u32(parts[0]) {
        Some(n) => n,
        None => return false,
    };
    if prefix_len == 0 {
        return true;
    }
    let mask = !((1u32 << (32 - prefix_len)) - 1);
    (ip_int & mask) == (net_int & mask)
}

fn ip_to_u32(ip: &str) -> Option<u32> {
    let octets: Vec<u32> = ip
        .split('.')
        .map(|o| o.parse::<u32>().ok())
        .collect::<Option<Vec<_>>>()?;
    if octets.len() != 4 || octets.iter().any(|&o| o > 255) {
        return None;
    }
    Some((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3])
}

/// Returns `true` if the given IP belongs to a known CDN and should be discarded.
pub fn is_cdn_ip(ip: &str) -> bool {
    CDN_CIDRS.iter().any(|cidr| ip_in_cidr(ip, cidr))
}
