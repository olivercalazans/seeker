use std::net::IpAddr;
use dns_lookup::lookup_addr;



pub fn get_host_name(ip: &str) -> String {
    let ip: IpAddr = ip.parse().unwrap();
    match lookup_addr(&ip) {
        Ok(hostname) => {
            if hostname.ends_with(".lan") {
                hostname.trim_end_matches(".lan").to_string()
            } else {
                hostname
            }
        }
        Err(_) => "Unknown".to_string(),
    }
}
