use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use ipnet::Ipv4Net;
use netdev::interface::{get_default_interface, get_interfaces};
use pnet::datalink::{self, MacAddr};
use crate::utils::abort;



pub fn default_iface_name() -> String {
    let iface_info = get_default_interface()
        .expect("[ ERROR ] It wasn't possible to get the interface information");

    iface_info.name
}



pub fn get_ipv4_net(iface_name: &String) -> Ipv4Net {
    let iface = get_interfaces()
        .into_iter()
        .find(|i| i.name == *iface_name)
        .unwrap_or_else(|| abort(&format!("Interface '{}' not found", iface_name)));

    *iface.ipv4.first()
        .unwrap_or_else(|| abort(format!("Interface '{}' has no IPv4 address", iface_name)))
}



pub fn get_ipv4_addr(iface_name: &String) -> Ipv4Addr {
    let iface_info = get_ipv4_net(&iface_name);
    iface_info.addr()
}



pub fn get_iface_cidr(iface_name: &String) -> String {
    let iface_info   = get_ipv4_net(iface_name);
    let network_addr = iface_info.network();
    let cidr         = iface_info.prefix_len();
    format!("{}/{}", network_addr, cidr)
}



pub fn default_iface_mac(iface_name: &String) -> MacAddr {
    let my_ip      = get_ipv4_addr(iface_name);
    let interfaces = datalink::interfaces();

    for iface in interfaces {
        for ip_network in iface.ips {
            if let std::net::IpAddr::V4(v4) = ip_network.ip() {
                if v4 == my_ip {
                    return iface.mac
                        .expect("[ERROR] The default interface does not have a MAC address");
                }
            }
        }
    }
    abort(format!("[ERROR] Could not find the default interface with IP {}", my_ip));
}



pub fn source_ip_from_iface(dst: Ipv4Addr) -> Ipv4Addr {
    let sockaddr = SocketAddrV4::new(dst, 53);
    
    let sock = UdpSocket::bind(("0.0.0.0", 0))
        .unwrap_or_else(|e| abort(&format!("Failed to bind UDP socket: {}", e)));
    
    sock.connect(sockaddr)
        .unwrap_or_else(|e| abort(&format!("Failed to connect UDP socket: {}", e)));

    match sock.local_addr().unwrap().ip() {
        std::net::IpAddr::V4(v4) => v4,
        _ => abort("Expected a local IPv4 address, but got IPv6"),
    }
}