use std::net::Ipv4Addr;
use ipnet::Ipv4Net;
use netdev::interface::get_default_interface;
use pnet::datalink::{self, MacAddr};
use crate::utils::abort;



pub fn default_ipv4_net() -> Ipv4Net {
    let iface_info = get_default_interface()
        .expect("[ ERROR ] It wasn't possible to get the interface information");

    *iface_info.ipv4.first()
        .expect("[ ERROR ] Interface has no IPv4 address")
}


pub fn default_ipv4_addr() -> Ipv4Addr {
    let iface_info = default_ipv4_net();
    iface_info.addr()
}


pub fn default_iface_cidr() -> String {
    let iface_info   = default_ipv4_net();
    let network_addr = iface_info.network();
    let cidr         = iface_info.prefix_len();
    format!("{}/{}", network_addr, cidr)
}


pub fn default_iface_mac() -> MacAddr {
    let my_ip = default_ipv4_addr();
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
