use crate::prelude::{Ipv4Addr, Ipv4Net, get_default_interface};



pub fn get_default_iface_info() -> Ipv4Net {
    let iface_info = get_default_interface()
        .expect("[ ERROR ] It wasn't possible to get the interface information");

    *iface_info.ipv4.first()
        .expect("[ ERROR ] Interface has no IPv4 address")
}


pub fn get_default_iface_ip() -> Ipv4Addr {
    let iface_info = get_default_iface_info();
    iface_info.addr()
}


pub fn get_network() -> String {
    let iface_info   = get_default_iface_info();
    let network_addr = iface_info.network();
    let cidr         = iface_info.prefix_len();
    format!("{}/{}", network_addr, cidr)
}