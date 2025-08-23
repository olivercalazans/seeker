use std::net::Ipv4Addr;
use default_net::interface;
use default_net::ip::Ipv4Net;



fn get_default_iface_info() -> Ipv4Net {
    let iface_info = interface::get_default_interface()
        .expect("[ ERROR ] It wasn't possible to get the interface information");

    *iface_info.ipv4.first()
        .expect("[ ERROR ]: Interface has no IPv4 address")
}



pub fn get_default_iface_ip() -> Ipv4Addr {
    let ipv4 = get_default_iface_info();
    ipv4.addr
}



pub fn get_default_iface_netmask() -> u8 {
    let ipv4    = get_default_iface_info();
    let netmask = ipv4.netmask();
    let cidr    = ipv4_mask_to_prefix(netmask);
    cidr
}



fn ipv4_mask_to_prefix(netmask: Ipv4Addr) -> u8 {
    let mask_int = u32::from(netmask);
    mask_int.count_ones() as u8
}