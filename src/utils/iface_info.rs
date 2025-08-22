use default_net::interface;
use default_net::ip::Ipv4Net;



fn get_default_iface_info() -> Ipv4Net {
    let iface_info = interface::get_default_interface()
        .expect("Error: It wasn't possible to get the interface information");

    *iface_info.ipv4.first()
        .expect("Error: Interface has no IPv4 address")
}



pub fn get_default_iface_ip() -> String {
    let ipv4 = get_default_iface_info();
    ipv4.addr.to_string()
}



pub fn get_default_iface_netmask() -> String {
    let ipv4 = get_default_iface_info();
    ipv4.netmask().to_string()
}