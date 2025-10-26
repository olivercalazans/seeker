use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::ffi::CStr;
use libc::{getifaddrs, freeifaddrs, ifaddrs, AF_INET, sockaddr_in};
use ipnet::Ipv4Net;
use netdev::interface::{get_default_interface, get_interfaces};
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



pub fn iface_name_from_ip(dst_ip: Ipv4Addr) -> String {
    let ip = source_ip_from_iface(dst_ip);
    unsafe {
        let mut ifap: *mut ifaddrs = std::ptr::null_mut();

        if getifaddrs(&mut ifap) != 0 {
            abort(&format!("[ERROR] getifaddrs failed: {}", std::io::Error::last_os_error()));
        }

        let mut ptr = ifap;
        while !ptr.is_null() {
            let ifa = &*ptr;

            if !ifa.ifa_addr.is_null() && (*ifa.ifa_addr).sa_family as i32 == AF_INET {
                let sockaddr   = &*(ifa.ifa_addr as *const sockaddr_in);
                let addr_bytes = sockaddr.sin_addr.s_addr.to_ne_bytes();
                let iface_ip   = Ipv4Addr::new(addr_bytes[0], addr_bytes[1], addr_bytes[2], addr_bytes[3]);

                if iface_ip == ip {
                    freeifaddrs(ifap);
                    let name = CStr::from_ptr(ifa.ifa_name).to_string_lossy().to_string();
                    return name;
                }
            }

            ptr = ifa.ifa_next;
        }

        freeifaddrs(ifap);
        abort(&format!("[ERROR] Could not find any interface with IP {}", ip));
    }
}
