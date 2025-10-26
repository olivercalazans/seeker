use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::ffi::CStr;
use libc::{getifaddrs, freeifaddrs, ifaddrs, AF_INET, sockaddr_in};
use ipnet::Ipv4Net;
use netdev::interface::get_interfaces;
use crate::utils::abort;



pub fn get_ipv4_net(iface_name: &String) -> Ipv4Net {
    let iface = get_interfaces()
        .into_iter()
        .find(|i| i.name == *iface_name)
        .unwrap_or_else(|| abort(&format!("Interface '{}' not found", iface_name)));

    *iface.ipv4.first()
        .unwrap_or_else(|| abort(format!("Interface '{}' has no IPv4 address", iface_name)))
}



unsafe fn get_ifaddrs_ptr() -> *mut ifaddrs {
    unsafe {
        let mut ifap: *mut ifaddrs = std::ptr::null_mut();
        
        if getifaddrs(&mut ifap) != 0 {
            abort(&format!("[ERROR] getifaddrs failed: {}", std::io::Error::last_os_error()));
        }

        ifap
    }
}



pub fn iface_name_from_ip(dst_ip: Ipv4Addr) -> String {
    let ip = src_ip_from_dst_ip(dst_ip);
    unsafe {
        let ifap     = get_ifaddrs_ptr();
        let mut ptr  = ifap;

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



pub fn src_ip_from_dst_ip(dst_ip: Ipv4Addr) -> Ipv4Addr {
    let sockaddr = SocketAddrV4::new(dst_ip, 53);
    
    let sock = UdpSocket::bind(("0.0.0.0", 0))
        .unwrap_or_else(|e| abort(&format!("Failed to bind UDP socket: {}", e)));
    
    sock.connect(sockaddr)
        .unwrap_or_else(|e| abort(&format!("Failed to connect UDP socket: {}", e)));

    match sock.local_addr().unwrap().ip() {
        std::net::IpAddr::V4(v4) => v4,
        _ => abort("Expected a local IPv4 address, but got IPv6"),
    }
}



pub fn default_iface_name() -> String {
    iface_name_from_ip(Ipv4Addr::new(8, 8, 8, 8))
}



pub fn iface_ip(iface_name: &str) -> Ipv4Addr {
    unsafe {
        let ifap    = get_ifaddrs_ptr();
        let mut cur = ifap;

        while !cur.is_null() {
            let ifa       = &*cur;
            let name_cstr = CStr::from_ptr(ifa.ifa_name);
            let name      = name_cstr.to_string_lossy();

            if name == iface_name && !ifa.ifa_addr.is_null() && (*ifa.ifa_addr).sa_family as i32 == AF_INET {
                let addr = &*(ifa.ifa_addr as *const sockaddr_in);
                let ip   = Ipv4Addr::from(addr.sin_addr.s_addr.to_ne_bytes());
                freeifaddrs(ifap);
                return ip;
            }

            cur = ifa.ifa_next;
        }

        freeifaddrs(ifap);
        abort(format!("Interface {} not found or has no IPv4 address", iface_name));
    }
}



pub fn iface_network_cidr(iface_name: &str) -> String {
    unsafe {
        let ifap    = get_ifaddrs_ptr();
        let mut cur = ifap;

        while !cur.is_null() {
            let ifa       = &*cur;
            let name_cstr = CStr::from_ptr(ifa.ifa_name);
            let name      = name_cstr.to_string_lossy();

            if name == iface_name
                && !ifa.ifa_addr.is_null()
                && !ifa.ifa_netmask.is_null()
                && (*ifa.ifa_addr).sa_family as i32 == AF_INET
            {
                let addr = &*(ifa.ifa_addr as *const sockaddr_in);
                let ip   = Ipv4Addr::from(addr.sin_addr.s_addr.to_ne_bytes());

                let netmask = &*(ifa.ifa_netmask as *const sockaddr_in);
                let mask    = Ipv4Addr::from(netmask.sin_addr.s_addr.to_ne_bytes());

                freeifaddrs(ifap);

                let cidr        = mask.octets().iter().map(|b| b.count_ones()).sum::<u32>() as u8;
                let ip_u32      = u32::from(ip);
                let mask_u32    = u32::from(mask);
                let network_u32 = ip_u32 & mask_u32;
                let network     = Ipv4Addr::from(network_u32.to_be_bytes());

                return format!("{}/{}", network, cidr);
            }

            cur = ifa.ifa_next;
        }

        freeifaddrs(ifap);
        abort(format!("Interface {} not found or missing IPv4/netmask", iface_name));
    }
}
