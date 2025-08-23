use std::collections::HashSet;
use std::net::Ipv4Addr;

use crate::utils::iface_info::{get_default_iface_ip, get_default_iface_netmask};



pub struct Data {
    active_ips: HashSet<String>,
    my_ip: Ipv4Addr,
    netmask: u8,
}


impl Data {
    pub fn new() -> Self {
        Self {
            active_ips: HashSet::new(),
            my_ip:      get_default_iface_ip(),
            netmask:    get_default_iface_netmask(),
        }
    }


    pub fn get_my_ip(&self) -> Ipv4Addr {
        self.my_ip.clone()
    }


    pub fn get_netmask(&self) -> u8 {
        self.netmask.clone()
    }


    pub fn add_active_ip(&mut self, ip:String) {
        self.active_ips.insert(ip);
    }
}