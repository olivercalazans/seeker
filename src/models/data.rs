use std::collections::HashSet;

use crate::utils::iface_info::{get_default_iface_ip, get_default_iface_netmask};



#[derive(Default)]
pub struct Data {
    my_ip:String,
    netmask: String,
    active_ips: HashSet<String>,
}


impl Data {
    pub fn new() -> Self {
        Self {
            my_ip:   get_default_iface_ip(),
            netmask: get_default_iface_netmask(),
            ..Default::default()
        }
    }


    pub fn get_my_ip(&self) -> String {
        self.my_ip.clone()
    }


    pub fn get_netmask(&self) -> String {
        self.netmask.clone()
    }


    pub fn add_active_ip(&mut self, ip:String) {
        self.active_ips.insert(ip);
    }
}