// MIT License
// Copyright (c) 2025 Oliver Calazans
// Repository: https://github.com/olivercalazans/seeker
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software...

use std::collections::HashSet;

use crate::utils::iface_info::{get_my_ip, get_netmask};


#[derive(Default)]
pub struct NetworkMapper {
    ip_range: Vec<String>,
    active_ips: HashSet<String>,
}


impl NetworkMapper {

    pub fn new() -> Self {
        Default::default()
    }


    pub fn add_active_ip(&mut self, ip:String) {
        self.active_ips.insert(ip);
    }


    pub fn execute(&self) {
        let ip = get_my_ip();
        let netmask = get_netmask();
        println!("My IP: {}, Netmask {}", ip, netmask);
    }
}