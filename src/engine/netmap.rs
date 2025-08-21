// MIT License
// Copyright (c) 2025 Oliver Calazans
// Repository: https://github.com/olivercalazans/seeker
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software...

use stc::collections::HashSet;


#[derive(Default)]
pub struct NetworkMapper {
    ip_range: Vec<String>,
    active_ips: HashSet<String>,
}


impl NetworkMapper {

    pub fn new() -> Self {
        Default::default()
    }


    pub add_active_ip(&mut self, ip:String) {
        self.active_ips.insert(ip);
    }


    pub fn execute(&self) {
        self
    }


    pub get_ip_range(&mut self) {

    }
}