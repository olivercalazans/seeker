use std::collections::{HashMap, HashSet};


pub struct NetworkWatcher {
    hosts: HashMap<String, HostInfo>
    dns: HashMap<String, String>,
}


#[derive(Default)]
pub struct HostInfo {
    ports: HashSet<u16>,
    sites: HashSet<String>,
}


impl NetworkWatcher {

    pub fn new() -> Self {
        Self { hosts: HashMap::new(), }
    }



    pub fn execute(&mut self) {

    }



    fn add_port(&mut self, ip: &str, port: u16) {
        self.hosts.entry(ip.to_string()).or_default().ports.insert(port);
    }



    fn add_site(&mut self, ip: &str, site: String) {
        self.hosts.entry(ip.to_string()).or_default().sites.insert(site);
    }

}