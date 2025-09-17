use std::collections::{HashMap, HashSet, VecDeque};
use std::thread;
use std::time::Duration;
use crossbeam::channel::unbounded;



pub struct NetworkWatcher {
    dns: HashMap<String, String>,
    hosts: HashMap<String, HashSet<String>>
    raw_packets: VecDeque,
}


impl NetworkWatcher {

    pub fn new() -> Self {
        Self {
            hosts: HashMap::new(),
            dns: HashMap::new(),
            raw_packets:VecDeque::new(),
        }
    }



    pub fn execute(&mut self) {

    }



    fn add_site(&mut self, ip: &str, site: String) {
        self.hosts.entryentry(ip.clone()).or_default().insert(site.clone());
    }

}