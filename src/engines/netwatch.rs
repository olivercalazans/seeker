use std::{
    collections::{HashMap, HashSet, VecDeque},
    thread,
    time::Duration,
    sync::{Arc, Mutex},
    sync::atomic::{AtomicBool, Ordering},
};
use crossbeam::channel::{unbounded, Receiver, Sender};
use crate::pkt_kit::{PacketDissector, PacketSniffer};
use crate::utils::get_host_name;



pub struct NetworkWatcher {
    dns:            Mutex<HashMap<String, String>>,
    hosts:          HashMap<String, HashSet<String>>,
    ips_receiver:   Receiver<String>,
    ips_sender:     Sender<String>,
    raw_packets:    VecDeque<Vec<u8>>,
    running:        Arc<AtomicBool>
}


impl NetworkWatcher {

    pub fn new() -> Self {
        let (tx, rx) = unbounded();
        Self {
            dns:            Mutex::new(HashMap::new()),
            hosts:          Mutex::new(HashMap::new()),
            ips_receiver:   rx,
            ips_sender:     tx,
            raw_packets:    VecDeque::new(),
            running:        Arc::new(AtomicBool::new(false)),
        }
    }



    pub fn execute(&mut self) {
        self.start_dns_thread();
    }



    fn start_dns_thread(self: Arc<Self>) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            while self.running.load(Ordering::Relaxed) {
                if let Some(ip) = self.receive_ip() {
                    if !self.is_resolved(&ip) {
                        self.resolve_and_store(ip);
                    }
                }
            }
        })
    }


    fn receive_ip(&self) -> Option<String> {
        match self.ips_receiver.recv() {
            Ok(ip) => Some(ip),
            Err(_) => None,
        }
    }


    fn is_resolved(&self, ip: &str) -> bool {
        let dns_map = self.dns.lock().unwrap();
        dns_map.contains_key(ip)
    }


    fn resolve_and_store(&self, ip: String) {
        let hostname = get_host_name(&ip);
        let mut dns_map = self.dns.lock().unwrap();
        dns_map.insert(ip, hostname);
    }


    
    fn queue_ip(&self, ip: String) {
        let _ = self.ips_sender.send(ip);
    }



    fn add_site(&mut self, ip: &str, site: String) {
        self.hosts.entryentry(ip.clone()).or_default().insert(site.clone());
    }

}