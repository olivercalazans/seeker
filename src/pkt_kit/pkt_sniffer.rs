use std::{
    thread,
    sync::{Arc, Mutex},
    sync::atomic::{AtomicBool, Ordering},
};
use pcap::{Device, Capture};
use crate::utils::{get_ipv4_addr, get_iface_cidr};



pub struct PacketSniffer {
    command:     String,
    handle:      Option<thread::JoinHandle<()>>,
    iface:       String,
    raw_packets: Arc<Mutex<Vec<Vec<u8>>>>,
    running:     Arc<AtomicBool>,
    src_ip:      String,
}



impl PacketSniffer {

    pub fn new(command: String, iface: String, target_ip: String) -> Self {
        Self {
            command,
            iface,
            handle:      None,
            raw_packets: Arc::new(Mutex::new(Vec::new())),
            running:     Arc::new(AtomicBool::new(false)),
            src_ip:      target_ip,
        }
    }



    pub fn start_buffered_sniffer(&mut self) {
        self.running.store(true, Ordering::Relaxed);
        let running = Arc::clone(&self.running);
        let packets = Arc::clone(&self.raw_packets);
        let cap     = self.create_sniffer();

        self.handle = Some(thread::spawn(move || {
            Self::capture_loop(cap, running, packets)
        }));
    }



    fn capture_loop(mut cap: Capture<pcap::Active>, running: Arc<AtomicBool>, packets: Arc<Mutex<Vec<Vec<u8>>>>) {
        while running.load(Ordering::Relaxed) {
            if let Ok(pkt) = cap.next_packet() {
                if let Ok(mut v) = packets.lock() {
                    v.push(pkt.data.to_vec());
                }
            }
        }
    }



    fn create_sniffer(&self) -> Capture<pcap::Active> {
        let dev     = PacketSniffer::get_default_iface();
        let mut cap = PacketSniffer::open_capture(dev);
        let filter  = self.get_bpf_filter_parameters();
        cap.filter(&filter, true).unwrap();
        
        let cap = cap.setnonblock().unwrap();
        cap
    }



    fn get_default_iface() -> Device {
        Device::lookup()
            .expect("No default interface")
            .unwrap()
    }



    fn open_capture(dev: Device) -> Capture<pcap::Active> {
        Capture::from_device(dev).unwrap()
            .promisc(false)
            .immediate_mode(true)
            .open()
            .unwrap()
    }



    fn get_bpf_filter_parameters(&self) -> String {
        let my_ip = get_ipv4_addr(&self.iface);

        match self.command.as_str() {
            "netmap"    => format!("tcp and dst host {} and src net {}", my_ip, get_iface_cidr(&self.iface)),
            "pscan-tcp" => format!("tcp[13] & 0x12 == 0x12 and dst host {} and src host {}", my_ip, self.src_ip),
            "pscan-udp" => format!("icmp and icmp[0] == 3 and icmp[1] == 3 and dst host {} and src host {}", my_ip, self.src_ip),
            _           => panic!("[ ERROR ] Unknown filter: {}", self.command),
        }
    }



    pub fn stop(&mut self) {
        self.running.store(false, Ordering::Relaxed);

        if let Some(handle) = self.handle.take() {
            handle.join().unwrap();
        }
    }



    pub fn get_packets(&self) -> Vec<Vec<u8>> {
        self.raw_packets.lock().unwrap().clone()
    }

}
