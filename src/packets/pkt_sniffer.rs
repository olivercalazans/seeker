use std::{
    thread,
    sync::{
        Arc, Mutexsync,
        atomic::AtomicBool, Ordering,
    },
};
use pcap::{Device, Capture};
use crate::utils::{get_default_iface_ip, get_network};



pub struct PacketSniffer {
    raw_packets: Arc<Mutex<Vec<Vec<u8>>>>,
    running: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
    my_ip: String,
    cmd_filter: String,
    src_ip: String
}



impl PacketSniffer {

    pub fn new(command: String, target_ip: String) -> Self {
        Self {
            raw_packets: Arc::new(Mutex::new(Vec::new())),
            running: Arc::new(AtomicBool::new(false)),
            handle: None,
            my_ip: get_default_iface_ip().to_string(),
            cmd_filter: command,
            src_ip: target_ip,
        }
    }



    pub fn start_sniffer(&mut self) {
        self.running.store(true, Ordering::Relaxed);
        let packets = Arc::clone(&self.raw_packets);
        let running = Arc::clone(&self.running);
        let mut cap = self.create_sniffer();

        let handle = thread::spawn(move || {
            while running.load(Ordering::Relaxed) {
                if let Ok(packet) = cap.next_packet() {
                    let data = packet.data.to_vec();
                    packets.lock().unwrap().push(data);
                }
            }
        });

        self.handle = Some(handle);
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
            .expect("Não conseguiu achar interface padrão")
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
        match self.cmd_filter.as_str() {
            "netmap" => format!("tcp and dst host {} and src net {}", self.my_ip, get_network()),
            "pscan"  => format!("tcp[13] & 0x12 == 0x12 and dst host {} and src host {}", self.my_ip, self.src_ip),
            _        => panic!("[ ERROR ] Unknown filter: {}", self.cmd_filter),
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
