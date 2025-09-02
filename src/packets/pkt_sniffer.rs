use std::thread;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use pcap::{Device, Capture};
use crate::utils::iface_info::{get_default_iface_ip, get_network};



#[derive(Default)]
pub struct PacketSniffer {
    raw_packets: Arc<Mutex<Vec<Vec<u8>>>>,
    running: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}


impl PacketSniffer {

    pub fn new() -> Self {
        Self {
            raw_packets: Arc::new(Mutex::new(Vec::new())),
            running: Arc::new(AtomicBool::new(false)),
            handle: None,
        }
    }


    pub fn start_sniffer(&mut self) {
        self.running.store(true, Ordering::Relaxed);
        let packets = Arc::clone(&self.raw_packets);
        let running = Arc::clone(&self.running);

        let handle = thread::spawn(move || {
            let mut cap = PacketSniffer::create_sniffer();

            while running.load(Ordering::Relaxed) {
                if let Ok(packet) = cap.next_packet() {
                    let data = packet.data.to_vec();
                    packets.lock().unwrap().push(data);
                    println!("pegou um")
                }
            }
        });

        self.handle = Some(handle);
    }



    fn create_sniffer() -> Capture<pcap::Active> {
        let dev     = PacketSniffer::get_default_iface();
        let mut cap = PacketSniffer::open_capture(dev);
        let filter  = PacketSniffer::get_bpf_filter_parameters();
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



    fn get_bpf_filter_parameters() -> String {
        format!(
            "tcp and dst host {} and src net {}",
            get_default_iface_ip().to_string(),
            get_network()
        )
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
