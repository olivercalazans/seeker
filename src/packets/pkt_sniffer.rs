use std::thread;
use std::sync::mpsc;
use std::net::Ipv4Addr;
use pcap::{Device, Capture};
use etherparse::{SlicedPacket, InternetSlice};
use crate::utils::iface_info::get_default_iface_ip;



#[derive(Default)]
pub struct PacketSniffer {
    packets:Vec
}


impl PacketSniffer {

    pub fn new() -> Self {
        Default::default()
    }


    pub fn start_sniffer(&self) {
        let (tx, rx) = mpsc::channel::<Ipv4Addr>();

        thread::spawn(move || {
            let dev     = PacketSniffer::get_default_iface();
            let mut cap = PacketSniffer::open_capture(dev);
            let filter  = PacketSniffer::get_bpf_filter_parameters();
            cap.filter(&filter, true).unwrap();

            while let Ok(packet) = cap.next_packet() {
                let data = packet.data.to_vec();
                packets.lock().unwrap().push(data);
            }
        });
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
            "tcp and dst host {} and \
            ((tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack)) \
            or (tcp[tcpflags] & tcp-rst != 0))",
            get_default_iface_ip().to_string()
        )
    }

}
