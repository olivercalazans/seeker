use std::time::Duration;
use std::thread;
use std::collections::HashSet;
use std::net::Ipv4Addr;
use ipnet::Ipv4AddrRange;
use crate::packets::pkt_builder::PacketBuilder;
use crate::packets::pkt_dissector::PacketDissector;
use crate::packets::pkt_sender::PacketSender;
use crate::packets::pkt_sniffer::PacketSniffer;
use crate::utils::iface_info::get_default_iface_info;



#[derive(Default)]
pub struct NetworkMapper {
    raw_packets: Vec<Vec<u8>>,
    active_ips: HashSet<Ipv4Addr>,
}


impl NetworkMapper {

    pub fn new() -> Self {
        Default::default()
    }



    pub fn execute(&mut self) {
        self.send_probes();
        self.process_raw_packets();
        self.display_result();
    }



    fn send_probes(&mut self) {
        let mut packet_builder = PacketBuilder::new();
        let mut packet_sender  = PacketSender::new();
        let mut packet_sniffer = PacketSniffer::new();

        packet_sniffer.start_sniffer();
        
        for ip in Self::get_ip_range() {
            let tcp_packet = packet_builder.build_tcp_packet(ip, 80);
            packet_sender.send_tcp(tcp_packet, ip);
        }
        
        thread::sleep(Duration::from_secs(10));
        
        packet_sniffer.stop();
        self.raw_packets = packet_sniffer.get_packets();
    }



    fn get_ip_range() -> Ipv4AddrRange {
        get_default_iface_info().hosts()
    }



    fn process_raw_packets(&mut self) {
        for packet in &self.raw_packets {
            if let Some(src_ip) = PacketDissector::get_src_ip(&packet) {
                self.active_ips.insert(src_ip);
            }
        }
    }



    fn display_result(&self) {
        for ip in &self.active_ips{
            println!("{}", ip);
        }
    }

}