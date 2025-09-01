use std::time::Duration;
use std::thread;
use std::collections::HashSet;
use std::net::Ipv4Addr;
use ipnet::Ipv4AddrRange;
use crate::packets::pkt_builder::PacketBuilder;
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
        let mut packet_builder = PacketBuilder::new();
        let mut packet_sender  = PacketSender::new();
        let mut packet_sniffer = PacketSniffer::new();

        packet_sniffer.start_sniffer();
        
        for ip in Self::get_ip_range() {
            let tcp_packet = packet_builder.build_tcp_packet(ip, 80);
            packet_sender.send_tcp(tcp_packet, ip);
        }
        
        thread::sleep(Duration::from_secs(10));
        self.raw_packets = packet_sniffer.get_packets();
    }


    fn get_ip_range() -> Ipv4AddrRange {
        get_default_iface_info().hosts()
    }

}