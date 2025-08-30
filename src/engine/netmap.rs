use ipnet::Ipv4AddrRange;
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::thread;
use std::time::Duration;
use crate::packets::pkt_builder::PacketBuilder;
use crate::packets::pkt_sender::PacketSender;
use crate::utils::iface_info::get_default_iface_info;



#[derive(Default)]
pub struct NetworkMapper {
    responses: Vec<u8>,
    active_ips: HashSet<Ipv4Addr>,
}


impl NetworkMapper {

    pub fn new() -> Self {
        Default::default()
    }


    pub fn execute(&self) {
        let mut packet_builder = PacketBuilder::new();
        let mut packet_sender  = PacketSender::new();
        
        for ip in Self::get_ip_range() {
            let tcp_packet = packet_builder.build_tcp_packet(ip, 80);
            packet_sender.send_tcp(tcp_packet, ip);
        }
    }


    fn get_ip_range() -> Ipv4AddrRange {
        get_default_iface_info().hosts()
    }

}