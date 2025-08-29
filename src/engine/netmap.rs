use ipnetwork::Ipv4Network;
use std::collections::HashSet;
use std::net::Ipv4Addr;
use crate::packets::pkt_builder::PacketBuilder;
use crate::packets::pkt_sender::PacketSender;
use crate::utils::iface_info::*;



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
        get_default_iface_netmask();
        let mut packet_builder = PacketBuilder::new();
        let packet_sender      = PacketSender::new();
        
        for ip in self.get_ip_range() {
            //let icmp_packet = packet_builder.build_ping_packet(ip);
            //packet_sender.send_icmp(icmp_packet, ip);

            let tcp_packet = packet_builder.build_tcp_packet(ip);
            packet_sender.send_tcp(tcp_packet, ip);
        }
    }


    pub fn get_ip_range(&self) -> impl Iterator<Item = Ipv4Addr> {
        let network = Ipv4Network::new(get_default_iface_ip(), get_default_iface_netmask())
            .expect("[ ERROR ] Invalid network");
        
        network.iter()
            .skip(1)
            .take(network.size() as usize - 2)
            .filter(move |&ip| ip != get_default_iface_ip())
    }

}