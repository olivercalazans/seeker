use pnet::packet::MutablePacket;
use pnet::packet::ipv4::{MutableIpv4Packet};
use pnet::packet::tcp::{MutableTcpPacket};
use pnet::packet::icmp::{IcmpTypes, MutableIcmpPacket};
use rand::Rng;
use std::net::Ipv4Addr;
use crate::utils::iface_info::get_default_iface_ip;



pub struct PacketBuilder {
    src_ip: Ipv4Addr,
    protocol: pnet::packet::ip::IpNextHeaderProtocol,
    total_len: u8,
    dst_port: u8
}


impl PacketBuilder {

    pub fn new() -> Self {
        Self {
            src_ip:    get_default_iface_ip(),
            protocol:  pnet::packet::ip::IpNextHeaderProtocol(0),
            total_len: 0,
            dst_port:  80,
        }
    }


    pub fn build_tcp_packet(&mut self, dst_ip:Ipv4Addr) -> Vec<u8> {
        self.protocol  = pnet::packet::ip::IpNextHeaderProtocols::Tcp;
        self.total_len = 40;
        let mut buffer = vec![0u8; 40];

        let mut ip_pkt = MutableIpv4Packet::new(&mut buffer).unwrap();
        self.add_ip_layer(&mut ip_pkt, dst_ip);

        let mut tcp_pkt = MutableTcpPacket::new(ip_pkt.payload_mut()).unwrap();
        self.add_tcp_layer(&mut tcp_pkt);

        self.calculate_tcp_checksum(&mut tcp_pkt, dst_ip);
        Self::calculate_ip_checksum(&mut ip_pkt);

        buffer
    }



    pub fn build_ping_packet(&mut self, dst_ip:Ipv4Addr) -> Vec<u8> {
        self.protocol  = pnet::packet::ip::IpNextHeaderProtocols::Icmp;
        self.total_len = 28;
        let mut buffer = vec![0u8; 28];
        
        let mut ip_pkt = MutableIpv4Packet::new(&mut buffer).unwrap();
        self.add_ip_layer(&mut ip_pkt, dst_ip);

        let mut icmp_pkt = MutableIcmpPacket::new(ip_pkt.payload_mut()).unwrap();
        Self::add_icmp_layer(&mut icmp_pkt);
        
        Self::calculate_icmp_checksum(&mut icmp_pkt);
        Self::calculate_ip_checksum(&mut ip_pkt);
        
        buffer
    }




    fn add_ip_layer(&self, packet:&mut MutableIpv4Packet, dst_ip:Ipv4Addr) {
        packet.set_version(4);
        packet.set_header_length(5);
        packet.set_total_length(self.total_len.into());
        packet.set_ttl(64);
        packet.set_next_level_protocol(self.protocol);
        packet.set_source(self.src_ip);
        packet.set_destination(dst_ip);
        packet.set_identification(rand::random::<u16>());
    }
    

    fn calculate_ip_checksum(packet:&mut MutableIpv4Packet) {
        let ip_checksum = pnet::packet::ipv4::checksum(&packet.to_immutable());
        packet.set_checksum(ip_checksum);
    }



    
    fn add_tcp_layer(&self, packet:&mut MutableTcpPacket) {
        let mut rng = rand::thread_rng();
        packet.set_source(rng.gen_range(10000..65536));
        packet.set_destination(self.dst_port.into());
        packet.set_sequence(rand::random::<u32>());
        packet.set_data_offset(5);
        packet.set_flags(0x02);
        packet.set_window(64240);
    }


    fn calculate_tcp_checksum(&self, packet:&mut MutableTcpPacket, dst_ip:Ipv4Addr) {
        let tcp_checksum = pnet::packet::tcp::ipv4_checksum(
            &packet.to_immutable(),
            &self.src_ip,
            &dst_ip
        );
        packet.set_checksum(tcp_checksum);
    }



    
    fn add_icmp_layer(packet:&mut MutableIcmpPacket) {
        packet.set_icmp_type(IcmpTypes::EchoRequest);
        packet.set_identifier(std::process::id() as u16);
        packet.set_sequence_number(1);
    }


    fn calculate_icmp_checksum(packet:&mut MutableIcmpPacket) {
        let icmp_checksum = pnet::packet::icmp::checksum(&packet.to_immutable());
        packet.set_checksum(icmp_checksum);
    }

}