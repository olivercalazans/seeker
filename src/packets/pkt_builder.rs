use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::tcp::{TcpPacket, MutableTcpPacket};
use pnet::packet::icmp::{IcmpPacket, IcmpTypes, MutableIcmpPacket};
use pnet::packet::Packet;
use anyhow::{Result, anyhow};
use rand::Rng;
use std::net::Ipv4Addr;
use crate::utils::iface_info::get_default_iface_ip;



struct PacketBuilder {
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    protocol: u8,
    total_len: u8,
    dst_port: u8
}


impl PacketBuilder {

    pub fn new() -> Self {
        Self {
            src_ip:    get_default_iface_ip(),
            dst_ip:    Ipv4Addr::new(0, 0, 0, 0),
            protocol:  0,
            total_len: 0,
            dst_port:  80,
        }
    }


    pub fn build_tcp_packet(&mut self, dst_ip:Ipv4Addr) -> Vec<u8> {
        self.protocol  = pnet::packet::ip::IpNextHeaderProtocols::Tcp;
        self.total_len = 40;
        let mut buffer = vec![0u8; 40];

        let mut ip_packet = MutableIpv4Packet::new(&mut buffer).unwrap();
        self.add_ip_layer(ip_packet);

        let mut tcp_packet = MutableTcpPacket::new(ip_packet.payload_mut()).unwrap();
        self.add_ip_layer(tcp_packet);
        self.calculate_tcp_checksum(tcp_packet, dst_ip)

        Self::calculate_ip_checksum(ip_packet)

        buffer
    }



    pub fn build_ping_packet(&mut self) -> Vec<u8> {
        self.protocol  = pnet::packet::ip::IpNextHeaderProtocols::Icmp;
        self.total_len = 28;
        let mut buffer = vec![0u8; 28];  // IP header (20) + ICMP (8)
        
        let mut ip_pkt = MutableIpv4Packet::new(&mut buffer).unwrap();
        ip_pkt         = self.add_ip_layer(ip_pkt, 28);

        let mut icmp_pkt = MutableIcmpPacket::new(ip_pkt.payload_mut()).unwrap();
        icmp_pkt         = Self::add_icmp_layer(icmp_pkt);
        
        Self::calculate_icmp_checksum(icmp_packet);
        Self::calculate_ip_checksum(ip_packet);
        
        buffer
    }




    fn add_ip_layer(&self, packet:&mut MutableIpv4Packet) {
        packet.set_version(4);
        packet.set_header_length(5);
        packet.set_total_length(self.total_len);
        packet.set_ttl(64);
        packet.set_next_level_protocol(self.protocol);
        packet.set_source(self.src_ip);
        packet.set_destination(self.dst_ip);
        packet.set_identification(rand::random::<u16>());
    }
    

    fn calculate_ip_checksum(packet:&mut MutableIpv4Packet) {
        let ip_checksum = pnet::packet::ipv4::checksum(&packet.to_immutable());
        packet.set_checksum(ip_checksum);
    }



    
    fn add_tcp_layer(&self, packet:&mut MutableTcpPacket) {
        packet.set_source_port(rng.gen_range(10000..65536));
        packet.set_destination_port(self.dst_port);
        packet.set_sequence(rand::random::<u32>());
        packet.set_data_offset(5); // 5 words = 20 bytes
        packet.set_flags(0x02);    // SYN flag
        packet.set_window(64240);
    }


    fn calculate_tcp_checksum(&self, packet:&mut MutableTcpPacket, dst_ip:Ipv4Addr) {
        let tcp_checksum = pnet::packet::tcp::ipv4_checksum(
            &tcp_packet.to_immutable(),
            &self.source_ip,
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