use pnet::packet::icmp::{IcmpPacket, IcmpTypes, MutableIcmpPacket};
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::Packet;
use socket2::{Socket, Domain, Type, Protocol};
use std::net::Ipv4Addr;
use anyhow::{Result, anyhow};



struct PacketBuilder {
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    protocol: u8,
}


impl PacketBuilder {

    pub fn new(my_ip:Ipv4Addr) -> Self {
        Self {
            src_ip:   my_ip,
            dst_ip:   Ipv4Addr(0, 0, 0, 0),
            protocol: 0,
        }
    }


    pub fn build_ping_packet(&mut self) -> Vec<u8> {
        self.protocol  = pnet::packet::ip::IpNextHeaderProtocols::Icmp;
        let mut packet = vec![0u8; 28];  // IP header (20) + ICMP (8)
        let mut ip_pkt = MutableIpv4Packet::new(&mut packet).unwrap();
        ip_pkt         = self.add_ip_layer(ip_pkt);

        let mut icmp_pkt = MutableIcmpPacket::new(ip_pkt.payload_mut()).unwrap();
        icmp_pkt         = Self::add_icmp_layer(icmp_pkt);

        let icmp_checksum = pnet::packet::icmp::checksum(&icmp_packet.to_immutable());
        icmp_packet.set_checksum(icmp_checksum);
        
        let ip_checksum = pnet::packet::ipv4::checksum(&ip_packet.to_immutable());
        ip_packet.set_checksum(ip_checksum);
        
        packet
    }


    fn add_ip_layer(&self, packet:Vec<u8>) -> Vec<u8> {
        packet.set_version(4);
        packet.set_header_length(5);
        packet.set_total_length(40);
        packet.set_ttl(64);
        packet.set_next_level_protocol(self.protocol);
        packet.set_source(self.src_ip);
        packet.set_destination(self.dst_ip);
        packet.set_identification(rand::random::<u16>());
        packet
    }


    fn add_icmp_layer(packet:Vec<u8>) -> Vec<u8> {
        packet.set_icmp_type(IcmpTypes::EchoRequest);
        packet.set_identifier(std::process::id() as u16);
        packet.set_sequence_number(1);
        packet
    }
}