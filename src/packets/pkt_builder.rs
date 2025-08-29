use pnet::packet::{MutablePacket, Packet};
use pnet::packet::ethernet::MutableEthernetPacket;
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{MutableIpv4Packet, checksum as ip_checksum};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, ipv4_checksum as tcp_checksum};
use pnet::packet::icmp::{IcmpTypes, MutableIcmpPacket, checksum as icmp_checksum};
use pnet::util::{MacAddr};
use rand::Rng;
use std::net::Ipv4Addr;
use crate::utils::iface_info::{get_default_iface_ip, get_default_mac_addr};



pub struct PacketBuilder {
    src_ip: Ipv4Addr,
    src_mac: MacAddr,
    dst_ip: Ipv4Addr,
    dst_mac: MacAddr,
    protocol: u8,
    dst_port: u16
}


impl PacketBuilder {

    pub fn new() -> Self {
        Self {
            src_ip:    get_default_iface_ip(),
            src_mac:   MacAddr::broadcast(), // TROCAR
            dst_ip:    Ipv4Addr::new(0, 0, 0, 0),
            dst_mac:   MacAddr::broadcast(),
            protocol:  0,
            dst_port:  80,
        }
    }


    pub fn build_tcp_packet(&mut self, dst_ip: Ipv4Addr) -> Vec<u8> {
        self.dst_ip    = dst_ip;
        self.protocol  = 6;
        let mut buffer = [0u8; 40];
        self.add_ip_layer(&buffer);
        self.add_tcp_layer(&buffer);
        self.build_ethernet_frame(&ip_packet)
    }



    pub fn build_ping_packet(&mut self, dst_ip: Ipv4Addr) -> Vec<u8> {
        self.protocol   = 13;
        let icmp_packet = Self::get_icmp_layer();
        let ip_packet   = self.add_ip_layer(&icmp_packet);
        self.build_ethernet_frame(&ip_packet)
    }


    
    fn get_icmp_layer() -> Vec<u8> {
        let mut buffer = vec![0u8; 28];
        let mut packet = MutableIcmpPacket::new(&mut buffer).unwrap();
        packet.set_icmp_type(IcmpTypes::EchoRequest);
        let checksum = icmp_checksum(&packet.to_immutable());
        packet.set_checksum(checksum);

        buffer
    }



    fn add_tcp_layer(&self, buffer: [u8]) {
        let mut tcp_header = MutableTcpPacket::new(&mut buffer[20..]).unwrap();
        tcp_header.set_source(12345);
        tcp_header.set_destination(80);
        tcp_header.set_sequence(1);
        tcp_header.set_flags(TcpFlags::SYN);
        tcp_header.set_window(64240);
        tcp_header.set_data_offset(5);

        let pseudo_header_sum = tcp_checksum(&tcp_header.to_immutable(), self.src_ip, self.dst_ip);
        tcp_header.set_checksum(pseudo_header_sum);
    }



    fn add_ip_layer(&self, buffer: &[u8]) {
        let mut ip_header = MutableIpv4Packet::new(&mut buffer[..20]).unwrap();
        ip_header.set_version(4);
        ip_header.set_header_length(5);
        ip_header.set_total_length(40);
        ip_header.set_ttl(64);
        ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip_header.set_source(Ipv4Addr::new(192, 168, 1, 197));
        ip_header.set_destination(Ipv4Addr::new(192, 168, 1, 1));

        let checksum = ipv4_checksum(&ip_header.to_immutable());
        ip_header.set_checksum(checksum);
    }



    fn build_ethernet_frame(&self, ip_packet: &[u8]) -> Vec<u8> {
        let eth_header_size     = 14;
        let total_size          = eth_header_size + ip_packet.len();
        let mut buffer          = vec![0u8; total_size];
        let mut ethernet_packet = MutableEthernetPacket::new(&mut buffer).unwrap();
        ethernet_packet.set_destination(MacAddr::broadcast());
        ethernet_packet.set_source(self.src_mac);
        ethernet_packet.set_ethertype(EtherTypes::Ipv4);        
        ethernet_packet.set_payload(ip_packet);
        
        buffer
    }

}