use std::net::Ipv4Addr;
use rand::{Rng, rngs::ThreadRng};
use pnet::datalink::MacAddr;
use pnet::packet::{
    util::checksum, Packet,
    ethernet::{EtherTypes, MutableEthernetPacket},
    ip::{IpNextHeaderProtocols, IpNextHeaderProtocol},
    ipv4::{MutableIpv4Packet, checksum as ip_checksum},
    icmp::{IcmpTypes, echo_request::{MutableEchoRequestPacket, IcmpCodes}},
    tcp::{MutableTcpPacket, TcpFlags, ipv4_checksum as tcp_checksum},
    udp::{MutableUdpPacket, ipv4_checksum as udp_checksum},
};
use crate::pkt_kit::{HeaderBuffer, PacketBuffer};
use crate::utils::{get_ipv4_addr};



pub struct PacketBuilder {
    headers: HeaderBuffer,
    packets: PacketBuffer,
    src_ip:  Ipv4Addr,
    rng:     ThreadRng,
}


impl PacketBuilder {

    pub fn new(iface: String, src_ip: Option<Ipv4Addr>) -> Self {
        Self {
            headers: HeaderBuffer::default(),
            packets: PacketBuffer::default(),
            src_ip:  src_ip.unwrap_or_else(|| get_ipv4_addr(&iface)),
            rng:     rand::thread_rng(),
        }
    }



    pub fn build_tcp_ether_packet(&mut self, src_ip: Ipv4Addr, dst_ip: Ipv4Addr) -> &[u8] {
        self.create_ether_header();
        self.create_ip_header(40, IpNextHeaderProtocols::Tcp, src_ip, dst_ip);
        self.create_tcp_header(src_ip, dst_ip, 80);
        
        self.packets.tcp_layer2[..14].copy_from_slice(&self.headers.ether);
        self.packets.tcp_layer2[14..34].copy_from_slice(&self.headers.ip);
        self.packets.tcp_layer2[34..].copy_from_slice(&self.headers.tcp);
        &self.packets.tcp_layer2
    }



    pub fn build_tcp_ip_packet(&mut self, dst_ip: Ipv4Addr, dst_port: u16) -> &[u8] {
        self.create_ip_header(40, IpNextHeaderProtocols::Tcp, self.src_ip, dst_ip);
        self.create_tcp_header(self.src_ip, dst_ip, dst_port);
        
        self.packets.tcp_layer3[..20].copy_from_slice(&self.headers.ip);
        self.packets.tcp_layer3[20..].copy_from_slice(&self.headers.tcp);
        &self.packets.tcp_layer3
    }



    pub fn build_udp_ether_packet(&mut self, src_ip: Ipv4Addr, dst_ip: Ipv4Addr) -> &[u8] {
        self.create_ether_header();
        self.create_ip_header(28, IpNextHeaderProtocols::Udp, src_ip, dst_ip);
        self.create_udp_header(src_ip, dst_ip, 53);

        self.packets.udp_layer2[..14].copy_from_slice(&self.headers.ether);
        self.packets.udp_layer2[14..34].copy_from_slice(&self.headers.ip);
        self.packets.udp_layer2[34..].copy_from_slice(&self.headers.udp);
        &self.packets.udp_layer2
    }



    pub fn build_udp_ip_packet(&mut self, dst_ip: Ipv4Addr, dst_port: u16) -> &[u8] {
        self.create_ip_header(28, IpNextHeaderProtocols::Udp, self.src_ip, dst_ip);
        self.create_udp_header(self.src_ip, dst_ip, dst_port);

        self.packets.udp_layer3[..20].copy_from_slice(&self.headers.ip);
        self.packets.udp_layer3[20..].copy_from_slice(&self.headers.udp);
        &self.packets.udp_layer3
    }



    pub fn build_icmp_echo_req_packet(&mut self, dst_ip: Ipv4Addr) -> &[u8] {
        self.create_ip_header(28, IpNextHeaderProtocols::Icmp, self.src_ip, dst_ip);
        self.create_icmp_header();

        self.packets.icmp_layer3[..20].copy_from_slice(&self.headers.ip);
        self.packets.icmp_layer3[20..].copy_from_slice(&self.headers.icmp);
        &self.packets.icmp_layer3
    }



    fn create_tcp_header(&mut self, src_ip: Ipv4Addr, dst_ip: Ipv4Addr, dst_port: u16) {
        let src_port = self.rng.gen_range(10000..=65535);
        
        let mut tcp_header = MutableTcpPacket::new(&mut self.headers.tcp).unwrap();
        tcp_header.set_source(src_port);
        tcp_header.set_destination(dst_port);
        tcp_header.set_sequence(1);
        tcp_header.set_flags(TcpFlags::SYN);
        tcp_header.set_window(64240);
        tcp_header.set_data_offset(5);

        let pseudo_header_sum = tcp_checksum(&tcp_header.to_immutable(), &src_ip, &dst_ip);
        tcp_header.set_checksum(pseudo_header_sum);
    }



    fn create_udp_header(&mut self, src_ip: Ipv4Addr, dst_ip: Ipv4Addr, dst_port: u16) {
        let src_port = self.rng.gen_range(10000..=65535);

        let mut udp_header = MutableUdpPacket::new(&mut self.headers.udp).unwrap();
        udp_header.set_source(src_port);
        udp_header.set_destination(dst_port);
        udp_header.set_length(8u16);

        let checksum = udp_checksum(&udp_header.to_immutable(), &src_ip, &dst_ip);
        udp_header.set_checksum(checksum);
    }



    fn create_icmp_header(&mut self) {
        let mut icmp_header = MutableEchoRequestPacket::new(&mut self.headers.icmp).unwrap();
        icmp_header.set_icmp_type(IcmpTypes::EchoRequest);
        icmp_header.set_icmp_code(IcmpCodes::NoCode);
        icmp_header.set_identifier(0x1234);
        icmp_header.set_sequence_number(1);
        icmp_header.set_payload(&[]);
        icmp_header.set_checksum(0);

        let checksum = checksum(&icmp_header.packet(), 1);
        icmp_header.set_checksum(checksum);
    }



    fn create_ip_header(&mut self, len: u8, protocol: IpNextHeaderProtocol, src_ip: Ipv4Addr, dst_ip:Ipv4Addr) {
        let mut ip_header = MutableIpv4Packet::new(&mut self.headers.ip).unwrap();
        ip_header.set_version(4);
        ip_header.set_header_length(5);
        ip_header.set_total_length(len.into());
        ip_header.set_ttl(64);
        ip_header.set_next_level_protocol(protocol);
        ip_header.set_source(src_ip);
        ip_header.set_destination(dst_ip);

        let checksum = ip_checksum(&ip_header.to_immutable());
        ip_header.set_checksum(checksum);
    }



    fn create_ether_header(&mut self) {
        let dst_mac        = self.random_mac();
        let src_mac        = self.random_mac();
        let mut eth_header = MutableEthernetPacket::new(&mut self.headers.ether).unwrap();
        eth_header.set_source(src_mac);
        eth_header.set_destination(dst_mac);
        eth_header.set_ethertype(EtherTypes::Ipv4);
    }



    fn random_mac(&mut self) -> MacAddr {
        let mut bytes = [0u8; 6];
        for b in bytes.iter_mut() { *b = self.rng.r#gen(); }
        bytes[0] = (bytes[0] | 0x02) & 0xFE;
        MacAddr::new(bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5])
    }

}