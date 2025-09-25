use std::net::Ipv4Addr;
use rand::{Rng, rngs::ThreadRng};
use pnet::datalink::MacAddr;
use pnet::packet::{
    ethernet::{EtherTypes, MutableEthernetPacket},
    ip::{IpNextHeaderProtocols, IpNextHeaderProtocol},
    ipv4::{MutableIpv4Packet, checksum as ip_checksum},
    tcp::{MutableTcpPacket, TcpFlags, ipv4_checksum as tcp_checksum},
};
use crate::utils::{default_ipv4_addr, default_iface_mac};



pub struct PacketBuilder {
    buffer:  [u8; 40],
    src_ip:  Ipv4Addr,
    src_mac: MacAddr,
    rng:     ThreadRng,
}


impl PacketBuilder {

    pub fn new() -> Self {
        Self {
            buffer:  [0u8; 40],
            src_ip:  default_ipv4_addr(),
            src_mac: default_iface_mac(),
            rng:     rand::thread_rng(),
        }
    }



    pub fn build_tcp_ether_packet(&mut self, dst_ip: Ipv4Addr) -> [u8; 40] {

    }



    pub fn build_tcp_ip_packet(&mut self, dst_ip: Ipv4Addr, dst_port: u16) -> [u8; 40] {
        self.add_ip_header(dst_ip, IpNextHeaderProtocols::Tcp);
        self.add_tcp_header(dst_ip, dst_port);
        self.buffer
    }



    fn add_tcp_header(&mut self, dst_ip: Ipv4Addr, dst_port: u16) {
        let src_port       = self.rng.gen_range(10000..=65535);
        let mut tcp_header = MutableTcpPacket::new(&mut self.buffer[20..]).unwrap();
        tcp_header.set_source(src_port);
        tcp_header.set_destination(dst_port);
        tcp_header.set_sequence(1);
        tcp_header.set_flags(TcpFlags::SYN);
        tcp_header.set_window(64240);
        tcp_header.set_data_offset(5);

        let pseudo_header_sum = tcp_checksum(&tcp_header.to_immutable(), &self.src_ip, &dst_ip);
        tcp_header.set_checksum(pseudo_header_sum);
    }



    fn add_ip_header(&mut self, dst_ip:Ipv4Addr, protocol: IpNextHeaderProtocol) {
        let mut ip_header = MutableIpv4Packet::new(&mut self.buffer[..20]).unwrap();
        ip_header.set_version(4);
        ip_header.set_header_length(5);
        ip_header.set_total_length(40);
        ip_header.set_ttl(64);
        ip_header.set_next_level_protocol(protocol);
        ip_header.set_source(self.src_ip);
        ip_header.set_destination(dst_ip);

        let checksum = ip_checksum(&ip_header.to_immutable());
        ip_header.set_checksum(checksum);
    }



    fn add_ether_header(&mut self) {
        let dst_mac        = self.random_mac();
        let mut eth_header = MutableEthernetPacket::new(&mut self.buffer[..14]).unwrap();
        eth_header.set_source(self.src_mac);
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