use std::net::Ipv4Addr;
use pnet::datalink::MacAddr;
use pnet::packet::{
    util::checksum, Packet,
    ethernet::{EtherTypes, MutableEthernetPacket},
    ip::IpNextHeaderProtocol,
    ipv4::{MutableIpv4Packet, checksum as ip_checksum},
    icmp::{IcmpTypes, echo_request::{MutableEchoRequestPacket, IcmpCodes}},
    tcp::{MutableTcpPacket, TcpFlags, ipv4_checksum as tcp_checksum},
};
use crate::pkt_kit::checksum::*;



pub struct HeaderBuilder;



impl HeaderBuilder { 

    pub fn create_tcp_header(
            tcp_buffer: &mut [u8],
            src_ip:     Ipv4Addr,
            src_port:   u16, 
            dst_ip:     Ipv4Addr,
            dst_port:   u16
        ) {  
            let mut tcp_header = MutableTcpPacket::new(tcp_buffer).unwrap();
            tcp_header.set_source(src_port);
            tcp_header.set_destination(dst_port);
            tcp_header.set_sequence(1);
            tcp_header.set_flags(TcpFlags::SYN);
            tcp_header.set_window(64240);
            tcp_header.set_data_offset(5);
            let pseudo_header_sum = tcp_checksum(&tcp_header.to_immutable(), &src_ip, &dst_ip);
            tcp_header.set_checksum(pseudo_header_sum);
    }



    pub fn create_udp_header(
            buffer:      &mut [u8],
            src_ip:      Ipv4Addr,
            src_port:    u16,
            dst_ip:      Ipv4Addr,
            dst_port:    u16,
            len_payload: u16
        ) {            
            buffer[0] = (src_port >> 8) as u8;
            buffer[1] = src_port as u8;
            
            buffer[2] = (dst_port >> 8) as u8;
            buffer[3] = src_port as u8;
            
            let len   = 8 + len_payload;
            buffer[4] = (len >> 8) as u8;
            buffer[5] = len as u8;

            let cksum = udp_checksum(&buffer[..8], &src_ip, &dst_ip);
            buffer[6] = (cksum >> 8) as u8;
            buffer[7] = cksum as u8;
    }



    pub fn create_icmp_header(
            icmp_buffer: &mut [u8]
        ) {
            let mut icmp_header = MutableEchoRequestPacket::new(icmp_buffer).unwrap();
            icmp_header.set_icmp_type(IcmpTypes::EchoRequest);
            icmp_header.set_icmp_code(IcmpCodes::NoCode);
            icmp_header.set_identifier(0x1234);
            icmp_header.set_sequence_number(1);
            icmp_header.set_payload(&[]);
            icmp_header.set_checksum(0);

            let checksum = checksum(&icmp_header.packet(), 1);
            icmp_header.set_checksum(checksum);
    }



    pub fn create_ip_header(
            ip_buffer: &mut [u8],
            len:       u8,
            protocol:  IpNextHeaderProtocol,
            src_ip:    Ipv4Addr,
            dst_ip:    Ipv4Addr
        ) {
            let mut ip_header = MutableIpv4Packet::new(ip_buffer).unwrap();
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



    pub fn create_ether_header(
            ether_buffer: &mut [u8],
            src_mac:      MacAddr,
            dst_mac:      MacAddr
        ) {
            let mut eth_header = MutableEthernetPacket::new(ether_buffer).unwrap();
            eth_header.set_source(src_mac);
            eth_header.set_destination(dst_mac);
            eth_header.set_ethertype(EtherTypes::Ipv4);
    }

}