use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{MutableIpv4Packet, checksum as ip_checksum};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, ipv4_checksum as tcp_checksum};
use std::net::Ipv4Addr;
use crate::utils::iface_info::{get_default_iface_ip};



pub struct PacketBuilder {
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    protocol: u8,
    dst_port: u16
}


impl PacketBuilder {

    pub fn new() -> Self {
        Self {
            src_ip:    get_default_iface_ip(),
            dst_ip:    Ipv4Addr::new(0, 0, 0, 0),
            protocol:  0,
            dst_port:  80,
        }
    }


    pub fn build_tcp_packet(&mut self, dst_ip: Ipv4Addr) -> [u8; 40] {
        self.dst_ip    = dst_ip;
        self.protocol  = 6;
        let mut buffer = [0u8; 40];
        self.add_ip_layer(&mut buffer);
        self.add_tcp_layer(&mut buffer);
        buffer
    }



    fn add_tcp_layer(&self, buffer: &mut [u8]) {
        let mut tcp_header = MutableTcpPacket::new(&mut buffer[20..]).unwrap();
        tcp_header.set_source(12345);
        tcp_header.set_destination(self.dst_port);
        tcp_header.set_sequence(1);
        tcp_header.set_flags(TcpFlags::SYN);
        tcp_header.set_window(64240);
        tcp_header.set_data_offset(5);

        let pseudo_header_sum = tcp_checksum(&tcp_header.to_immutable(), &self.src_ip, &self.dst_ip);
        tcp_header.set_checksum(pseudo_header_sum);
    }



    fn add_ip_layer(&self, buffer: &mut [u8]) {
        let mut ip_header = MutableIpv4Packet::new(&mut buffer[..20]).unwrap();
        ip_header.set_version(4);
        ip_header.set_header_length(5);
        ip_header.set_total_length(40);
        ip_header.set_ttl(64);
        ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip_header.set_source(self.src_ip);
        ip_header.set_destination(self.dst_ip);

        let checksum = ip_checksum(&ip_header.to_immutable());
        ip_header.set_checksum(checksum);
    }

}