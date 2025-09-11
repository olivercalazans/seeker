use std::net::Ipv4Addr;
use rand::Rng;
use pnet::{
    packet::{
        ip::{IpNextHeaderProtocols, IpNextHeaderProtocol},
        ipv4::{MutableIpv4Packet, checksum as ip_checksum},
        tcp::{MutableTcpPacket, TcpFlags, ipv4_checksum as tcp_checksum},
    },
};
use crate::utils::get_default_iface_ip,



pub struct PacketBuilder {
    src_ip: Ipv4Addr,
}


impl PacketBuilder {

    pub fn new() -> Self {
        Self { src_ip: get_default_iface_ip() }
    }


    pub fn build_tcp_packet(&self, dst_ip: Ipv4Addr, dst_port: u16) -> [u8; 40] {
        let mut buffer = [0u8; 40];
        let mut rng    = rand::thread_rng();
        let src_port   = rng.gen_range(10000..=65535);

        self.add_ip_layer(&mut buffer, dst_ip, IpNextHeaderProtocols::Tcp);
        
        let mut tcp_header = MutableTcpPacket::new(&mut buffer[20..]).unwrap();
        tcp_header.set_source(src_port);
        tcp_header.set_destination(dst_port);
        tcp_header.set_sequence(1);
        tcp_header.set_flags(TcpFlags::SYN);
        tcp_header.set_window(64240);
        tcp_header.set_data_offset(5);

        let pseudo_header_sum = tcp_checksum(&tcp_header.to_immutable(), &self.src_ip, &dst_ip);
        tcp_header.set_checksum(pseudo_header_sum);
        
        buffer
    }



    fn add_ip_layer(&self, buffer: &mut [u8], dst_ip:Ipv4Addr, protocol: IpNextHeaderProtocol) {
        let mut ip_header = MutableIpv4Packet::new(&mut buffer[..20]).unwrap();
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

}