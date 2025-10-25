use std::net::Ipv4Addr;
use pnet::datalink::MacAddr;
use pnet::packet::ip::IpNextHeaderProtocols as ProtoID;
use rand::{Rng, rngs::ThreadRng};
use crate::pkt_kit::{PacketBuffer, HeaderBuilder};
use crate::utils::get_ipv4_addr;



pub struct PacketBuilder {
    pkt_buf: PacketBuffer,
    src_ip:  Ipv4Addr,
    rng:     ThreadRng,
}



impl PacketBuilder {

    pub fn new(iface: String, src_ip: Option<Ipv4Addr>) -> Self {
        Self {
            pkt_buf: PacketBuffer::default(),
            src_ip:  src_ip.unwrap_or_else(|| get_ipv4_addr(&iface)),
            rng:     rand::thread_rng(),
        }
    }



    pub fn build_tcp_over_udp_pkt(&mut self, dst_ip: Ipv4Addr) -> &[u8] {
        let src_port       = self.rng.gen_range(10000..=65535);
        let mut tcp_buffer = [0u8; 27];
        
        HeaderBuilder::create_tcp_header(&mut tcp_buffer, self.src_ip, src_port, dst_ip, 80);
        HeaderBuilder::create_udp_header(&mut self.pkt_buf.layer4, self.src_ip, src_port, dst_ip, 53, 35);
        HeaderBuilder::create_ip_header(&mut self.pkt_buf.ip, 40, ProtoID::Udp, self.src_ip, dst_ip);

        self.pkt_buf.packet[..20].copy_from_slice(&self.pkt_buf.ip);
        self.pkt_buf.packet[20..28].copy_from_slice(&self.pkt_buf.layer4[..8]);
        self.pkt_buf.packet[28..].copy_from_slice(&tcp_buffer);
        &self.pkt_buf.packet
    }



    pub fn build_tcp_ether_pkt(&mut self, src_ip: Ipv4Addr, dst_ip: Ipv4Addr) -> &[u8] {
        let src_port = self.rng.gen_range(10000..=65535);
        let src_mac  = self.random_mac();
        let dst_mac  = self.random_mac();

        HeaderBuilder::create_tcp_header(&mut self.pkt_buf.layer4, src_ip, src_port, dst_ip, 80);
        HeaderBuilder::create_ip_header(&mut self.pkt_buf.ip, 40, ProtoID::Tcp, src_ip, dst_ip);
        HeaderBuilder::create_ether_header(&mut self.pkt_buf.ether, src_mac, dst_mac);
        
        self.pkt_buf.packet[..14].copy_from_slice(&self.pkt_buf.ether);
        self.pkt_buf.packet[14..34].copy_from_slice(&self.pkt_buf.ip);
        self.pkt_buf.packet[34..54].copy_from_slice(&self.pkt_buf.layer4);
        &self.pkt_buf.packet[..54]
    }



    pub fn build_udp_ether_pkt(&mut self, src_ip: Ipv4Addr, dst_ip: Ipv4Addr) -> &[u8] {
        let src_port = self.rng.gen_range(10000..=65535);
        let src_mac  = self.random_mac();
        let dst_mac  = self.random_mac();

        HeaderBuilder::create_udp_header(&mut self.pkt_buf.layer4, src_ip, src_port, dst_ip, 53, 8);
        HeaderBuilder::create_ip_header(&mut self.pkt_buf.ip, 28, ProtoID::Udp, src_ip, dst_ip);
        HeaderBuilder::create_ether_header(&mut self.pkt_buf.ether, src_mac, dst_mac);

        self.pkt_buf.packet[..14].copy_from_slice(&self.pkt_buf.ether);
        self.pkt_buf.packet[14..34].copy_from_slice(&self.pkt_buf.ip);
        self.pkt_buf.packet[34..42].copy_from_slice(&self.pkt_buf.layer4);
        &self.pkt_buf.packet[..42]
    }



    pub fn build_tcp_ip_pkt(&mut self, dst_ip: Ipv4Addr, dst_port: u16) -> &[u8] {
        let src_port = self.rng.gen_range(10000..=65535);

        HeaderBuilder::create_tcp_header(&mut self.pkt_buf.layer4, self.src_ip, src_port, dst_ip, dst_port);
        HeaderBuilder::create_ip_header(&mut self.pkt_buf.ip, 40, ProtoID::Tcp, self.src_ip, dst_ip);
        
        self.pkt_buf.packet[..20].copy_from_slice(&self.pkt_buf.ip);
        self.pkt_buf.packet[20..40].copy_from_slice(&self.pkt_buf.layer4);
        &self.pkt_buf.packet[..40]
    }



    pub fn build_udp_ip_pkt(&mut self, dst_ip: Ipv4Addr, dst_port: u16) -> &[u8] {
        let src_port = self.rng.gen_range(10000..=65535);

        HeaderBuilder::create_udp_header(&mut self.pkt_buf.layer4, self.src_ip, src_port, dst_ip, dst_port, 8);
        HeaderBuilder::create_ip_header(&mut self.pkt_buf.ip, 28, ProtoID::Udp, self.src_ip, dst_ip);

        self.pkt_buf.packet[..20].copy_from_slice(&self.pkt_buf.ip);
        self.pkt_buf.packet[20..28].copy_from_slice(&self.pkt_buf.layer4);
        &self.pkt_buf.packet[..28]
    }



    pub fn build_icmp_echo_req_pkt(&mut self, dst_ip: Ipv4Addr) -> &[u8] {
        HeaderBuilder::create_icmp_header(&mut self.pkt_buf.layer4);
        HeaderBuilder::create_ip_header(&mut self.pkt_buf.ip, 28, ProtoID::Icmp, self.src_ip, dst_ip);

        self.pkt_buf.packet[..20].copy_from_slice(&self.pkt_buf.ip);
        self.pkt_buf.packet[20..28].copy_from_slice(&self.pkt_buf.layer4);
        &self.pkt_buf.packet[..28]
    }



    fn random_mac(&mut self) -> [u8; 6] {
        let mut bytes = [0u8; 6];
        for b in bytes.iter_mut() { *b = self.rng.r#gen(); }
        bytes[0] = (bytes[0] | 0x02) & 0xFE;
        bytes
    }

}