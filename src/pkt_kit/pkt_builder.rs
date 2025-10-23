use std::net::Ipv4Addr;
use pnet::datalink::MacAddr;
use pnet::packet::ip::IpNextHeaderProtocols as ProtoID;
use rand::{Rng, rngs::ThreadRng};
use crate::pkt_kit::{HeaderBuffer, PacketBuffer, HeaderBuilder};
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
        let src_port = self.rng.gen_range(10000..=65535);
        let src_mac  = self.random_mac();
        let dst_mac  = self.random_mac();

        HeaderBuilder::create_ether_header(&mut self.headers.ether, src_mac, dst_mac);
        HeaderBuilder::create_ip_header(&mut self.headers.ip, 40, ProtoID::Tcp, src_ip, dst_ip);
        HeaderBuilder::create_tcp_header(&mut self.headers.tcp, src_ip, src_port, dst_ip, 80);
        
        self.packets.tcp_layer2[..14].copy_from_slice(&self.headers.ether);
        self.packets.tcp_layer2[14..34].copy_from_slice(&self.headers.ip);
        self.packets.tcp_layer2[34..].copy_from_slice(&self.headers.tcp);
        &self.packets.tcp_layer2
    }



    pub fn build_tcp_ip_packet(&mut self, dst_ip: Ipv4Addr, dst_port: u16) -> &[u8] {
        let src_port = self.rng.gen_range(10000..=65535);

        HeaderBuilder::create_ip_header(&mut self.headers.ip, 40, ProtoID::Tcp, self.src_ip, dst_ip);
        HeaderBuilder::create_tcp_header(&mut self.headers.tcp, self.src_ip, src_port, dst_ip, dst_port);
        
        self.packets.tcp_layer3[..20].copy_from_slice(&self.headers.ip);
        self.packets.tcp_layer3[20..].copy_from_slice(&self.headers.tcp);
        &self.packets.tcp_layer3
    }



    pub fn build_udp_ether_packet(&mut self, src_ip: Ipv4Addr, dst_ip: Ipv4Addr) -> &[u8] {
        let src_port = self.rng.gen_range(10000..=65535);
        let src_mac  = self.random_mac();
        let dst_mac  = self.random_mac();

        HeaderBuilder::create_ether_header(&mut self.headers.ether, src_mac, dst_mac);
        HeaderBuilder::create_ip_header(&mut self.headers.ip, 28, ProtoID::Udp, src_ip, dst_ip);
        HeaderBuilder::create_udp_header(&mut self.headers.udp, src_ip, src_port, dst_ip, 53);

        self.packets.udp_layer2[..14].copy_from_slice(&self.headers.ether);
        self.packets.udp_layer2[14..34].copy_from_slice(&self.headers.ip);
        self.packets.udp_layer2[34..].copy_from_slice(&self.headers.udp);
        &self.packets.udp_layer2
    }



    pub fn build_udp_ip_packet(&mut self, dst_ip: Ipv4Addr, dst_port: u16) -> &[u8] {
        let src_port = self.rng.gen_range(10000..=65535);

        HeaderBuilder::create_ip_header(&mut self.headers.ip, 28, ProtoID::Udp, self.src_ip, dst_ip);
        HeaderBuilder::create_udp_header(&mut self.headers.udp, self.src_ip, src_port, dst_ip, dst_port);

        self.packets.udp_layer3[..20].copy_from_slice(&self.headers.ip);
        self.packets.udp_layer3[20..].copy_from_slice(&self.headers.udp);
        &self.packets.udp_layer3
    }



    pub fn build_icmp_echo_req_packet(&mut self, dst_ip: Ipv4Addr) -> &[u8] {
        HeaderBuilder::create_ip_header(&mut self.headers.ip, 28, ProtoID::Icmp, self.src_ip, dst_ip);
        HeaderBuilder::create_icmp_header(&mut self.headers.icmp);

        self.packets.icmp_layer3[..20].copy_from_slice(&self.headers.ip);
        self.packets.icmp_layer3[20..].copy_from_slice(&self.headers.icmp);
        &self.packets.icmp_layer3
    }



    fn random_mac(&mut self) -> MacAddr {
        let mut bytes = [0u8; 6];
        for b in bytes.iter_mut() { *b = self.rng.r#gen(); }
        bytes[0] = (bytes[0] | 0x02) & 0xFE;
        MacAddr::new(bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5])
    }

}