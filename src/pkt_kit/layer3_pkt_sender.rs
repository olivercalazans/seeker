use std::net::Ipv4Addr;
use pnet::{
    packet::{ip::IpNextHeaderProtocols, ipv4::MutableIpv4Packet},
    transport::{transport_channel, TransportChannelType::Layer3, TransportSender},
};



pub struct Layer3PacketSender {
    layer3_tcp_socket:  TransportSender,
    layer3_udp_socket:  TransportSender,
    layer3_icmp_socket: TransportSender,
}


impl Layer3PacketSender {

    pub fn new() -> Self{
        Self {
            layer3_tcp_socket:  Self::create_layer3_tcp_socket(),
            layer3_udp_socket:  Self::create_layer3_udp_socket(),
            layer3_icmp_socket: Self::create_layer3_icmp_socket(),
        }
    }

    

    fn create_layer3_tcp_socket() -> TransportSender {
        let (tcp_sender, _) = transport_channel(4096, Layer3(IpNextHeaderProtocols::Tcp))
            .expect("[ ERROR ] Could not create TCP transport channel");
        
        tcp_sender
    }



    fn create_layer3_udp_socket() -> TransportSender {
        let (udp_sender, _) = transport_channel(4096, Layer3(IpNextHeaderProtocols::Udp))
            .expect("[ ERROR ] Could not create UDP transport channel");

        udp_sender
    }



    fn create_layer3_icmp_socket() -> TransportSender {
        let (icmp_sender, _) = transport_channel(4096, Layer3(IpNextHeaderProtocols::Icmp))
            .expect("[ ERROR ] Could not create ICMP transport channel");

        icmp_sender
    }



    pub fn send_layer3_tcp(&mut self, packet: &[u8], dst_ip: Ipv4Addr) {
        self.layer3_tcp_socket.send_to(
            MutableIpv4Packet::owned(packet.to_vec()).unwrap(),
            std::net::IpAddr::V4(dst_ip)
        ).unwrap();
    }



    pub fn send_layer3_udp(&mut self, packet: &[u8], dst_ip: Ipv4Addr) {
        self.layer3_udp_socket.send_to(
            MutableIpv4Packet::owned(packet.to_vec()).unwrap(),
            std::net::IpAddr::V4(dst_ip)
        ).unwrap();
    }



    pub fn send_layer3_icmp(&mut self, packet: &[u8], dst_ip: Ipv4Addr) {
        self.layer3_icmp_socket.send_to(
            MutableIpv4Packet::owned(packet.to_vec()).unwrap(),
            std::net::IpAddr::V4(dst_ip)
        ).unwrap();
    }

}