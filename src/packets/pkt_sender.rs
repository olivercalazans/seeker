use std::net:Ipv4Addr;
use pnet::{
    packet::{
        ip::IpNextHeaderProtocols,
        ipv4::MutableIpv4Packet,
    },
    transport::{transport_channel, TransportChannelType::Layer3, TransportSender},
};



pub struct PacketSender {
    tcp_socket: TransportSender,
}


impl PacketSender {

    pub fn new() -> Self{
        let (tcp_sender, _) = transport_channel(4096, Layer3(IpNextHeaderProtocols::Tcp))
            .expect("[ERROR] Could not create TCP transport channel");
        
        Self {
            tcp_socket: tcp_sender,
        }
    }
    

    pub fn send_tcp(&mut self, packet: [u8; 40], dst_ip: Ipv4Addr) {
        self.tcp_socket.send_to(
            MutableIpv4Packet::owned(packet.to_vec()).unwrap(),
            std::net::IpAddr::V4(dst_ip)
        ).unwrap();
    }

}