use std::net::Ipv4Addr;
use pnet::{
    datalink::{self, Channel::Ethernet, DataLinkSender},
    packet::{ip::IpNextHeaderProtocols, ipv4::MutableIpv4Packet},
    transport::{transport_channel, TransportChannelType::Layer3, TransportSender},
};
use crate::utils::default_iface_name;



pub struct PacketSender {
    layer2_socket:     Box<dyn DataLinkSender>,
    layer3_tcp_socket: TransportSender,
}


impl PacketSender {

    pub fn new() -> Self{
        Self {
            layer2_socket:     Self::create_layer2_sender(),
            layer3_tcp_socket: Self::create_layer3_tcp_socket(),
        }
    }



    fn create_layer2_sender() -> Box<dyn DataLinkSender> {
        let iface_name = default_iface_name();
        
        let interface  = datalink::interfaces()
            .into_iter()
            .find(|iface| iface.name == iface_name)
            .expect("Interface not found");

        let (tx, _rx) = match datalink::channel(&interface, Default::default()) {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            Ok(_)  => panic!("Unhandled channel type"),
            Err(e) => panic!("Error creating datalink channel: {}", e),
        };

        tx
    }

    

    fn create_layer3_tcp_socket() -> TransportSender {
        let (tcp_sender, _) = transport_channel(4096, Layer3(IpNextHeaderProtocols::Tcp))
            .expect("[ERROR] Could not create TCP transport channel");
        
        tcp_sender
    }



    pub fn send_layer3_tcp(&mut self, packet: [u8; 40], dst_ip: Ipv4Addr) {
        self.layer3_tcp_socket.send_to(
            MutableIpv4Packet::owned(packet.to_vec()).unwrap(),
            std::net::IpAddr::V4(dst_ip)
        ).unwrap();
    }

}