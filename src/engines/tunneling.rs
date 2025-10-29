use std::net::Ipv4Addr;
use crate::arg_parser::TunnelArgs;
use crate::pkt_kit::{PacketBuilder, Layer2RawSocket};
use crate::utils::iface_ip;



pub struct ProtocolTunneler {
    pkt_builder: PacketBuilder,
    socket:      Layer2RawSocket,
    src_ip:      Ipv4Addr,
}



impl ProtocolTunneler {

    pub fn new(args: TunnelArgs) -> Self {
        Self {
            src_ip:      args.src_ip.unwrap_or_else(|| iface_ip(&args.iface)),
            pkt_builder: PacketBuilder::new(),
            socket:      Layer2RawSocket::new(&args.iface),
        }
    }



    pub fn execute(&mut self) {
        self.send_tcp_over_udp();
    }



    fn send_tcp_over_udp(&mut self) {
        let dst_ip = Ipv4Addr::new(8, 8, 8, 8);
        let pkt = self.pkt_builder.tcp_over_udp(
            self.src_ip.clone(), dst_ip
        );
        self.socket.send_to(pkt);
        println!("> TCP over UDP packet sent")
    }

}