use std::net::Ipv4Addr;
use crate::arg_parser::TunnelArgs;
use crate::pkt_kit::{PacketBuilder, Layer2RawSocket, PacketSniffer};



pub struct ProtocolTunneler {
    args:        TunnelArgs,
    pkt_builder: PacketBuilder,
    socket:      Layer2RawSocket,
}



impl ProtocolTunneler {

    pub fn new(args: TunnelArgs) -> Self {
        Self {
            pkt_builder: PacketBuilder::new(),
            socket:      Layer2RawSocket::new(&args.iface),
            args,
        }
    }



    pub fn execute(&mut self) {
        self.send_tcp_over_udp();
    }



    fn send_tcp_over_udp(&mut self) {
        let dst_ip = Ipv4Addr::new(8, 8, 8, 8);
        let pkt    = self.pkt_builder.build_tcp_over_udp_pkt(dst_ip);
        self.socket.send_to(pkt);
        println!("> TCP over UDP packet sent")
    }

}