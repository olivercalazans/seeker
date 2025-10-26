use std::net::Ipv4Addr;
use crate::arg_parser::TunnelArgs;
use crate::pkt_kit::{PacketBuilder, Layer3RawSocket};



pub struct ProtocolTunneler {
    pkt_builder: PacketBuilder,
    pkt_sender:  Layer3RawSocket,
}



impl ProtocolTunneler {

    pub fn new(args: TunnelArgs) -> Self {
        Self {
            pkt_builder: PacketBuilder::new(args.iface.clone(), None),
            pkt_sender:  Layer3RawSocket::new(&args.iface),
        }
    }



    pub fn execute(&mut self) {
        self.send_tcp_over_udp();
    }



    fn send_tcp_over_udp(&mut self) {
        let dst_ip = Ipv4Addr::new(8, 8, 8, 8);
        let pkt    = self.pkt_builder.build_tcp_over_udp_pkt(dst_ip);
        self.pkt_sender.send_to(pkt, dst_ip);
        println!("> TCP over UDP packet sent")
    }

}