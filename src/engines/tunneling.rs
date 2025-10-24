use crate::arg_parser::TunnelArgs;
use crate::pkt_kit::{PacketBuilder, Layer3PacketSender};



pub struct ProtocolTunneler {
    pkt_builder: PacketBuilder,
    pkt_sender:  Layer3PacketSender,
}



impl ProtocolTunneler {

    pub fn new(args: TunnelArgs) -> Self {
        Self {
            pkt_builder: PacketBuilder::new(args.iface.clone(), None),
            pkt_sender:  Layer3PacketSender::new(),
        }
    }



    pub fn execute(&mut self) {
        self.send_tcp_over_udp();
    }



    fn send_tcp_over_udp(&mut self) {
        
    }

}