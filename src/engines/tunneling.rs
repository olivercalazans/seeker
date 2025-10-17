use crate::pkt_kit::{PacketBuilder, Layer3PacketSender};


pub struct ProtocolTunnel;


impl ProtocolTunnel {

    pub fn execute() {
        Self::send_probes();
    }



    fn setup_tools(iface: String) -> (PacketBuilder, Layer2PacketSender) {
        let pkt_builder = PacketBuilder::new(iface.clone(), None);
        let pkt_sender  = Layer3PacketSender::new(iface.clone());
        (pkt_builder, pkt_sender)
    }



    fn send_probes() {
        let (mut pkt_builder, mut pkt_sender) = Self::setup_tools();
    }

}