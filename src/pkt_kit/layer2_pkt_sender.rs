use pnet::datalink::{self, Channel::Ethernet, DataLinkSender};



pub struct Layer2PacketSender {
    layer2_socket:     Box<dyn DataLinkSender>,
}



impl Layer2PacketSender {

    pub fn new(iface: String) -> Self{
        Self {
            layer2_socket: Self::create_layer2_sender(iface),
        }
    }



    fn create_layer2_sender(iface_name: String) -> Box<dyn DataLinkSender> {        
        let interface  = datalink::interfaces()
            .into_iter()
            .find(|iface| iface.name == iface_name)
            .expect("[ ERROR ] Interface not found");

        let (tx, _rx) = match datalink::channel(&interface, Default::default()) {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            Ok(_)  => panic!("[ ERROR ] Unhandled channel type"),
            Err(e) => panic!("[ ERROR ] Error creating datalink channel: {}", e),
        };

        tx
    }


    pub fn send_layer2_frame(&mut self, packet: &[u8]) {
        let _ = self.layer2_socket.send_to(packet, None)
                    .expect("[ ERROR ] Failed to send frame via datalink");
    }

}