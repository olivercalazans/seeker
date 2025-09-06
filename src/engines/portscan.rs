use crate::prelude::{
    Duration, thread, Ipv4Addr,
    CommandExec, PacketBuilder, PacketDissector, PacketSender, PacketSniffer, display_error_and_exit
};



pub struct PortScanner {
    raw_packets: Vec<Vec<u8>>,
    target_ip: Ipv4Addr,
    open_ports: Vec<String>,
}



impl CommandExec for PortScanner {
    fn execute(&mut self, arguments: Vec<String>) {
        self.validate_arguments(arguments);
        self.send_and_receive();
        self.process_raw_packets();
        self.display_result();
    }
}



impl PortScanner {

    pub fn new() -> Self {
        Self {
            raw_packets: Vec::new(),
            target_ip: Ipv4Addr::new(0, 0, 0, 0),
            open_ports: Vec::new(),
        }
    }



    fn validate_arguments(&mut self, mut arguments: Vec<String>) {
        if arguments.len() < 2 {
            display_error_and_exit("No IP entered");
        }

        let ip = arguments.remove(1);

        self.target_ip = ip.parse::<Ipv4Addr>()
            .unwrap_or_else(|_| { 
                display_error_and_exit(format!("Invalid IP: {}", ip));
            });
    }



    fn send_and_receive(&mut self) {
        let (pkt_builder, mut pkt_sender, mut pkt_sniffer) = self.setup_tools();
        self.send_probes(&pkt_builder, &mut pkt_sender);
        self.raw_packets = Self::finish_tools(&mut pkt_sniffer);
    }



    fn setup_tools(&self) -> (PacketBuilder, PacketSender, PacketSniffer) {
        let pkt_builder     = PacketBuilder::new();
        let pkt_sender      = PacketSender::new();
        let mut pkt_sniffer = PacketSniffer::new("pscan".to_string(), self.target_ip.to_string());

        pkt_sniffer.start_sniffer();
        thread::sleep(Duration::from_secs_f32(0.5));
        
        (pkt_builder, pkt_sender, pkt_sniffer)
    }



    fn send_probes(&self, pkt_builder: &PacketBuilder, pkt_sender: &mut PacketSender) {
        for port in 1..=100 {
            let tcp_packet = pkt_builder.build_tcp_packet(self.target_ip, port);
            pkt_sender.send_tcp(tcp_packet, self.target_ip);
            thread::sleep(Duration::from_secs_f32(0.02));
        }
    }



    fn finish_tools(pkt_sniffer: &mut PacketSniffer) -> Vec<Vec<u8>> {
        thread::sleep(Duration::from_secs(5));
        pkt_sniffer.stop();
        pkt_sniffer.get_packets()
    }



    fn process_raw_packets(&mut self) {
        for packet in &self.raw_packets {
            let port = PacketDissector::get_src_port(packet);
            self.open_ports.push(port);
        }
    }



    fn display_result(&self) {
        println!("Open ports from {}", self.target_ip);
        for port in &self.open_ports{
            println!(" -> {}", port);
        }
    }

}