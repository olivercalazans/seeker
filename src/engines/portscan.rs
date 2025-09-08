use crate::prelude::{
    Duration, thread, PortScanArgs, Parser,
    PacketBuilder, PacketDissector, PacketSender, PacketSniffer,
    get_host_name, display_progress
};




pub struct PortScanner {
    raw_packets: Vec<Vec<u8>>,
    args: PortScanArgs,
    open_ports: Vec<String>,
}


impl PortScanner {

    pub fn new(args_vec: Vec<String>) -> Self {
        let arguments = PortScanArgs::parse_from(args_vec);

        Self {
            raw_packets: Vec::new(),
            args: arguments,
            open_ports: Vec::new(),
        }
    }



    pub fn execute(&mut self) {
        self.send_and_receive();
        self.process_raw_packets();
        self.display_result();
    }



    fn send_and_receive(&mut self) {
        let (pkt_builder, mut pkt_sender, mut pkt_sniffer) = self.setup_tools();
        self.send_probes(&pkt_builder, &mut pkt_sender);
        self.raw_packets = Self::finish_tools(&mut pkt_sniffer);
    }



    fn setup_tools(&self) -> (PacketBuilder, PacketSender, PacketSniffer) {
        let pkt_builder     = PacketBuilder::new();
        let pkt_sender      = PacketSender::new();
        let mut pkt_sniffer = PacketSniffer::new("pscan".to_string(), self.args.target_ip.to_string());

        pkt_sniffer.start_sniffer();
        thread::sleep(Duration::from_secs_f32(0.5));
        
        (pkt_builder, pkt_sender, pkt_sniffer)
    }



    fn send_probes(&self, pkt_builder: &PacketBuilder, pkt_sender: &mut PacketSender) {
        let ip: String = self.args.target_ip.to_string();

        for port in 1..=100 {
            let tcp_packet = pkt_builder.build_tcp_packet(self.args.target_ip, port);
            pkt_sender.send_tcp(tcp_packet, self.args.target_ip);
            
            display_progress(format!("Packet sent to port: {} - {}", port, ip));
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
        let device_name = get_host_name(&self.args.target_ip.to_string());

        println!("\nOpen ports from {} ({})", device_name, self.args.target_ip);
        for port in &self.open_ports{
            println!(" -> {}", port);
        }
    }

}