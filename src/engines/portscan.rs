use crate::prelude::{
    BTreeSet, Duration, thread, SliceRandom, PortScanArgs, Parser,
    PacketBuilder, PacketDissector, PacketSender, PacketSniffer,
    get_host_name, display_progress, display_error_and_exit
};




pub struct PortScanner {
    args: PortScanArgs,
    raw_packets: Vec<Vec<u8>>,
    open_ports: Vec<String>,
}


impl PortScanner {

    pub fn new(args_vec: Vec<String>) -> Self {
        Self {
            args: PortScanArgs::parse_from(args_vec),
            raw_packets: Vec::new(),
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
        let ip    = self.args.target_ip.to_string();
        let ports = self.get_ports(); 

        for port in ports {
            let tcp_packet = pkt_builder.build_tcp_packet(self.args.target_ip, port);
            pkt_sender.send_tcp(tcp_packet, self.args.target_ip);
            
            display_progress(format!("Packet sent to port: {:<5} - {:<15}", port, ip));
            thread::sleep(Duration::from_secs_f32(0.02));
        }
    }



    fn get_ports(&self) -> Vec<u16> {
        let mut ports_vec: Vec<u16> = match self.args.ports {
            Some(_) => self.generate_specified_ports(),
            None   => (1..=100).collect(),
        };

        if self.args.random {
            Self::shuffle_ports(&mut ports_vec);
        }
        
        ports_vec
    }



    fn generate_specified_ports(&self) -> Vec<u16> {
        let mut ports: BTreeSet<u16> = BTreeSet::new();
        let parts: Vec<&str>         = self.args.ports.as_ref().clone().unwrap().split(",").collect();
        
        for part in parts {
            if part.contains("-") {
                ports.extend(Self::get_port_range(part.to_string()));
            } else {
                ports.insert(Self::validate_port(part.to_string()));
            }
        }

        let ports_vec: Vec<u16> = ports.into_iter().collect();
        ports_vec
    }



    fn get_port_range(port_range: String) -> Vec<u16> {
        let parts: Vec<&str> = port_range.split("-").collect();
        let start: u16       = Self::validate_port(parts[0].to_string());
        let end: u16         = Self::validate_port(parts[1].to_string());
        
        if start >= end {
            display_error_and_exit(format!("Invalid range format {}-{}", start, end));
        }

        (start..=end).collect()
    }



    fn validate_port(port_str: String) -> u16 {
        let port: u16 = port_str.parse().unwrap_or_else(|_| {
            display_error_and_exit(format!("Invalid port: {}", port_str));
        });

        port
    }



    fn shuffle_ports(ports_vec: &mut Vec<u16>) {
        let mut rng = rand::thread_rng();
        ports_vec.shuffle(&mut rng);
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