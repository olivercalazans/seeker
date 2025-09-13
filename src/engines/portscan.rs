use std::{thread, time::Duration};
use clap::Parser;
use crate::arg_parser::PortScanArgs;
use crate::packets::{PacketBuilder, PacketDissector, PacketSender, PacketSniffer};
use crate::utils::{PortGenerator, display_progress, get_host_name, DelayTimeGenerator};



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
        let (ip, ports, delays) = self.get_data_for_loop();

        for (port, delay) in ports.zip(delays) {
            let tcp_packet = pkt_builder.build_tcp_packet(self.args.target_ip, port);
            pkt_sender.send_tcp(tcp_packet, self.args.target_ip);
            
            display_progress(format!("Packet sent to port: {:<5} - {:<15}", port, ip));
            thread::sleep(Duration::from_secs_f32(delay));
        }
    }



    fn get_data_for_loop(&self) -> (String, Vec<u32>, Vec<f32>) {
        let ip     = self.args.target_ip.to_string();
        let ports  = PortGenerator::get_ports(self.args.ports.clone(), self.args.random.clone());
        let delays = DelayTimeGenerator::get_delay_list(self.args.delay.clone(), ports.len())
        (ip, ports, delays)
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