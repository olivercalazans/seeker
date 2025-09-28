use std::{thread, time::Duration};
use crate::arg_parser::PortScanArgs;
use crate::pkt_kit::{PacketBuilder, PacketDissector, PacketSender, PacketSniffer};
use crate::utils::{PortGenerator, inline_display, get_host_name, DelayTimeGenerator};



pub struct PortScanner {
    args:        PortScanArgs,
    return_data: bool,
    raw_packets: Vec<Vec<u8>>,
    open_ports:  Vec<String>,
    ports:       Vec<u16>
}


impl PortScanner {

    pub fn new(args: PortScanArgs, return_data: bool) -> Self {
        Self {
            args,
            return_data,
            raw_packets: Vec::new(),
            open_ports:  Vec::new(),
            ports:       Vec::new(),
        }
    }



    pub fn execute(&mut self) -> Vec<String> {
        self.prepare_ports();
        self.send_and_receive();
        self.process_raw_packets();
        
        if self.return_data {
            return self.open_ports.clone()
        }
        
        self.display_result();
        Vec::new()
    }



    fn prepare_ports(&mut self) {
        self.ports = PortGenerator::get_ports(self.args.ports.clone(), self.args.random.clone());
    }



    fn send_and_receive(&mut self) {
        let (mut pkt_builder, mut pkt_sender, mut pkt_sniffer) = self.setup_tools();
        self.send_probes(&mut pkt_builder, &mut pkt_sender);
        self.raw_packets = Self::finish_tools(&mut pkt_sniffer);
    }



    fn setup_tools(&self) -> (PacketBuilder, PacketSender, PacketSniffer) {
        let pkt_builder     = PacketBuilder::new();
        let pkt_sender      = PacketSender::new();
        let mut pkt_sniffer = PacketSniffer::new(self.filter_key(), self.args.target_ip.to_string());

        pkt_sniffer.start_buffered_sniffer();
        thread::sleep(Duration::from_secs_f32(0.5));
        
        (pkt_builder, pkt_sender, pkt_sniffer)
    }



    fn filter_key(&self) -> String {
        if self.args.udp {
            return "pscan-udp".to_string()
        }

        "pscan-tcp".to_string()
    }



    fn send_probes(&self, pkt_builder: &mut PacketBuilder, pkt_sender: &mut PacketSender) {
        let (ip, delays) = self.get_data_for_loop();

        for (port, delay) in self.ports.iter().zip(delays.iter())  {

            if !self.args.udp {
                let tcp_packet = pkt_builder.build_tcp_ip_packet(self.args.target_ip, *port);
                pkt_sender.send_layer3_tcp(tcp_packet, self.args.target_ip);
            }

            if self.args.udp {
                let udp_packet = pkt_builder.build_udp_ip_packet(self.args.target_ip, *port);
                pkt_sender.send_layer3_udp(udp_packet, self.args.target_ip);
            }

            Self::display_progress(ip.clone(), *port, *delay);
            thread::sleep(Duration::from_secs_f32(*delay));
        }
        println!("");
    }



    fn get_data_for_loop(&self) -> (String, Vec<f32>) {
        let ip     = self.args.target_ip.to_string();
        let delays = DelayTimeGenerator::get_delay_list(self.args.delay.clone(), self.ports.len());
        (ip, delays)
    }



    fn display_progress(ip: String, port: u16, delay: f32) {
        let msg = format!("Packet sent to {} port {:<5} - delay: {:.2}", ip, port, delay);
        inline_display(msg);
    }



    fn finish_tools(pkt_sniffer: &mut PacketSniffer) -> Vec<Vec<u8>> {
        thread::sleep(Duration::from_secs(3));
        pkt_sniffer.stop();
        pkt_sniffer.get_packets()
    }



    fn process_raw_packets(&mut self) {
        if self.args.udp {
            self.process_udp_packets();
        } else {
            self.process_tcp_packets();
        }
    }



    fn process_tcp_packets(&mut self) {
        for packet in &self.raw_packets {
            let port = PacketDissector::get_tcp_src_port(packet);
            self.open_ports.push(port);
        }
    }



    fn process_udp_packets(&mut self) {
        let mut closed_ports: Vec<u16> = Vec::new();

        for packet in &self.raw_packets {
            let port = PacketDissector::extract_udp_dst_port_from_icmp(packet);
            if let Some(p) = port{
                closed_ports.push(p);
            }
        }

        self.remove_closed(&closed_ports);
    }



    fn remove_closed(&mut self, closed_ports: &[u16]) {
        self.open_ports = self.ports
            .iter()
            .copied()
            .filter(|port| !closed_ports.contains(port))
            .map(|port| port.to_string())
            .collect();
    }



    fn display_result(&self) {
        let device_name = get_host_name(&self.args.target_ip.to_string());
        let ports       = self.open_ports.join(", ");

        println!("\nOpen ports from {} ({})", device_name, self.args.target_ip);
        println!("{}", ports);
    }

}