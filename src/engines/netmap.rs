use std::{thread, time::Duration};
use clap::Parser;
use ipnet::Ipv4AddrRange;
use crate::arg_parser::{NetMapArgs, PortScanArgs};
use crate::engines::PortScanner;
use crate::pkt_kit::{PacketBuilder, PacketDissector, Layer3PacketSender, PacketSniffer};
use crate::utils::{inline_display, default_ipv4_net, get_host_name, DelayTimeGenerator};



pub struct NetworkMapper {
    args:        NetMapArgs,
    raw_packets: Vec<Vec<u8>>,
    active_ips:  Vec<Vec<String>>,
}


impl NetworkMapper {

    pub fn new(args:NetMapArgs) -> Self {
        Self {
            args,
            raw_packets: Vec::new(),
            active_ips:  Vec::new(),
        }
    }



    pub fn execute(&mut self) {
        self.send_and_receive();
        self.process_raw_packets();
        self.display_result();
    }



    fn send_and_receive(&mut self) {
        let (mut pkt_builder, mut pkt_sender, mut pkt_sniffer) = Self::setup_tools();
        self.send_probes(&mut pkt_builder, &mut pkt_sender);
        self.raw_packets = Self::finish_tools(&mut pkt_sniffer);
    }



    fn setup_tools() -> (PacketBuilder, Layer3PacketSender, PacketSniffer) {
        let pkt_builder     = PacketBuilder::new();
        let pkt_sender      = Layer3PacketSender::new();
        let mut pkt_sniffer = PacketSniffer::new("netmap".to_string(), "".to_string());

        pkt_sniffer.start_buffered_sniffer();
        (pkt_builder, pkt_sender, pkt_sniffer)
    }



    fn send_probes(&self, pkt_builder: &mut PacketBuilder, pkt_sender: &mut Layer3PacketSender) {
        let (ip_range, total, delays) = self.get_data_for_loop();

        for (i, (ip, delay)) in ip_range.into_iter().zip(delays.iter()).enumerate() {
            let tcp_packet = pkt_builder.build_tcp_ip_packet(ip, 80);
            pkt_sender.send_layer3_tcp(tcp_packet, ip);
            
            Self::display_progress(i+1, total, ip.to_string(), *delay);
            thread::sleep(Duration::from_secs_f32(*delay));
        }
        println!("");
    }



    fn get_data_for_loop(&self) -> (Ipv4AddrRange, usize, Vec<f32>) {
        let ip_range = Self::get_ip_range();
        let total    = ip_range.clone().count();
        let delays   = DelayTimeGenerator::get_delay_list(self.args.delay.clone(), total);
        (ip_range, total, delays)
    }



    fn get_ip_range() -> Ipv4AddrRange {
        default_ipv4_net().hosts()
    }



    fn display_progress(i: usize, total: usize, ip: String, delay: f32) {
        let msg = format!("Packets sent: {}/{} - {:<15} - delay: {:.2}", i, total, ip, delay);
        inline_display(msg);
    }


    
    fn finish_tools(pkt_sniffer: &mut PacketSniffer) -> Vec<Vec<u8>> {
        thread::sleep(Duration::from_secs(3));
        pkt_sniffer.stop();
        pkt_sniffer.get_packets()
    }



    fn process_raw_packets(&mut self) {
        for packet in &self.raw_packets {
            let mut info = Self::get_data_from_packet(packet);
            
            if self.args.portscan {
                let ports = Self::scan_ports(info[0].clone());
                info.push(ports);
            }

            self.active_ips.push(info);
        }
    }



    fn get_data_from_packet(packet: &Vec<u8>) -> Vec<String> {
        let mut info: Vec<String> = Vec::new();

        let src_ip = PacketDissector::get_src_ip(packet);
        info.push(src_ip.to_string());

        let mac_addr = PacketDissector::get_src_mac(packet);
        info.push(mac_addr);

        let device_name = get_host_name(&src_ip);
        info.push(device_name);

        info
    }



    fn scan_ports(ip: String) -> String {
        let args      = vec!["pscan".to_string(), ip];
        let cmd_args  = PortScanArgs::parse_from(args);
        let mut pscan = PortScanner::new(cmd_args, true);
        let ports_vec = pscan.execute();
        if ports_vec.is_empty() { return "None".to_string() }
        ports_vec.join(", ")
    }



    fn display_result(&self) {
        Self::display_header();

        for host in &self.active_ips{
            println!("{}", format!("{:<15}  {}  {}", host[0], host[1], host[2]));

            if self.args.portscan { 
                println!("{}\n", format!("Open ports: {:#}", host[3]));
            }
        }
    }



    fn display_header() {
        println!("{}", format!("\n{:<15}  {:<17}  {}", "IP Address", "MAC Address", "Hostname"));
        println!("{}", format!("{}  {}  {}", "-".repeat(15), "-".repeat(17), "-".repeat(8)));
    }

}