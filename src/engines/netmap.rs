use std::{thread, time::Duration, collections::HashMap, mem};
use clap::Parser;
use crate::arg_parser::{NetMapArgs, PortScanArgs};
use crate::engines::PortScanner;
use crate::iterators::{Ipv4Iter, DelayIter};
use crate::pkt_kit::{PacketBuilder, PacketDissector, Layer3RawSocket, PacketSniffer};
use crate::utils::{abort, iface_network_cidr, inline_display, get_host_name, iface_ip};



struct PacketTools {
    sniffer: PacketSniffer,
    builder: PacketBuilder,
    socket:  Layer3RawSocket,
}



struct Iterators {
    ips:    Ipv4Iter,
    delays: DelayIter,
    len:    usize,
}



pub struct NetworkMapper {
    args:        NetMapArgs,
    raw_packets: Vec<Vec<u8>>,
    active_ips:  HashMap<String, Vec<String>>,
}



impl NetworkMapper {

    pub fn new(args:NetMapArgs) -> Self {
        Self {
            args,
            active_ips:  HashMap::new(),
            raw_packets: Vec::new(),
        }
    }



    pub fn execute(&mut self) {
        self.send_and_receive();
        self.process_raw_packets();
        self.display_result();
    }



    fn send_and_receive(&mut self) {
        let mut pkt_tools = self.setup_tools();
        let mut iters     = self.setup_iterators();
        
        pkt_tools.sniffer.start_buffered_sniffer();
        
        println!("Sending ICMP probes");
        self.send_probes("icmp", &mut pkt_tools, &mut iters);
        
        iters.ips.reset();
        iters.delays.reset();

        println!("Sending TCP probes");
        self.send_probes("tcp", &mut pkt_tools, &mut iters);        
        
        Self::finish_tools(&mut pkt_tools);
        self.raw_packets = pkt_tools.sniffer.get_packets()
    }



    fn setup_tools(&self) -> PacketTools {
        PacketTools {
            sniffer: PacketSniffer::new("netmap".to_string(), self.args.iface.clone(), "".to_string()),
            builder: PacketBuilder::new(),
            socket:  Layer3RawSocket::new(&self.args.iface),
        }
    }



    fn setup_iterators(&self) -> Iterators {
        let cidr   = iface_network_cidr(&self.args.iface);
        let ips    = Ipv4Iter::new(&cidr, None);
        let len    = ips.total as usize;
        let delays = DelayIter::new(&self.args.delay, len);
        
        Iterators {ips, delays, len}
    }



    fn send_probes(&self, probe_type: &str, pkt_tools: &mut PacketTools, iters: &mut Iterators) {
        let src_ip = iface_ip(&self.args.iface);

        for (i, (ip, delay)) in iters.ips.by_ref().zip(iters.delays.by_ref()).enumerate() {
            let pkt = match probe_type {
                "icmp" => pkt_tools.builder.build_icmp_echo_req_pkt(src_ip, ip),
                "tcp"  => pkt_tools.builder.build_tcp_ip_pkt(src_ip, ip, 80),
                &_     => abort(format!("Unknown protocol type: {}", probe_type)),
            };
            pkt_tools.socket.send_to(&pkt, ip);

            Self::display_progress(i + 1, iters.len - 2 , ip.to_string(), delay);
            thread::sleep(Duration::from_secs_f32(delay));
        }
        println!("");
    }



    fn display_progress(i: usize, total: usize, ip: String, delay: f32) {
        let msg = format!("\tPackets sent: {}/{} - {:<15} - delay: {:.2}", i, total, ip, delay);
        inline_display(msg);
    }


    
    fn finish_tools(pkt_tools: &mut PacketTools){
        thread::sleep(Duration::from_secs(3));
        pkt_tools.sniffer.stop();
    }



    fn process_raw_packets(&mut self) {
        let raw_packets = mem::take(&mut self.raw_packets);

        for packet in raw_packets.into_iter() {
            let src_ip = PacketDissector::get_src_ip(&packet);

            if self.active_ips.contains_key(&src_ip) { continue }

            let mut info: Vec<String> = Vec::new();

            let mac_addr = PacketDissector::get_src_mac(&packet);
            info.push(mac_addr);

            let device_name = get_host_name(&src_ip);
            info.push(device_name);
            
            if self.args.portscan {
                let ports = Self::scan_ports(src_ip.clone());
                info.push(ports);
            }

            self.active_ips.insert(src_ip, info);
        }
    }



    fn scan_ports(ip: String) -> String {
        let args      = vec!["pscan".to_string(), ip];
        let cmd_args  = PortScanArgs::parse_from(args);
        let mut pscan = PortScanner::new(cmd_args, true);
        let ports_vec = pscan.execute();
        if ports_vec.is_empty() { return "None".to_string() }
        ports_vec.join(", ")
    }



    fn display_result(&mut self) {
        Self::display_header();
        let active_ips = mem::take(&mut self.active_ips);

        for (ip, host) in active_ips {
            println!("{}", format!("{:<15}  {}  {}", ip, host[0], host[1]));

            if self.args.portscan { 
                println!("{}\n", format!("Open ports: {:#}", host[2]));
            }
        }
    }



    fn display_header() {
        println!("{}", format!("\n{:<15}  {:<17}  {}", "IP Address", "MAC Address", "Hostname"));
        println!("{}", format!("{}  {}  {}", "-".repeat(15), "-".repeat(17), "-".repeat(8)));
    }

}