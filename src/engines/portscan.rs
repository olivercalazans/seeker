use std::{thread, time::Duration, mem};
use crate::arg_parser::PortScanArgs;
use crate::iterators::{DelayIter, PortIter};
use crate::pkt_kit::{PacketBuilder, PacketDissector, Layer3RawSocket, PacketSniffer};
use crate::utils::{inline_display, get_host_name, iface_name_from_ip, iface_ip};



struct PacketTools {
    sniffer: PacketSniffer,
    builder: PacketBuilder,
    socket:  Layer3RawSocket,
}



struct Iterators {
    ports:  PortIter,
    delays: DelayIter,
    ip:     String,
}



pub struct PortScanner {
    args:        PortScanArgs,
    return_data: bool,
    raw_packets: Vec<Vec<u8>>,
    open_ports:  Vec<String>
}



impl PortScanner {

    pub fn new(args: PortScanArgs, return_data: bool) -> Self {
        Self {
            args,
            return_data,
            raw_packets: Vec::new(),
            open_ports:  Vec::new(),
        }
    }



    pub fn execute(&mut self) -> Vec<String> {
        self.send_and_receive();
        self.process_raw_packets();
        
        if self.return_data {
            return self.open_ports.clone()
        }
        
        self.display_result();
        Vec::new()
    }



    fn send_and_receive(&mut self) {
        let mut pkt_tools = self.setup_tools();
        let mut iters     = self.setup_iterators();

        pkt_tools.sniffer.start_buffered_sniffer();
        self.send_probes(&mut pkt_tools, &mut iters);
        Self::finish_tools(&mut pkt_tools);
        
        self.raw_packets = pkt_tools.sniffer.get_packets();
    }



    fn setup_tools(&self) -> PacketTools {
        let iface  = iface_name_from_ip(self.args.target_ip.clone());
        let src_ip = iface_ip(&iface);

        PacketTools {
            sniffer: PacketSniffer::new(self.filter(), iface.clone(), self.args.target_ip.to_string()),
            builder: PacketBuilder::new(iface.clone(), Some(src_ip)),
            socket:  Layer3RawSocket::new(&iface),
        }
    }



    fn setup_iterators(&self) -> Iterators {
        let ports  = PortIter::new(&self.args.ports, self.args.random.clone());
        let delays = DelayIter::new(&self.args.delay, ports.len());
        let ip     = self.args.target_ip.to_string();
        Iterators {ports, delays, ip}
    }



    fn filter(&self) -> String {
        "pscan-tcp".to_string()
    }



    fn send_probes(&mut self, pkt_tools: &mut PacketTools, iters: &mut Iterators) {
        for (port, delay) in iters.ports.by_ref().zip(iters.delays.by_ref())  {

            let pkt = pkt_tools.builder.build_tcp_ip_pkt(self.args.target_ip, port);
            pkt_tools.socket.send_to(pkt, self.args.target_ip);

            Self::display_progress(&iters.ip, port, delay);
            thread::sleep(Duration::from_secs_f32(delay));
        }
        println!("");
    }



    fn display_progress(ip: &str, port: u16, delay: f32) {
        let msg = format!("Packet sent to {} port {:<5} - delay: {:.2}", ip, port, delay);
        inline_display(msg);
    }



    fn finish_tools(pkt_tools: &mut PacketTools) {
        thread::sleep(Duration::from_secs(3));
        pkt_tools.sniffer.stop();
    }



    fn process_raw_packets(&mut self) {
        self.process_tcp_packets();
    }



    fn process_tcp_packets(&mut self) {
        let tcp_packets = mem::take(&mut self.raw_packets);

        for packet in tcp_packets.into_iter() {
            let port = PacketDissector::get_src_tcp_port(&packet);
            self.open_ports.push(port);
        }
    }



    fn display_result(&self) {
        let device_name = get_host_name(&self.args.target_ip.to_string());
        let ports       = self.open_ports.join(", ");

        println!("\nOpen ports from {} ({})", device_name, self.args.target_ip);
        println!("{}", ports);
    }

}