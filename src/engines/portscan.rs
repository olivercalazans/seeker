use std::{thread, time::Duration, mem};
use crate::arg_parser::PortScanArgs;
use crate::iterators::{DelayTimeGenerator, PortIter};
use crate::pkt_kit::{PacketBuilder, PacketDissector, Layer3RawSocket, PacketSniffer};
use crate::utils::{inline_display, get_host_name, iface_name_from_ip, iface_ip};



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
        let (mut pkt_builder, mut pkt_sender, mut pkt_sniffer) = self.setup_tools();
        self.send_probes(&mut pkt_builder, &mut pkt_sender);
        self.raw_packets = Self::finish_tools(&mut pkt_sniffer);
    }



    fn setup_tools(&self) -> (PacketBuilder, Layer3RawSocket, PacketSniffer) {
        let iface           = iface_name_from_ip(self.args.target_ip.clone());
        let src_ip          = iface_ip(&iface);
        let pkt_builder     = PacketBuilder::new(iface.clone(), Some(src_ip));
        let pkt_sender      = Layer3RawSocket::new(&iface);
        let mut pkt_sniffer = PacketSniffer::new(self.filter(), iface.clone(), self.args.target_ip.to_string());

        pkt_sniffer.start_buffered_sniffer();
        thread::sleep(Duration::from_secs_f32(0.5));
        
        (pkt_builder, pkt_sender, pkt_sniffer)
    }



    fn filter(&self) -> String {
        "pscan-tcp".to_string()
    }



    fn send_probes(&mut self, pkt_builder: &mut PacketBuilder, pkt_sender: &mut Layer3RawSocket) {
        let (ports, delays, ip) = self.get_data_for_loop();

        for (port, delay) in ports.zip(delays.into_iter())  {

            let pkt = pkt_builder.build_tcp_ip_pkt(self.args.target_ip, port);
            pkt_sender.send_to(pkt, self.args.target_ip);

            Self::display_progress(&ip, port, delay);
            thread::sleep(Duration::from_secs_f32(delay));
        }
        println!("");
    }



    fn get_data_for_loop(&self) -> (PortIter, Vec<f32>, String) {
        let ports  = PortIter::new(&self.args.ports, self.args.random.clone());
        let delays = DelayTimeGenerator::get_delay_list(self.args.delay.clone(), ports.len());
        let ip     = self.args.target_ip.to_string();
        (ports, delays, ip)
    }



    fn display_progress(ip: &str, port: u16, delay: f32) {
        let msg = format!("Packet sent to {} port {:<5} - delay: {:.2}", ip, port, delay);
        inline_display(msg);
    }



    fn finish_tools(pkt_sniffer: &mut PacketSniffer) -> Vec<Vec<u8>> {
        thread::sleep(Duration::from_secs(3));
        pkt_sniffer.stop();
        pkt_sniffer.get_packets()
    }



    fn process_raw_packets(&mut self) {
        self.process_tcp_packets();
    }



    fn process_tcp_packets(&mut self) {
        let tcp_packets = mem::take(&mut self.raw_packets);

        for packet in tcp_packets.into_iter() {
            let port = PacketDissector::get_tcp_src_port(&packet);
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