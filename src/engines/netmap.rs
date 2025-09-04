use std::time::Duration;
use std::thread;
use std::collections::HashSet;
use std::net::Ipv4Addr;
use ipnet::Ipv4AddrRange;
use crate::engines::_command_exec::CommandExec;
use crate::packets::pkt_builder::PacketBuilder;
use crate::packets::pkt_dissector::PacketDissector;
use crate::packets::pkt_sender::PacketSender;
use crate::packets::pkt_sniffer::PacketSniffer;
use crate::utils::iface_info::get_default_iface_info;



#[derive(Default)]
pub struct NetworkMapper {
    raw_packets: Vec<Vec<u8>>,
    active_ips: HashSet<Ipv4Addr>,
}



impl CommandExec for NetworkMapper {
    fn execute(&mut self, arguments:Vec<String>) {
        self.send_and_receive();
        self.process_raw_packets();
        self.display_result();
    }
}



impl NetworkMapper {

    pub fn new() -> Self {
        Default::default()
    }



    fn send_and_receive(&mut self) {
        let (mut pkt_builder, mut pkt_sender, pkt_sniffer) = Self::setup_tools();
        self.send_probes(&mut pkt_builder, &mut pkt_sender);
        self.raw_packets = Self::finish_tools(pkt_sniffer);
    }



    fn setup_tools() -> (PacketBuilder, PacketSender, PacketSniffer) {
        let pkt_builder = PacketBuilder::new();
        let pkt_sender  = PacketSender::new();
        let mut pkt_sniffer = PacketSniffer::new();

        pkt_sniffer.start_sniffer();
        (pkt_builder, pkt_sender, pkt_sniffer)
    }



    fn send_probes(&self, pkt_builder: &mut PacketBuilder, pkt_sender: &mut PacketSender) {
        for ip in Self::get_ip_range() {
            let tcp_packet = pkt_builder.build_tcp_packet(ip, 80);
            pkt_sender.send_tcp(tcp_packet, ip);
        }
    }



    fn get_ip_range() -> Ipv4AddrRange {
        get_default_iface_info().hosts()
    }


    
    fn finish_tools(mut sniffer: PacketSniffer) -> Vec<Vec<u8>> {
        thread::sleep(Duration::from_secs(10));
        sniffer.stop();
        sniffer.get_packets()
    }



    fn process_raw_packets(&mut self) {
        for packet in &self.raw_packets {
            if let Some(src_ip) = PacketDissector::get_src_ip(&packet) {
                self.active_ips.insert(src_ip);
            }
        }
    }



    fn display_result(&self) {
        println!("IP Address");
        for ip in &self.active_ips{
            println!("{}", ip);
        }
    }

}