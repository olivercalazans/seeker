use std::time::Duration;
use std::thread;
use std::net::Ipv4Addr;
use crate::packets::pkt_builder::PacketBuilder;
use crate::packets::pkt_dissector::PacketDissector;
use crate::packets::pkt_sender::PacketSender;
use crate::packets::pkt_sniffer::PacketSniffer;



#[derive(Default)]
struct PortScanner {
    raw_packets: Vec<Vec<u8>>,
    target_ip: Ipv4Addr,
}


impl PortScanner {

    pub fn new() -> Self {
        Default::default()
    }



    pub fn execute(&mut self, target_ip: String) {
        self.send_probes();
    }



    fn send_probes(&mut self) {
        let mut packet_builder = PacketBuilder::new();
        let mut packet_sender  = PacketSender::new();
        let mut packet_sniffer = PacketSniffer::new();

        packet_sniffer.start_sniffer();

        for port in 1..=100 {
            let tcp_packet = packet_builder.build_tcp_packet(self.target_ip, port);
            packet_sender.send_tcp(tcp_packet, self.target_ip);
        }

        thread::sleep(Duration::from_secs(10));
        
        packet_sniffer.stop();
        self.raw_packets = packet_sniffer.get_packets();
    }

}