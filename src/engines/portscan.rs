use std::time::Duration;
use std::thread;
use std::net::Ipv4Addr;
use crate::engines::_command_exec::CommandExec;
use crate::packets::pkt_builder::PacketBuilder;
use crate::packets::pkt_dissector::PacketDissector;
use crate::packets::pkt_sender::PacketSender;
use crate::packets::pkt_sniffer::PacketSniffer;
use crate::utils::error_msg::display_error_and_exit;



#[derive(Default)]
struct PortScanner {
    raw_packets: Vec<Vec<u8>>,
    target_ip: Ipv4Addr,
}



impl CommandExec for PortScanner {
    fn execute(&mut self, arguments: Vec<String>) {
        self.validate_arguments(arguments);
        self.send_probes();
    }
}



impl PortScanner {

    pub fn new() -> Self {
        Default::default()
    }



    fn validate_arguments(&mut self, mut arguments: Vec<String>) {
        if arguments.len() < 2 {
            display_error_and_exit("No IP entered");
        }

        let ip = arguments.remove(1);

        self.target_ip = ip.parse::<Ipv4Addr>()
            .unwrap_or_else(|_| { display_error_and_exit("Invalid IP: {}", ip); });
    }



    fn send_and_receive(&mut self) {
        let (mut pkt_builder, mut pkt_sender, pkt_sniffer) = Self::setup_tools();
        self.send_probes(&mut pkt_builder, &mut pkt_sender);
        self.raw_packets = Self::finish_tools(pkt_sniffer);
    }



    fn setup_tools() -> (PacketBuilder, PacketSender, PacketSniffer) {
        let mut pkt_builder = PacketBuilder::new();
        let mut pkt_sender  = PacketSender::new();
        let mut pkt_sniffer = PacketSniffer::new();

        pkt_sniffer.start_sniffer();
        (pkt_builder, pkt_sender, pkt_sniffer)
    }



    fn send_probes(&self, pkt_builder: &mut PacketBuilder, pkt_sender: &mut PacketSender) {
        for port in 1..=100 {
            let tcp_packet = pkt_builder.build_tcp_packet(self.target_ip, port);
            pkt_sender.send_tcp(tcp_packet, self.target_ip);
        }
    }



    fn finish_tools(mut sniffer: PacketSniffer) -> Vec<Vec<u8>> {
        thread::sleep(Duration::from_secs(10));
        sniffer.stop();
        sniffer.get_packets()
    }

}