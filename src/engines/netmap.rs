use crate::prelude::{
    Duration, thread, Ipv4AddrRange,
    PacketBuilder, PacketDissector, PacketSender, PacketSniffer,
    get_default_iface_info, get_host_name, display_progress
};



#[derive(Default)]
pub struct NetworkMapper {
    raw_packets: Vec<Vec<u8>>,
    active_ips: Vec<Vec<String>>,
}


impl NetworkMapper {

    pub fn new(args_vec:Vec<String>) -> Self {
        Default::default()
    }



    pub fn execute(&mut self) {
        self.send_and_receive();
        self.process_raw_packets();
        self.display_result();
    }



    fn send_and_receive(&mut self) {
        let (pkt_builder, mut pkt_sender, mut pkt_sniffer) = Self::setup_tools();
        self.send_probes(&pkt_builder, &mut pkt_sender);
        self.raw_packets = Self::finish_tools(&mut pkt_sniffer);
    }



    fn setup_tools() -> (PacketBuilder, PacketSender, PacketSniffer) {
        let pkt_builder     = PacketBuilder::new();
        let pkt_sender      = PacketSender::new();
        let mut pkt_sniffer = PacketSniffer::new("netmap".to_string(), "".to_string());

        pkt_sniffer.start_sniffer();
        (pkt_builder, pkt_sender, pkt_sniffer)
    }



    fn get_ip_range() -> Ipv4AddrRange {
        get_default_iface_info().hosts()
    }



    fn send_probes(&self, pkt_builder: &PacketBuilder, pkt_sender: &mut PacketSender) {
        let ip_range    = Self::get_ip_range();
        let total:usize = ip_range.clone().count();

        for (i, ip) in ip_range.enumerate() {
            let tcp_packet = pkt_builder.build_tcp_packet(ip, 80);
            pkt_sender.send_tcp(tcp_packet, ip);
            
            display_progress(format!("Packets sent: {}/{} - {}", i+1, total, ip.to_string()));
            thread::sleep(Duration::from_secs_f32(0.02));
        }
    }


    
    fn finish_tools(pkt_sniffer: &mut PacketSniffer) -> Vec<Vec<u8>> {
        thread::sleep(Duration::from_secs(10));
        pkt_sniffer.stop();
        pkt_sniffer.get_packets()
    }



    fn process_raw_packets(&mut self) {
        for packet in &self.raw_packets {
            let mut info: Vec<String> = Vec::new();

            let src_ip = PacketDissector::get_src_ip(&packet);
            info.push(src_ip.to_string());

            let mac_addr = PacketDissector::get_src_mac(&packet);
            info.push(mac_addr);

            let device_name = get_host_name(&src_ip);
            info.push(device_name);

            self.active_ips.push(info);
        }
    }



    fn display_result(&self) {
        Self::display_header();
        for host in &self.active_ips{
            println!("{:<15}  {}  {}", host[0], host[1], host[2]);
        }
    }



    fn display_header() {
        println!("\n{:<15}  {:<17}  {}", "IP Address", "MAC Address", "Hostname");
        println!("{}  {}  {}", "-".repeat(15), "-".repeat(17), "-".repeat(8));
    }

}