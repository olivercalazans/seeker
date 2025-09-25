use std::net::Ipv4Addr;
use rand::{Rng, rngs::ThreadRng};
use crate::pkt_kit::{PacketBuilder, PacketSender};
use crate::utils::{default_ipv4_net};



pub struct PacketFlood {
    start: u32,
    end:   u32,
    rng:   ThreadRng,
}


impl PacketFlood {

    pub fn new() -> Self {
        Self {
            start: 0,
            end:   0,
            rng:   rand::thread_rng(),
        }
    }



    pub fn execute(&mut self){
        self.set_ip_range();
        self.send_endlessly();
    }



    fn set_ip_range(&mut self) {
        let net    = default_ipv4_net();
        self.start = net.network().into();
        self.end   = net.broadcast().into();
    }



    fn send_endlessly(&mut self) {
        while true {
            let ip = self.get_random_ip();
            println!("{}", ip);
        }
    }



    fn get_random_ip(&mut self) -> Ipv4Addr {
        let rand_num     = self.rng.gen_range(self.start..=self.end);
        let ip: Ipv4Addr = rand_num.into();
        ip
    }

}