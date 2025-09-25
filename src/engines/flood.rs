use std::net::Ipv4Addr;
use ipnet::Ipv4Net;
use rand::{Rng, rngs::ThreadRng};
use crate::pkt_kit::{PacketBuilder, PacketSender};
use crate::utils::{default_ipv4_net};



pub struct PacketFlood {
    net:   Ipv4Net,
    start: u32,
    end:   u32,
    rng:   ThreadRng,
}


impl PacketFlood {

    pub fn new() -> Self {
        Self {
            net:   default_ipv4_net(),
            start: 0,
            end:   0,
            rng:   rand::thread_rng(),
        }
    }



    pub fn execute(&mut self){
        self.start = self.net.network().into();
        self.end = self.net.broadcast().into();
        while true {
            let rand_num = self.rng.gen_range(self.start..=self.end);
            let ip: Ipv4Addr = rand_num.into();
            println!("{}", ip);
        }
    }

}