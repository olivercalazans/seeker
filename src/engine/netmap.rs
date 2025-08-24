use ipnetwork::Ipv4Network;
use std::collections::HashSet;
use std::net::Ipv4Addr;
use crate::models::data::Data;



#[derive(Default)]
pub struct NetworkMapper {
    responses: Vec<u8>,
    active_ips: HashSet<Ipv4Addr>,
}


impl NetworkMapper {

    pub fn new() -> Self {
        Default::default()
    }


    pub fn execute(&self) {
        for ip in self.get_ip_range(){
            println!("IP: {}", ip);
        }
    }


    pub fn get_ip_range(&self) -> impl Iterator<Item = Ipv4Addr> {
        let network = Ipv4Network::new(self.data.get_my_ip(), self.data.get_netmask())
            .expect("[ ERROR ] Invalid network");
        
        network.iter()
            .skip(1)
            .take(network.size() as usize - 2)
            .filter(move |&ip| ip != self.data.get_my_ip())
    }
}