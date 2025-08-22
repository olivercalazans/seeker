use crate::models::data::Data;


pub struct NetworkMapper {
    data: Data,
}


impl NetworkMapper {

    pub fn new() -> Self {
        Self { data: Data::new() }
    }


    pub fn execute(&self) {
        let ip = self.data.get_my_ip();
        let netmask = self.data.get_netmask();
        println!("My IP: {}, Netmask {}", ip, netmask);
    }
}