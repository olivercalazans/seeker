use crate::models::data::Data;



#[derive(Default)]
struct NetworkMapperData {
    raw_packets: Vec<u8>,
}


impl Data for NetworkMapperData {

    pub fn new() -> Self {
        Default::default()
    }


    fn add_raw_packet(&mut self, raw_packet:Vec<u8>) {
        self.raw_packets.push(raw_packet)
    }
    

    fn get_raw_packets(&self) -> Vec<Vec<u8>> {
        self.raw_packets
    }

}