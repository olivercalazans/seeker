pub trait Data {
    fn add_raw_packet(&mut self, raw_packet:Vec<u8>);
    fn get_raw_packets(&self) -> Vec<Vec<u8>>;
}