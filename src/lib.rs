//pub mod arg_parser;

pub mod engine {
    pub mod netmap;
}


pub mod models {
    pub mod data;
    pub mod netmap_data;
}


pub mod packets {
    pub mod pkt_builder;
    pub mod pkt_sender;
    pub mod pkt_sniffer;
}


pub mod utils {
    pub mod iface_info;
}