use std::net::Ipv4Addr;
use etherparse::{SlicedPacket, InternetSlice};



pub struct PacketDissector;


impl PacketDissector {

    pub fn get_src_ip(packet: &[u8]) -> Option<Ipv4Addr> {
        if let Ok(sliced) = SlicedPacket::from_ethernet(packet) {
            if let Some(InternetSlice::Ipv4(ipv4)) = sliced.net {
                let hdr    = ipv4.header();
                let src_ip = Ipv4Addr::new(
                    hdr.source()[0], hdr.source()[1],
                    hdr.source()[2], hdr.source()[3],
                );
                return Some(src_ip);
            }
        }
        None
    }
}
