use crate::prelude::{SlicedPacket, InternetSlice, LinkSlice};



pub struct PacketDissector;

impl PacketDissector {

    pub fn get_src_port(packet: &[u8]) -> String {
        if let Ok(sliced) = SlicedPacket::from_ethernet(packet) {
            if let Some(etherparse::TransportSlice::Tcp(tcp)) = sliced.transport {
                return tcp.source_port().to_string();
            }
        }
        "unknown".to_string()
    }

    

    pub fn get_src_ip(packet: &[u8]) -> String {
        if let Ok(sliced) = SlicedPacket::from_ethernet(packet) {
            if let Some(InternetSlice::Ipv4(ipv4)) = sliced.net {
                let hdr = ipv4.header();
                return format!(
                    "{}.{}.{}.{}",
                    hdr.source()[0], hdr.source()[1],
                    hdr.source()[2], hdr.source()[3]
                );
            }
        }
        "unknown".to_string()
    }




    pub fn get_src_mac(packet: &[u8]) -> String {
        if let Ok(sliced) = SlicedPacket::from_ethernet(packet) {
            if let Some(LinkSlice::Ethernet2(eth)) = sliced.link {
                return eth.source()
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<Vec<_>>()
                    .join(":");
            }
        }
        "unknown".to_string()
}



}
