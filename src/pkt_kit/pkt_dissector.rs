use etherparse::{SlicedPacket, InternetSlice, LinkSlice};



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

    

    fn get_ipv4_header(packet: &[u8]) -> Option<Ipv4Header> {
        let sliced = SlicedPacket::from_ethernet(packet).ok()?;
        match sliced.net {
            Some(InternetSlice::Ipv4(ipv4)) => Some(ipv4.header()),
            _ => None,
        }
    }


    
    pub fn get_src_ip(packet: &[u8]) -> String {
        if let Some(hdr) = get_ipv4_header(packet) {
            let [a, b, c, d] = hdr.source();
            format!("{}.{}.{}.{}", a, b, c, d)
        } else {
            "unknown".to_string()
        }
    }



    pub fn get_dst_ip(packet: &[u8]) -> String {
        if let Some(hdr) = get_ipv4_header(packet) {
            let [a, b, c, d] = hdr.destination();
            format!("{}.{}.{}.{}", a, b, c, d)
        } else {
            "unknown".to_string()
        }
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
