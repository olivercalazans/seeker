use etherparse::{SlicedPacket, InternetSlice, LinkSlice};



pub struct PacketDissector;



impl PacketDissector {

    fn get_headers(packet: &[u8]) -> Option<SlicedPacket<'_>> {
        SlicedPacket::from_ethernet(packet).ok()
    }



    pub fn get_tcp_src_port(packet: &[u8]) -> String {
        Self::get_headers(packet)
            .and_then(|sliced| match sliced.transport {
                Some(etherparse::TransportSlice::Tcp(tcp)) => Some(tcp.source_port().to_string()),
                _ => None,
            })
            .unwrap_or_else(|| "unknown".to_string())
    }



    pub fn get_src_ip(packet: &[u8]) -> String {
        Self::get_headers(packet)
            .and_then(|sliced| match sliced.net {
                Some(InternetSlice::Ipv4(ipv4)) => {
                    let [a, b, c, d] = ipv4.header().source();
                    Some(format!("{}.{}.{}.{}", a, b, c, d))
                }
                _ => None,
            })
            .unwrap_or_else(|| "unknown".to_string())
    }



    pub fn get_dst_ip(packet: &[u8]) -> String {
        Self::get_headers(packet)
            .and_then(|sliced| match sliced.net {
                Some(InternetSlice::Ipv4(ipv4)) => {
                    let [a, b, c, d] = ipv4.header().destination();
                    Some(format!("{}.{}.{}.{}", a, b, c, d))
                }
                _ => None,
            })
            .unwrap_or_else(|| "unknown".to_string())
    }



    pub fn get_src_mac(packet: &[u8]) -> String {
        Self::get_headers(packet)
            .and_then(|sliced| match sliced.link {
                Some(LinkSlice::Ethernet2(eth)) => Some(
                    eth.source()
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join(":"),
                ),
                _ => None,
            })
            .unwrap_or_else(|| "unknown".to_string())
    }
    
}
