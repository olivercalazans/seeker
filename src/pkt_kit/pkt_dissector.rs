use etherparse::{SlicedPacket, InternetSlice, LinkSlice, Ipv4HeaderSlice};

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


    
    pub fn extract_udp_dst_port_from_icmp(frame: &[u8]) -> Option<u16> {
        let outer_ipv4 = Ipv4HeaderSlice::from_slice(frame).ok()?;
        let ihl_bytes  = (outer_ipv4.ihl() as usize) * 4;

        let icmp_start        = ihl_bytes;
        let embedded_ip_start = icmp_start + 8;

        let inner_ipv4      = Ipv4HeaderSlice::from_slice(&frame[embedded_ip_start..]).ok()?;
        let inner_ihl_bytes = (inner_ipv4.ihl() as usize) * 4;

        let embedded_udp_start = embedded_ip_start + inner_ihl_bytes;

        if frame.len() < embedded_udp_start + 4 {
            return None;
        }

        let dst_port = u16::from_be_bytes([frame[embedded_udp_start + 2], frame[embedded_udp_start + 3],]);
        Some(dst_port)
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
