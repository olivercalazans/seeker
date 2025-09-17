use etherparse::{SlicedPacket, InternetSlice, LinkSlice};



pub struct PacketDissector;

impl PacketDissector {

    pub fn get_src_port(packet: &[u8]) -> String {
        let port = try {
            let sliced = SlicedPacket::from_ethernet(packet).ok()?;
            let tcp    = match sliced.transport {
                Some(etherparse::TransportSlice::Tcp(tcp)) => tcp,
                _ => None?,
            };
            tcp.source_port().to_string()
        };

        port.unwrap_or_else(|| "unknown".to_string())
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
        let mac = try {
            let sliced = SlicedPacket::from_ethernet(packet).ok()?;
            let eth    = match sliced.link {
                Some(etherparse::LinkSlice::Ethernet2(eth)) => eth,
                _ => None?,
            };
            eth.source().iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(":")
        };

        mac.unwrap_or_else(|| "unknown".to_string())
    }

}
