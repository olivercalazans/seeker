use etherparse::{SlicedPacket};



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
        if packet.len() < 30 {
            return "unknown".into();
        }

        let ethertype = u16::from_be_bytes([packet[12], packet[13]]);
        if ethertype != 0x0800 {
            return "unknown".into();
        }

        let src = &packet[26..30];
        format!("{}.{}.{}.{}", src[0], src[1], src[2], src[3])
    }




    pub fn get_src_mac(packet: &[u8]) -> String {
        if packet.len() < 12 {
            return "unknown".into();
        }

        packet[6..12]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(":")
    }

}
