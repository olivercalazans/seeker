pub struct HeaderBuffer {
    pub tcp:   [u8; 20],
    pub udp:   [u8; 8],
    pub icmp:  [u8; 8],
    pub ip:    [u8; 20],
    pub ether: [u8; 14],
}

impl Default for HeaderBuffer {
    fn default() -> Self {
        Self {
            tcp:   [0; 20],
            udp:   [0; 8],
            icmp:  [0; 8],
            ip:    [0; 20],
            ether: [0; 14],
        }
    }
}



pub struct PacketBuffer {
    pub tcp_layer2:  [u8; 54],
    pub tcp_layer3:  [u8; 40],
    pub udp_layer2:  [u8; 42],
    pub udp_layer3:  [u8; 28],
    pub icmp_layer3: [u8; 28],
}

impl Default for PacketBuffer {
    fn default() -> Self {
        Self {
            tcp_layer2:  [0; 54],
            tcp_layer3:  [0; 40],
            udp_layer2:  [0; 42],
            udp_layer3:  [0; 28],
            icmp_layer3: [0; 28],
        }
    }
}
