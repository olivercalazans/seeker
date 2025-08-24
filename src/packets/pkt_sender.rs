struct RawPacketSender {
    icmp_socket: Socket,
    tcp_socket: Socket,
}

impl RawPacketSender {

    fn new() -> Result<Self, anyhow::Error> {
        Ok(Self {
            icmp_socket: Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))?,
            tcp_socket:  Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP))?,
        })
    }


    fn send_icmp(&self, dest_ip: Ipv4Addr, packet: &[u8]) -> Result<(), anyhow::Error> {
        self.icmp_socket.send_to(packet, &dest_ip.into())?;
        Ok(())
    }
    

    fn send_tcp(&self, dest_ip: Ipv4Addr, packet: &[u8]) -> Result<(), anyhow::Error> {
        self.tcp_socket.send_to(packet, &dest_ip.into())?;
        Ok(())
    }
}