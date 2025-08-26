use std::net::{Ipv4Addr, SocketAddrV4};
use socket2::{Socket, Domain, Type, Protocol, SockAddr};



pub struct RawPacketSender {
    icmp_socket: Socket,
    tcp_socket: Socket,
}


impl PacketSender {

    pub fn new() -> Result<Self, anyhow::Error> {
        Ok(Self {
            icmp_socket: Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))?,
            tcp_socket:  Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP))?,
        })
    }


    pub fn send_icmp(&self, packet: &[u8], dst_ip: Ipv4Addr) -> Result<(), anyhow::Error> {
        self.icmp_socket.send_to(packet, &SockAddr::from(SocketAddrV4::new(dst_ip, 0)))?;
        Ok(())
    }
    

    pub fn send_tcp(&self, packet: &[u8], dst_ip: Ipv4Addr) -> Result<(), anyhow::Error> {
        self.tcp_socket.send_to(packet, &dst_ip.into())?;
        Ok(())
    }

}