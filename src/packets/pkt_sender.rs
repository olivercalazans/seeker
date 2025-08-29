use std::net::{Ipv4Addr, SocketAddrV4};
use socket2::{Socket, Domain, Type, Protocol, SockAddr};
use libc;



pub struct PacketSender {
    icmp_socket: Socket,
    tcp_socket: Socket,
}


impl PacketSender {

    pub fn new() -> Self{
        Self {
            icmp_socket: Socket::new(Domain::IPV4, Type::from(libc::SOCK_RAW), Some(Protocol::ICMPV4))
                .expect("[ ERROR ] It was not possible to create a ICMP socket\n"),
            tcp_socket:  Socket::new(Domain::IPV4, Type::from(libc::SOCK_RAW), Some(Protocol::TCP))
                .expect("[ ERROR ] It was not possible to create a TCP socket\n"),
        }
    }


    pub fn send_icmp(&self, packet: Vec<u8>, dst_ip: Ipv4Addr) {
        self.icmp_socket.send_to(&packet, &SockAddr::from(SocketAddrV4::new(dst_ip, 0)));
    }
    

    pub fn send_tcp(&self, packet: Vec<u8>, dst_ip: Ipv4Addr) {
        println!("MALDITO IP: {}", dst_ip);
        self.tcp_socket.send_to(&packet, &SockAddr::from(SocketAddrV4::new(dst_ip, 80)));
    }

}