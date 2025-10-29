use std::net::Ipv4Addr;
use clap::Parser;
use crate::arg_parser::parse_mac;
use crate::utils::default_iface_name;


#[derive(Parser)]
#[command(name = "flood", about = "Packet Flooder")]
pub struct FloodArgs {

    /// Define a network interface to send the packets
    #[arg(short, long, default_value_t = default_iface_name())]
    pub iface: String,


    /// Define a source IP
    #[arg(long)]
    pub src_ip: Option<Ipv4Addr>,


    /// Define a source MAC
    #[arg(long, value_parser = parse_mac)]
    pub src_mac: Option<[u8; 6]>,


    /// Define a destination IP
    #[arg(long)]
    pub dst_ip: Option<Ipv4Addr>,


    /// Define a destination MAC
    #[arg(long, value_parser = parse_mac)]
    pub dst_mac: Option<[u8; 6]>,
    

}