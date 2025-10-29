use std::net::Ipv4Addr;
use clap::Parser;
use crate::arg_parser::parse_mac;
use crate::utils::default_iface_name;


#[derive(Parser)]
#[command(name = "protun", about = "Protocol tunneling")]
pub struct TunnelArgs {

    /// Define a network interface to send the probes
    #[arg(short, long, default_value_t = default_iface_name())]
    pub iface: String,


    /// Define a source IP
    #[arg(long)]
    pub src_ip: Option<Ipv4Addr>,


    /// Define a source MAC address
    #[arg(long, value_parser = parse_mac)]
    pub src_mac: Option<[u8; 6]>,
    
}