use std::net::Ipv4Addr;
use clap::Parser;
use crate::utils::default_iface_name;


#[derive(Parser)]
#[command(name = "protun", about = "Protocol tunneling")]
pub struct TunnelArgs {

    /// Define a network interface to send the probes
    #[arg(short, long, default_value_t = default_iface_name())]
    pub iface: String,


    #[arg(short, long)]
    pub src_ip: Option<Ipv4Addr>,


    #[arg(short, long)]
    pub src_mac: Option<Ipv4Addr>,
    
}