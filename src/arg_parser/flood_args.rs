pub use std::net::Ipv4Addr;
pub use clap::Parser;


#[derive(Parser)]
#[command(name = "flood", about = "Packet Flooder")]
pub struct FloodArgs {

    /// Define a source IP
    #[arg(long = "src-ip")]
    pub src_ip: Option<Ipv4Addr>,


    /// Define a destination IP
    #[arg(long = "dst-ip")]
    pub dst_ip: Option<Ipv4Addr>,

}