use clap::Parser;
use crate::utils::default_iface_name;


#[derive(Parser)]
#[command(name = "netmap", about = "Network Mapper")]
pub struct NetMapArgs {

    /// Add a delay between packet transmissions.
    ///
    /// Examples: 0.5 or 1-2 (seconds).
    #[arg(short, long, default_value = "0.03")]
    pub delay: String,


    /// Define a network interface to send the packets
    #[arg(short, long, default_value_t = default_iface_name())]
    pub iface: String,


    /// Scan ports on active hosts
    #[arg(short = 'P', long = "Portscan")]
    pub portscan: bool,


    /// Send packets to hosts in random order
    #[arg(short, long)]
    pub random: bool,

}