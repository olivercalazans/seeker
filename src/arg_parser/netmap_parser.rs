pub use clap::Parser;



#[derive(Parser)]
#[command(name = "netmap", about = "Network Mapper")]
pub struct NetMapArgs {

    /// Send packets to hosts in random order
    #[arg(short, long)]
    pub random: bool,


    /// Add a delay between packet transmissions.
    ///
    /// Examples: 0.5 or 1-2 (seconds).
    #[arg(short, long)]
    pub delay: Option<String>,

}