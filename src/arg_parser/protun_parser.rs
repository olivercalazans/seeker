pub use clap::Parser;
use crate::utils::default_iface_name;


#[derive(Parser)]
#[command(name = "protun", about = "Protocol tunneling")]
pub struct NetMapArgs {}