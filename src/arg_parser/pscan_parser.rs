use crate::prelude::{Parser, Ipv4Addr};


#[derive(Parser)]
pub struct PortScanArgs {

    pub target_ip: Ipv4Addr,

    
    #[arg(short, long)]
    pub ports: Option<String>,


    #[arg(short, long)]
    pub random: bool,

}
