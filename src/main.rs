pub mod arg_parser;
pub mod engines;
pub mod pkt_kit;
pub mod utils;

use std::env;
use clap::Parser;
use crate::arg_parser::*;
use crate::engines::*;
use crate::utils::abort;



fn main() {
    let mut seeker = Command::new();
    seeker.run();
}



#[derive(Default)]
struct Command {
    arguments: Vec<String>,
    command:   String,
}


impl Command {

    pub fn new() -> Self {
        Default::default()
    }



    pub fn run(&mut self) {
        self.validate_input();
        self.execute_function();
    }



    fn validate_input(&mut self) {
        let input: Vec<String> = env::args().skip(1).collect();
        
        if input.is_empty() {
            abort("No input found");
        }

        self.command   = input[0].clone();
        self.arguments = input;
    }



    fn execute_function(&mut self) {
        match self.command.as_str() {
            "-h"     => Self::display_commands(),
            "--help" => Self::display_commands(),
            "flood"  => self.execute_flood(),
            "netmap" => self.execute_netmap(),
            "pscan"  => self.execute_pscan(),
            "protun" => self.execute_protun(),
            _        => abort(format!("No command '{}'", self.command)),
        }
    }


    
    fn display_commands() {
        println!("\nAvailable commands:");
        println!("\tflood  -> Packet Flooding");
        println!("\tnetmap -> Network Mapping");
        println!("\tpscan  -> Port Scanning");
        println!("\tprotun -> Protocol Tunneling");
        println!("\n");
    }


    
    fn execute_flood(&self) {
        let cmd_args  = FloodArgs::parse_from(self.arguments.clone());
        let mut flood = PacketFlood::new(cmd_args);
        flood.execute();
    }


    
    fn execute_netmap(&self) {
        let cmd_args   = NetMapArgs::parse_from(self.arguments.clone());
        let mut mapper = NetworkMapper::new(cmd_args);
        mapper.execute();
    }


    
    fn execute_pscan(&self) {
        let cmd_args    = PortScanArgs::parse_from(self.arguments.clone());
        let mut scanner = PortScanner::new(cmd_args, false);
        scanner.execute();
    }


    
    fn execute_protun(&self) {
        //let cmd_args   = TunnelArgs::parse_from(self.arguments.clone());
        //let mut tunnel = ProtocolTunneler::execute(cmd_args);
        //tunnel.execute();
    }

}