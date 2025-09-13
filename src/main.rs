pub mod arg_parser;
pub mod engines;
pub mod packets;
pub mod utils;

use std::env;
use crate::engines::{NetworkMapper, PortScanner};
use crate::utils::display_error_and_exit;



fn main() {
    let mut seeker = Command::new();
    seeker.run();
}



#[derive(Default)]
struct Command {
    arguments: Vec<String>,
    command: String,
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
        
        if input.get(0).is_none() {
            display_error_and_exit("No input found");
        }

        self.command   = input[0].clone();
        self.arguments = input;
    }



    fn execute_function(&mut self) {
        match self.command.as_str() {
            "pscan" => {
                let mut scanner = PortScanner::new(self.arguments.clone(), false);
                scanner.execute();
            }
            "netmap" => {
                let mut mapper = NetworkMapper::new(self.arguments.clone());
                mapper.execute();
            }
            _ => eprintln!("[ ERROR ] No command '{}'", self.command),
        }
    }

}