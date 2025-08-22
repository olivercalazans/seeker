// MIT License
// Copyright (c) 2025 Oliver Calazans
// Repository: https://github.com/olivercalazans/seeker
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software...

use std::env;
use std::collections::HashMap;

mod engine;
use crate::engine::netmap::NetworkMapper;

mod utils;



fn main() {
    let mut seeker = Command::new();
    seeker.run();
}



#[derive(Default)]
struct Command {
    all_commands: HashMap<String, fn()>,
    arguments: Vec<String>,
    command: String,
}


impl Command {

    pub fn new() -> Self {
        Default::default()
    }



    pub fn run(&mut self) {
        self.validate_input();
        self.get_command_list();
        self.validate_command_name();
    }



    fn exit(error: impl Into<String>) -> ! {
        eprintln!("Error: {}", error.into());
        std::process::exit(1);
    }



    fn validate_input(&mut self) {
        let mut input: Vec<String> = env::args().collect();
        
        if input.get(1).is_none() {
            Self::exit("No input found");
        }

        self.command   = input.remove(1);
        self.arguments = input;
    }



    fn get_command_list(&mut self) {
        self.all_commands.insert("--help".to_string(), Self::display_help);
        self.all_commands.insert("netmap".to_string(), Self::run_netmap);
    }



    fn validate_command_name(&self) {
        if self.all_commands.get(&self.command).is_none(){
            Self::exit(format!("no command '{}'", self.command))
        }
        
        self.execute();
    }



    fn execute(&self) {
        let cmd = self.all_commands.get(&self.command).unwrap();
        cmd()
    }


    
    fn display_help() {
        println!(
            "# Seeker is a tool for network exploration\n\
             # For more information visite the repository:\n\
             # https://github.com/olivercalazans/seeker\n\
             \n\
             Available commands:
        ");
        println!("  > netmap: Network Mapping");
        println!("\nOBS.: Use --help with the command for more details")
    }


    
    fn run_netmap() {
        let netmapper = NetworkMapper::new();
        netmapper.execute();
    }
}