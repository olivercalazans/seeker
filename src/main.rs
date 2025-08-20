// MIT License
// Copyright (c) 2025 Oliver Calazans
// Repository: https://github.com/olivercalazans/seeker
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software...

use std::env;
use std::collections::HashMap;

mod engine;
use crate::engine::netmap::netmap::NetworkMapper;



fn main() {
    let mut args: Vec<String> = env::args().collect();
    let all_commands      = get_commands();
    let command:String    = args.remove(1);

    if let Some(cmd) = all_commands.get(&command){
        cmd();
    } else {
        println!("ERROR: no command {}", command)
    }
}


fn get_commands() -> HashMap<String, fn()> {
    let mut commands:HashMap<String, fn()> = HashMap::new();
    commands.insert("netmap".to_string(), run_netmap);
    return commands
}


fn run_netmap() {
    let netmapper = NetworkMapper::new();
    netmapper.execute();
}