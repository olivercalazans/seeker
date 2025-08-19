// MIT License
// Copyright (c) 2025 Oliver Calazans
// Repository: https://github.com/olivercalazans/seeker
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


#[derive(Default)]
pub struct Data {
    command_name: String,
}


impl Data {
    
    pub fn new() -> Self {
        Default::default()
    }
    

    pub fn display_command_name(&self) {
        println!("Command name: {}", self.command_name);
    }
    
    
    pub fn set_command_name(&mut self, new_value: String) {
        self.command_name = new_value;
    }
}
