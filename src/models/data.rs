// MIT License
// Copyright (c) 2025 Oliver Calazans
// Repository: https://github.com/olivercalazans/seeker
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


#[derive(Default)]
pub struct Data {
    command: String,
    target_ip: String,
}


impl Data {
    
    pub fn new() -> Self {
        Default::default()
    }
    
    
    
    pub fn set_command(&mut self, new_value:String) {
        self.command = new_value;
    }

    pub fn get_command(&self) -> String {
        return self.command.clone();
    }



    pub fn set_target_ip(&mut self, ip:String) {
        self.target_ip = ip;
    }

    pub rn get_target_ip(&self) -> String {
        return self.target_ip.clone();
    }
}
