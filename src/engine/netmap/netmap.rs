// MIT License
// Copyright (c) 2025 Oliver Calazans
// Repository: https://github.com/olivercalazans/seeker
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software...

//mod data
//use crate::models::data::Data;


pub struct NetworkMapper {
    message:String,
}


impl NetworkMapper {

    pub fn new() -> Self {
        Self {
            message: "Command OK".to_string(),
        }
    }


    pub fn execute(&self) {
        println!("{}", self.message)
    }
}