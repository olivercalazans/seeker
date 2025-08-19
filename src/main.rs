// MIT License
// Copyright (c) 2025 Oliver Calazans
// Repository: https://github.com/olivercalazans/seeker
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software...



use std::env;

mod data;



fn main() {
    let args: Vec<String> = env::args().collect();
    let mut data = data::Data::new();

    data.set_command_name(args[1].clone());
    data.display_command_name();   
}