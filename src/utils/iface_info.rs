// MIT License
// Copyright (c) 2025 Oliver Calazans
// Repository: https://github.com/olivercalazans/seeker
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software...

use default_net::interface;



fn get_default_iface_info() -> interface::Interface {
    interface::get_default_interface()
        .expect("Error: It wasn't possible to get the interface information")
}



pub fn get_my_ip() -> String {
    let iface_info = get_default_iface_info();
    
    let ipv4 = iface_info.ipv4.first()
        .expect("Error: Interface has no IPv4 address");

    ipv4.addr.to_string()
}
