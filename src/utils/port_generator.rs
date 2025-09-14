use std::collections::BTreeSet;
pub use rand::seq::SliceRandom;
use crate::utils::abort;


pub struct PortGenerator;

impl PortGenerator {

    pub fn get_ports(ports_str: Option<String>, random: bool) -> Vec<u16> {
        let mut ports_vec: Vec<u16> = match ports_str {
            Some(p) => Self::generate_specified_ports(p),
            None    => (1..=100).collect(),
        };

        if random {
            Self::shuffle_ports(&mut ports_vec);
        }
        
        ports_vec
    }



    fn generate_specified_ports(ports_str: String) -> Vec<u16> {
        let mut ports: BTreeSet<u16> = BTreeSet::new();
        let parts: Vec<&str>         = ports_str.split(",").collect();
        
        for part in parts {
            if part.contains("-") {
                ports.extend(Self::get_port_range(part.to_string()));
            } else {
                ports.insert(Self::validate_port(part.to_string()));
            }
        }

        let ports_vec: Vec<u16> = ports.into_iter().collect();
        ports_vec
    }



    fn get_port_range(port_range: String) -> Vec<u16> {
        let parts: Vec<&str> = port_range.split("-").collect();
        let start: u16       = Self::validate_port(parts[0].to_string());
        let end: u16         = Self::validate_port(parts[1].to_string());
        
        if start >= end {
            abort(format!("Invalid range format {}-{}", start, end));
        }

        (start..=end).collect()
    }



    fn validate_port(port_str: String) -> u16 {
        let port: u16 = port_str.parse().unwrap_or_else(|_| {
            abort(format!("Invalid port: {}", port_str));
        });

        port
    }



    fn shuffle_ports(ports_vec: &mut Vec<u16>) {
        let mut rng = rand::thread_rng();
        ports_vec.shuffle(&mut rng);
    }

}