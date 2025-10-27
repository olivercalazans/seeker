use std::collections::BTreeSet;
use rand::seq::SliceRandom;
use crate::utils::abort;



pub struct PortIter {
    ports: Vec<u16>,
    index: usize,
}



impl PortIter {

    pub fn new(ports_str: &str, random: bool) -> Self {
        let mut ports_set = BTreeSet::new();

        for part in ports_str.split(',') {
            if part.contains('-') {
                ports_set.extend(Self::get_port_range(part));
            } else {
                ports_set.insert(Self::validate_port(part));
            }
        }

        let mut ports: Vec<u16> = ports_set.into_iter().collect();
        if random {
            let mut rng = rand::thread_rng();
            ports.shuffle(&mut rng);
        }

        Self { ports, index: 0 }
    }



    fn get_port_range(port_range: &str) -> Vec<u16> {
        let parts: Vec<&str> = port_range.split('-').collect();
        if parts.len() != 2 {
            abort(&format!("Invalid port range format: {}", port_range));
        }

        let start = Self::validate_port(parts[0]);
        let end = Self::validate_port(parts[1]);

        if start >= end {
            abort(&format!("Invalid range: {}-{}", start, end));
        }

        (start..=end).collect()
    }



    fn validate_port(port_str: &str) -> u16 {
        port_str.parse().unwrap_or_else(|_| {
            abort(&format!("Invalid port: {}", port_str));
        })
    }



    pub fn len(&self) -> usize {
        self.ports.len()
    }

}



impl Iterator for PortIter {

    type Item = u16;
    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.ports.len() {
            let port = self.ports[self.index];
            self.index += 1;
            Some(port)
        } else {
            None
        }
    }

}
