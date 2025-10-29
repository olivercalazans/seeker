use std::net::Ipv4Addr;
use crate::utils::abort;



pub struct Ipv4Iter {
    next:              u32,
    remaining:         u64,
    include_network:   bool,
    include_broadcast: bool,
    pub total:         u64,
    start:             u32,
    limit:             u64,
}



impl Ipv4Iter {
    
    pub fn new(cidr: &str, max_addrs: Option<u64>) -> Self {
        Self::with_flags(cidr, false, false, max_addrs)
    }



    pub fn with_flags(
        cidr:              &str,
        include_network:   bool,
        include_broadcast: bool,
        max_addrs:         Option<u64>,
    ) -> Self {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            abort(&format!("invalid CIDR: {}", cidr));
        }

        let ip: Ipv4Addr = parts[0].parse().unwrap_or_else(|e| {
            abort(&format!("invalid IP in CIDR '{}': {}", cidr, e));
        });

        let prefix: u8 = parts[1].parse::<u8>().unwrap_or_else(|e| {
            abort(&format!("invalid prefix in CIDR '{}': {}", cidr, e));
        });
        if prefix > 32 {
            abort(&format!("prefix out of range in CIDR '{}': {}", cidr, prefix));
        }

        let host_bits = 32u32 - (prefix as u32);
        let total = if host_bits == 32 {
            1u128 << 32
        } else {
            1u128 << (host_bits as u128)
        };

        let total_u64 = total as u64;
        let limit     = max_addrs.unwrap_or(total_u64);
        if limit > total_u64 {
            abort(&format!(
                "max_addrs ({}) exceeds total addresses ({}) in CIDR {}",
                limit, total_u64, cidr
            ));
        }

        let ip_u32   = u32::from_be_bytes(ip.octets());
        let mask_u32 = if prefix == 0 {
            0u32
        } else {
            (!0u32).checked_shl(host_bits).unwrap_or(0)
        };
        let network_u32 = ip_u32 & mask_u32;

        Ipv4Iter {
            next: network_u32,
            remaining: limit,
            include_network,
            include_broadcast,
            total: limit,
            start: network_u32,
            limit,
        }
    }



    pub fn reset(&mut self) {
        self.next = self.start;
        self.remaining = self.limit;
    }

}



impl Iterator for Ipv4Iter {
    
    type Item = Ipv4Addr;
    
    fn next(&mut self) -> Option<Ipv4Addr> {
        while self.remaining > 0 {
            let index = (self.total - self.remaining) as u64;
            let is_network = index == 0;
            let is_broadcast = index == (self.total - 1);

            self.remaining -= 1;
            let cur = self.next;
            self.next = self.next.wrapping_add(1);

            if (!self.include_network && is_network)
                || (!self.include_broadcast && is_broadcast)
            {
                continue;
            }

            return Some(Ipv4Addr::from(cur.to_be_bytes()));
        }
        None
    }

}