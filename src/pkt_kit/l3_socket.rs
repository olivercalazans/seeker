use std::{mem, net::Ipv4Addr, os::raw::c_void};
use libc::{
    socket, setsockopt, sendto, sockaddr_in, AF_INET, SOCK_RAW, IPPROTO_RAW, IPPROTO_IP, IP_HDRINCL,
    close,
};
use crate::utils::abort;



pub struct Layer3RawSocket {
    file_desc: i32,
}



impl Layer3RawSocket {

    pub fn new() -> Self {
            let file_desc = Self::create_socket();
            Self::enable_ip_hdrincl(file_desc);

            Self { file_desc }
    }



    fn create_socket() -> i32 {
        unsafe {
            let file_desc = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
            if file_desc < 0 {
                abort(&format!(
                    "Failed to create RAW socket: {}",
                    std::io::Error::last_os_error()
                ));
            }

            file_desc
        }
    }



    fn enable_ip_hdrincl(file_desc: i32) {
        unsafe {
            let optval: i32 = 1;
            if setsockopt(
                file_desc,
                IPPROTO_IP,
                IP_HDRINCL,
                &optval as *const _ as *const c_void,
                mem::size_of_val(&optval) as u32,
            ) < 0
            {
                let err = std::io::Error::last_os_error();
                close(file_desc);
                abort(&format!(
                    "Failed to set IP_HDRINCL on RAW socket: {}",
                    err
                ));
            }
        }
    }


    
    pub fn send_to(&self, packet: &[u8], dst: Ipv4Addr) {
        unsafe {
            let mut addr: sockaddr_in = mem::zeroed();
            addr.sin_family      = AF_INET as u16;
            addr.sin_port        = 0u16.to_be();
            addr.sin_addr.s_addr = u32::from_be_bytes(dst.octets());

            let ret = sendto(
                self.file_desc,
                packet.as_ptr() as *const c_void,
                packet.len(),
                0,
                &addr as *const _ as *const _,
                mem::size_of::<sockaddr_in>() as u32,
            );

            if ret < 0 {
                abort(&format!(
                    "Failed to send packet to {}: {}",
                    dst,
                    std::io::Error::last_os_error()
                ));
            }
        }
    }

}



impl Drop for Layer3RawSocket {

    fn drop(&mut self) {
        unsafe {
            let _ = close(self.file_desc);
        }
    }

}
