use std::thread;
use std::sync::mpsc;
use std::net::Ipv4Addr;
use pcap::{Device, Capture};
use etherparse::{SlicedPacket, TransportSlice, InternetSlice};
use crate::utils::iface_info::get_default_iface_ip;



impl PacketSniffer {

    fn get_default_iface() -> Device {
        Device::lookup()
            .expect("Não conseguiu achar interface padrão")
            .unwrap()
    }


    fn open_capture() -> Capture {
        Capture::from_device(dev).unwrap()
            .promisc(false)
            .immediate_mode(true)
            .open()
            .unwrap()
    }


    fn get_bpf_filter_parameters() -> String {
        format!(
            "tcp and dst host {} and \
            ((tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack)) \
            or (tcp[tcpflags] & tcp-rst != 0))",
            get_default_iface_ip().to_string()
        )
    }


    pub fn start_sniffer() -> anyhow::Result<mpsc::Receiver<Ipv4Addr>> {
        let (tx, rx) = mpsc::channel::<Ipv4Addr>();

        thread::spawn(move || {
            let dev     = PacketSniffer::get_default_iface();
            let mut cap = PacketSniffer::open_capture();
            let filter  = PacketSniffer::get_bpf_filter_parameters();
            cap.filter(&filter, true).unwrap();

            while let Ok(packet) = cap.next_packet() {
                if let Ok(sp) = SlicedPacket::from_ethernet(packet.data) {
                    if let Some(InternetSlice::Ipv4(ipv4)) = sp.net {
                        // Extrai o IP de origem
                        let hdr = ipv4.header();
                        let src_ip = Ipv4Addr::new(
                            hdr.source()[0], hdr.source()[1],
                            hdr.source()[2], hdr.source()[3],
                        );

                        // Envia o IP para a thread principal
                        let _ = tx.send(src_ip);
                    }
                }
            }
        });

        Ok(rx)
    }
}
