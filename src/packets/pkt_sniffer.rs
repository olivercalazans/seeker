use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::thread;
use std::time::Duration;



pub struct Sniffer {
    running: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}


impl Sniffer {
    fn start() -> Self {
        let running = Arc::new(AtomicBool::new(true));
        let running_sniffer = running.clone();

        let handle = thread::spawn(move || {
            while running_sniffer.load(Ordering::Relaxed) {
                println!("Sniffer rodando...");
                thread::sleep(Duration::from_millis(500));
            }
            println!("Sniffer parado!");
        });

        Sniffer {
            running,
            handle: Some(handle),
        }
    }


    fn stop_sniffer(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        self.join();
    }

    
    fn join(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.join().unwrap();
        }
    }
}
