use std::io::{self, Write};


pub fn abort(error: impl Into<String>) -> ! {
    eprintln!("[ ERROR ] {}", error.into());
    std::process::exit(1);
}


pub fn display_progress(message: String) {
    print!("\r{}", message);
    io::stdout().flush().unwrap();
}