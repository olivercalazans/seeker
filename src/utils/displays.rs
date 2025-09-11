use std::io::{self, Write};


pub fn display_error_and_exit(error: impl Into<String>) -> ! {
    eprintln!("[ ERROR ] {}", error.into());
    std::process::exit(1);
}


pub fn display_progress(message: String) {
    print!("\r{}", message);
    io::stdout().flush().unwrap();
}