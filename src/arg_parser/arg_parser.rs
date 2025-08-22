use clap::Parser;


struct Commands {
    #[command(subcommand)]
    command: Commands,
}


enum Commands {

    Netmap {    
        #[arg(short, long)]
        start: Option<String>,

        #[arg(short, long,)]
        end: Option<String>,
    },
}

#[derive(Parser, Debug)]
#[command(name = "seeker", version = "1.0", author = "Oliver Calazans")]
#[command(about = "Tool for network exploration", long_about = None)]
struct Commands {

}