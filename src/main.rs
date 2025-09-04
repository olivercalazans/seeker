use std::env;
use std::collections::HashMap;
use seeker::utils::error_msg::display_error_and_exit;
use seeker::engines::_command_exec::CommandExec;
use seeker::engines::netmap::NetworkMapper;



fn main() {
    let mut seeker = Command::new();
    seeker.run();
}



#[derive(Default)]
struct Command {
    all_commands: HashMap<String, fn() -> Box<dyn CommandExec>>,
    arguments: Vec<String>,
    command: String,
}


impl Command {

    pub fn new() -> Self {
        Default::default()
    }



    pub fn run(&mut self) {
        self.validate_input();
        self.get_command_list();
        self.validate_command_name();
        self.execute_function();
    }



    fn validate_input(&mut self) {
        let mut input: Vec<String> = env::args().collect();
        
        if input.get(1).is_none() {
            display_error_and_exit("No input found");
        }

        self.command   = input.remove(1);
        self.arguments = input;
    }



    fn get_command_list(&mut self) {
        self.all_commands.insert("netmap".to_string(), || Box::new(NetworkMapper::new()));
        //self.all_commands.insert("pscan".to_string(), || Box::new(PortScanner::new()));
    }



    fn validate_command_name(&self) {
        if self.all_commands.get(&self.command).is_none(){
            display_error_and_exit(format!("no command '{}'", self.command))
        }
    }



    fn execute_function(&mut self) {
        if let Some(constructor) = self.all_commands.get(&self.command) {
            let mut cmd = constructor();
            cmd.execute(self.arguments.clone());
        }
    }
    
}