pub trait CommandExec {
    fn execute(&mut self, arguments:Vec<String>);
}