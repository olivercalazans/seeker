use rand::Rng;
use crate::utils::display_error_and_exit;


pub struct DelayTimeGenerator;

impl DelayTimeGenerator {

    pub fn get_delay_list(delay_arg: Option<String>, quantity: usize) -> Vec<f32> {
        if delay_arg.is_none() {
            return Self::fixed_delay_range("0.02".to_string(), quantity)
        }

        let delay_str = delay_arg.unwrap();

        if delay_str.contains("-") {
            return Self::random_delay_range(delay_str, quantity)
        }

        Self::fixed_delay_range(delay_str, quantity)
    }



    fn fixed_delay_range(value_str: String, quantity: usize) -> Vec<f32> {
        let value            = Self::validate_number(&value_str);
        let vector: Vec<f32> = vec![value; quantity];
        vector
    }



    fn random_delay_range(range_str: String, quantity: usize) -> Vec<f32> {
        let parts: Vec<&str> = range_str.split("-").collect();
        let min              = Self::validate_number(&parts[0]);
        let max              = Self::validate_number(&parts[1]);

        if min >= max || parts.len() > 2 {
            display_error_and_exit(format!("Invalid range: {}", range_str));
        };

        let mut rng          = rand::thread_rng();
        let vector: Vec<f32> = (0..quantity)
            .map(|_| rng.gen_range(min..=max))
            .collect();

        vector
    }



    fn validate_number(number_str: &str) -> f32 {        
        let number32: f32 = number_str.parse().unwrap_or_else(|_| {
            display_error_and_exit(format!("Invalid number: {}", number_str));
        });
        number32
    }

}