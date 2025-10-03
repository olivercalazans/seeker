use rand::Rng;
use crate::utils::abort;


pub struct DelayTimeGenerator;

impl DelayTimeGenerator {

    pub fn get_delay_list(delay_arg: String, quantity: usize) -> Vec<f32> {
        if delay_arg.contains("-") {
            return Self::random_delay_range(delay_arg, quantity)
        }

        Self::fixed_delay_range(delay_arg, quantity)
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
            abort(format!("Invalid range: {}", range_str));
        };

        let mut rng          = rand::thread_rng();
        let vector: Vec<f32> = (0..quantity)
            .map(|_| rng.gen_range(min..=max))
            .collect();

        vector
    }



    fn validate_number(number_str: &str) -> f32 {        
        let number32: f32 = number_str.parse().unwrap_or_else(|_| {
            abort(format!("Invalid number: {}", number_str));
        });
        number32
    }

}