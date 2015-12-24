extern crate bcrypt;

use bcrypt::{DEFAULT_COST, hash, verify};

fn main() {
    let hashed = match hash("hunter2", DEFAULT_COST) {
        Ok(h) => h,
        Err(_) => panic!()
    };

    let valid = match verify("hunter2", &hashed) {
        Ok(valid) => valid,
        Err(_) => panic!()
    };
    println!("{:?}", valid);
}
