extern crate bcrypt;

use bcrypt::{hash, verify, DEFAULT_COST};

fn main() {
    let hashed = hash("hunter2", DEFAULT_COST).unwrap();
    let valid = verify("hunter2", &hashed).unwrap();
    println!("{:?}", valid);
}
