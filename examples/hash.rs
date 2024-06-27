extern crate bcrypt;

#[cfg(any(feature = "alloc", feature = "std"))]
use bcrypt::{hash, verify, DEFAULT_COST};

#[cfg(any(feature = "alloc", feature = "std"))]
fn main() {
    let hashed = hash("hunter2", DEFAULT_COST).unwrap();
    let valid = verify("hunter2", &hashed).unwrap();
    println!("{:?}", valid);
}

#[cfg(not(any(feature = "alloc", feature = "std")))]
fn main() {}
