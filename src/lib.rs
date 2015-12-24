//! Easily hash and verify passwords using bcrypt
//!

#![cfg_attr(feature = "dev", allow(unstable_features))]
#![cfg_attr(feature = "dev", feature(plugin))]
#![cfg_attr(feature = "dev", plugin(clippy))]

extern crate crypto;
extern crate rand;
extern crate rustc_serialize;

use std::io;

use crypto::bcrypt::bcrypt;
use crypto::util::fixed_time_eq;
use rand::{Rng, OsRng};
use rustc_serialize::base64::{self, ToBase64, FromBase64};

mod base64;

// Cost constants
static MIN_COST: u32 = 4;
static MAX_COST: u32 = 31;
static DEFAULT_COST: u32 = 12;


#[derive(Debug, PartialEq)]
struct HashParts {
 cost: u32,
 salt: String,
 hash: String,
}

impl HashParts {
    fn format(self) -> String {
        // Cost need to have a length of 2 so padding with a 0 if cost < 10
        let cost_str = if self.cost < 10 {
            format!("0{}", self.cost)
        } else {
            format!("{}", self.cost)
        };

        format!("$2y${}${}{}", cost_str, self.salt, self.hash)
    }
}

fn null_terminate(password: &str) -> Vec<u8> {
    let mut v: Vec<_> = password.bytes().collect();
    v.push(0);
    v
}

fn _hash(password: &str, cost: u32, salt: &[u8]) -> HashParts {
    // Output is 24
    let mut output = [0u8; 24];
    // We only consider the first 72 chars
    let password_bytes: &[u8] = password.as_ref();
    let pass = if password_bytes.len() > 72 { &password_bytes[..72] } else { password_bytes };
    bcrypt(cost, &salt, pass, &mut output);

    println!("{:?}", salt.to_base64(base64::BCRYPT));
    println!("{:?}", salt.to_base64(base64::STANDARD));
    HashParts {
        cost: cost,
        salt: salt.to_base64(base64::BCRYPT),
        hash: output.to_base64(base64::BCRYPT)
    }
}

pub fn hash(password: &str, cost: u32) -> io::Result<String> {
    // TODO: check cost value and error if necessary
    let salt = {
        let mut s = [0u8; 16];
        let mut rng = try!(OsRng::new());
        rng.fill_bytes(&mut s);
        s
    };
    let hash_parts = _hash(password, cost, &salt);

    Ok(hash_parts.format())
}

fn split_hash(hash: &str) -> HashParts {
    let mut i = 0;
    let mut parts = HashParts {
        cost: 0,
        salt: "".to_owned(),
        hash: "".to_owned()
    };

    for part in hash.split('$') {
        match i {
            0 => (),
            1 => match part {
                "2y" | "2b" | "2a" => (),
                _ => ()
            },
            2 => {
                if let Ok(c) = part.parse::<u32>() {
                    parts.cost = c;
                } else {
                    ()
                }
            },
            3 => {
                if part.len() == 53 {
                    parts.salt = part[..22].chars().collect();
                    parts.hash = part[22..].chars().collect();
                }
            },
            _ => ()
        }
        i += 1;
    }

    parts
}

pub fn verify(password: &str, hash: &str) -> Result<bool, ()> {
    let parts = split_hash(hash);
    println!("{:?}", parts);
    let salt = parts.salt.from_base64().unwrap();

    let generated = _hash(
        &String::from_utf8(null_terminate(password)).unwrap(),
        parts.cost,
        &salt
    );
    // Hashes should be the same given same salt and round number
    Ok(fixed_time_eq(parts.hash.as_ref(), generated.hash.as_ref()))
}


#[cfg(test)]
mod tests {
    use super::{hash, verify, HashParts, split_hash};

    #[test]
    fn can_split_hash() {
        let hash = "$2y$12$L6Bc/AlTQHyd9liGgGEZyOFLPHNgyxeEPfgYfBCVxJ7JIlwxyVU3u";
        let output = split_hash(hash);
        let expected = HashParts {
            cost: 12,
            salt: "L6Bc/AlTQHyd9liGgGEZyO".to_owned(),
            hash: "FLPHNgyxeEPfgYfBCVxJ7JIlwxyVU3u".to_owned()
        };
        assert_eq!(output, expected);
    }

    #[test]
    fn can_verify_hash_generated_from_some_online_tool() {
        let hash = "$2a$04$UuTkLRZZ6QofpDOlMz32MuuxEHA43WOemOYHPz6.SjsVsyO1tDU96";
        assert_eq!(true, verify("password", hash).unwrap());
    }

    // #[test]
    // fn can_verify_own_generated() {
    //     let hashed = hash("hunter2", 4).unwrap();
    //     assert_eq!(true, verify("hunter2", &hashed));
    // }
}
