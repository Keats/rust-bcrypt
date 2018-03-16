//! Easily hash and verify passwords using bcrypt


#[macro_use]
extern crate lazy_static;
extern crate blowfish;
extern crate rand;
extern crate base64;
extern crate byte_tools;

use rand::{Rng, OsRng};

mod b64;
mod errors;
mod bcrypt;

pub use errors::{BcryptResult, BcryptError};


// Cost constants
static MIN_COST: u32 = 4;
static MAX_COST: u32 = 31;
pub static DEFAULT_COST: u32 = 12;


#[derive(Debug, PartialEq)]
/// A bcrypt hash result before concatenating
struct HashParts {
    cost: u32,
    salt: String,
    hash: String,
}

impl HashParts {
    /// Creates the bcrypt hash string from all its part
    fn format(self) -> String {
        // Cost need to have a length of 2 so padding with a 0 if cost < 10
        format!("$2y${:02}${}{}", self.cost, self.salt, self.hash)
    }
}

/// The main meat: actually does the hashing and does some verification with
/// the cost to ensure it's a correct one
fn _hash_password(password: &str, cost: u32, salt: &[u8]) -> BcryptResult<HashParts> {
    if cost > MAX_COST || cost < MIN_COST {
        return Err(BcryptError::InvalidCost(cost));
    }

    // Output is 24
    let mut output = [0u8; 24];
    let password_bytes: &[u8] = password.as_ref();
    // Passwords need to be null terminated
    let mut vec: Vec<u8> = Vec::new();
    vec.extend_from_slice(password_bytes);
    vec.push(0);
    // We only consider the first 72 chars; truncate if neceessary.
    // `bcrypt` below will panic if len > 72
    let truncated = if vec.len() > 72 {
        &vec[..72]
    } else {
        &vec
    };

    bcrypt::bcrypt(cost, salt, truncated, &mut output);

    Ok(HashParts {
        cost: cost,
        salt: b64::encode(salt),
        hash: b64::encode(&output[..23]), // remember to remove the last byte
    })
}

/// Takes a full hash and split it into 3 parts:
/// cost, salt and hash
fn split_hash(hash: &str) -> BcryptResult<HashParts> {
    let mut parts = HashParts {
        cost: 0,
        salt: "".to_owned(),
        hash: "".to_owned(),
    };

    for (i, part) in hash.split('$').enumerate() {
        match i {
            1 => {
                match part {
                    "2y" | "2b" | "2a" => (),
                    supplied => {
                        return Err(BcryptError::InvalidPrefix(supplied.to_string()));
                    }
                }
            }
            2 => {
                if let Ok(c) = part.parse::<u32>() {
                    parts.cost = c;
                } else {
                    ()
                }
            }
            3 => {
                if part.len() == 53 {
                    parts.salt = part[..22].chars().collect();
                    parts.hash = part[22..].chars().collect();
                }
            }
            _ => (),
        }
    }

    Ok(parts)
}

/// Generates a password hash using the cost given.
/// The salt is generated randomly using the OS randomness
pub fn hash(password: &str, cost: u32) -> BcryptResult<String> {
    let salt = {
        let mut s = [0u8; 16];
        let mut rng = try!(OsRng::new());
        rng.fill_bytes(&mut s);
        s
    };
    let hash_parts = try!(_hash_password(password, cost, &salt));

    Ok(hash_parts.format())
}

/// Verify that a password is equivalent to the hash provided
pub fn verify(password: &str, hash: &str) -> BcryptResult<bool> {
    let parts = try!(split_hash(hash));
    let salt = b64::decode(&parts.salt);
    let generated = try!(_hash_password(password, parts.cost, &salt));

    Ok(&b64::decode(&parts.hash) == &b64::decode(&generated.hash))
}


#[cfg(test)]
mod tests {
    use std::iter;
    use super::{hash, verify, HashParts, split_hash};

    #[test]
    fn can_split_hash() {
        let hash = "$2y$12$L6Bc/AlTQHyd9liGgGEZyOFLPHNgyxeEPfgYfBCVxJ7JIlwxyVU3u";
        let output = split_hash(hash).unwrap();
        let expected = HashParts {
            cost: 12,
            salt: "L6Bc/AlTQHyd9liGgGEZyO".to_owned(),
            hash: "FLPHNgyxeEPfgYfBCVxJ7JIlwxyVU3u".to_owned(),
        };
        assert_eq!(output, expected);
    }

    #[test]
    fn can_verify_hash_generated_from_some_online_tool() {
        let hash = "$2a$04$UuTkLRZZ6QofpDOlMz32MuuxEHA43WOemOYHPz6.SjsVsyO1tDU96";
        assert!(verify("password", hash).unwrap());
    }

    #[test]
    fn can_verify_hash_generated_from_python() {
        let hash = "$2b$04$EGdrhbKUv8Oc9vGiXX0HQOxSg445d458Muh7DAHskb6QbtCvdxcie";
        assert!(verify("correctbatteryhorsestapler", hash).unwrap());
    }

    #[test]
    fn can_verify_hash_generated_from_node() {
        let hash = "$2a$04$n4Uy0eSnMfvnESYL.bLwuuj0U/ETSsoTpRT9GVk5bektyVVa5xnIi";
        assert!(verify("correctbatteryhorsestapler", hash).unwrap());
    }

    #[test]
    fn a_wrong_password_is_false() {
        let hash = "$2b$04$EGdrhbKUv8Oc9vGiXX0HQOxSg445d458Muh7DAHskb6QbtCvdxcie";
        assert!(!verify("wrong", hash).unwrap());
    }

    #[test]
    fn can_verify_own_generated() {
        let hashed = hash("hunter2", 4).unwrap();
        assert_eq!(true, verify("hunter2", &hashed).unwrap());
    }

    #[test]
    fn long_passwords_truncate_correctly() {
        // produced with python -c 'import bcrypt; bcrypt.hashpw(b"x"*100, b"$2a$05$...............................")'
        let hash = "$2a$05$......................YgIDy4hFBdVlc/6LHnD9mX488r9cLd2";
        assert!(verify(iter::repeat("x").take(100).collect::<String>().as_ref(), hash).unwrap());
    }
}
