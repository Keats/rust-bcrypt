//! Easily hash and verify passwords using bcrypt
use rand::{rngs::OsRng, RngCore};
use std::convert::AsRef;
use std::fmt;

mod b64;
mod bcrypt;
mod errors;

pub use crate::bcrypt::bcrypt;
pub use crate::errors::{BcryptError, BcryptResult};

// Cost constants
const MIN_COST: u32 = 4;
const MAX_COST: u32 = 31;
pub const DEFAULT_COST: u32 = 12;

#[derive(Debug, PartialEq)]
/// A bcrypt hash result before concatenating
pub struct HashParts {
    cost: u32,
    salt: String,
    hash: String,
}

/// BCrypt hash version
/// https://en.wikipedia.org/wiki/Bcrypt#Versioning_history
pub enum Version {
    TwoA,
    TwoX,
    TwoY,
    TwoB,
}

impl HashParts {
    /// Creates the bcrypt hash string from all its parts
    fn format(self) -> String {
        self.format_for_version(Version::TwoB)
    }

    /// Creates the bcrypt hash string from all its part, allowing to customize the version.
    pub fn format_for_version(&self, version: Version) -> String {
        // Cost need to have a length of 2 so padding with a 0 if cost < 10
        format!("${}${:02}${}{}", version, self.cost, self.salt, self.hash)
    }
}

impl ToString for HashParts {
    fn to_string(&self) -> String {
        self.format_for_version(Version::TwoY)
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let str = match self {
            Version::TwoA => "2a",
            Version::TwoB => "2b",
            Version::TwoX => "2x",
            Version::TwoY => "2y",
        };
        write!(f, "{}", str)
    }
}

/// The main meat: actually does the hashing and does some verification with
/// the cost to ensure it's a correct one
fn _hash_password(password: &[u8], cost: u32, salt: &[u8]) -> BcryptResult<HashParts> {
    if cost > MAX_COST || cost < MIN_COST {
        return Err(BcryptError::CostNotAllowed(cost));
    }
    if password.contains(&0u8) {
        return Err(BcryptError::InvalidPassword);
    }

    // Output is 24
    let mut output = [0u8; 24];
    // Passwords need to be null terminated
    let mut vec: Vec<u8> = Vec::new();
    vec.extend_from_slice(password);
    vec.push(0);
    // We only consider the first 72 chars; truncate if necessary.
    // `bcrypt` below will panic if len > 72
    let truncated = if vec.len() > 72 { &vec[..72] } else { &vec };

    bcrypt::bcrypt(cost, salt, truncated, &mut output);

    Ok(HashParts {
        cost,
        salt: b64::encode(salt),
        hash: b64::encode(&output[..23]), // remember to remove the last byte
    })
}

/// Takes a full hash and split it into 3 parts:
/// cost, salt and hash
fn split_hash(hash: &str) -> BcryptResult<HashParts> {
    let mut parts = HashParts {
        cost: 0,
        salt: "".to_string(),
        hash: "".to_string(),
    };

    // Should be [prefix, cost, hash]
    let raw_parts: Vec<_> = hash.split('$').filter(|s| !s.is_empty()).collect();

    if raw_parts.len() != 3 {
        return Err(BcryptError::InvalidHash(hash.to_string()));
    }

    if raw_parts[0] != "2y" && raw_parts[0] != "2b" && raw_parts[0] != "2a" {
        return Err(BcryptError::InvalidPrefix(raw_parts[0].to_string()));
    }

    if let Ok(c) = raw_parts[1].parse::<u32>() {
        parts.cost = c;
    } else {
        return Err(BcryptError::InvalidCost(raw_parts[1].to_string()));
    }

    if raw_parts[2].len() == 53 {
        parts.salt = raw_parts[2][..22].chars().collect();
        parts.hash = raw_parts[2][22..].chars().collect();
    } else {
        return Err(BcryptError::InvalidHash(hash.to_string()));
    }

    Ok(parts)
}

/// Generates a password hash using the cost given.
/// The salt is generated randomly using the OS randomness
pub fn hash<P: AsRef<[u8]>>(password: P, cost: u32) -> BcryptResult<String> {
    hash_with_result(password, cost).map(|r| r.format())
}

/// Generates a password hash using the cost given.
/// The salt is generated randomly using the OS randomness.
/// The function returns a result structure and allows to format the hash in different versions.
pub fn hash_with_result<P: AsRef<[u8]>>(password: P, cost: u32) -> BcryptResult<HashParts> {
    let salt = {
        let mut s = [0u8; 16];
        OsRng.fill_bytes(&mut s);
        s
    };

    _hash_password(password.as_ref(), cost, salt.as_ref())
}

/// Verify that a password is equivalent to the hash provided
pub fn verify<P: AsRef<[u8]>>(password: P, hash: &str) -> BcryptResult<bool> {
    let parts = split_hash(hash)?;
    let salt = b64::decode(&parts.salt)?;
    let generated = _hash_password(password.as_ref(), parts.cost, &salt)?;
    let source_decoded = b64::decode(&parts.hash)?;
    let generated_decoded = b64::decode(&generated.hash)?;
    if source_decoded.len() != generated_decoded.len() {
        return Ok(false);
    }

    for (a, b) in source_decoded.into_iter().zip(generated_decoded) {
        if a != b {
            return Ok(false);
        }
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::{
        _hash_password, hash, split_hash, verify, BcryptError, BcryptResult, HashParts, Version,
        DEFAULT_COST,
    };
    use quickcheck::{quickcheck, TestResult};
    use std::iter;

    #[test]
    fn can_split_hash() {
        let hash = "$2y$12$L6Bc/AlTQHyd9liGgGEZyOFLPHNgyxeEPfgYfBCVxJ7JIlwxyVU3u";
        let output = split_hash(hash).unwrap();
        let expected = HashParts {
            cost: 12,
            salt: "L6Bc/AlTQHyd9liGgGEZyO".to_string(),
            hash: "FLPHNgyxeEPfgYfBCVxJ7JIlwxyVU3u".to_string(),
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
    fn errors_with_invalid_hash() {
        // there is another $ in the hash part
        let hash = "$2a$04$n4Uy0eSnMfvnESYL.bLwuuj0U/ETSsoTpRT9GVk$5bektyVVa5xnIi";
        assert!(verify("correctbatteryhorsestapler", hash).is_err());
    }

    #[test]
    fn errors_with_non_number_cost() {
        // the cost is not a number
        let hash = "$2a$ab$n4Uy0eSnMfvnESYL.bLwuuj0U/ETSsoTpRT9GVk$5bektyVVa5xnIi";
        assert!(verify("correctbatteryhorsestapler", hash).is_err());
    }

    #[test]
    fn errors_with_a_hash_too_long() {
        // the cost is not a number
        let hash = "$2a$04$n4Uy0eSnMfvnESYL.bLwuuj0U/ETSsoTpRT9GVk$5bektyVVa5xnIerererereri";
        assert!(verify("correctbatteryhorsestapler", hash).is_err());
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
        assert!(verify(iter::repeat("x").take(100).collect::<String>(), hash).unwrap());
    }

    #[test]
    fn generate_versions() {
        let password = "hunter2".as_bytes();
        let salt = vec![0; 16];
        let result = _hash_password(password, DEFAULT_COST, salt.as_slice()).unwrap();
        assert_eq!(
            "$2a$12$......................21jzCB1r6pN6rp5O2Ev0ejjTAboskKm",
            result.format_for_version(Version::TwoA)
        );
        assert_eq!(
            "$2b$12$......................21jzCB1r6pN6rp5O2Ev0ejjTAboskKm",
            result.format_for_version(Version::TwoB)
        );
        assert_eq!(
            "$2x$12$......................21jzCB1r6pN6rp5O2Ev0ejjTAboskKm",
            result.format_for_version(Version::TwoX)
        );
        assert_eq!(
            "$2y$12$......................21jzCB1r6pN6rp5O2Ev0ejjTAboskKm",
            result.format_for_version(Version::TwoY)
        );
        let hash = result.to_string();
        assert_eq!(true, verify("hunter2", &hash).unwrap());
    }

    #[test]
    fn forbid_null_bytes() {
        fn assert_invalid_password(password: &[u8]) {
            match hash(password, DEFAULT_COST) {
                Ok(_) => panic!(format!(
                    "NULL bytes must be forbidden, but {:?} is allowed.",
                    password
                )),
                Err(BcryptError::InvalidPassword) => {}
                Err(e) => panic!(format!(
                    "NULL bytes are forbidden but error differs: {} for {:?}.",
                    e, password
                )),
            }
        }
        assert_invalid_password("\0".as_bytes());
        assert_invalid_password("\0\0\0\0\0\0\0\0".as_bytes());
        assert_invalid_password("passw0rd\0".as_bytes());
        assert_invalid_password("passw0rd\0with tail".as_bytes());
        assert_invalid_password("\0passw0rd".as_bytes());
    }

    quickcheck! {
        fn can_verify_arbitrary_own_generated(pass: Vec<u8>) -> BcryptResult<bool> {
            let mut pass = pass;
            pass.retain(|&b| b != 0);
            let hashed = hash(&pass, 4)?;
            verify(pass, &hashed)
        }

        fn doesnt_verify_different_passwords(a: Vec<u8>, b: Vec<u8>) -> BcryptResult<TestResult> {
            let mut a = a;
            a.retain(|&b| b != 0);
            let mut b = b;
            b.retain(|&b| b != 0);
            if a == b {
                return Ok(TestResult::discard());
            }
            let hashed = hash(a, 4)?;
            Ok(TestResult::from_bool(!verify(b, &hashed)?))
        }
    }
}
