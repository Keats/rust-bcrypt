//! Easily hash and verify passwords using bcrypt
#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(any(feature = "alloc", feature = "std", test))]
extern crate alloc;

#[cfg(any(feature = "alloc", feature = "std", test))]
use alloc::string::String;

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

use base64::{alphabet::BCRYPT, engine::GeneralPurpose, engine::general_purpose::NO_PAD};
use core::fmt;
#[cfg(any(feature = "alloc", feature = "std"))]
use {base64::Engine, core::convert::AsRef, core::str::FromStr};

mod bcrypt;
mod errors;

pub use crate::bcrypt::bcrypt;
pub use crate::errors::{BcryptError, BcryptResult};

// Cost constants
const MIN_COST: u32 = 4;
const MAX_COST: u32 = 31;
/// The default cost parameter.
pub const DEFAULT_COST: u32 = 12;
/// Base64 variant used by bcrypt.
pub const BASE_64: GeneralPurpose = GeneralPurpose::new(&BCRYPT, NO_PAD);

#[cfg(any(feature = "alloc", feature = "std"))]
#[derive(Debug, PartialEq, Eq)]
/// A bcrypt hash result before concatenating
pub struct HashParts {
    cost: u32,
    salt: [u8; 16],
    hash: [u8; 23],
}

#[derive(Clone, Debug)]
/// BCrypt hash version
/// https://en.wikipedia.org/wiki/Bcrypt#Versioning_history
pub enum Version {
    /// Version `$2a$`.
    TwoA,
    /// Version `$2x$`.
    TwoX,
    /// Version `$2y$`.
    TwoY,
    /// Version `$2b$`.
    TwoB,
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl HashParts {
    /// Creates the bcrypt hash string (version 2b) into a fixed-size stack buffer.
    /// The full bcrypt hash string is always exactly 60 bytes.
    fn format(&self) -> [u8; 60] {
        struct ByteBuf<const N: usize> {
            buf: [u8; N],
            pos: usize,
        }
        impl<const N: usize> fmt::Write for ByteBuf<N> {
            fn write_str(&mut self, s: &str) -> fmt::Result {
                let bytes = s.as_bytes();
                self.buf[self.pos..self.pos + bytes.len()].copy_from_slice(bytes);
                self.pos += bytes.len();
                Ok(())
            }
        }
        let mut w = ByteBuf {
            buf: [0u8; 60],
            pos: 0,
        };
        self.write_for_version(Version::TwoB, &mut w)
            .expect("writing into a correctly sized buffer is infallible");
        w.buf
    }

    /// Get the bcrypt hash cost
    pub fn get_cost(&self) -> u32 {
        self.cost
    }

    /// Get the bcrypt hash salt as a base64-encoded string
    pub fn get_salt(&self) -> String {
        BASE_64.encode(self.salt)
    }

    /// Get the raw salt bytes
    pub fn get_salt_raw(&self) -> [u8; 16] {
        self.salt
    }

    /// Creates the bcrypt hash string from all its parts, allowing to customize the version.
    pub fn format_for_version(&self, version: Version) -> String {
        let mut s = String::with_capacity(60);
        self.write_for_version(version, &mut s)
            .expect("writing into a String is infallible");
        s
    }

    /// Writes the bcrypt hash string into any `fmt::Write` sink without allocating.
    /// Useful for writing into stack buffers (e.g. `arrayvec`, `heapless::String`).
    pub fn write_for_version<W: fmt::Write>(&self, version: Version, w: &mut W) -> fmt::Result {
        let mut salt_buf = [0u8; 22];
        let mut hash_buf = [0u8; 31];
        BASE_64
            .encode_slice(self.salt, &mut salt_buf)
            .expect("salt encoding into correctly sized buffer is infallible");
        BASE_64
            .encode_slice(self.hash, &mut hash_buf)
            .expect("hash encoding into correctly sized buffer is infallible");
        write!(
            w,
            "${}${:02}${}{}",
            version,
            self.cost,
            core::str::from_utf8(&salt_buf).expect("base64 output is always valid UTF-8"),
            core::str::from_utf8(&hash_buf).expect("base64 output is always valid UTF-8")
        )
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl FromStr for HashParts {
    type Err = BcryptError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        split_hash(s)
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl fmt::Display for HashParts {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.write_for_version(Version::TwoB, f)
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
/// the cost to ensure it's a correct one. If err_on_truncation, this method will return
/// `BcryptError::Truncation`; otherwise it will truncate the password.
#[cfg(any(feature = "alloc", feature = "std"))]
fn _hash_password(
    password: &[u8],
    cost: u32,
    salt: [u8; 16],
    err_on_truncation: bool,
) -> BcryptResult<HashParts> {
    if !(MIN_COST..=MAX_COST).contains(&cost) {
        return Err(BcryptError::CostNotAllowed(cost));
    }

    let password_len = password.len();
    if err_on_truncation && password_len >= 72 {
        return Err(BcryptError::Truncation(password_len + 1));
    }

    // The bcrypt spec specifies that passwords should be null terminated
    // strings, but if longer than 72 bytes, are truncated at 72 bytes (thereby
    // losing the null byte at the end).
    let copy_len = password_len.min(72);
    let mut pass = [0u8; 72];
    pass[..copy_len].copy_from_slice(&password[..copy_len]);
    let used = (copy_len + 1).min(72);
    let truncated = &pass[..used];

    let output = bcrypt::bcrypt(cost, salt, truncated);

    #[cfg(feature = "zeroize")]
    pass.zeroize();

    Ok(HashParts {
        cost,
        salt,
        hash: output[..23].try_into().unwrap(), // infallible: output is [u8; 24]
    })
}

/// Takes a full hash and split it into 3 parts:
/// cost, salt and hash
#[cfg(any(feature = "alloc", feature = "std"))]
fn split_hash(hash: &str) -> BcryptResult<HashParts> {
    // A valid bcrypt hash is always exactly 60 bytes:
    if hash.len() != 60 {
        return Err(BcryptError::InvalidHash(
            "the hash format is malformed; expected 60 bytes",
        ));
    }

    let bytes = hash.as_bytes();
    if bytes[0] != b'$' || bytes[3] != b'$' || bytes[6] != b'$' {
        return Err(BcryptError::InvalidHash("the hash format is malformed"));
    }

    let version = &hash[1..3];
    if version != "2y" && version != "2b" && version != "2a" && version != "2x" {
        return Err(BcryptError::InvalidHash(
            "the hash prefix is not a bcrypt prefix",
        ));
    }

    let cost = hash[4..6]
        .parse::<u32>()
        .map_err(|_| BcryptError::InvalidHash("the cost value is not a number"))?;

    let salt_and_hash = &hash[7..];
    let mut salt = [0u8; 16];
    let mut hash_bytes = [0u8; 23];
    BASE_64
        .decode_slice(&salt_and_hash[..22], &mut salt)
        .map_err(|_| BcryptError::InvalidHash("the salt part is not valid base64"))?;
    BASE_64
        .decode_slice(&salt_and_hash[22..], &mut hash_bytes)
        .map_err(|_| BcryptError::InvalidHash("the hash part is not valid base64"))?;

    Ok(HashParts {
        cost,
        salt,
        hash: hash_bytes,
    })
}

/// Generates a password hash using the cost given.
/// The salt is generated randomly using the OS randomness
#[cfg(any(feature = "alloc", feature = "std"))]
pub fn hash<P: AsRef<[u8]>>(password: P, cost: u32) -> BcryptResult<String> {
    hash_with_result(password, cost).map(|r| {
        String::from(
            core::str::from_utf8(&r.format()).expect("base64 output is always valid UTF-8"),
        )
    })
}

/// Generates a password hash using the cost given.
/// The salt is generated randomly using the OS randomness
/// Will return BcryptError::Truncation if password is longer than 72 bytes
#[cfg(any(feature = "alloc", feature = "std"))]
pub fn non_truncating_hash<P: AsRef<[u8]>>(password: P, cost: u32) -> BcryptResult<String> {
    non_truncating_hash_with_result(password, cost).map(|r| {
        String::from(
            core::str::from_utf8(&r.format()).expect("base64 output is always valid UTF-8"),
        )
    })
}

/// Generates a password hash using the cost given, returning a fixed-size stack buffer.
/// The salt is generated randomly using the OS randomness.
/// The returned buffer is always exactly 60 bytes of valid UTF-8 (version 2b format).
#[cfg(any(feature = "alloc", feature = "std"))]
pub fn hash_bytes<P: AsRef<[u8]>>(password: P, cost: u32) -> BcryptResult<[u8; 60]> {
    hash_with_result(password, cost).map(|r| r.format())
}

/// Generates a password hash using the cost given, returning a fixed-size stack buffer.
/// The salt is generated randomly using the OS randomness.
/// The returned buffer is always exactly 60 bytes of valid UTF-8 (version 2b format).
/// Will return BcryptError::Truncation if password is longer than 72 bytes
#[cfg(any(feature = "alloc", feature = "std"))]
pub fn non_truncating_hash_bytes<P: AsRef<[u8]>>(password: P, cost: u32) -> BcryptResult<[u8; 60]> {
    non_truncating_hash_with_result(password, cost).map(|r| r.format())
}

/// Generates a password hash using the cost given.
/// The salt is generated randomly using the OS randomness.
/// The function returns a result structure and allows to format the hash in different versions.
#[cfg(any(feature = "alloc", feature = "std"))]
pub fn hash_with_result<P: AsRef<[u8]>>(password: P, cost: u32) -> BcryptResult<HashParts> {
    let salt = {
        let mut s = [0u8; 16];
        getrandom::fill(&mut s).map(|_| s)
    }?;

    _hash_password(password.as_ref(), cost, salt, false)
}

/// Generates a password hash using the cost given.
/// The salt is generated randomly using the OS randomness.
/// The function returns a result structure and allows to format the hash in different versions.
/// Will return BcryptError::Truncation if password is longer than 72 bytes
#[cfg(any(feature = "alloc", feature = "std"))]
pub fn non_truncating_hash_with_result<P: AsRef<[u8]>>(
    password: P,
    cost: u32,
) -> BcryptResult<HashParts> {
    let salt = {
        let mut s = [0u8; 16];
        getrandom::fill(&mut s).map(|_| s)
    }?;

    _hash_password(password.as_ref(), cost, salt, true)
}

/// Generates a password given a hash and a cost.
/// The function returns a result structure and allows to format the hash in different versions.
#[cfg(any(feature = "alloc", feature = "std"))]
pub fn hash_with_salt<P: AsRef<[u8]>>(
    password: P,
    cost: u32,
    salt: [u8; 16],
) -> BcryptResult<HashParts> {
    _hash_password(password.as_ref(), cost, salt, false)
}

/// Generates a password given a hash and a cost, returning a fixed-size stack buffer.
/// The returned buffer is always exactly 60 bytes of valid UTF-8 (version 2b format).
#[cfg(any(feature = "alloc", feature = "std"))]
pub fn hash_with_salt_bytes<P: AsRef<[u8]>>(
    password: P,
    cost: u32,
    salt: [u8; 16],
) -> BcryptResult<[u8; 60]> {
    _hash_password(password.as_ref(), cost, salt, false).map(|r| r.format())
}

/// Generates a password given a hash and a cost.
/// The function returns a result structure and allows to format the hash in different versions.
/// Will return BcryptError::Truncation if password is longer than 72 bytes
#[cfg(any(feature = "alloc", feature = "std"))]
pub fn non_truncating_hash_with_salt<P: AsRef<[u8]>>(
    password: P,
    cost: u32,
    salt: [u8; 16],
) -> BcryptResult<HashParts> {
    _hash_password(password.as_ref(), cost, salt, true)
}

/// Generates a password given a hash and a cost, returning a fixed-size stack buffer.
/// The returned buffer is always exactly 60 bytes of valid UTF-8 (version 2b format).
/// Will return BcryptError::Truncation if password is longer than 72 bytes
#[cfg(any(feature = "alloc", feature = "std"))]
pub fn non_truncating_hash_with_salt_bytes<P: AsRef<[u8]>>(
    password: P,
    cost: u32,
    salt: [u8; 16],
) -> BcryptResult<[u8; 60]> {
    _hash_password(password.as_ref(), cost, salt, true).map(|r| r.format())
}

/// Verify the password against the hash by extracting the salt from the hash and recomputing the
/// hash from the password. If `err_on_truncation` is set to true, then this method will return
/// `BcryptError::Truncation`.
#[cfg(any(feature = "alloc", feature = "std"))]
fn _verify<P: AsRef<[u8]>>(password: P, hash: &str, err_on_truncation: bool) -> BcryptResult<bool> {
    use subtle::ConstantTimeEq;

    let parts = split_hash(hash)?;
    let generated = _hash_password(password.as_ref(), parts.cost, parts.salt, err_on_truncation)?;

    Ok(parts.hash.ct_eq(&generated.hash).into())
}

/// Verify that a password is equivalent to the hash provided
#[cfg(any(feature = "alloc", feature = "std"))]
pub fn verify<P: AsRef<[u8]>>(password: P, hash: &str) -> BcryptResult<bool> {
    _verify(password, hash, false)
}

/// Verify that a password is equivalent to the hash provided.
/// Only use this if you are only using `non_truncating_hash` to generate the hash.
/// It will return an error for inputs that will work if generated from other sources.
#[cfg(any(feature = "alloc", feature = "std"))]
pub fn non_truncating_verify<P: AsRef<[u8]>>(password: P, hash: &str) -> BcryptResult<bool> {
    _verify(password, hash, true)
}

#[cfg(all(test, any(feature = "alloc", feature = "std")))]
mod tests {
    use crate::non_truncating_hash;

    use super::{
        _hash_password, BcryptError, BcryptResult, DEFAULT_COST, HashParts, Version,
        alloc::{
            string::{String, ToString},
            vec,
            vec::Vec,
        },
        hash, hash_bytes, hash_with_salt, hash_with_salt_bytes, non_truncating_hash_bytes,
        non_truncating_hash_with_salt_bytes, non_truncating_verify, split_hash, verify,
    };
    use base64::Engine as _;
    use core::convert::TryInto;
    use core::iter;
    use core::str::FromStr;
    use quickcheck::{TestResult, quickcheck};

    #[test]
    fn can_split_hash() {
        let hash = "$2y$12$L6Bc/AlTQHyd9liGgGEZyOFLPHNgyxeEPfgYfBCVxJ7JIlwxyVU3u";
        let output = split_hash(hash).unwrap();
        assert_eq!(output.get_cost(), 12);
        assert_eq!(output.get_salt(), "L6Bc/AlTQHyd9liGgGEZyO");
        assert_eq!(
            output.format_for_version(Version::TwoY),
            "$2y$12$L6Bc/AlTQHyd9liGgGEZyOFLPHNgyxeEPfgYfBCVxJ7JIlwxyVU3u"
        );
    }

    #[test]
    fn can_output_cost_and_salt_from_parsed_hash() {
        let hash = "$2y$12$L6Bc/AlTQHyd9liGgGEZyOFLPHNgyxeEPfgYfBCVxJ7JIlwxyVU3u";
        let parsed = HashParts::from_str(hash).unwrap();
        assert_eq!(parsed.get_cost(), 12);
        assert_eq!(parsed.get_salt(), "L6Bc/AlTQHyd9liGgGEZyO".to_string());
    }

    #[test]
    fn can_get_raw_salt_from_parsed_hash() {
        let hash = "$2y$12$L6Bc/AlTQHyd9liGgGEZyOFLPHNgyxeEPfgYfBCVxJ7JIlwxyVU3u";
        let parsed = HashParts::from_str(hash).unwrap();
        // Raw salt must round-trip back to the same base64 string
        assert_eq!(
            super::BASE_64.encode(parsed.get_salt_raw()),
            "L6Bc/AlTQHyd9liGgGEZyO"
        );
    }

    #[test]
    fn can_write_hash_for_version_without_allocating() {
        let hash = "$2y$12$L6Bc/AlTQHyd9liGgGEZyOFLPHNgyxeEPfgYfBCVxJ7JIlwxyVU3u";
        let parsed = HashParts::from_str(hash).unwrap();
        let mut buf = String::new();
        parsed.write_for_version(Version::TwoY, &mut buf).unwrap();
        assert_eq!(buf, hash);
    }

    #[test]
    fn write_for_version_matches_format_for_version() {
        let salt = [0u8; 16];
        let result = _hash_password("hunter2".as_bytes(), DEFAULT_COST, salt, false).unwrap();
        let formatted = result.format_for_version(Version::TwoA);
        let mut written = String::new();
        result
            .write_for_version(Version::TwoA, &mut written)
            .unwrap();
        assert_eq!(formatted, written);
    }

    #[test]
    fn returns_an_error_if_a_parsed_hash_is_baddly_formated() {
        let hash1 = "$2y$12$L6Bc/AlTQHyd9lGEZyOFLPHNgyxeEPfgYfBCVxJ7JIlwxyVU3u";
        assert!(HashParts::from_str(hash1).is_err());

        let hash2 = "!2y$12$L6Bc/AlTQHyd9liGgGEZyOFLPHNgyxeEPfgYfBCVxJ7JIlwxyVU3u";
        assert!(HashParts::from_str(hash2).is_err());

        let hash3 = "$2y$-12$L6Bc/AlTQHyd9liGgGEZyOFLPHNgyxeEPfgYfBCVxJ7JIlwxyVU3u";
        assert!(HashParts::from_str(hash3).is_err());
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
    fn can_verify_hash_generated_from_go() {
        /*
            package main
            import (
                "io"
                "os"
                "golang.org/x/crypto/bcrypt"
            )
            func main() {
                buf, err := io.ReadAll(os.Stdin)
                if err != nil {
                    panic(err)
                }
                out, err := bcrypt.GenerateFromPassword(buf, bcrypt.MinCost)
                if err != nil {
                    panic(err)
                }
                os.Stdout.Write(out)
                os.Stdout.Write([]byte("\n"))
            }
        */
        let binary_input = vec![
            29, 225, 195, 167, 223, 236, 85, 195, 114, 227, 7, 0, 209, 239, 189, 24, 51, 105, 124,
            168, 151, 75, 144, 64, 198, 197, 196, 4, 241, 97, 110, 135,
        ];
        let hash = "$2a$04$tjARW6ZON3PhrAIRW2LG/u9aDw5eFdstYLR8nFCNaOQmsH9XD23w.";
        assert!(verify(binary_input, hash).unwrap());
    }

    #[test]
    fn invalid_hash_does_not_panic() {
        let binary_input = vec![
            29, 225, 195, 167, 223, 236, 85, 195, 114, 227, 7, 0, 209, 239, 189, 24, 51, 105, 124,
            168, 151, 75, 144, 64, 198, 197, 196, 4, 241, 97, 110, 135,
        ];
        let hash = "$2a$04$tjARW6ZON3PhrAIRW2LG/u9a.";
        assert!(verify(binary_input, hash).is_err());
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
    fn non_truncating_operations() {
        assert!(matches!(
            non_truncating_hash(iter::repeat("x").take(72).collect::<String>(), DEFAULT_COST),
            BcryptResult::Err(BcryptError::Truncation(73))
        ));
        assert!(matches!(
            non_truncating_hash(iter::repeat("x").take(71).collect::<String>(), DEFAULT_COST),
            BcryptResult::Ok(_)
        ));

        let hash = "$2a$05$......................YgIDy4hFBdVlc/6LHnD9mX488r9cLd2";
        assert!(matches!(
            non_truncating_verify(iter::repeat("x").take(100).collect::<String>(), hash),
            Err(BcryptError::Truncation(101))
        ));
    }

    #[test]
    fn generate_versions() {
        let password = "hunter2".as_bytes();
        let salt = vec![0; 16];
        let result =
            _hash_password(password, DEFAULT_COST, salt.try_into().unwrap(), false).unwrap();
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
    fn allow_null_bytes() {
        // hash p1, check the hash against p2:
        fn hash_and_check(p1: &[u8], p2: &[u8]) -> Result<bool, BcryptError> {
            let fast_cost = 4;
            match hash(p1, fast_cost) {
                Ok(s) => verify(p2, &s),
                Err(e) => Err(e),
            }
        }
        fn assert_valid_password(p1: &[u8], p2: &[u8], expected: bool) {
            match hash_and_check(p1, p2) {
                Ok(checked) => {
                    if checked != expected {
                        panic!(
                            "checked {:?} against {:?}, incorrect result {}",
                            p1, p2, checked
                        )
                    }
                }
                Err(e) => panic!("error evaluating password: {} for {:?}.", e, p1),
            }
        }

        // bcrypt should consider all of these distinct:
        let test_passwords = vec![
            "\0",
            "passw0rd\0",
            "password\0with tail",
            "\0passw0rd",
            "a",
            "a\0",
            "a\0b\0",
        ];

        for (i, p1) in test_passwords.iter().enumerate() {
            for (j, p2) in test_passwords.iter().enumerate() {
                assert_valid_password(p1.as_bytes(), p2.as_bytes(), i == j);
            }
        }

        // this is a quirk of the bcrypt algorithm: passwords that are entirely null
        // bytes hash to the same value, even if they are different lengths:
        assert_valid_password("\0\0\0\0\0\0\0\0".as_bytes(), "\0".as_bytes(), true);
    }

    #[test]
    fn hash_with_fixed_salt() {
        let salt = [
            38, 113, 212, 141, 108, 213, 195, 166, 201, 38, 20, 13, 47, 40, 104, 18,
        ];
        let hashed = hash_with_salt("My S3cre7 P@55w0rd!", 5, salt)
            .unwrap()
            .to_string();
        assert_eq!(
            "$2b$05$HlFShUxTu4ZHHfOLJwfmCeDj/kuKFKboanXtDJXxCC7aIPTUgxNDe",
            &hashed
        );
    }

    #[test]
    fn hash_bytes_returns_valid_utf8_bcrypt_string() {
        let result = hash_bytes("hunter2", 4).unwrap();
        let s = core::str::from_utf8(&result).unwrap();
        assert!(s.starts_with("$2b$04$"));
        assert_eq!(s.len(), 60);
        assert!(verify("hunter2", s).unwrap());
    }

    #[test]
    fn non_truncating_hash_bytes_returns_valid_utf8_bcrypt_string() {
        let result = non_truncating_hash_bytes("hunter2", 4).unwrap();
        let s = core::str::from_utf8(&result).unwrap();
        assert!(s.starts_with("$2b$04$"));
        assert_eq!(s.len(), 60);
        assert!(verify("hunter2", s).unwrap());
    }

    #[test]
    fn non_truncating_hash_bytes_errors_on_long_password() {
        use core::iter;
        let result = non_truncating_hash_bytes(iter::repeat("x").take(72).collect::<String>(), 4);
        assert!(matches!(result, Err(BcryptError::Truncation(73))));
    }

    #[test]
    fn hash_with_salt_bytes_matches_hash_with_salt() {
        let salt = [
            38, 113, 212, 141, 108, 213, 195, 166, 201, 38, 20, 13, 47, 40, 104, 18,
        ];
        let expected = hash_with_salt("My S3cre7 P@55w0rd!", 5, salt)
            .unwrap()
            .to_string();
        let result = hash_with_salt_bytes("My S3cre7 P@55w0rd!", 5, salt).unwrap();
        let s = core::str::from_utf8(&result).unwrap();
        assert_eq!(expected, s);
    }

    #[test]
    fn non_truncating_hash_with_salt_bytes_errors_on_long_password() {
        use core::iter;
        let salt = [0u8; 16];
        let result = non_truncating_hash_with_salt_bytes(
            iter::repeat("x").take(72).collect::<String>(),
            4,
            salt,
        );
        assert!(matches!(result, Err(BcryptError::Truncation(73))));
    }

    #[test]
    fn hash_bytes_matches_hash_string() {
        let salt = [0u8; 16];
        let result_parts = _hash_password("hunter2".as_bytes(), 4, salt, false).unwrap();
        let from_parts = result_parts.format_for_version(Version::TwoB);
        let bytes_result = hash_with_salt_bytes("hunter2", 4, salt).unwrap();
        let from_bytes = core::str::from_utf8(&bytes_result).unwrap();
        assert_eq!(from_parts, from_bytes);
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

    #[test]
    fn does_no_error_on_char_boundary_splitting() {
        // Just checks that it does not panic
        let _ = verify(
            &[],
            "2a$$$0$OOOOOOOOOOOOOOOOOOOOO£OOOOOOOOOOOOOOOOOOOOOOOOOOOOOO",
        );
    }
}
