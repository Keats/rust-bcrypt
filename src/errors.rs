#[cfg(any(feature = "alloc", feature = "std"))]
use alloc::string::String;
use core::fmt;

#[cfg(feature = "std")]
use std::error;

/// Library generic result type.
pub type BcryptResult<T> = Result<T, BcryptError>;

#[derive(Debug)]
/// All the errors we can encounter while hashing/verifying
/// passwords
pub enum BcryptError {
    /// Raised when the cost value is outside of the allowed 4-31 range.
    ///
    /// Cost is provided as an argument to hashing functions, and extracted from the hash in
    /// verification functions.
    CostNotAllowed(u32),
    /// Raised when verifying against an incorrectly formatted hash.
    #[cfg(any(feature = "alloc", feature = "std"))]
    InvalidCost(String),
    /// Raised when verifying against an incorrectly formatted hash.
    #[cfg(any(feature = "alloc", feature = "std"))]
    InvalidPrefix(String),
    /// Raised when verifying against an incorrectly formatted hash.
    #[cfg(any(feature = "alloc", feature = "std"))]
    InvalidHash(String),
    /// Raised when verifying against an incorrectly formatted hash.
    InvalidSaltLen(usize),
    /// Raised when verifying against an incorrectly formatted hash.
    InvalidBase64(base64::DecodeError),
    /// Raised when an error occurs when generating a salt value.
    #[cfg(any(feature = "alloc", feature = "std"))]
    Rand(getrandom::Error),
    /// Raised when the input to a `non_truncating_*` function contains more than 72 bytes.
    /// This variant contains the length of the input in bytes.
    Truncation(usize),
}

macro_rules! impl_from_error {
    ($f: ty, $e: expr) => {
        impl From<$f> for BcryptError {
            fn from(f: $f) -> BcryptError {
                $e(f)
            }
        }
    };
}

impl_from_error!(base64::DecodeError, BcryptError::InvalidBase64);
#[cfg(any(feature = "alloc", feature = "std"))]
impl_from_error!(getrandom::Error, BcryptError::Rand);

impl fmt::Display for BcryptError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            #[cfg(any(feature = "alloc", feature = "std"))]
            BcryptError::InvalidCost(ref cost) => write!(f, "Invalid Cost: {}", cost),
            BcryptError::CostNotAllowed(ref cost) => write!(
                f,
                "Cost needs to be between {} and {}, got {}",
                crate::MIN_COST,
                crate::MAX_COST,
                cost
            ),
            #[cfg(any(feature = "alloc", feature = "std"))]
            BcryptError::InvalidPrefix(ref prefix) => write!(f, "Invalid Prefix: {}", prefix),
            #[cfg(any(feature = "alloc", feature = "std"))]
            BcryptError::InvalidHash(ref hash) => write!(f, "Invalid hash: {}", hash),
            BcryptError::InvalidBase64(ref err) => write!(f, "Base64 error: {}", err),
            BcryptError::InvalidSaltLen(len) => {
                write!(f, "Invalid salt len: expected 16, received {}", len)
            }
            #[cfg(any(feature = "alloc", feature = "std"))]
            BcryptError::Rand(ref err) => write!(f, "Rand error: {}", err),
            BcryptError::Truncation(len) => {
                write!(f, "Expected 72 bytes or fewer; found {len} bytes")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for BcryptError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            BcryptError::InvalidCost(_)
            | BcryptError::CostNotAllowed(_)
            | BcryptError::InvalidPrefix(_)
            | BcryptError::InvalidHash(_)
            | BcryptError::InvalidSaltLen(_)
            | BcryptError::Truncation(_) => None,
            BcryptError::InvalidBase64(ref err) => Some(err),
            BcryptError::Rand(ref err) => Some(err),
        }
    }
}
