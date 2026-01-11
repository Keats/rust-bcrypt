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
    InvalidHash(&'static str),
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

#[cfg(any(feature = "alloc", feature = "std"))]
impl_from_error!(getrandom::Error, BcryptError::Rand);

impl fmt::Display for BcryptError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            BcryptError::CostNotAllowed(ref cost) => write!(
                f,
                "Cost needs to be between {} and {}, got {}",
                crate::MIN_COST,
                crate::MAX_COST,
                cost
            ),
            #[cfg(any(feature = "alloc", feature = "std"))]
            BcryptError::InvalidHash(ref reason) => write!(f, "Invalid hash: {}", reason),
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
            BcryptError::CostNotAllowed(_)
            | BcryptError::InvalidHash(_)
            | BcryptError::Truncation(_) => None,
            BcryptError::Rand(ref err) => Some(err),
        }
    }
}
