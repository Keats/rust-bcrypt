use alloc::string::String;
use core::fmt;

#[cfg(feature = "std")]
use std::error;
#[cfg(feature = "std")]
use std::io;

/// Library generic result type.
pub type BcryptResult<T> = Result<T, BcryptError>;

#[derive(Debug)]
/// All the errors we can encounter while hashing/verifying
/// passwords
pub enum BcryptError {
    #[cfg(feature = "std")]
    Io(io::Error),
    CostNotAllowed(u32),
    InvalidCost(String),
    InvalidPrefix(String),
    InvalidHash(String),
    InvalidSaltLen(usize),
    InvalidBase64(base64::DecodeError),
    Rand(getrandom::Error),
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
#[cfg(feature = "std")]
impl_from_error!(io::Error, BcryptError::Io);
impl_from_error!(getrandom::Error, BcryptError::Rand);

impl fmt::Display for BcryptError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            #[cfg(feature = "std")]
            BcryptError::Io(ref err) => write!(f, "IO error: {}", err),
            BcryptError::InvalidCost(ref cost) => write!(f, "Invalid Cost: {}", cost),
            BcryptError::CostNotAllowed(ref cost) => write!(
                f,
                "Cost needs to be between {} and {}, got {}",
                crate::MIN_COST,
                crate::MAX_COST,
                cost
            ),
            BcryptError::InvalidPrefix(ref prefix) => write!(f, "Invalid Prefix: {}", prefix),
            BcryptError::InvalidHash(ref hash) => write!(f, "Invalid hash: {}", hash),
            BcryptError::InvalidBase64(ref err) => write!(f, "Base64 error: {}", err),
            BcryptError::InvalidSaltLen(len) => {
                write!(f, "Invalid salt len: expected 16, received {}", len)
            }
            BcryptError::Rand(ref err) => write!(f, "Rand error: {}", err),
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for BcryptError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            BcryptError::Io(ref err) => Some(err),
            BcryptError::InvalidCost(_)
            | BcryptError::CostNotAllowed(_)
            | BcryptError::InvalidPrefix(_)
            | BcryptError::InvalidHash(_)
            | BcryptError::InvalidSaltLen(_) => None,
            BcryptError::InvalidBase64(ref err) => Some(err),
            BcryptError::Rand(ref err) => Some(err),
        }
    }
}
