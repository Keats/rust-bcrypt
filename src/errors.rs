use std::error;
use std::fmt;
use std::io;

/// Library generic result type.
pub type BcryptResult<T> = Result<T, BcryptError>;

#[derive(Debug)]
/// All the errors we can encounter while hashing/verifying
/// passwords
pub enum BcryptError {
    Io(io::Error),
    InvalidCost(u32),
    InvalidPrefix(String),
}

macro_rules! impl_from_error {
    ($f: ty, $e: expr) => {
        impl From<$f> for BcryptError {
            fn from(f: $f) -> BcryptError { $e(f) }
        }
    }
}

impl_from_error!(io::Error, BcryptError::Io);


impl fmt::Display for BcryptError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            BcryptError::Io(ref err) => write!(f, "IO error: {}", err),
            BcryptError::InvalidCost(ref cost_supplied) => {
                write!(f, "Invalid Cost: {}", cost_supplied)
            }
            BcryptError::InvalidPrefix(ref prefix) => write!(f, "Invalid Prefix: {}", prefix),
        }
    }
}

impl error::Error for BcryptError {
    fn description(&self) -> &str {
        match *self {
            BcryptError::Io(ref err) => err.description(),
            BcryptError::InvalidCost(_) => "Invalid Cost",
            BcryptError::InvalidPrefix(_) => "Invalid Prefix",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            BcryptError::Io(ref err) => Some(err),
            BcryptError::InvalidCost(_) | BcryptError::InvalidPrefix(_) => None,
        }
    }
}
