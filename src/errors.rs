use std::error;
use std::fmt;
use std::io;
use rand;

/// Library generic result type.
pub type BcryptResult<T> = Result<T, BcryptError>;

#[derive(Debug)]
/// All the errors we can encounter while hashing/verifying
/// passwords
pub enum BcryptError {
    Io(io::Error),
    CostNotAllowed(u32),
    InvalidPassword,
    InvalidCost(String),
    InvalidPrefix(String),
    InvalidHash(String),
    InvalidBase64(char, String),
    Rand(rand::Error)
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

impl_from_error!(io::Error, BcryptError::Io);
impl_from_error!(rand::Error, BcryptError::Rand);

impl fmt::Display for BcryptError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            BcryptError::Io(ref err) => write!(f, "IO error: {}", err),
            BcryptError::InvalidCost(ref cost) => write!(f, "Invalid Cost: {}", cost),
            BcryptError::CostNotAllowed(ref cost) => {
                write!(f, "Cost needs to be between {} and {}, got {}", ::MIN_COST, ::MAX_COST, cost)
            },
            BcryptError::InvalidPassword => write!(f, "Invalid password: contains NULL byte"),
            BcryptError::InvalidPrefix(ref prefix) => write!(f, "Invalid Prefix: {}", prefix),
            BcryptError::InvalidHash(ref hash) => write!(f, "Invalid hash: {}", hash),
            BcryptError::InvalidBase64(ref c, ref hash) => write!(f, "Invalid base64 char {} in {}", c, hash),
            BcryptError::Rand(ref err) => write!(f, "Rand error: {}", err),
        }
    }
}

impl error::Error for BcryptError {
    fn description(&self) -> &str {
        match *self {
            BcryptError::Io(ref err) => err.description(),
            BcryptError::InvalidCost(_) => "Invalid Cost",
            BcryptError::CostNotAllowed(_) => "Cost not allowed",
            BcryptError::InvalidPassword => "Invalid Password: contains NULL byte",
            BcryptError::InvalidPrefix(_) => "Invalid Prefix",
            BcryptError::InvalidHash(_) => "Invalid hash",
            BcryptError::InvalidBase64(_, _) => "Invalid base64 char",
            BcryptError::Rand(ref err) => err.description(),
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            BcryptError::Io(ref err) => Some(err),
            BcryptError::InvalidCost(_)
            | BcryptError::CostNotAllowed(_)
            | BcryptError::InvalidPassword
            | BcryptError::InvalidPrefix(_)
            | BcryptError::InvalidBase64(_, _)
            | BcryptError::InvalidHash(_) => None,
            BcryptError::Rand(ref err) => Some(err),
        }
    }
}
