use std::io;


/// Library generic result type.
pub type BcryptResult<T> = Result<T, BcryptError>;

#[derive(Debug)]
/// All the errors we can encounter while hashing/verifying
/// passwords
pub enum BcryptError {
    Io(io::Error),
    InvalidCost,
    InvalidPrefix
}

macro_rules! impl_from_error {
    ($f: ty, $e: expr) => {
        impl From<$f> for BcryptError {
            fn from(f: $f) -> BcryptError { $e(f) }
        }
    }
}

impl_from_error!(io::Error, BcryptError::Io);
