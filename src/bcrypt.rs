use blowfish::Blowfish;
#[cfg(feature = "kdf")]
use kdf::{Kdf, Pbkdf};

#[cfg(any(feature = "kdf", feature = "password-hash"))]
use crate::BcryptError;

fn setup(cost: u32, salt: &[u8], key: &[u8]) -> Blowfish {
    assert!(cost < 32);
    let mut state = Blowfish::bc_init_state();

    state.salted_expand_key(salt, key);
    for _ in 0..1u32 << cost {
        state.bc_expand_key(key);
        state.bc_expand_key(salt);
    }

    state
}

pub fn bcrypt(cost: u32, salt: [u8; 16], password: &[u8]) -> [u8; 24] {
    assert!(!password.is_empty() && password.len() <= 72);

    let mut output = [0; 24];

    let state = setup(cost, &salt, password);
    // OrpheanBeholderScryDoubt
    #[allow(clippy::unreadable_literal)]
    let mut ctext = [
        0x4f727068, 0x65616e42, 0x65686f6c, 0x64657253, 0x63727944, 0x6f756274,
    ];
    for i in 0..3 {
        let i: usize = i * 2;
        for _ in 0..64 {
            let [l, r] = state.bc_encrypt([ctext[i], ctext[i + 1]]);
            ctext[i] = l;
            ctext[i + 1] = r;
        }

        let buf = ctext[i].to_be_bytes();
        output[i * 4..][..4].copy_from_slice(&buf);
        let buf = ctext[i + 1].to_be_bytes();
        output[(i + 1) * 4..][..4].copy_from_slice(&buf);
    }

    output
}

#[cfg(any(feature = "kdf", feature = "password-hash"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// bcrypt context.
pub struct Bcrypt {
    pub(crate) cost: u32,
}

#[cfg(any(feature = "kdf", feature = "password-hash"))]
impl Bcrypt {
    /// Creates a new [`Bcrypt`] with the given `cost`.
    pub const fn new(cost: u32) -> Result<Self, BcryptError> {
        match cost {
            cost @ 4..=31 => Ok(Self { cost }),
            cost => Err(BcryptError::CostNotAllowed(cost)),
        }
    }
}

#[cfg(any(feature = "kdf", feature = "password-hash"))]
impl Default for Bcrypt {
    fn default() -> Self {
        Self {
            cost: crate::DEFAULT_COST,
        }
    }
}

#[cfg(feature = "kdf")]
impl Kdf for Bcrypt {
    fn derive_key(&self, password: &[u8], salt: &[u8], out: &mut [u8]) -> kdf::Result<()> {
        let salt = salt.try_into().map_err(|_| kdf::Error)?;
        let hash = bcrypt(self.cost, salt, password);
        out.copy_from_slice(&hash);
        Ok(())
    }
}

#[cfg(feature = "kdf")]
impl Pbkdf for Bcrypt {}

#[cfg(test)]
mod tests {
    use super::bcrypt;
    #[cfg(feature = "kdf")]
    use super::{Bcrypt, Kdf};

    #[test]
    fn raw_bcrypt() {
        // test vectors unbase64ed from
        // https://github.com/djmdjm/jBCrypt/blob/master/test/org/mindrot/jbcrypt/TestBCrypt.java

        // $2a$06$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s.
        let pw = b"\0";
        let cost = 6;
        let salt = [
            0x14, 0x4b, 0x3d, 0x69, 0x1a, 0x7b, 0x4e, 0xcf, 0x39, 0xcf, 0x73, 0x5c, 0x7f, 0xa7,
            0xa7, 0x9c,
        ];
        let result = [
            0x55, 0x7e, 0x94, 0xf3, 0x4b, 0xf2, 0x86, 0xe8, 0x71, 0x9a, 0x26, 0xbe, 0x94, 0xac,
            0x1e, 0x16, 0xd9, 0x5e, 0xf9, 0xf8, 0x19, 0xde, 0xe0,
        ];
        assert_eq!(bcrypt(cost, salt, pw)[..23], result);

        // $2a$06$m0CrhHm10qJ3lXRY.5zDGO3rS2KdeeWLuGmsfGlMfOxih58VYVfxe
        let pw = b"a\0";
        let cost = 6;
        let salt = [
            0xa3, 0x61, 0x2d, 0x8c, 0x9a, 0x37, 0xda, 0xc2, 0xf9, 0x9d, 0x94, 0xda, 0x3, 0xbd,
            0x45, 0x21,
        ];
        let result = [
            0xe6, 0xd5, 0x38, 0x31, 0xf8, 0x20, 0x60, 0xdc, 0x8, 0xa2, 0xe8, 0x48, 0x9c, 0xe8,
            0x50, 0xce, 0x48, 0xfb, 0xf9, 0x76, 0x97, 0x87, 0x38,
        ];
        assert_eq!(bcrypt(cost, salt, pw)[..23], result);

        // // $2a$08$aTsUwsyowQuzRrDqFflhgekJ8d9/7Z3GV3UcgvzQW3J5zMyrTvlz.
        let pw = b"abcdefghijklmnopqrstuvwxyz\0";
        let cost = 8;
        let salt = [
            0x71, 0x5b, 0x96, 0xca, 0xed, 0x2a, 0xc9, 0x2c, 0x35, 0x4e, 0xd1, 0x6c, 0x1e, 0x19,
            0xe3, 0x8a,
        ];
        let result = [
            0x98, 0xbf, 0x9f, 0xfc, 0x1f, 0x5b, 0xe4, 0x85, 0xf9, 0x59, 0xe8, 0xb1, 0xd5, 0x26,
            0x39, 0x2f, 0xbd, 0x4e, 0xd2, 0xd5, 0x71, 0x9f, 0x50,
        ];
        assert_eq!(bcrypt(cost, salt, pw)[..23], result);
    }

    #[cfg(feature = "kdf")]
    #[test]
    fn derive_key() {
        // test vectors unbase64ed from
        // https://github.com/djmdjm/jBCrypt/blob/master/test/org/mindrot/jbcrypt/TestBCrypt.java

        // $2a$06$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s.
        let pw = b"\0";
        let cost = 6;
        let salt = [
            0x14, 0x4b, 0x3d, 0x69, 0x1a, 0x7b, 0x4e, 0xcf, 0x39, 0xcf, 0x73, 0x5c, 0x7f, 0xa7,
            0xa7, 0x9c,
        ];
        let result = [
            0x55, 0x7e, 0x94, 0xf3, 0x4b, 0xf2, 0x86, 0xe8, 0x71, 0x9a, 0x26, 0xbe, 0x94, 0xac,
            0x1e, 0x16, 0xd9, 0x5e, 0xf9, 0xf8, 0x19, 0xde, 0xe0,
        ];
        let bcrypt = Bcrypt::new(cost).unwrap();
        let mut output = [0_u8; 24];
        bcrypt.derive_key(pw, &salt, &mut output).unwrap();
        assert_eq!(output[..23], result);

        // $2a$06$m0CrhHm10qJ3lXRY.5zDGO3rS2KdeeWLuGmsfGlMfOxih58VYVfxe
        let pw = b"a\0";
        let cost = 6;
        let salt = [
            0xa3, 0x61, 0x2d, 0x8c, 0x9a, 0x37, 0xda, 0xc2, 0xf9, 0x9d, 0x94, 0xda, 0x3, 0xbd,
            0x45, 0x21,
        ];
        let result = [
            0xe6, 0xd5, 0x38, 0x31, 0xf8, 0x20, 0x60, 0xdc, 0x8, 0xa2, 0xe8, 0x48, 0x9c, 0xe8,
            0x50, 0xce, 0x48, 0xfb, 0xf9, 0x76, 0x97, 0x87, 0x38,
        ];
        let bcrypt = Bcrypt::new(cost).unwrap();
        let mut output = [0_u8; 24];
        bcrypt.derive_key(pw, &salt, &mut output).unwrap();
        assert_eq!(output[..23], result);

        // // $2a$08$aTsUwsyowQuzRrDqFflhgekJ8d9/7Z3GV3UcgvzQW3J5zMyrTvlz.
        let pw = b"abcdefghijklmnopqrstuvwxyz\0";
        let cost = 8;
        let salt = [
            0x71, 0x5b, 0x96, 0xca, 0xed, 0x2a, 0xc9, 0x2c, 0x35, 0x4e, 0xd1, 0x6c, 0x1e, 0x19,
            0xe3, 0x8a,
        ];
        let result = [
            0x98, 0xbf, 0x9f, 0xfc, 0x1f, 0x5b, 0xe4, 0x85, 0xf9, 0x59, 0xe8, 0xb1, 0xd5, 0x26,
            0x39, 0x2f, 0xbd, 0x4e, 0xd2, 0xd5, 0x71, 0x9f, 0x50,
        ];
        let bcrypt = Bcrypt::new(cost).unwrap();
        let mut output = [0_u8; 24];
        bcrypt.derive_key(pw, &salt, &mut output).unwrap();
        assert_eq!(output[..23], result);
    }
}
