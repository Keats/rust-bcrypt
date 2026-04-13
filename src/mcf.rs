//! Implementation of the [`password_hash`] traits for Modular Crypt Format
//! (MCF) password hash strings which begin with `$2b$` or any other alternative
//! prefix:
//!
//! <https://man.archlinux.org/man/crypt.5#bcrypt>

pub use mcf::{PasswordHash, PasswordHashRef};
use password_hash::{CustomizedPasswordHasher, Error, PasswordHasher, PasswordVerifier, Result};

use crate::{Bcrypt, Version};

impl CustomizedPasswordHasher<PasswordHash> for Bcrypt {
    type Params = u32;

    fn hash_password_customized(
        &self,
        password: &[u8],
        salt: &[u8],
        alg_id: Option<&str>,
        version: Option<password_hash::Version>,
        cost: Self::Params,
    ) -> Result<PasswordHash> {
        let hash_version = match alg_id {
            Some("2a") => Version::TwoA,
            Some("2b") | None => Version::TwoB,
            Some("2x") => Version::TwoX,
            Some("2y") => Version::TwoY,
            _ => return Err(Error::Algorithm),
        };

        if version.is_some() {
            return Err(Error::Version);
        }

        let salt = salt.try_into().map_err(|_| Error::Internal)?;
        let hash = crate::hash_with_salt(password, cost, salt).map_err(|_| Error::Internal)?;

        let mcf_hash = hash.format_for_version(hash_version);
        let mcf_hash = PasswordHash::new(mcf_hash).unwrap();
        Ok(mcf_hash)
    }
}

impl PasswordHasher<PasswordHash> for Bcrypt {
    fn hash_password_with_salt(&self, password: &[u8], salt: &[u8]) -> Result<PasswordHash> {
        self.hash_password_customized(password, salt, None, None, crate::DEFAULT_COST)
    }
}

impl PasswordVerifier<PasswordHash> for Bcrypt {
    fn verify_password(&self, password: &[u8], hash: &PasswordHash) -> Result<()> {
        self.verify_password(password, hash.as_password_hash_ref())
    }
}

impl PasswordVerifier<PasswordHashRef> for Bcrypt {
    fn verify_password(&self, password: &[u8], hash: &PasswordHashRef) -> Result<()> {
        let is_valid = crate::verify(password, hash.as_str()).map_err(|_| Error::Internal)?;
        if is_valid {
            Ok(())
        } else {
            Err(Error::PasswordInvalid)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Bcrypt, CustomizedPasswordHasher, Error, PasswordHash, PasswordHashRef, PasswordHasher,
        PasswordVerifier,
    };

    #[test]
    fn hash_password() {
        // 2a
        let actual_hash: PasswordHash = Bcrypt
            .hash_password_customized(b"hunter2", &[0; 16], Some("2a"), None, crate::DEFAULT_COST)
            .unwrap();
        let expected_hash =
            PasswordHash::new("$2a$12$......................21jzCB1r6pN6rp5O2Ev0ejjTAboskKm")
                .unwrap();
        assert_eq!(expected_hash, actual_hash);
        // 2b
        let actual_hash: PasswordHash = Bcrypt
            .hash_password_with_salt(b"hunter2", &[0; 16])
            .unwrap();
        let expected_hash =
            PasswordHash::new("$2b$12$......................21jzCB1r6pN6rp5O2Ev0ejjTAboskKm")
                .unwrap();
        assert_eq!(expected_hash, actual_hash);
        // 2x
        let actual_hash: PasswordHash = Bcrypt
            .hash_password_customized(b"hunter2", &[0; 16], Some("2x"), None, crate::DEFAULT_COST)
            .unwrap();
        let expected_hash =
            PasswordHash::new("$2x$12$......................21jzCB1r6pN6rp5O2Ev0ejjTAboskKm")
                .unwrap();
        assert_eq!(expected_hash, actual_hash);
        // 2y
        let actual_hash: PasswordHash = Bcrypt
            .hash_password_customized(b"hunter2", &[0; 16], Some("2y"), None, crate::DEFAULT_COST)
            .unwrap();
        let expected_hash =
            PasswordHash::new("$2y$12$......................21jzCB1r6pN6rp5O2Ev0ejjTAboskKm")
                .unwrap();
        assert_eq!(expected_hash, actual_hash);
    }

    #[test]
    fn verify_password() {
        // `can_verify_hash_generated_from_some_online_tool`
        let hash =
            PasswordHashRef::new("$2a$04$UuTkLRZZ6QofpDOlMz32MuuxEHA43WOemOYHPz6.SjsVsyO1tDU96")
                .unwrap();
        assert_eq!(Bcrypt.verify_password(b"password", hash), Ok(()));
        // `can_verify_hash_generated_from_python`
        let hash =
            PasswordHashRef::new("$2b$04$EGdrhbKUv8Oc9vGiXX0HQOxSg445d458Muh7DAHskb6QbtCvdxcie")
                .unwrap();
        assert_eq!(
            Bcrypt.verify_password(b"correctbatteryhorsestapler", hash),
            Ok(())
        );
        // `can_verify_hash_generated_from_node`
        let hash =
            PasswordHashRef::new("$2a$04$n4Uy0eSnMfvnESYL.bLwuuj0U/ETSsoTpRT9GVk5bektyVVa5xnIi")
                .unwrap();
        assert_eq!(
            Bcrypt.verify_password(b"correctbatteryhorsestapler", hash),
            Ok(())
        );
        // `can_verify_hash_generated_from_go`
        let binary_input = [
            29, 225, 195, 167, 223, 236, 85, 195, 114, 227, 7, 0, 209, 239, 189, 24, 51, 105, 124,
            168, 151, 75, 144, 64, 198, 197, 196, 4, 241, 97, 110, 135,
        ];
        let hash =
            PasswordHashRef::new("$2a$04$tjARW6ZON3PhrAIRW2LG/u9aDw5eFdstYLR8nFCNaOQmsH9XD23w.")
                .unwrap();
        assert_eq!(Bcrypt.verify_password(&binary_input, hash), Ok(()));

        // `invalid_hash_does_not_panic`
        let binary_input = [
            29, 225, 195, 167, 223, 236, 85, 195, 114, 227, 7, 0, 209, 239, 189, 24, 51, 105, 124,
            168, 151, 75, 144, 64, 198, 197, 196, 4, 241, 97, 110, 135,
        ];
        let hash = PasswordHashRef::new("$2a$04$tjARW6ZON3PhrAIRW2LG/u9a.").unwrap();
        assert_eq!(
            Bcrypt.verify_password(&binary_input, hash),
            Err(Error::Internal)
        );
        // `a_wrong_password_is_false`
        let hash =
            PasswordHashRef::new("$2b$04$EGdrhbKUv8Oc9vGiXX0HQOxSg445d458Muh7DAHskb6QbtCvdxcie")
                .unwrap();
        assert_eq!(
            Bcrypt.verify_password(b"wrong", hash),
            Err(Error::PasswordInvalid)
        );
        // `errors_with_invalid_hash`
        let hash =
            PasswordHashRef::new("$2a$04$n4Uy0eSnMfvnESYL.bLwuuj0U/ETSsoTpRT9GVk$5bektyVVa5xnIi")
                .unwrap();
        assert_eq!(
            Bcrypt.verify_password(b"correctbatteryhorsestapler", hash),
            Err(Error::Internal)
        );
        // `errors_with_non_number_cost`
        let hash =
            PasswordHashRef::new("$2a$ab$n4Uy0eSnMfvnESYL.bLwuuj0U/ETSsoTpRT9GVk$5bektyVVa5xnIi")
                .unwrap();
        assert_eq!(
            Bcrypt.verify_password(b"correctbatteryhorsestapler", hash),
            Err(Error::Internal)
        );
        // `errors_with_a_hash_too_long`
        let hash = PasswordHashRef::new(
            "$2a$04$n4Uy0eSnMfvnESYL.bLwuuj0U/ETSsoTpRT9GVk$5bektyVVa5xnIerererereri",
        )
        .unwrap();
        assert_eq!(
            Bcrypt.verify_password(b"correctbatteryhorsestapler", hash),
            Err(Error::Internal)
        );
    }
}
