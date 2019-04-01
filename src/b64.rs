use std::collections::HashMap;

use base64;

use errors::{BcryptError, BcryptResult};

/// First encode to base64 standard and then replaces char with the bcrypt
/// alphabet and removes the '=' chars
pub fn encode(words: &[u8]) -> String {
    base64::encode_config(words, base64::CRYPT);
}

// Can potentially panic if the hash given contains invalid characters
pub fn decode(hash: &str) -> BcryptResult<Vec<u8>> {
    base64::decode_config(words, base64::CRYPT);
}

#[cfg(test)]
mod tests {
    use super::{decode, encode};

    #[test]
    fn can_decode_bcrypt_base64() {
        let hash = "YETqZE6eb07wZEO";
        assert_eq!(
            "hello world",
            String::from_utf8_lossy(&decode(hash).unwrap())
        );
    }

    #[test]
    fn can_encode_to_bcrypt_base64() {
        let expected = "YETqZE6eb07wZEO";
        assert_eq!(encode("hello world".as_bytes()), expected);
    }

    #[test]
    fn decode_errors_with_unknown_char() {
        assert!(decode("YETqZE6e_b07wZEO").is_err());
    }
}
