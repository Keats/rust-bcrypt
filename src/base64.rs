static B64_CHARS_BCRYPT: &'static str = "
    ./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789
";

/// A trait for converting from base64 encoded values.
trait Base64 {
    /// Converts the value of `self`, interpreted as base64 encoded data, into
    /// an owned vector of bytes, returning the vector.
    fn from_base64(&self) -> Option<Vec<u8>>;
    // fn to_base64(&self) -> String;
}

impl Base64 for [u8] {
    fn from_base64(&self) -> Option<Vec<u8>> {
        let mut r = Vec::with_capacity(self.len());

        for byte in self.iter() {
            println!("{:?}", byte);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Base64};

    #[test]
    fn can_decode() {
        let encoded = "L6Bc/AlTQHyd9liGgGEZyO";
        let decoded = encoded.as_bytes().from_base64();
        assert_eq!(encoded, decoded);
    }
}
