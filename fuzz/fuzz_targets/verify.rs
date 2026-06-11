#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: (&[u8], &str)| {
    // Exercise the hash-string parser by feeding both arbitrary
    // password bytes and arbitrary &str inputs to verify().
    // The &str input is what reaches split_hash; this is the
    // surface that #62 (and its regression) lived in.
    let _ = bcrypt::verify(data.0, data.1);
});
