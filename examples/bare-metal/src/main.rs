#![no_std]
#![no_main]

use panic_halt as _;
use cortex_m_rt::entry;

#[entry]
fn main() -> ! {
    let salt = [1u8; 16];
    let _crypt = bcrypt::bcrypt(6, salt, b"password");
    loop {}
}
