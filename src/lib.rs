#![allow(unsafe_code)]
#![deny(clippy::all, clippy::pedantic)]

pub mod crypto;
pub mod ratchet;
pub mod identity;
pub mod store;
pub mod wire;
pub mod session;
pub mod kt;
pub mod envelope;
pub mod ffi;


pub const HL_INFO: &str = "hardlock/v1.1";
pub const HL_VERSION: u16 = 0x0110;

pub mod suites {
    pub const HL1_BASE: u8 = 0x01;
    pub const HL1_AUTH: u8 = 0x02;
    pub const HL1_HYB:  u8 = 0x11;
}
