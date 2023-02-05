#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SocketV4 {
    pub address: u32,
    pub port: u16,
    padding: u16,
}

impl SocketV4 {
    #[inline(always)]
    pub fn new(address: u32, port: u16) -> Self {
        SocketV4 {
            address,
            port,
            padding: 0,
        }
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SocketV4 {}
