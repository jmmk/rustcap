extern crate pcap_sys;
extern crate bitflags;
extern crate libc;
#[cfg(windows)]
extern crate winapi;
#[cfg(feature = "libpnet")]
extern crate pnet;

pub mod core;

#[cfg(feature = "libpnet")]
pub mod libpnet;
