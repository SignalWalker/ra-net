#![feature(new_uninit)]
#![feature(maybe_uninit_slice)]
#![feature(maybe_uninit_write_slice)]
#![feature(alloc_layout_extra, ptr_metadata)]
#![feature(get_mut_unchecked)]
#![feature(io_error_uncategorized)]

// pub mod pkg_stats {
//     include!(concat!(env!("OUT_DIR"), "/built.rs"));
// }

mod packet;
pub use packet::*;

mod socket;
pub use socket::*;

const PROTOCOL_ID_SEED: u32 = 0b1001_1001__0110_0110__0110_0110__1001_1001u32;
pub const PROTOCOL_ID: u32 = xxhash_rust::const_xxh32::xxh32(
    concat!(env!("CARGO_PKG_VERSION"), env!("CARGO_PKG_NAME")).as_bytes(),
    PROTOCOL_ID_SEED,
);

pub const MAX_DGRAM_BYTES: usize = 2048;
