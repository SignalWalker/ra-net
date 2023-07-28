#![feature(new_uninit)]
#![feature(maybe_uninit_slice)]
#![feature(maybe_uninit_write_slice)]
#![feature(alloc_layout_extra, ptr_metadata)]
#![feature(get_mut_unchecked)]
#![feature(io_error_uncategorized)]
#![feature(const_size_of_val)]
#![feature(const_trait_impl)]
#![feature(const_mut_refs)]
#![feature(const_slice_from_raw_parts_mut)]
#![feature(adt_const_params)]
#![feature(generic_const_exprs)]

// pub mod pkg_stats {
//     include!(concat!(env!("OUT_DIR"), "/built.rs"));
// }

pub mod packet;
pub mod socket;

// const PROTOCOL_ID_SEED: u32 = 0b1001_1001__0110_0110__0110_0110__1001_1001u32;
// pub const PROTOCOL_ID: u32 =
//     xxhash_rust::const_xxh32::xxh32(pkg_stats::PKG_VERSION_MAJOR.as_bytes(), PROTOCOL_ID_SEED);
