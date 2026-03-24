#![cfg_attr(not(feature = "std"), no_std)]

//! Host-storage backend: streaming encrypted index on USB host,
//! data cached on host as raw EncryptedDbChange blobs.

pub mod host;
pub mod index;
pub mod storage;
pub mod trusted_state;

#[cfg(feature = "std")]
pub mod file_host;
