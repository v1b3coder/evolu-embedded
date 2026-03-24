#![cfg_attr(not(feature = "std"), no_std)]

//! Host-storage backend: streaming encrypted index on USB host,
//! data cached on host as raw EncryptedDbChange blobs.

pub mod host;
pub mod index;
pub mod storage;
pub mod trusted_state;

#[cfg(feature = "std")]
pub mod file_host;

/// std Platform implementation (system clock + getrandom).
#[cfg(feature = "std")]
pub mod std_platform {
    use evolu_core::platform::Platform;
    use std::time::{SystemTime, UNIX_EPOCH};

    pub struct StdPlatform;

    impl Platform for StdPlatform {
        fn now_millis(&self) -> u64 {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64
        }

        fn fill_random(&mut self, buf: &mut [u8]) {
            getrandom::getrandom(buf).expect("getrandom failed");
        }
    }
}
