//! std Platform implementation — SystemTime + getrandom.
//!
//! Use this on any std system (Linux, macOS, Windows).

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
