//! Platform trait — clock and randomness.
//!
//! Abstracted because these are hardware-dependent:
//! - std: `SystemTime::now()` + `getrandom`
//! - STM32U5: RTC + hardware TRNG
//! - Host-provided: USB command for time, hardware RNG for random

/// Platform services needed by the Evolu protocol.
///
/// Implementations:
/// - `StdPlatform` (std) — system clock + getrandom
/// - STM32U5 — RTC + TRNG peripheral
/// - Host-delegated — time from USB, random from hardware
pub trait Platform {
    /// Current time in milliseconds since Unix epoch.
    fn now_millis(&self) -> u64;

    /// Fill buffer with cryptographically secure random bytes.
    fn fill_random(&mut self, buf: &mut [u8]);
}
