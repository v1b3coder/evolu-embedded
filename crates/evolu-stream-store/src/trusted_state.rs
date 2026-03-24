//! On-chip trusted state — the minimal data that must be stored on the
//! device's internal flash (never on the untrusted host).
//!
//! ## What's stored (64 bytes)
//!
//! - `device_key` (32B): XChaCha20-Poly1305 encryption key. Never leaves the chip.
//! - `dir_sequence` (8B): The sequence number used when the directory page was
//!   last written. On boot, the device reads the directory and checks that the
//!   embedded sequence matches this value. If it doesn't, the host replayed an
//!   older snapshot.
//! - `clock` (16B): HLC timestamp state. Must not be rollback-able.
//! - `initialized` (8B): Magic value indicating valid state.
//!
//! Total: 64 bytes.
//!
//! ## Why this is sufficient
//!
//! Each page is encrypted with AEAD where AAD = (page_id, sequence). This means:
//! - The host can't tamper with any page (AEAD authentication fails)
//! - The host can't swap pages (page_id in AAD)
//! - The host can't replay an old directory (dir_sequence check)
//! - Data pages are referenced by the directory — if the directory is authentic
//!   and the data pages decrypt correctly, the entire dataset is consistent
//!
//! The directory is always written last after any mutation. Its sequence is
//! always the highest. So checking only the directory sequence is enough.

/// Magic value indicating the trusted state file is valid.
const MAGIC: u64 = 0x45564F4C555F5453; // "EVOLU_TS"

/// Total serialized size.
pub const TRUSTED_STATE_SIZE: usize = 64;

/// On-chip trusted state (64 bytes).
#[derive(Clone)]
pub struct TrustedState {
    /// Encryption key for all pages. Generated once, never leaves the device.
    pub device_key: [u8; 32],
    /// Sequence number of the last directory page write.
    /// On boot, the device verifies the directory's embedded sequence matches.
    pub dir_sequence: u64,
    /// HLC clock state (16 bytes = TimestampBytes).
    pub clock: [u8; 16],
}

impl TrustedState {
    /// Create a new trusted state with a fresh device key.
    pub fn new(device_key: [u8; 32]) -> Self {
        TrustedState {
            device_key,
            dir_sequence: 0,
            clock: [0u8; 16],
        }
    }

    /// Serialize to 64 bytes.
    pub fn serialize(&self) -> [u8; TRUSTED_STATE_SIZE] {
        let mut buf = [0u8; TRUSTED_STATE_SIZE];
        buf[0..8].copy_from_slice(&MAGIC.to_le_bytes());
        buf[8..40].copy_from_slice(&self.device_key);
        buf[40..48].copy_from_slice(&self.dir_sequence.to_le_bytes());
        buf[48..64].copy_from_slice(&self.clock);
        buf
    }

    /// Deserialize from 64 bytes. Returns None if magic doesn't match.
    pub fn deserialize(data: &[u8]) -> Option<Self> {
        if data.len() < TRUSTED_STATE_SIZE {
            return None;
        }
        let magic = u64::from_le_bytes(data[0..8].try_into().ok()?);
        if magic != MAGIC {
            return None;
        }
        let mut device_key = [0u8; 32];
        device_key.copy_from_slice(&data[8..40]);
        let dir_sequence = u64::from_le_bytes(data[40..48].try_into().ok()?);
        let mut clock = [0u8; 16];
        clock.copy_from_slice(&data[48..64]);

        Some(TrustedState {
            device_key,
            dir_sequence,
            clock,
        })
    }
}

/// File-based trusted state persistence (for demo/std environments).
#[cfg(feature = "std")]
pub mod file {
    use super::*;
    use std::path::Path;

    /// Load trusted state from a file.
    pub fn load(path: &Path) -> Option<TrustedState> {
        let data = std::fs::read(path).ok()?;
        TrustedState::deserialize(&data)
    }

    /// Save trusted state to a file (atomic: tmp + rename).
    pub fn save(path: &Path, state: &TrustedState) -> std::io::Result<()> {
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &state.serialize())?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let mut state = TrustedState::new([0x42; 32]);
        state.dir_sequence = 99;
        state.clock = [1u8; 16];
        let bytes = state.serialize();
        let restored = TrustedState::deserialize(&bytes).unwrap();
        assert_eq!(restored.device_key, state.device_key);
        assert_eq!(restored.dir_sequence, 99);
        assert_eq!(restored.clock, [1u8; 16]);
    }

    #[test]
    fn invalid_magic_rejected() {
        let mut bytes = [0u8; TRUSTED_STATE_SIZE];
        bytes[0..8].copy_from_slice(&0u64.to_le_bytes());
        assert!(TrustedState::deserialize(&bytes).is_none());
    }

    #[test]
    fn too_short_rejected() {
        assert!(TrustedState::deserialize(&[0u8; 10]).is_none());
    }
}
