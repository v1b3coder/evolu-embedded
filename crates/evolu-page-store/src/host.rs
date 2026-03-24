//! Host interface — pure storage operations.
//!
//! The host stores:
//! - **Timestamp index**: one sequential blob, streamed in chunks
//! - **Data cache**: key-value store (timestamp → EncryptedDbChange blob)

/// Host storage interface (index + data cache).
///
/// No clock or randomness — those are in `evolu_core::platform::Platform`.
pub trait HostInterface {
    type Error: core::fmt::Debug;

    // ── Timestamp index (streaming, encrypted) ──────────────────

    /// Total size of the stored index blob in bytes. 0 if no index.
    fn index_size(&mut self) -> Result<u64, Self::Error>;

    /// Read a chunk of the index at the given byte offset.
    fn index_read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize, Self::Error>;

    /// Begin writing a new index (atomic replace).
    fn index_write_begin(&mut self) -> Result<(), Self::Error>;

    /// Append a chunk to the index being written.
    fn index_write_append(&mut self, data: &[u8]) -> Result<(), Self::Error>;

    /// Commit the new index, atomically replacing the old one.
    fn index_write_commit(&mut self) -> Result<(), Self::Error>;

    // ── Data cache ──────────────────────────────────────────────

    /// Store a data blob keyed by timestamp.
    fn cache_store(&mut self, key: &[u8; 16], data: &[u8]) -> Result<(), Self::Error>;

    /// Read a cached data blob by timestamp key into the buffer.
    /// Returns the number of bytes read, or 0 if not cached.
    fn cache_read(&mut self, key: &[u8; 16], buf: &mut [u8]) -> Result<usize, Self::Error>;
}
