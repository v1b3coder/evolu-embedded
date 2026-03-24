//! Host interface for the host-storage backend.
//!
//! The host stores:
//! - **Timestamp index**: one sequential blob, streamed in chunks
//! - **Data cache**: key-value store (timestamp → EncryptedDbChange blob)
//!   Data is already AEAD-encrypted by the protocol, so no additional
//!   encryption is needed for the cache.

/// Host interface for index and data cache operations.
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

    // ── Data cache (raw EncryptedDbChange blobs) ────────────────

    /// Store a data blob keyed by timestamp.
    /// The blob is an EncryptedDbChange — already AEAD-authenticated
    /// by the protocol layer. No additional encryption needed.
    fn cache_store(&mut self, key: &[u8; 16], data: &[u8]) -> Result<(), Self::Error>;

    /// Read a cached data blob by timestamp key into the buffer.
    /// Returns the number of bytes read, or 0 if not cached.
    fn cache_read(&mut self, key: &[u8; 16], buf: &mut [u8]) -> Result<usize, Self::Error>;

    // ── Utilities ───────────────────────────────────────────────

    /// Current time in milliseconds since Unix epoch.
    fn now_millis(&self) -> u64;

    /// Fill buffer with cryptographically secure random bytes.
    fn fill_random(&mut self, buf: &mut [u8]);
}
