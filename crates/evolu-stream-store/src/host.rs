//! Host store — encrypted index + blob cache.
//!
//! The host stores two things for the device:
//!
//! - **Encrypted index**: a single sequential blob, streamed in chunks.
//!   Device-managed, device-encrypted. The host can't read or tamper with it.
//!
//! - **Blob cache**: opaque `EncryptedDbChange` blobs keyed by timestamp.
//!   Already encrypted by the Evolu protocol — the host just stores bytes.
//!   Populated during sync (blobs arrive via transport), read by the
//!   application when it needs to materialize data.

/// Host store interface (encrypted index + blob cache).
///
/// No clock or randomness — those are in `evolu_core::platform::Platform`.
pub trait HostStore {
    type Error: core::fmt::Debug;

    // ── Encrypted index (streaming, device-managed) ──────────

    /// Total size of the stored index blob in bytes. 0 if no index.
    fn index_size(&mut self) -> Result<u64, Self::Error>;

    /// Read a chunk of the index at the given byte offset.
    fn index_read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize, Self::Error>;

    /// Begin writing a new index (atomic replace).
    ///
    /// The old index must remain readable via `index_read_at` until
    /// `index_write_commit` is called. This enables streaming merge:
    /// reading from the old index while writing the new one.
    fn index_write_begin(&mut self) -> Result<(), Self::Error>;

    /// Append a chunk to the index being written.
    fn index_write_append(&mut self, data: &[u8]) -> Result<(), Self::Error>;

    /// Commit the new index, atomically replacing the old one.
    fn index_write_commit(&mut self) -> Result<(), Self::Error>;

    // ── Blob cache (opaque EncryptedDbChange, key-value) ─────

    /// Store an EncryptedDbChange blob keyed by timestamp.
    fn put_blob(&mut self, ts: &[u8; 16], data: &[u8]) -> Result<(), Self::Error>;

    /// Retrieve an EncryptedDbChange blob by timestamp.
    /// Returns the number of bytes read, or 0 if not available.
    fn get_blob(&mut self, ts: &[u8; 16], buf: &mut [u8]) -> Result<usize, Self::Error>;
}
