//! Storage backend trait for the Evolu sync protocol.
//!
//! Two implementations:
//!
//! - **Host storage** (`evolu-host-storage`): Streaming encrypted index on
//!   USB host. Data cached on host as raw EncryptedDbChange blobs. Suitable
//!   for embedded devices with minimal RAM.
//!
//! - **Flash storage** (`evolu-flash-storage`): Everything on local flash.
//!   No encryption, no streaming. Direct memory access. Suitable for devices
//!   with enough flash to hold the dataset.
//!
//! The sync engine, relay client, and application code are generic over this trait.

use crate::types::*;

/// Storage backend for the Evolu sync protocol.
///
/// Provides the operations needed by the RBSR sync engine:
/// - Timestamp enumeration and fingerprint computation
/// - Data storage and retrieval (opaque EncryptedDbChange blobs)
///
/// Implementations handle persistence, encryption, and indexing internally.
pub trait StorageBackend {
    type Error: core::fmt::Debug;

    /// Total number of timestamps in storage.
    fn size(&mut self) -> Result<u32, Self::Error>;

    /// XOR fingerprint for timestamp index range [begin, end).
    ///
    /// The fingerprint is the XOR of `SHA-256(timestamp)[0..12]` for each
    /// timestamp in the range. Used by RBSR to efficiently detect which
    /// ranges differ between client and relay.
    ///
    /// Returns `ZERO_FINGERPRINT` for empty ranges.
    fn fingerprint(&mut self, begin: u32, end: u32) -> Result<Fingerprint, Self::Error>;

    /// Iterate timestamps in sorted order over index range [begin, end).
    ///
    /// Callback receives `(timestamp_bytes, index)`. Return `false` to stop early.
    ///
    /// This is the hot path — called on every sync round. Implementations should
    /// be efficient even for large datasets.
    fn iterate(
        &mut self,
        begin: u32,
        end: u32,
        cb: &mut dyn FnMut(&TimestampBytes, u32) -> bool,
    ) -> Result<(), Self::Error>;

    /// Store a new CRDT entry: timestamp + opaque data payload.
    ///
    /// The payload is typically an `EncryptedDbChange` — either produced locally
    /// or received from a relay. The backend stores it opaquely.
    ///
    /// Idempotent — inserting a duplicate timestamp is a no-op.
    fn insert(&mut self, ts: &TimestampBytes, data: &[u8]) -> Result<(), Self::Error>;

    /// Batch insert multiple entries.
    ///
    /// Implementations that rewrite an index on every insert (e.g. streaming
    /// encrypted index) override this to do a single merge-write for the
    /// whole batch. The default loops `insert()`.
    fn insert_batch(
        &mut self,
        entries: &[(&TimestampBytes, &[u8])],
    ) -> Result<(), Self::Error> {
        for &(ts, data) in entries {
            self.insert(ts, data)?;
        }
        Ok(())
    }

    /// Read the data payload associated with a timestamp.
    ///
    /// Returns:
    /// - `Ok(Some(bytes))` — data available
    /// - `Ok(None)` — timestamp exists but data not available locally
    ///   (e.g., host cache miss)
    /// - `Err(...)` — storage error
    ///
    /// The returned slice borrows from an internal buffer and is valid
    /// until the next mutable call on this backend.
    fn read(&mut self, ts: &TimestampBytes) -> Result<Option<&[u8]>, Self::Error>;
}
