//! Stream-storage backend: streaming encrypted index + blob cache on host.
//!
//! Implements `StorageBackend` from `evolu-core`.

use crate::host::HostStore;
use crate::index::{self, IndexEntry, IndexError};
use crate::trusted_state::TrustedState;
use evolu_core::crypto::timestamp_to_fingerprint;
use evolu_core::platform::Platform;
use evolu_core::storage::StorageBackend;
use evolu_core::types::*;

/// Maximum blob size for reads.
const BLOB_BUF_SIZE: usize = 4096;

#[derive(Clone, Debug, PartialEq)]
pub enum StreamStorageError {
    Host,
    Index(IndexError),
}

impl From<IndexError> for StreamStorageError {
    fn from(e: IndexError) -> Self {
        StreamStorageError::Index(e)
    }
}

/// Stream-storage backend.
///
/// Uses a `HostStore` for persistent storage:
/// - Encrypted timestamp index: streamed in chunks, device-managed
/// - Blob cache: opaque EncryptedDbChange blobs, populated during sync
///
/// After any mutation, persist `trusted_state()` to on-chip flash.
pub struct StreamStorage<H: HostStore, P: Platform> {
    host: H,
    platform: P,
    trusted: TrustedState,
    blob_buf: [u8; BLOB_BUF_SIZE],
    blob_len: usize,
}

impl<H: HostStore, P: Platform> StreamStorage<H, P> {
    pub fn new(host: H, platform: P, trusted: TrustedState) -> Self {
        StreamStorage {
            host,
            platform,
            trusted,
            blob_buf: [0u8; BLOB_BUF_SIZE],
            blob_len: 0,
        }
    }

    pub fn host(&self) -> &H {
        &self.host
    }

    pub fn host_mut(&mut self) -> &mut H {
        &mut self.host
    }

    /// Get trusted state. **Persist to on-chip flash after every mutation.**
    pub fn trusted_state(&self) -> &TrustedState {
        &self.trusted
    }

    /// Boot-time validation and crash recovery.
    ///
    /// If the index was committed but `TrustedState` was not persisted
    /// (power loss between index commit and flash write), this detects the
    /// off-by-one sequence and recovers automatically.
    ///
    /// Call this after constructing `StreamStorage` and before any reads/writes.
    /// **Persist `trusted_state()` to flash after this returns `Ok`.**
    pub fn validate_and_recover(&mut self) -> Result<(), StreamStorageError> {
        index::validate_and_recover(&mut self.host, &mut self.trusted)?;
        Ok(())
    }
}

impl<H: HostStore, P: Platform> StorageBackend for StreamStorage<H, P> {
    type Error = StreamStorageError;

    fn size(&mut self) -> Result<u32, Self::Error> {
        let header = index::read_index_header(&mut self.host)?;
        match header {
            None => Ok(0),
            Some((sequence, _, count)) => {
                if self.trusted.dir_sequence != 0 && sequence != self.trusted.dir_sequence {
                    return Err(IndexError::TamperDetected.into());
                }
                Ok(count)
            }
        }
    }

    fn fingerprint(&mut self, begin: u32, end: u32) -> Result<Fingerprint, Self::Error> {
        if begin >= end {
            return Ok(ZERO_FINGERPRINT);
        }
        let mut fp = ZERO_FINGERPRINT;
        index::read_index(&mut self.host, &self.trusted, |entry, idx| {
            if idx >= begin && idx < end {
                fp = fingerprint_xor(&fp, &entry.fingerprint);
            }
            idx < end
        })?;
        Ok(fp)
    }

    fn iterate(
        &mut self,
        begin: u32,
        end: u32,
        cb: &mut dyn FnMut(&TimestampBytes, u32) -> bool,
    ) -> Result<(), Self::Error> {
        if begin >= end {
            return Ok(());
        }
        index::read_index(&mut self.host, &self.trusted, |entry, idx| {
            if idx >= end {
                return false;
            }
            if idx >= begin {
                return cb(&entry.timestamp, idx);
            }
            true
        })?;
        Ok(())
    }

    fn insert(&mut self, ts: &TimestampBytes, data: &[u8]) -> Result<(), Self::Error> {
        self.insert_batch(&[(ts, data)])
    }

    fn insert_batch(
        &mut self,
        entries: &[(&TimestampBytes, &[u8])],
    ) -> Result<(), Self::Error> {
        if entries.is_empty() {
            return Ok(());
        }

        // Build sorted, deduplicated IndexEntry batch
        let mut new_entries: heapless::Vec<IndexEntry, 256> = heapless::Vec::new();
        for &(ts, _) in entries {
            let entry = IndexEntry {
                timestamp: *ts,
                fingerprint: timestamp_to_fingerprint(ts),
                page_id: 0,
            };
            new_entries.push(entry).map_err(|_| StreamStorageError::Index(IndexError::BatchFull))?;
        }
        // Sort by timestamp
        new_entries.sort_unstable_by(|a, b| a.timestamp.cmp(&b.timestamp));
        // Dedup (heapless::Vec lacks dedup_by)
        if new_entries.len() > 1 {
            let mut write = 0;
            for read in 1..new_entries.len() {
                if new_entries[read].timestamp != new_entries[write].timestamp {
                    write += 1;
                    new_entries[write] = new_entries[read];
                }
            }
            new_entries.truncate(write + 1);
        }

        // Store blobs on host (each is individually atomic)
        for &(ts, data) in entries {
            if !data.is_empty() {
                self.host.put_blob(ts, data).map_err(|_| StreamStorageError::Host)?;
            }
        }

        // Pre-scan to count duplicates and compute total
        let old_count = match index::read_index_header(&mut self.host)? {
            Some((_, _, count)) => count,
            None => 0,
        };
        let dup_count = index::pre_scan_duplicates(
            &mut self.host,
            &self.trusted,
            &new_entries,
        )?;
        let new_unique = new_entries.len() as u32 - dup_count;
        if new_unique == 0 {
            return Ok(()); // all duplicates
        }
        let total = old_count + new_unique;

        // Streaming merge-write
        index::streaming_merge_write(
            &mut self.host,
            &mut self.platform,
            &mut self.trusted,
            &new_entries,
            total,
        )?;

        Ok(())
    }

    fn read(&mut self, ts: &TimestampBytes) -> Result<Option<&[u8]>, Self::Error> {
        let n = self.host.get_blob(ts, &mut self.blob_buf).map_err(|_| StreamStorageError::Host)?;
        if n == 0 {
            return Ok(None);
        }
        self.blob_len = n;
        Ok(Some(&self.blob_buf[..self.blob_len]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file_host::FileHost;
    use evolu_core::timestamp::timestamp_to_bytes;

    fn make_ts(millis: u64) -> TimestampBytes {
        timestamp_to_bytes(&Timestamp::new(
            Millis::new(millis).unwrap(),
            Counter::new(0),
            NodeId::MIN,
        ))
    }

    use evolu_std_platform::StdPlatform;

    fn create_storage() -> StreamStorage<FileHost, StdPlatform> {
        let dir = tempfile::tempdir().unwrap();
        let host = FileHost::new(dir.into_path()).unwrap();
        let trusted = TrustedState::new([0x42; 32]);
        StreamStorage::new(host, StdPlatform, trusted)
    }

    #[test]
    fn empty() {
        let mut s = create_storage();
        assert_eq!(s.size().unwrap(), 0);
    }

    #[test]
    fn insert_and_count() {
        let mut s = create_storage();
        s.insert(&make_ts(100), b"data A").unwrap();
        s.insert(&make_ts(200), b"data B").unwrap();
        s.insert(&make_ts(50), b"data C").unwrap();
        assert_eq!(s.size().unwrap(), 3);
    }

    #[test]
    fn idempotent() {
        let mut s = create_storage();
        s.insert(&make_ts(100), b"data").unwrap();
        s.insert(&make_ts(100), b"data").unwrap();
        assert_eq!(s.size().unwrap(), 1);
    }

    #[test]
    fn sorted_order() {
        let mut s = create_storage();
        s.insert(&make_ts(300), b"c").unwrap();
        s.insert(&make_ts(100), b"a").unwrap();
        s.insert(&make_ts(200), b"b").unwrap();

        let mut ts_list = Vec::new();
        s.iterate(0, 3, &mut |ts, _| { ts_list.push(*ts); true }).unwrap();
        assert!(ts_list[0] < ts_list[1] && ts_list[1] < ts_list[2]);
    }

    #[test]
    fn read_blob() {
        let mut s = create_storage();
        let ts = make_ts(100);
        s.insert(&ts, b"Hello world!").unwrap();

        let data = s.read(&ts).unwrap().unwrap();
        assert_eq!(data, b"Hello world!");
    }

    #[test]
    fn read_miss() {
        let mut s = create_storage();
        let ts = make_ts(999);
        assert!(s.read(&ts).unwrap().is_none());
    }

    #[test]
    fn iterate_range() {
        let mut s = create_storage();
        for i in 0..10 {
            s.insert(&make_ts(i * 100), &[i as u8]).unwrap();
        }
        let mut idxs = Vec::new();
        s.iterate(3, 7, &mut |_, idx| { idxs.push(idx); true }).unwrap();
        assert_eq!(idxs, vec![3, 4, 5, 6]);
    }

    #[test]
    fn fingerprint_consistency() {
        let mut s = create_storage();
        let ts1 = make_ts(100);
        let ts2 = make_ts(200);
        let ts3 = make_ts(300);
        s.insert(&ts1, b"a").unwrap();
        s.insert(&ts2, b"b").unwrap();
        s.insert(&ts3, b"c").unwrap();

        let fp_all = s.fingerprint(0, 3).unwrap();
        let f1 = timestamp_to_fingerprint(&ts1);
        let f2 = timestamp_to_fingerprint(&ts2);
        let f3 = timestamp_to_fingerprint(&ts3);
        assert_eq!(fp_all, fingerprint_xor(&fingerprint_xor(&f1, &f2), &f3));
    }

    #[test]
    fn fingerprint_partitions() {
        let mut s = create_storage();
        for i in 0..5 { s.insert(&make_ts(i * 100), &[i as u8]).unwrap(); }

        let fp_a = s.fingerprint(0, 2).unwrap();
        let fp_b = s.fingerprint(2, 5).unwrap();
        let fp_all = s.fingerprint(0, 5).unwrap();
        assert_eq!(fingerprint_xor(&fp_a, &fp_b), fp_all);
    }

    #[test]
    fn replay_detection() {
        let mut s = create_storage();
        s.insert(&make_ts(100), b"v1").unwrap();
        let old_idx = std::fs::read(s.host().base_dir().join("index.bin")).unwrap();

        s.insert(&make_ts(200), b"v2").unwrap();

        std::fs::write(s.host().base_dir().join("index.bin"), &old_idx).unwrap();
        assert!(matches!(s.size(), Err(StreamStorageError::Index(IndexError::TamperDetected))));
    }

    #[test]
    fn data_encrypted_on_host() {
        let mut s = create_storage();
        let ts = make_ts(12345678);
        s.insert(&ts, b"secret payload").unwrap();

        let raw = std::fs::read(s.host().base_dir().join("index.bin")).unwrap();
        assert!(!raw.windows(16).any(|w| w == &ts), "timestamp in index plaintext");
    }

    #[test]
    fn many_entries() {
        let mut s = create_storage();
        for i in 0..100 { s.insert(&make_ts(i * 10), &[i as u8]).unwrap(); }
        assert_eq!(s.size().unwrap(), 100);

        let mut prev = [0u8; 16];
        let mut count = 0;
        s.iterate(0, 100, &mut |ts, _| {
            if count > 0 { assert!(ts > &prev); }
            prev = *ts;
            count += 1;
            true
        }).unwrap();
        assert_eq!(count, 100);
    }

    // ── insert_batch tests ──────────────────────────────────────

    #[test]
    fn batch_insert_multiple() {
        let mut s = create_storage();
        let ts1 = make_ts(100);
        let ts2 = make_ts(200);
        let ts3 = make_ts(50);
        s.insert_batch(&[
            (&ts1, b"a" as &[u8]),
            (&ts2, b"b"),
            (&ts3, b"c"),
        ]).unwrap();
        assert_eq!(s.size().unwrap(), 3);

        // Verify sorted order
        let mut ts_list = Vec::new();
        s.iterate(0, 3, &mut |ts, _| { ts_list.push(*ts); true }).unwrap();
        assert!(ts_list[0] < ts_list[1] && ts_list[1] < ts_list[2]);

        // Verify blobs
        assert_eq!(s.read(&ts1).unwrap().unwrap(), b"a");
        assert_eq!(s.read(&ts2).unwrap().unwrap(), b"b");
        assert_eq!(s.read(&ts3).unwrap().unwrap(), b"c");
    }

    #[test]
    fn batch_with_duplicates_in_batch() {
        let mut s = create_storage();
        let ts = make_ts(100);
        s.insert_batch(&[
            (&ts, b"a" as &[u8]),
            (&ts, b"a"),
        ]).unwrap();
        assert_eq!(s.size().unwrap(), 1);
    }

    #[test]
    fn batch_with_existing_duplicates() {
        let mut s = create_storage();
        let ts1 = make_ts(100);
        let ts2 = make_ts(200);
        s.insert(&ts1, b"a").unwrap();

        // Batch with ts1 (dup) and ts2 (new)
        s.insert_batch(&[
            (&ts1, b"a" as &[u8]),
            (&ts2, b"b"),
        ]).unwrap();
        assert_eq!(s.size().unwrap(), 2);
    }

    #[test]
    fn batch_all_duplicates() {
        let mut s = create_storage();
        let ts = make_ts(100);
        s.insert(&ts, b"a").unwrap();

        s.insert_batch(&[(&ts, b"a" as &[u8])]).unwrap();
        assert_eq!(s.size().unwrap(), 1);
    }

    #[test]
    fn batch_empty() {
        let mut s = create_storage();
        s.insert_batch(&[]).unwrap();
        assert_eq!(s.size().unwrap(), 0);
    }

    #[test]
    fn batch_then_single_insert() {
        let mut s = create_storage();
        let ts1 = make_ts(100);
        let ts2 = make_ts(200);
        let ts3 = make_ts(150);
        s.insert_batch(&[
            (&ts1, b"a" as &[u8]),
            (&ts2, b"b"),
        ]).unwrap();
        s.insert(&ts3, b"c").unwrap();
        assert_eq!(s.size().unwrap(), 3);

        // Verify order: 100, 150, 200
        let mut ts_list = Vec::new();
        s.iterate(0, 3, &mut |ts, _| { ts_list.push(*ts); true }).unwrap();
        assert_eq!(ts_list[0], ts1);
        assert_eq!(ts_list[1], ts3);
        assert_eq!(ts_list[2], ts2);
    }

    #[test]
    fn batch_large_crosses_chunks() {
        let mut s = create_storage();
        // 130 entries in one batch — spans 3 chunks (64 + 64 + 2)
        let timestamps: Vec<TimestampBytes> = (0..130).map(|i| make_ts(i * 10)).collect();
        let batch: Vec<(&TimestampBytes, &[u8])> = timestamps
            .iter()
            .map(|ts| (ts, b"x" as &[u8]))
            .collect();
        s.insert_batch(&batch).unwrap();
        assert_eq!(s.size().unwrap(), 130);

        // Verify sorted
        let mut prev = [0u8; 16];
        let mut count = 0;
        s.iterate(0, 130, &mut |ts, _| {
            if count > 0 { assert!(ts > &prev); }
            prev = *ts;
            count += 1;
            true
        }).unwrap();
        assert_eq!(count, 130);
    }

    // ── validate_and_recover tests ──────────────────────────────

    #[test]
    fn validate_and_recover_consistent() {
        let mut s = create_storage();
        s.insert(&make_ts(100), b"a").unwrap();
        assert!(s.validate_and_recover().is_ok());
    }

    #[test]
    fn validate_and_recover_off_by_one() {
        let mut s = create_storage();
        s.insert(&make_ts(100), b"a").unwrap();
        // Simulate crash: roll back dir_sequence
        let seq = s.trusted.dir_sequence;
        s.trusted.dir_sequence = seq - 1;

        assert!(s.validate_and_recover().is_ok());
        assert_eq!(s.trusted.dir_sequence, seq);
    }
}
